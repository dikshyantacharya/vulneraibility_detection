"""Parse existing CLI log lines into structured DashboardEvent data.

The build / evaluate / validate / serve commands already emit compact,
pipe-delimited progress lines such as::

    student_challenge.progress | processed=277/1178 | ready=237 | skipped=50 | failed=0 | vuln=118 | safe=119 | eta=37m42s | rate=23.9/min | project=engine | function=foo | sample=18127
    challenge.kg_ready | sample=18127 | project=engine | label=1 | kg=kg_abc
    eval.progress | processed=20/231 | elapsed=1m51s | rate=10.76 samples/min | eta=19m36s
    eval.query.done | sample=42 | kind=evidence_slice | nodes=350 | edges=933 | engine_cache_hit=true | time=0.15
    api.query.done | kg=kg_abc | kind=security_context | nodes=350 | edges=933 | engine_cache_hit=true | time=0.15s

This module turns those lines into ``(event_type, phase, fields)`` so the job
manager can emit rich progress/agent_query events without changing any of the
existing producers.
"""

from __future__ import annotations

import re
from typing import Any

_TAG_RE = re.compile(r"^([a-zA-Z0-9_.]+)\s*\|")
# vckg run.log lines are prefixed with "HH:MM:SS | LEVEL | " — strip it so the
# message tag (if any) is parsed the same way as student-CLI lines.
_LOGPREFIX_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\s*\|\s*[A-Z]+\s*\|\s*")
_KV_RE = re.compile(r"([a-zA-Z0-9_]+)=([^|]+)")
_DURATION_RE = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$")


def _parse_duration_seconds(text: str) -> float | None:
    text = text.strip()
    if not text:
        return None
    m = _DURATION_RE.match(text)
    if not m or not any(m.groups()):
        try:
            return float(text)
        except ValueError:
            return None
    h, mn, s = m.groups()
    total = 0.0
    if h:
        total += int(h) * 3600
    if mn:
        total += int(mn) * 60
    if s:
        total += float(s)
    return total


def _coerce(value: str) -> Any:
    v = value.strip()
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if "/" in v and all(p.strip().isdigit() for p in v.split("/", 1)):
        a, b = v.split("/", 1)
        return {"current": int(a), "total": int(b)}
    try:
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
        return float(v)
    except ValueError:
        return v


# Tag prefixes mapped to a (event_type, phase) hint.
_PHASE_MAP = {
    "student_challenge.progress": ("progress", "kg_build"),
    "challenge.progress": ("progress", "kg_build"),
    "challenge.kg_ready": ("kg_ready", "kg_build"),
    "eval.progress": ("progress", "evaluation"),
    "eval.query.done": ("agent_query", "evaluation"),
    "eval.query.start": ("agent_query", "evaluation"),
    "api.query.done": ("agent_query", "serve"),
    "validate.progress": ("progress", "validation"),
    "package.progress": ("progress", "packaging"),
    # research / vckg run pipeline tags
    "sample.start": ("sample_start", "research"),
    "sample.graph": ("sample_graph", "research"),
    "retrieval.start": ("retrieval", "research"),
    "retrieval.done": ("retrieval", "research"),
    "agent.start": ("agent", "research"),
    "agent.kg_tools": ("kg_query", "research"),
    "model.generate_start": ("llm_prompt", "research"),
    "model.generate_done": ("llm_response", "research"),
    "audit.verdict": ("audit_verdict", "research"),
}


def parse_line(line: str) -> dict[str, Any] | None:
    """Return a normalized dict for a known log line, else ``None``.

    The returned dict has keys: ``type``, ``phase``, ``message``, ``data``.
    Unknown but tagged lines are returned as generic ``log`` events so nothing
    is silently dropped.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None
    stripped = _LOGPREFIX_RE.sub("", line.strip())  # drop vckg "HH:MM:SS | LEVEL | "
    tag_match = _TAG_RE.match(stripped)
    if not tag_match:
        return None
    tag = tag_match.group(1)

    fields: dict[str, Any] = {}
    for key, raw in _KV_RE.findall(line):
        key = key.strip()
        if key in ("eta", "elapsed") or key.endswith("_seconds"):
            secs = _parse_duration_seconds(raw)
            fields[key if key.endswith("_seconds") else f"{key}_seconds"] = secs
        elif key == "rate":
            num = re.search(r"[\d.]+", raw)
            fields["rate_per_minute"] = float(num.group()) if num else None
        elif key == "time":
            fields["time_seconds"] = _parse_duration_seconds(raw.replace("s", ""))
        else:
            fields[key] = _coerce(raw)

    # Flatten processed=current/total
    proc = fields.pop("processed", None)
    if isinstance(proc, dict):
        fields["processed"] = proc.get("current")
        fields["total"] = proc.get("total")
    elif proc is not None:
        fields["processed"] = proc

    etype, phase = _PHASE_MAP.get(tag, ("log", None))
    return {"type": etype, "phase": phase, "tag": tag, "message": line.strip(), "data": fields}
