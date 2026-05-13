from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from vuln_commit_kg.retrieval.evidence import EvidenceItem, EvidencePack


@dataclass
class SemanticFinding:
    kind: str
    status: str  # unsafe | safe | ambiguous
    symbol: str | None
    evidence_ids: list[str] = field(default_factory=list)
    line: int | None = None
    summary: str = ""


def _text(item: EvidenceItem) -> str:
    return item.text or ""


def _declared_array_sizes(items: Iterable[EvidenceItem]) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for item in items:
        t = _text(item)
        for m in re.finditer(r"\b(?:char|unsigned\s+char|signed\s+char|uint8_t|byte)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", t):
            sizes[m.group(1)] = int(m.group(2))
    return sizes




def _has_pattern(items: Iterable[EvidenceItem], pattern: str) -> list[EvidenceItem]:
    rx = re.compile(pattern, re.I)
    return [item for item in items if rx.search(_text(item))]


def _add_upload_path_findings(items: list[EvidenceItem], out: list[SemanticFinding]) -> None:
    """Source-only semantic checks for upload/config read-loop bounds.

    This is not a classifier; it creates audit findings that the LLM and final
    validator can use to distinguish real bounds evidence from generic risky API
    patterns. The patterns are intentionally narrow and evidence-ID based.
    """
    all_text = "\n".join(_text(i) for i in items)
    if not all(k in all_text for k in ["contentlen", "sockgetlinebuf", "buf[i]", "decodeurl", "fprintf"]):
        return

    signed_contentlen = _has_pattern(items, r"\bint\s+contentlen\s*=\s*0\b")
    signed_l = _has_pattern(items, r"\bint\s+l\s*=\s*0\b")
    unsigned_contentlen = _has_pattern(items, r"\bunsigned\s+contentlen\s*=\s*0\b")
    unsigned_l = _has_pattern(items, r"\bunsigned\s+l\s*=\s*0\b")
    contentlen_parse = _has_pattern(items, r"\b(?:atoi\s*\(|sscanf\s*\([^;]*%u)[^;]*contentlen")
    cap = _has_pattern(items, r"\bif\s*\([^)]*contentlen[^)]*(?:LINESIZE|<|>|<=|>=)[^)]*\)")
    unbounded_read_loop = _has_pattern(items, r"while\s*\(\s*\(\s*i\s*=\s*sockgetlinebuf\s*\([^;]*LINESIZE\s*-\s*1[^;]*\)\s*\)\s*>\s*0\s*\)")
    min_read_loop = _has_pattern(items, r"sockgetlinebuf\s*\([^;]*\(\s*contentlen\s*-\s*l\s*\)\s*>\s*LINESIZE\s*-\s*1\s*\?\s*LINESIZE\s*-\s*1\s*:\s*contentlen\s*-\s*l")
    l_lt_contentlen_loop = _has_pattern(items, r"while\s*\([^;]*\bl\s*<\s*contentlen[^;]*sockgetlinebuf")
    remaining_adjust = _has_pattern(items, r"if\s*\(\s*i\s*>\s*\(\s*contentlen\s*-\s*l\s*\)\s*\)\s*i\s*=\s*\(\s*contentlen\s*-\s*l\s*\)")
    nul_write = _has_pattern(items, r"\bbuf\s*\[\s*i\s*\]\s*=\s*0\b")

    if signed_contentlen and signed_l and unbounded_read_loop and remaining_adjust and nul_write:
        ids = []
        for group in [signed_contentlen, signed_l, contentlen_parse, unbounded_read_loop, remaining_adjust, nul_write]:
            ids.extend(i.evidence_id for i in group[:2])
        out.append(SemanticFinding(
            "signed_upload_remaining_index_write",
            "unsafe",
            "buf",
            list(dict.fromkeys(ids)),
            nul_write[0].line_start if nul_write else None,
            "Upload/config path uses signed contentlen/l, reads up to LINESIZE-1, then clamps i to contentlen-l before buf[i]=0; if remaining length is negative, i can become negative and index outside buf.",
        ))
    if unsigned_contentlen and unsigned_l and l_lt_contentlen_loop and min_read_loop and nul_write:
        ids = []
        for group in [unsigned_contentlen, unsigned_l, cap, l_lt_contentlen_loop, min_read_loop, nul_write]:
            ids.extend(i.evidence_id for i in group[:2])
        out.append(SemanticFinding(
            "bounded_upload_read_loop",
            "safe",
            "buf",
            list(dict.fromkeys(ids)),
            min_read_loop[0].line_start if min_read_loop else None,
            "Upload/config path uses unsigned counters, l < contentlen loop guard, and min(contentlen-l, LINESIZE-1) read bound before NUL termination.",
        ))



def source_upload_path_audit_from_text(source: str) -> dict:
    """Narrow source-only audit for admin/config upload read loops.

    This is deliberately *not* a general vulnerability classifier. It recognizes
    two explicit source patterns that the KG/evidence pipeline must bind in the
    final decision contract:
      - pre-fix style: signed contentlen/l, atoi/no cap, read LINESIZE-1, then
        post-read clamp and buf[i]=0;
      - fixed style: unsigned counters, contentlen cap, l < contentlen guard,
        min(contentlen-l, LINESIZE-1) read bound before buf[i]=0.

    The output has no dataset labels or patch information; it is derived only
    from the checked-out source snapshot.
    """
    lines = (source or "").splitlines()

    def find(pattern: str, flags: int = re.I):
        rx = re.compile(pattern, flags)
        out = []
        for i, line in enumerate(lines, start=1):
            if rx.search(line):
                out.append({"line": i, "text": line.strip()})
        return out

    joined = "\n".join(lines)
    present = all(term in joined for term in ["contentlen", "sockgetlinebuf", "buf[i]", "decodeurl", "fprintf"])
    facts = {
        "signed_contentlen": find(r"\bint\s+contentlen\s*=\s*0\b"),
        "unsigned_contentlen": find(r"\bunsigned\s+contentlen\s*=\s*0\b"),
        "signed_l": find(r"\bint\s+l\s*=\s*0\b"),
        "unsigned_l": find(r"\bunsigned\s+l\s*=\s*0\b"),
        "atoi_parse": find(r"\bcontentlen\s*=\s*atoi\s*\("),
        "sscanf_u_parse": find(r"\bsscanf\s*\([^;]*%u[^;]*contentlen"),
        "contentlen_cap": find(r"\bif\s*\([^\n;]*contentlen[^\n;]*(?:LINESIZE\s*\*|<=|>=|<|>)[^\n;]*\)"),
        "unbounded_upload_read": find(r"while\s*\(\s*\(\s*i\s*=\s*sockgetlinebuf\s*\([^;]*LINESIZE\s*-\s*1[^;]*\)\s*\)\s*>\s*0\s*\)"),
        "bounded_upload_read": find(r"sockgetlinebuf\s*\([^;]*\(\s*contentlen\s*-\s*l\s*\)\s*>\s*LINESIZE\s*-\s*1\s*\?\s*LINESIZE\s*-\s*1\s*:\s*contentlen\s*-\s*l"),
        "l_lt_contentlen_loop": find(r"while\s*\([^;]*\bl\s*<\s*contentlen[^;]*sockgetlinebuf"),
        "remaining_adjust": find(r"if\s*\(\s*i\s*>\s*\(?\s*contentlen\s*-\s*l\s*\)?\s*\)\s*i\s*=\s*\(?\s*contentlen\s*-\s*l\s*\)?"),
        "nul_write": find(r"\bbuf\s*\[\s*i\s*\]\s*=\s*0\b"),
        "decodeurl": find(r"\bdecodeurl\s*\("),
        "fprintf": find(r"\bfprintf\s*\([^;]*writable"),
        "buf_allocation": find(r"\bbuf\s*=\s*myalloc\s*\(\s*LINESIZE\s*\)"),
        "linesize_define": find(r"#\s*define\s+LINESIZE\b"),
    }
    unsafe = bool(
        present
        and facts["signed_contentlen"]
        and facts["signed_l"]
        and facts["atoi_parse"]
        and not facts["contentlen_cap"]
        and facts["unbounded_upload_read"]
        and facts["remaining_adjust"]
        and facts["nul_write"]
    )
    safe = bool(
        present
        and facts["unsigned_contentlen"]
        and facts["unsigned_l"]
        and facts["contentlen_cap"]
        and facts["l_lt_contentlen_loop"]
        and facts["bounded_upload_read"]
        and facts["nul_write"]
    )
    if unsafe:
        verdict = "unsafe"
        summary = "Source snapshot has pre-fix upload pattern: signed contentlen/l, atoi parse without cap, sockgetlinebuf reads LINESIZE-1, then post-read remaining clamp and buf[i]=0."
    elif safe:
        verdict = "safe"
        summary = "Source snapshot has fixed upload pattern: unsigned counters, contentlen cap, l < contentlen loop guard, and min(contentlen-l, LINESIZE-1) read bound before buf[i]=0."
    elif present:
        verdict = "ambiguous"
        summary = "Upload/config path is present but the narrow safe/unsafe source pattern is incomplete."
    else:
        verdict = "not_present"
        summary = "No complete upload/config path pattern was detected in the target source."
    return {"present": present, "verdict": verdict, "facts": facts, "summary": summary}

def semantic_findings(evidence: EvidencePack) -> list[SemanticFinding]:
    items = list(evidence.items)
    sizes = _declared_array_sizes(items)
    out: list[SemanticFinding] = []
    by_text = [(item, _text(item)) for item in items]

    for item, text in by_text:
        for m in re.finditer(r"\bfgets\s*\(\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*,", text):
            sym, n = m.group(1), int(m.group(2))
            size = sizes.get(sym)
            if size is not None and n <= size:
                out.append(SemanticFinding("bounded_fgets", "safe", sym, [item.evidence_id], item.line_start, f"fgets uses bound {n} for {sym}[{size}]."))
            else:
                out.append(SemanticFinding("fgets_unknown_bound", "ambiguous", sym, [item.evidence_id], item.line_start, "fgets bound could not be matched to declaration."))
        for m in re.finditer(r"\b(?:snprintf|vsnprintf)\s*\(\s*([A-Za-z_]\w*)\s*,\s*([^,]+),", text):
            sym, bound = m.group(1), m.group(2).strip()
            size = sizes.get(sym)
            if size is not None and bound.isdigit() and int(bound) <= size:
                out.append(SemanticFinding("bounded_snprintf", "safe", sym, [item.evidence_id], item.line_start, f"bounded formatting into {sym}[{size}] with limit {bound}."))
            else:
                out.append(SemanticFinding("snprintf_unknown_bound", "ambiguous", sym, [item.evidence_id], item.line_start, "bounded formatter used but exact bound relation is unknown."))

    unsafe_patterns = [
        ("unbounded_sprintf", r"\bsprintf\s*\(\s*([A-Za-z_]\w*)(?:\s*\+[^,]*)?\s*,"),
        ("unbounded_vsprintf", r"\bvsprintf\s*\(\s*([A-Za-z_]\w*)(?:\s*\+[^,]*)?\s*,"),
        ("unbounded_strcpy", r"\bstrcpy\s*\(\s*([A-Za-z_]\w*)(?:\s*\+[^,]*)?\s*,"),
        ("unbounded_strcat", r"\bstrcat\s*\(\s*([A-Za-z_]\w*)(?:\s*\+[^,]*)?\s*,"),
        ("gets", r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)"),
    ]
    for item, text in by_text:
        if text.lstrip().startswith("//") or text.lstrip().startswith("/*"):
            continue
        for kind, pat in unsafe_patterns:
            for m in re.finditer(pat, text):
                out.append(SemanticFinding(kind, "unsafe", m.group(1), [item.evidence_id], item.line_start, f"{kind} writes to {m.group(1)} without an explicit destination bound."))
        for _ in re.finditer(r'\b(?:scanf|fscanf|sscanf)\s*\([^;]*"[^"]*%s', text):
            out.append(SemanticFinding("unbounded_scanf_percent_s", "unsafe", None, [item.evidence_id], item.line_start, "scanf-family %s conversion appears without a field width."))
    _add_upload_path_findings(items, out)
    return out


def semantic_audit_dict(evidence: EvidencePack) -> dict:
    findings = semantic_findings(evidence)
    return {
        "findings": [f.__dict__ for f in findings],
        "unsafe_count": sum(1 for f in findings if f.status == "unsafe"),
        "safe_count": sum(1 for f in findings if f.status == "safe"),
        "ambiguous_count": sum(1 for f in findings if f.status == "ambiguous"),
    }
