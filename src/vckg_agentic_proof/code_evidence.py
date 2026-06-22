from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set


_CODE_NODE_KINDS = {
    "target_statement",
    "caller_function",
    "callee_function",
    "codekg_function",
    "codekg_assignment",
    "codekg_callexpression",
    "codekg_controlstructure",
    "codekg_global",
    "codekg_globalvariable",
    "codekg_macro",
    "codekg_typedef",
    "codekg_struct",
    "codekg_enum",
    "codekg_fieldidentifier",
}

_NOISE_KINDS = {
    "codekg_query_summary",
    "codekg_functionparameter",
    "codekg_localvariable",
    "codekg_semanticfact",
    "deterministic_source_fact",
}

_SECURITY_OPERATORS = (
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "sprintf", "snprintf",
    "fread", "read", "recv", "recvfrom", "write", "send", "malloc", "calloc", "realloc", "free",
    "open", "fopen", "system", "popen", "exec", "chmod", "chown", "access", "stat",
    "[", "]", "->", "+=", "-=", "*=", "<<", ">>", "*", "/", "%",
)

_SECURITY_WORDS = {
    "len", "length", "size", "count", "offset", "index", "idx", "pos", "ptr", "raw",
    "buffer", "buf", "array", "rows", "items", "itemsize", "alloc", "null", "guard",
    "auth", "permission", "access", "token", "session", "key", "nonce", "random", "crypto",
    "path", "file", "command", "user", "input", "parse", "read", "write", "copy",
}


def _as_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "model_dump"):
        return dict(item.model_dump(mode="json"))
    return {"text": str(item)}


def _eid(item: Dict[str, Any]) -> str:
    return str(item.get("id") or item.get("evidence_id") or item.get("node_id") or "unknown").strip()


def clean_code_text(text: str, *, max_chars: int = 2600) -> str:
    """Return source-like code, not graph metadata.

    CodeKG snippets often contain decorations such as `512 |`, repeated terminal
    labels (`function`, `file.c`), and AST tags such as `Assignment@67`.
    This normalizer keeps the code itself and removes those decorations before
    the LLM sees it.
    """
    raw = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for line in raw.split("\n"):
        line = re.sub(r"^\s*\d+\s*\|\s?", "", line).rstrip()
        # Remove CodeKG/Joern AST suffixes when they are exported on the same
        # line as source code: `raw += n;\nAssignment@67` or `...; Assignment@67`.
        line = re.sub(r"\s+(Assignment|Loop|ReturnStatement|CallExpression|ControlStructure|Identifier|Literal|Condition)@\d+\s*$", "", line)
        if re.fullmatch(r"\s*(Assignment|Loop|ReturnStatement|CallExpression|ControlStructure|Identifier|Literal|Condition)@\d+\s*", line):
            continue
        lines.append(line)

    while lines and not lines[-1].strip():
        lines.pop()

    # Remove repeated labels appended by graph export, e.g. `func\nfile.c`.
    for _ in range(4):
        if not lines:
            break
        tail = lines[-1].strip()
        if re.fullmatch(r"[A-Za-z_][\w$]*", tail):
            lines.pop()
            continue
        if re.fullmatch(r"[\w./\\-]+\.(c|cc|cpp|cxx|h|hpp|hh)", tail, flags=re.I):
            lines.pop()
            continue
        break

    cleaned = "\n".join(lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 42].rstrip() + "\n/* ... omitted for prompt budget ... */"
    return cleaned


def _symbols_from_hypothesis(hypothesis: Dict[str, Any] | Iterable[Dict[str, Any]] | None) -> Set[str]:
    if hypothesis is None:
        blob = ""
    elif isinstance(hypothesis, dict):
        blob = "\n".join(str(v) for v in hypothesis.values())
    else:
        blob = "\n".join(str(x) for x in hypothesis)
    symbols = set(re.findall(r"`([A-Za-z_]\w*)`", blob))
    stop = {
        "the", "and", "for", "with", "from", "that", "this", "into", "when", "where",
        "buffer", "overflow", "underflow", "vulnerability", "hypothesis", "attacker",
        "memory", "safety", "parser", "state", "class", "input", "source",
    }
    for tok in re.findall(r"\b[A-Za-z_]\w{2,}\b", blob):
        if tok.lower() not in stop and (tok[0].islower() or "_" in tok or tok.isupper()):
            symbols.add(tok)
    return symbols


def _role(item: Dict[str, Any], target_function: str) -> str:
    kind = str(item.get("kind") or "")
    rel = str(item.get("relation") or "")
    fn = str(item.get("function") or "")
    text = str(item.get("text") or "")
    if kind == "target_statement" or (target_function and fn == target_function):
        return "target_related_code"
    if "caller" in rel or kind == "caller_function":
        return "caller_code"
    if "callee" in rel or kind == "callee_function":
        return "callee_code"
    if any(x in kind for x in ("global", "macro", "typedef", "struct", "enum")):
        return "definition_code"
    if "function" in kind:
        return "related_function_code"
    if any(x in kind for x in ("assignment", "call", "control")):
        return "statement_or_guard_code"
    return "supporting_code"


def _looks_like_code(kind: str, code: str) -> bool:
    if not code.strip():
        return False
    if kind in _NOISE_KINDS:
        return False
    if kind not in _CODE_NODE_KINDS and not any(tok in code for tok in ("{", "}", ";", "#define", "typedef", "struct", "enum")):
        return False
    compact = re.sub(r"\s+", " ", code).strip()
    if compact in {"{", "}", "else", "else {", "} else {"}:
        return False
    # Drop one-token declarations unless they carry pointer/array/constant context.
    if re.fullmatch(r"(?:const\s+)?(?:unsigned\s+)?(?:long\s+|short\s+|int\s+|char\s+|bool\s+|size_t\s+|uint\d+_t\s+)[A-Za-z_]\w*\s*;", compact):
        return False
    return True


def _score(item: Dict[str, Any], *, target_function: str, symbols: Set[str], code: str) -> int:
    kind = str(item.get("kind") or "")
    fn = str(item.get("function") or "")
    rel = str(item.get("relation") or "")
    low = code.lower()
    s = 0
    if target_function and fn == target_function:
        s += 85
    if kind == "target_statement":
        s += 60
    if kind in {"caller_function", "callee_function", "codekg_function"}:
        s += 70
    if "caller" in rel:
        s += 45
    if "callee" in rel:
        s += 40
    if any(x in kind for x in ("global", "macro", "typedef", "struct", "enum")):
        s += 55
    if symbols and any(re.search(rf"\b{re.escape(sym)}\b", code) for sym in symbols):
        s += 55
    if any(op in code for op in _SECURITY_OPERATORS):
        s += 35
    if any(w in low for w in _SECURITY_WORDS):
        s += 25
    if kind in {"codekg_assignment", "codekg_callexpression", "codekg_controlstructure"}:
        s += 30
    return s


def _dedupe_key(item: Dict[str, Any], code: str) -> str:
    kind = str(item.get("kind") or "")
    fn = str(item.get("function") or "")
    norm = re.sub(r"\s+", " ", code).strip().lower()
    return f"{kind}|{fn}|{norm[:400]}"


def _card(item: Dict[str, Any], *, target_function: str, max_code_chars: int) -> Dict[str, Any]:
    code = clean_code_text(str(item.get("text") or ""), max_chars=max_code_chars)
    out: Dict[str, Any] = {
        "id": _eid(item),
        "role": _role(item, target_function),
        "symbol": item.get("function") or item.get("symbol") or item.get("name"),
        "file": item.get("file") or item.get("relpath"),
        "code": code,
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def build_code_evidence_bundle(
    evidence: List[Dict[str, Any]] | None,
    *,
    target_function: str,
    target_source: str = "",
    target_file: str = "",
    hypothesis: Dict[str, Any] | Iterable[Dict[str, Any]] | None = None,
    max_sections: int = 22,
    max_code_chars: int = 2600,
) -> Dict[str, Any]:
    """Build a source-code-only evidence bundle for LLM verification.

    This is intentionally not a summary.  It is a compact collection of function
    bodies, caller/callee code, definitions, constants, and exact guard/sink
    statements relevant to the current hypothesis.  Graph scores, line spans,
    semantic summaries, and query summaries are excluded.
    """
    raw = [_as_dict(e) for e in (evidence or [])]
    symbols = _symbols_from_hypothesis(hypothesis)
    selected: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    omitted: Counter[str] = Counter()

    if target_source.strip():
        selected.append({
            "id": "TARGET-SOURCE",
            "role": "target_function_source",
            "symbol": target_function or None,
            "file": target_file or None,
            "code": clean_code_text(target_source, max_chars=max_code_chars * 2),
        })
        seen.add("target-source")

    candidates: List[tuple[int, Dict[str, Any], str]] = []
    for item in raw:
        kind = str(item.get("kind") or "")
        code = clean_code_text(str(item.get("text") or ""), max_chars=max_code_chars)
        if not _looks_like_code(kind, code):
            omitted[f"non_code_or_noise_{kind or 'unknown'}"] += 1
            continue
        sc = _score(item, target_function=target_function, symbols=symbols, code=code)
        if sc < 35:
            omitted["low_relevance_code"] += 1
            continue
        candidates.append((sc, item, code))

    # Function bodies and definitions first; exact target statements next.  This
    # gives the LLM the human-like review context: target, callers, callees,
    # constants/types, then local slices.
    def _order(row: tuple[int, Dict[str, Any], str]) -> tuple[int, int, str]:
        sc, item, _code = row
        role = _role(item, target_function)
        role_rank = {
            "caller_code": 0,
            "callee_code": 1,
            "related_function_code": 2,
            "definition_code": 3,
            "target_related_code": 4,
            "statement_or_guard_code": 5,
        }.get(role, 6)
        return (-sc, role_rank, _eid(item))

    for _sc, item, code in sorted(candidates, key=_order):
        key = _dedupe_key(item, code)
        if key in seen:
            omitted["duplicate_code"] += 1
            continue
        selected.append(_card(item, target_function=target_function, max_code_chars=max_code_chars))
        seen.add(key)
        if len(selected) >= max_sections:
            break

    shown = {str(x.get("id")) for x in selected}
    available: List[Dict[str, Any]] = []
    for item in raw:
        eid = _eid(item)
        if eid in shown:
            continue
        kind = str(item.get("kind") or "evidence")
        if kind in _NOISE_KINDS or kind == "codekg_query_summary":
            continue
        code = clean_code_text(str(item.get("text") or ""), max_chars=240)
        if not _looks_like_code(kind, code):
            continue
        available.append({
            "id": eid,
            "role": _role(item, target_function),
            "symbol": item.get("function") or item.get("symbol") or item.get("name"),
            "file": item.get("file") or item.get("relpath"),
        })
        if len(available) >= 80:
            break

    bundle: Dict[str, Any] = {
        "policy": "Source-code-only evidence. No graph score, no line span fields, no semantic summaries, no query-summary nodes. Cite code section ids.",
        "target_function": target_function or None,
        "hypothesis_id": hypothesis.get("hypothesis_id") if isinstance(hypothesis, dict) else None,
        "code_sections": selected,
        "available_code_index": [x for x in available if any(v for v in x.values())],
        "omitted_counts": dict(sorted(omitted.items())),
        "raw_evidence_count": len(raw),
        "shown_code_section_count": len(selected),
    }
    return {k: v for k, v in bundle.items() if v not in (None, "", [], {})}


def build_code_evidence_capsules(
    evidence: List[Dict[str, Any]] | None,
    *,
    target_function: str,
    target_source: str = "",
    target_file: str = "",
    hypothesis: Dict[str, Any] | Iterable[Dict[str, Any]] | None = None,
    max_capsules: int = 10,
    max_code_chars: int = 1400,
    max_index_items: int = 32,
) -> Dict[str, Any]:
    """Build a tiny source-code capsule bundle for one narrow LLM review.

    This is intentionally smaller than ``build_code_evidence_bundle``.  It is
    used by per-hypothesis verification/counter/final stages so the LLM receives
    enough code for the current proof step, not the whole KG subgraph.
    """
    bundle = build_code_evidence_bundle(
        evidence,
        target_function=target_function,
        target_source=target_source,
        target_file=target_file,
        hypothesis=hypothesis,
        max_sections=max_capsules,
        max_code_chars=max_code_chars,
    )
    capsules = []
    for i, sec in enumerate(bundle.get("code_sections") or [], start=1):
        code = clean_code_text(str(sec.get("code") or ""), max_chars=max_code_chars)
        if not code.strip():
            continue
        capsules.append({
            "capsule_id": sec.get("id") or f"CAP-{i:02d}",
            "role": sec.get("role"),
            "symbol": sec.get("symbol"),
            "file": sec.get("file"),
            "code": code,
        })
    index = list(bundle.get("available_code_index") or [])[:max_index_items]
    out = {
        "policy": (
            "Tiny source-code evidence capsules. No graph score, no line spans, "
            "no semantic summaries, no query-summary nodes. Cite capsule_id values."
        ),
        "target_function": target_function or None,
        "hypothesis_id": hypothesis.get("hypothesis_id") if isinstance(hypothesis, dict) else None,
        "code_capsules": capsules,
        "available_code_index": index,
        "omitted_counts": bundle.get("omitted_counts") or {},
        "raw_evidence_count": bundle.get("raw_evidence_count"),
        "shown_capsule_count": len(capsules),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def compact_code_evidence_index(evidence: List[Dict[str, Any]] | None, *, target_function: str = "") -> List[Dict[str, Any]]:
    """Small code-only index for gap prompts."""
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for item0 in evidence or []:
        item = _as_dict(item0)
        eid = _eid(item)
        if not eid or eid in seen:
            continue
        kind = str(item.get("kind") or "")
        code = clean_code_text(str(item.get("text") or ""), max_chars=240)
        if not _looks_like_code(kind, code):
            continue
        seen.add(eid)
        out.append({
            "id": eid,
            "role": _role(item, target_function),
            "symbol": item.get("function") or item.get("symbol") or item.get("name"),
            "file": item.get("file") or item.get("relpath"),
        })
        if len(out) >= 120:
            break
    return [x for x in out if any(v for v in x.values())]
