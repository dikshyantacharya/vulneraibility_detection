from __future__ import annotations

"""Prompt-facing evidence curation for the research agentic proof loop.

The raw CodeKG evidence is intentionally rich: it contains node ranks, line
locations, graph summaries, standalone parameter nodes, and large function
snippets.  That is useful for dashboards and debugging, but it is poor evidence
for a verifier LLM.  This module converts raw evidence into compact, stable,
source-grounded evidence cards:

* keep stable evidence IDs so the LLM can cite them;
* keep only code/summary needed for reasoning;
* remove line_start/line_end/score/ranking noise from model-visible prompts;
* clean line-numbered snippets into normal code;
* de-duplicate isolated statements when a full function card already covers them;
* expose enough caller/callee/global context for iterative human-like audit.
"""

import re
from collections import Counter, defaultdict
from typing import Any, Iterable, List, Dict


_NOISY_KINDS = {
    "codekg_query_summary",
    "codekg_functionparameter",
}

_CODE_LIKE_KINDS = {
    "target_statement",
    "caller_function",
    "callee_function",
    "source_snippet",
    "codekg_function",
    "codekg_assignment",
    "codekg_callexpression",
    "codekg_returnstatement",
    "codekg_controlstructure",
    "codekg_localvariable",
    "codekg_globalvariable",
    "codekg_identifier",
    "codekg_literal",
    "deterministic_source_fact",
    "codekg_semanticfact",
}

_SECURITY_TERMS = {
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "snprintf",
    "scanf", "gets", "read", "fread", "recv", "send", "write", "fwrite",
    "malloc", "calloc", "realloc", "free", "new", "delete",
    "open", "fopen", "exec", "system", "popen", "chown", "chmod",
    "overflow", "underflow", "bounds", "guard", "check", "length", "size",
    "count", "offset", "index", "pointer", "null", "buffer", "array",
    "auth", "permission", "access", "crypto", "hash", "random", "nonce",
}

_OPERATOR_HINTS = ("[", "]", "->", ".", "+=", "-=", "*=", "<<", ">>", "^", "&", "|", "*", "malloc", "free", "fread", "mem", "str", "sprintf")


def _as_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "model_dump"):
        return dict(item.model_dump(mode="json"))
    return {"text": str(item)}


def _eid(item: Dict[str, Any]) -> str:
    return str(item.get("id") or item.get("evidence_id") or item.get("node_id") or "unknown").strip()


def _clean_code_text(text: str, *, max_chars: int = 1800) -> str:
    """Normalize CodeKG snippets for a human/LLM security review.

    Removes leading `123 | ` line decorations and repeated terminal labels such
    as `function\nfile.c`.  It deliberately keeps the original code order.
    """
    raw = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    for line in raw.split("\n"):
        # CodeKG function snippets often include `  512 | code`.
        line = re.sub(r"^\s*\d+\s*\|\s?", "", line)
        lines.append(line.rstrip())
    # Strip repeated trailing labels: `func`, `file.c`, `symbol` lines that are
    # not code and only repeat metadata already available in the evidence card.
    while lines and not lines[-1].strip():
        lines.pop()
    for _ in range(3):
        if not lines:
            break
        tail = lines[-1].strip()
        if re.fullmatch(r"[A-Za-z_][\w$]*", tail) or re.fullmatch(r"[\w./\\-]+\.(c|cc|cpp|cxx|h|hpp|hh)", tail):
            lines.pop()
        else:
            break
    cleaned = "\n".join(lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 32].rstrip() + "\n/* ... omitted for prompt budget ... */"
    return cleaned


def _one_line(text: str, *, max_chars: int = 280) -> str:
    out = re.sub(r"\s+", " ", _clean_code_text(text, max_chars=max_chars * 2)).strip()
    return out if len(out) <= max_chars else out[: max_chars - 3].rstrip() + "..."


def _extract_symbols_from_hypotheses(hypotheses: Iterable[Dict[str, Any]] | None) -> set[str]:
    blob = "\n".join(str(h) for h in (hypotheses or []))
    symbols = set(re.findall(r"`([A-Za-z_]\w*)`", blob))
    # Add identifier-looking tokens from hypothesis fields, but avoid common prose.
    stop = {
        "If", "The", "This", "What", "Where", "When", "How", "Are", "Is",
        "Buffer", "Overflow", "Out", "Bounds", "Read", "Write", "NULL",
        "Pointer", "Integer", "Hypothesis", "Vulnerability", "Class",
    }
    for tok in re.findall(r"\b[A-Za-z_]\w{2,}\b", blob):
        if tok not in stop and (tok[0].islower() or "_" in tok or tok.isupper()):
            symbols.add(tok)
    return symbols


def _is_noisy_statement(item: Dict[str, Any], text: str) -> bool:
    kind = str(item.get("kind") or "")
    if kind == "codekg_query_summary":
        return True
    if kind == "codekg_functionparameter":
        return True
    compact = re.sub(r"\s+", " ", text).strip()
    # Standalone declarations such as `int i;` usually distract unless they carry
    # array size, pointer, or security-relevant initialisation information.
    if re.fullmatch(r"(?:const\s+)?(?:unsigned\s+)?(?:long\s+|short\s+|int\s+|char\s+|size_t\s+|uint\d+_t\s+|bool\s+)[A-Za-z_]\w*\s*;", compact):
        return True
    if compact in {"{", "}", "}else{", "else {", "else{"}:
        return True
    return False


def _role(item: Dict[str, Any], target_function: str) -> str:
    kind = str(item.get("kind") or "")
    rel = str(item.get("relation") or "")
    fn = str(item.get("function") or "")
    text = str(item.get("text") or "").lower()
    if kind == "deterministic_source_fact":
        return "deterministic_source_fact"
    if kind == "target_statement" or fn == target_function:
        if any(op in text for op in ("[", "memcpy", "strcpy", "sprintf", "malloc", "fread", "realloc", "free", "+=", "-=")):
            return "target_risky_operation_or_guard"
        return "target_context"
    if "caller" in rel or kind == "caller_function":
        return "caller_context"
    if "callee" in rel or kind == "callee_function":
        return "callee_context"
    if "global" in kind or "macro" in kind or "constant" in kind:
        return "definition_or_constant"
    if "semanticfact" in kind:
        return "semantic_fact"
    if "function" in kind:
        return "related_function_context"
    if "assignment" in kind or "call" in kind or "control" in kind:
        return "statement_context"
    return "supporting_context"


def _score_for_prompt(item: Dict[str, Any], *, target_function: str, symbols: set[str], full_functions: set[str]) -> int:
    text = _clean_code_text(str(item.get("text") or ""), max_chars=2200)
    kind = str(item.get("kind") or "")
    fn = str(item.get("function") or "")
    rel = str(item.get("relation") or "")
    if _is_noisy_statement(item, text):
        return -100
    s = 0
    if kind == "deterministic_source_fact":
        s += 90
    if fn == target_function:
        s += 70
    if kind == "target_statement":
        s += 45
    if "caller" in rel or kind == "caller_function":
        s += 55
    if "callee" in rel or kind == "callee_function":
        s += 45
    if kind == "codekg_function":
        s += 40
    if any(t in text.lower() for t in _SECURITY_TERMS):
        s += 30
    if any(op in text for op in _OPERATOR_HINTS):
        s += 25
    if symbols and any(re.search(rf"\b{re.escape(sym)}\b", text) for sym in symbols):
        s += 35
    # If a full function card is already present, isolated statements from the
    # same function are useful only if they are direct risky operations/guards.
    if kind == "target_statement" and fn in full_functions:
        if not any(op in text for op in _OPERATOR_HINTS) and "if" not in text and "for" not in text and "while" not in text:
            s -= 70
    if kind in _NOISY_KINDS:
        s -= 80
    return s


def _dedupe_key(item: Dict[str, Any], code: str) -> str:
    fn = str(item.get("function") or "")
    kind = str(item.get("kind") or "")
    normalized = re.sub(r"\s+", " ", code).strip().lower()
    return f"{kind}|{fn}|{normalized[:260]}"


def _summarize_item(item: Dict[str, Any], code: str, role: str) -> str:
    low = code.lower()
    if role == "caller_context":
        calls = re.findall(r"\b([A-Za-z_]\w*)\s*\(", code)
        calls = [c for c in calls if c not in {"if", "while", "for", "switch", "return", "sizeof"}]
        call_text = f" Calls: {', '.join(dict.fromkeys(calls)[:8])}." if calls else ""
        return "Caller-side context showing argument construction, preconditions, and call path." + call_text
    if role == "callee_context":
        return "Callee context that may define, transform, validate, allocate, or return values used by the target function."
    if "fread" in low or "read" in low or "recv" in low:
        return "Input/length source or bounded read evidence."
    if any(x in low for x in ("malloc", "calloc", "realloc", "free")):
        return "Allocation/lifetime evidence."
    if any(x in low for x in ("if", "while", "for", "assert")) and any(x in low for x in ("<", ">", "==", "!=", "&&", "||")):
        return "Guard/control-flow evidence that may bound or fail to bound a risky value."
    if "[" in code and "]" in code:
        return "Indexing or array-access evidence."
    if role == "deterministic_source_fact":
        return _one_line(code)
    return "Source-grounded evidence item selected as relevant to current hypotheses."


def _make_card(item: Dict[str, Any], *, target_function: str, max_code_chars: int) -> Dict[str, Any]:
    code = _clean_code_text(str(item.get("text") or ""), max_chars=max_code_chars)
    role = _role(item, target_function)
    card: Dict[str, Any] = {
        "id": _eid(item),
        "role": role,
        "evidence_type": item.get("kind") or "evidence",
        "function": item.get("function"),
        "summary": _summarize_item(item, code, role),
    }
    file_ = item.get("file") or item.get("relpath")
    if file_:
        # Keep only file identity, not line spans. File identity is often useful
        # to distinguish caller/callee/global definitions without wasting tokens.
        card["source_file"] = file_
    if code:
        key = "fact" if role in {"deterministic_source_fact", "semantic_fact"} else "code"
        card[key] = code
    meta = item.get("metadata") or {}
    if isinstance(meta, dict):
        fact_type = meta.get("fact_type")
        if fact_type:
            card["fact_type"] = fact_type
        query = meta.get("query")
        if isinstance(query, dict):
            qkind = query.get("kind") or query.get("query_type")
            if qkind:
                card["retrieved_by"] = qkind
    return {k: v for k, v in card.items() if v not in (None, "", [], {})}


def curate_evidence_for_prompt(
    evidence: List[Dict[str, Any]] | None,
    *,
    target_function: str = "",
    hypotheses: List[Dict[str, Any]] | None = None,
    max_items: int = 36,
    max_code_chars: int = 1800,
) -> Dict[str, Any]:
    """Return compact, LLM-facing evidence for verification/counter/final stages.

    The return value is JSON-serialisable and intentionally omits raw graph scores
    and line locations. Stable IDs remain because downstream schemas require the
    model to cite evidence IDs.
    """
    raw = [_as_dict(e) for e in (evidence or [])]
    symbols = _extract_symbols_from_hypotheses(hypotheses)
    full_functions = {
        str(e.get("function") or "")
        for e in raw
        if str(e.get("kind") or "") in {"codekg_function", "caller_function", "callee_function"}
        and str(e.get("function") or "")
    }

    scored: list[tuple[int, Dict[str, Any]]] = []
    omitted_by_reason: Counter[str] = Counter()
    for item in raw:
        kind = str(item.get("kind") or "")
        text = _clean_code_text(str(item.get("text") or ""), max_chars=max_code_chars)
        if not text.strip():
            omitted_by_reason["empty_text"] += 1
            continue
        if _is_noisy_statement(item, text):
            omitted_by_reason[f"noisy_{kind or 'unknown'}"] += 1
            continue
        score = _score_for_prompt(item, target_function=target_function, symbols=symbols, full_functions=full_functions)
        if score < 20:
            omitted_by_reason["low_relevance"] += 1
            continue
        scored.append((score, item))

    # Prefer high-value context but preserve source order inside equal roles via id.
    scored.sort(key=lambda x: (-x[0], _eid(x[1])))
    selected: list[Dict[str, Any]] = []
    seen_keys: set[str] = set()
    role_counts: Counter[str] = Counter()
    for _score, item in scored:
        code = _clean_code_text(str(item.get("text") or ""), max_chars=max_code_chars)
        key = _dedupe_key(item, code)
        if key in seen_keys:
            omitted_by_reason["duplicate"] += 1
            continue
        role = _role(item, target_function)
        # Keep diversity: one huge function class should not crowd out caller,
        # callee, globals, and facts.
        per_role_limit = {
            "target_risky_operation_or_guard": 10,
            "target_context": 4,
            "caller_context": 8,
            "callee_context": 8,
            "related_function_context": 8,
            "definition_or_constant": 8,
            "deterministic_source_fact": 12,
            "semantic_fact": 8,
        }.get(role, 6)
        if role_counts[role] >= per_role_limit:
            omitted_by_reason[f"role_limit_{role}"] += 1
            continue
        selected.append(_make_card(item, target_function=target_function, max_code_chars=max_code_chars))
        seen_keys.add(key)
        role_counts[role] += 1
        if len(selected) >= max_items:
            break

    selected_ids = {str(c.get("id")) for c in selected}
    available_index: list[Dict[str, Any]] = []
    for item in raw:
        eid = _eid(item)
        if eid in selected_ids:
            continue
        kind = str(item.get("kind") or "evidence")
        if kind in _NOISY_KINDS:
            continue
        entry = {"id": eid, "type": kind}
        fn = item.get("function")
        if fn:
            entry["function"] = fn
        role = _role(item, target_function)
        if role:
            entry["role"] = role
        available_index.append(entry)
        if len(available_index) >= 80:
            break

    return {
        "curation_policy": (
            "Evidence cards are selected from CodeKG results for verification. "
            "Graph scores, raw line_start/line_end fields, and redundant parameter/summary nodes are omitted. "
            "Use evidence IDs for citations; request follow-up KG queries when a proof element is missing."
        ),
        "target_function": target_function or None,
        "selected_evidence": selected,
        "available_but_not_shown_index": available_index,
        "omitted_counts": dict(sorted(omitted_by_reason.items())),
        "raw_evidence_count": len(raw),
        "selected_evidence_count": len(selected),
    }


def compact_evidence_index(evidence: List[Dict[str, Any]] | None, *, target_function: str = "") -> List[Dict[str, Any]]:
    """Small index for gap prompts: id + role + function + type only."""
    out: list[Dict[str, Any]] = []
    seen: set[str] = set()
    for item0 in evidence or []:
        item = _as_dict(item0)
        eid = _eid(item)
        if not eid or eid in seen:
            continue
        seen.add(eid)
        kind = str(item.get("kind") or "evidence")
        if kind == "codekg_query_summary":
            continue
        entry: Dict[str, Any] = {
            "id": eid,
            "type": kind,
            "role": _role(item, target_function),
        }
        if item.get("function"):
            entry["function"] = item.get("function")
        out.append(entry)
        if len(out) >= 120:
            break
    return out
