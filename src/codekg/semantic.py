from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass
class SemanticFinding:
    rule_name: str
    fact_type: str
    severity: str
    evidence: str
    line_start: int
    line_end: int
    detail: str
    confidence: float = 0.75


CALL_NAMES_BUFFER = {
    "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "memset", "sprintf", "snprintf",
    "vsprintf", "vsnprintf", "gets", "fgets", "scanf", "sscanf", "fscanf", "read", "write",
    "recv", "send", "recvfrom", "sendto", "strlcpy", "strlcat", "bcopy",
}
ALLOC_NAMES = {"malloc", "calloc", "realloc", "free", "alloca", "new", "delete"}
INTEGER_TYPES = r"(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|uintptr_t|intptr_t|unsigned\s+int|signed\s+int|unsigned|signed|long|short|int)"


def _has_word(text: str, words: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(w)}\b", text) for w in words)


def semantic_findings_for_statement(
    code: str,
    line_start: int,
    context_lines_before: Optional[List[str]] = None,
    statement_type: str = "Statement",
) -> List[SemanticFinding]:
    """Deterministic code-oriented semantic overlays.

    This is not vulnerability classification. Rules only tag structural/code patterns
    and always return source evidence.
    """
    ctx = "\n".join(context_lines_before or [])
    text = code.strip()
    compact = re.sub(r"\s+", " ", text)
    findings: List[SemanticFinding] = []

    def add(rule: str, fact: str, detail: str, severity: str = "info", confidence: float = 0.75) -> None:
        findings.append(
            SemanticFinding(
                rule_name=rule,
                fact_type=fact,
                severity=severity,
                evidence=compact[:500],
                line_start=line_start,
                line_end=line_start + max(0, code.count("\n")),
                detail=detail,
                confidence=confidence,
            )
        )

    if not compact:
        return findings

    # Pointer dereference: -> or unary * before an identifier. Avoid matching multiplication in simple arithmetic.
    if "->" in compact or re.search(r"(^|[=,(;\s])\*\s*[A-Za-z_]\w+", compact):
        add("pointer_dereference", "pointer_dereference", "Pointer/member dereference syntax appears in this statement.", "medium")

    # Pointer arithmetic: identifier +/- integer or increment/decrement on identifiers commonly used as pointers.
    if re.search(r"\b[A-Za-z_]\w*\s*(?:\+\+|--|\+\s*\d+|-\s*\d+)", compact) and not re.search(r"\b(return|case)\b", compact):
        add("pointer_arithmetic", "pointer_arithmetic", "Identifier arithmetic or increment/decrement may be pointer/index arithmetic.", "medium", 0.55)

    if re.search(r"\b[A-Za-z_]\w*\s*\[[^\]]+\]", compact):
        add("array_indexing", "array_indexing", "Array indexing expression detected.", "medium")

    call_matches = re.findall(r"\b([A-Za-z_]\w*)\s*\(", compact)
    buffer_calls = sorted(set(c for c in call_matches if c in CALL_NAMES_BUFFER))
    if buffer_calls:
        add("buffer_io_or_copy_call", "buffer_copy_read_write", f"Buffer/string/memory I/O call(s): {', '.join(buffer_calls)}.", "medium")
        if any(c in {"strcpy", "strcat", "sprintf", "vsprintf", "gets"} for c in buffer_calls):
            add("unchecked_buffer_api", "suspicious_unchecked_flow", "Unbounded legacy buffer API detected.", "high", 0.8)
        if not re.search(r"\b(size|len|length|count|sizeof|capacity|limit|max)\b", compact, flags=re.I):
            add("buffer_call_without_obvious_size", "suspicious_unchecked_flow", "Buffer-related call has no obvious size/length argument in the same statement.", "medium", 0.6)

    alloc_calls = sorted(set(c for c in call_matches if c in ALLOC_NAMES))
    if alloc_calls:
        add("allocation_or_free", "allocation_free", f"Allocation/free style call(s): {', '.join(alloc_calls)}.", "medium")

    if re.search(r"\b(size|len|length|count|nbytes|capacity|limit|width|height|rows|cols)\b", compact, flags=re.I) and re.search(r"[+\-*/]", compact):
        add("size_length_arithmetic", "size_length_count_arithmetic", "Arithmetic involving a size/length/count-like symbol.", "medium")

    if re.search(r"\b(size|len|length|count|nbytes|capacity|rows|cols)\b", compact, flags=re.I) and "*" in compact:
        add("multiplication_size_computation", "multiplication_used_in_size_computation", "Multiplication appears in a size/length/count computation.", "medium")

    if statement_type == "Condition" or re.match(r"\s*(if|while|for)\s*\(", compact):
        cond = compact
        if re.search(r"(<=|>=|<|>)", cond) and re.search(r"\b(size|len|length|count|i|idx|index|n|rows|cols)\b", cond, flags=re.I):
            add("bounds_check", "bounds_check", "Conditional expression resembles a bounds or range check.", "info")
        if re.search(r"(==|!=)\s*(NULL|nullptr|0)\b|!\s*[A-Za-z_]\w+", cond):
            add("null_check", "null_check", "Conditional expression resembles a null check.", "info")
        if re.search(r"\b(assert|abort|exit)\s*\(", cond) or re.search(r"\b(return|goto)\b", compact):
            add("sanitizer_like_guard", "sanitizer_like_guard", "Conditional/guard-like statement contains assert, abort, return, or goto.", "info", 0.55)

    if statement_type == "Loop" or re.match(r"\s*(for|while)\s*\(", compact):
        if re.search(r"\b(size|len|length|count|rows|cols|i|idx|index|n)\b", compact, flags=re.I) or "[" in compact:
            add("loop_over_buffer_or_range", "loops_over_buffers", "Loop condition/update appears to iterate over a buffer/range-like value.", "medium", 0.65)

    if re.search(rf"\(\s*{INTEGER_TYPES}\s*\)", compact):
        add("integer_cast", "integer_cast", "Explicit integer-family cast detected.", "medium")

    if re.search(r"\bunsigned\b", compact) and re.search(r"\bsigned\b|\bint\b", compact):
        add("signed_unsigned_conversion", "signed_unsigned_conversion", "Signed/unsigned type terms co-occur in this statement.", "medium", 0.6)

    if re.match(r"\s*return\b", compact) and re.search(r"\b(-1|NULL|nullptr|false|0)\b", compact):
        add("error_return", "error_return", "Return statement uses a common sentinel/error-like value.", "info", 0.65)

    # Context-sensitive unchecked flow marker: buffer operation soon after no nearby guard.
    if buffer_calls and not re.search(r"\b(if|assert)\b", ctx + "\n" + compact):
        add("nearby_guard_not_seen", "suspicious_unchecked_flow", "No nearby guard/check was observed immediately before this buffer operation.", "medium", 0.45)

    return findings
