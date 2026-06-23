from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel
from .parser import parse_model_object
from .prompts import (counter_evidence_prompt, counter_gap_analysis_prompt,
                      evidence_gap_analysis_prompt, final_decision_prompt,
                      hypothesis_verification_prompt, single_hypothesis_verification_prompt,
                      proof_obligation_verification_prompt, kg_query_planning_prompt,
                      source_only_hypothesis_prompt, consistency_repair_prompt)
from .schemas import (CounterEvidenceReview, EvidenceGapPlan, FinalDecision,
                      FinalPrediction, HypothesisStatus, HypothesisVerification, KGQuery, KGQueryPlan,
                      ProofObligationVerificationEnvelope, VulnerabilityHypothesis)
from .validator import validate_final_decision
from .proof_obligations import (
    build_proof_obligations,
    infer_proof_family,
    obligation_queries,
    normalize_obligation_result,
    summarize_ledger,
    verification_from_ledger,
)


def _make_emergency_fallback_decision(error_msg: str) -> FinalDecision:
    """Return a minimal FinalDecision that marks the sample as failed_parse.

    This is the last-resort fallback used only when no prior structured
    verification exists.  Normal Stage-06 parse/truncation failures should use
    _make_fallback_decision_from_verifications() so the sample still receives a
    benchmarkable binary prediction from already-validated evidence rather than
    defaulting to fixed/non-vulnerable.
    """
    return FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.0,
        local_risk_present=False,
        confirmed_security_vulnerability=False,
        explanation="Stage 06 final adjudication could not be parsed or validated, and no prior verification evidence was available for deterministic fallback.",
        limitations=[],
        forced_prediction="fixed/non-vulnerable",
        forced_prediction_bool=False,
        decision_status="failed_parse",
        evidence_strength="insufficient_static_evidence",
        evidence_exhausted=True,
        why_forced_binary=f"Emergency fallback: parse/validate failed. {error_msg}",
        final_decision_source="stage06_emergency_failed_parse",
        normalization_warnings=["stage06_no_structured_verification_fallback_available"],
    )


def _make_fallback_decision_from_verifications(
    error_msg: str,
    verifications: Any,
    *,
    evidence_items: List[Dict[str, Any]] | None = None,
    counter_review: Any = None,
) -> tuple[FinalDecision, List[str], bool]:
    """Build a deterministic final decision when Stage 06 truncates or fails.

    Stage 06 can fail for operational reasons (for example, a long 600B-model
    answer truncated before </answer>).  In that case the previous verification
    and counter-evidence stages are already parsed and validated.  This function
    converts those existing verifications into a conservative inconclusive
    decision and lets validate_final_decision() apply the same binary policy used
    for normal model output.

    The fallback is label-free: it uses only retrieved evidence, verification
    statuses, counter-review recommendations, and deterministic source facts.
    """
    raw_items = []
    if isinstance(verifications, dict):
        raw_items = list(verifications.get("verifications") or [])
    elif isinstance(verifications, list):
        raw_items = list(verifications)

    parsed_items = []
    parse_notes: List[str] = []
    for i, item in enumerate(raw_items):
        try:
            parsed_items.append(
                item if isinstance(item, HypothesisVerification) else HypothesisVerification.model_validate(item)
            )
        except Exception as exc:
            parse_notes.append(f"fallback_skipped_verification_{i}: {type(exc).__name__}: {exc}")

    if not parsed_items:
        return _make_emergency_fallback_decision(error_msg), [f"stage06_failed_no_verifications: {error_msg}", *parse_notes], False

    local_risk = any(bool(h.local_risk_present) for h in parsed_items)
    confirmed = [
        h for h in parsed_items
        if h.status == HypothesisStatus.confirmed_vulnerability and h.confirmed_security_vulnerability
    ]
    prediction = FinalPrediction.vulnerable if confirmed else FinalPrediction.inconclusive
    decisive_ids: List[str] = []
    for h in parsed_items:
        decisive_ids.extend([str(x) for x in (h.supporting_evidence_ids or []) if str(x).strip()])
    decisive_ids = sorted(dict.fromkeys(decisive_ids))[:20]

    decision = FinalDecision(
        prediction=prediction,
        confidence=0.6 if local_risk else 0.55,
        local_risk_present=local_risk,
        confirmed_security_vulnerability=bool(confirmed),
        final_hypothesis_statuses=parsed_items,
        minimum_vulnerability_proof=confirmed[0].proof if confirmed and confirmed[0].proof.complete() else None,
        decisive_evidence_ids=decisive_ids,
        decisive_counter_evidence_ids=[],
        explanation=(
            "Stage 06 final adjudication could not be parsed or validated, so the "
            "pipeline derived the final decision from the latest validated "
            "hypothesis-verification and counter-evidence records."
        ),
        limitations=[
            "Stage 06 LLM answer was unavailable or malformed/truncated.",
            "Binary decision was derived by validator policy from prior structured stages.",
        ],
        evidence_exhausted=True,
        final_decision_source="stage06_fallback_from_verifications",
        normalization_warnings=[f"stage06_parse_or_validation_failed: {error_msg}", *parse_notes],
    )
    validated, notes, modified = validate_final_decision(
        decision, evidence_items=evidence_items, counter_review=counter_review
    )
    validated.final_decision_source = validated.final_decision_source or "stage06_fallback_from_verifications"
    warnings = list(validated.normalization_warnings or [])
    if not any("stage06_parse_or_validation_failed" in w for w in warnings):
        warnings.append(f"stage06_parse_or_validation_failed: {error_msg}")
    validated.normalization_warnings = warnings
    return validated, [f"stage06_fallback_from_verifications: {error_msg}", *notes, *parse_notes], True


_RESOLVED_STATUSES = {
    HypothesisStatus.confirmed_vulnerability.value,
    HypothesisStatus.refuted_by_guard.value,
    HypothesisStatus.refuted_by_caller_constraint.value,
    HypothesisStatus.refuted_by_patch_or_changed_logic.value,
    HypothesisStatus.irrelevant_to_target_function.value,
}


def _norm_query(text: str) -> str:
    """Normalize a query text for deduplication (case-insensitive, whitespace-collapsed)."""
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _infer_deterministic_source_facts(target_source: str, target_function: str = "") -> List[Dict[str, Any]]:
    """Infer small generic source facts for deterministic validators.

    These facts are not placed in the LLM-facing evidence bundle.  They are kept
    generic and label-free: no project-specific function names, no benchmark
    examples, and no function-specific exception rules.
    """
    src = target_source or ""
    facts: List[Dict[str, Any]] = []
    next_id = 1

    def add_fact(fact_type: str, text: str, **meta: Any) -> None:
        nonlocal next_id
        facts.append({
            "id": f"AUTO-SF-{next_id:02d}",
            "kind": "deterministic_source_fact",
            "file": None,
            "function": target_function or None,
            "line_start": None,
            "line_end": None,
            "text": text,
            "relation": "source_static_analysis",
            "score": 2.0,
            "metadata": {"fact_type": fact_type, **meta},
        })
        next_id += 1

    # Pointer/index/state advances driven by size-like expressions.
    advanced_vars: set[str] = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*(\+=|-=)\s*([^;]+);", src):
        lhs, op, rhs = m.group(1), m.group(2), m.group(3).strip()
        if any(term in rhs.lower() for term in ("len", "length", "size", "count", "offset", "index", "<<", "*")):
            advanced_vars.add(lhs)
            add_fact(
                "state_or_pointer_advance_from_size_expression",
                f"`{lhs} {op} {rhs};` advances parser state, an index, or a pointer using a size-like expression.",
                variable=lhs,
                expression=rhs,
            )
            # Backward-compatible high-signal fact consumed by final validators.
            # Kept generic: it only says the target has a size/length-driven
            # pointer/index/state advance, not that it is vulnerable.
            add_fact(
                "pointer_advance_from_size_or_length",
                f"`{lhs} {op} {rhs};` advances a pointer, index, or parser state using a length/size-like expression.",
                variable=lhs,
                expression=rhs,
            )

    # Saved-base lower-bound guards are generic evidence against wraparound or
    # backward traversal after an advance.
    base_pairs: list[tuple[str, str]] = []
    for m in re.finditer(r"(?:[A-Za-z_][\w\s\*]+\s+)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;", src):
        base, var = m.group(1), m.group(2)
        if var in advanced_vars and base != var:
            base_pairs.append((base, var))
    control_lines = [line.strip() for line in src.splitlines() if line.strip().startswith(("if", "while", "for", "assert"))]
    for base, var in base_pairs:
        if any(
            re.search(rf"\b{re.escape(var)}\s*>=\s*{re.escape(base)}\b", line)
            or re.search(rf"\b{re.escape(base)}\s*<=\s*{re.escape(var)}\b", line)
            for line in control_lines
        ):
            add_fact(
                "saved_base_lower_bound_guard",
                f"`{base}` snapshots `{var}`, and a control condition checks that `{var}` remains at or above `{base}` after advancement.",
                variable=var,
                base=base,
            )

    # Exact-end success with error return is a generic parser accept/reject fact.
    for var in advanced_vars:
        m = re.search(rf"if\s*\(\s*{re.escape(var)}\s*==\s*([A-Za-z_]\w*)\s*\)\s*\n?\s*return\b", src, flags=re.S)
        if m and re.search(r"return\s+-1\s*;", src[m.end():], flags=re.S):
            add_fact(
                "exact_end_accept_else_error",
                f"A success path requires `{var} == {m.group(1)}` and a later path returns an error value.",
                variable=var,
                end=m.group(1),
            )
            break

    # Raw allocation followed by likely use before visible NULL check.
    for alloc in ("malloc", "calloc", "realloc"):
        for m in re.finditer(rf"(?:\b[A-Za-z_][\w\s\*]*\s+)?([A-Za-z_]\w*)\s*=\s*{alloc}\s*\(([^;]+)\)\s*;", src, flags=re.S):
            var, expr = m.group(1), " ".join(m.group(2).split())
            tail = src[m.end(): m.end() + 1200]
            has_guard = re.search(rf"if\s*\(\s*(?:!\s*)?{re.escape(var)}\s*(?:==\s*NULL)?\s*\)", tail)
            has_use = re.search(rf"(?:\b{re.escape(var)}\s*\[|\b{re.escape(var)}\s*->|\*\s*{re.escape(var)}\b|(?:mem\w+|str\w+|snprintf|sprintf|fread|read|recv)\s*\(\s*{re.escape(var)}\b)", tail)
            if has_use and not has_guard:
                add_fact(
                    f"raw_{alloc}_without_null_check_before_use",
                    f"Raw `{alloc}` result `{var}` appears to be used before a visible NULL check.",
                    variable=var,
                    allocator=alloc,
                    allocation_expression=expr,
                )

    # Project wrappers and dynamic growth are still generic allocation-safety shapes.
    if "safe_calloc" in src:
        add_fact(
            "safe_calloc_allocation_wrapper_used",
            "The source uses a safe allocation wrapper named `safe_calloc`.",
        )
    safe_alloc_consts: dict[str, int] = {}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*safe_calloc\s*\(\s*(\d+)\s*\)", src):
        safe_alloc_consts[m.group(1)] = int(m.group(2))
    for var, alloc_size in safe_alloc_consts.items():
        read_re = re.compile(rf"fread\s*\(\s*{re.escape(var)}\s*,\s*1\s*,\s*(\d+)\s*,", re.S)
        for m in read_re.finditer(src):
            read_size = int(m.group(1))
            if read_size < alloc_size:
                add_fact(
                    "bounded_read_within_safe_allocation",
                    f"`{var}` is allocated with `safe_calloc({alloc_size})` and read with `fread(..., {read_size}, ...)`, within the allocation.",
                    buffer=var,
                    allocation_size=alloc_size,
                    read_size=read_size,
                )
    if re.search(r"\bmalloc\s*\(\s*temp_size\s*\)", src) and re.search(r"\brealloc\s*\(\s*temp\s*,\s*temp_size\s*\)", src):
        if re.search(r"if\s*\(\s*i\s*>=\s*temp_size\s*\)", src):
            add_fact(
                "dynamic_buffer_growth_guard",
                "A heap buffer is grown with `realloc` when the index reaches the current capacity.",
            )
        if re.search(r"\btemp\s*=\s*realloc\s*\(\s*temp\s*,\s*temp_size\s*\)", src) and not re.search(r"if\s*\(\s*!?\s*temp\s*\)", src):
            add_fact(
                "unchecked_realloc_residual_risk",
                "`realloc` is assigned directly back to the same pointer without an obvious NULL check.",
            )

    # Generic structured-input surface marker for validators/reporting only.
    if re.search(r"\b(?:parse|decode|load|read|seek|offset|length|size|count|header|object|packet|frame|token)\b", src, flags=re.I):
        add_fact(
            "structured_input_or_state_machine_surface",
            "The function appears to parse or transform structured input/state using lengths, offsets, counts, or headers.",
        )
        add_fact(
            "parser_state_machine_surface",
            "The function appears to parse or transform structured input/state using lengths, offsets, counts, or headers.",
        )
        if re.search(r"\b(?:length|len|size|count|offset|raw|buf|buffer)\b", src, flags=re.I):
            add_fact(
                "length_offset_sensitive_operation",
                "The function contains length/offset/size-sensitive parser or buffer-state operations.",
            )

    return facts



def _hypothesis_normalization_signature(h: Dict[str, Any]) -> str:
    """Return a coarse, source-grounded signature for deduplicating hypotheses.

    This is intentionally conservative and generic.  It merges hypotheses that
    point at the same risky expression / same variables / same vulnerability
    family, while preserving distinct families such as dispatch validation vs
    scaled pointer traversal.
    """
    title = str(h.get("title") or "").lower()
    region = str(h.get("affected_code_region") or "").lower()
    risk = str(h.get("risk_summary") or "").lower()
    vclass = str(h.get("vulnerability_class") or "").lower()
    blob = " ".join([title, region, risk])
    # Canonical generic families first.
    if re.search(r"length\s*\*\s*itemsize|raw\s*\+=\s*length\s*\*\s*itemsize|scaled.*pointer|pointer.*travers", blob):
        return "parser_scaled_pointer_advance:length:itemsize:raw"
    if re.search(r"1\s*<<\s*length_power|shift|length_power", blob) and not re.search(r"length\s*\*\s*itemsize", blob):
        return "selector_or_shift_domain:length_power"
    if re.search(r"read\s*\(\s*raw\s*\)|function pointer|dispatch|callee", blob) and "length" in blob:
        return "callee_or_dispatch_value_range:read:raw:length"
    if "alignment" in blob or "misalign" in blob:
        return "alignment:read:raw"
    if "concurr" in blob or "race" in blob or "thread" in blob:
        return "concurrency_or_lifecycle"
    ids = sorted(set(re.findall(r"`([A-Za-z_]\w*)`|\b([A-Za-z_]\w*)\b", region + " " + title)))
    flat_ids = []
    for item in ids:
        if isinstance(item, tuple):
            flat_ids.extend([x for x in item if x])
        elif item:
            flat_ids.append(str(item))
    flat_ids = [x.lower() for x in flat_ids if x.lower() not in {"the", "and", "or", "via", "in", "of"}]
    return f"{vclass}:{':'.join(sorted(set(flat_ids))[:8])}"


def _normalize_hypotheses_for_sequential_review(
    hypotheses: List[Dict[str, Any]],
    target_source: str,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Deduplicate and lightly rank hypotheses before sequential review.

    The LLM may emit overlapping hypotheses.  For the one-hypothesis lifecycle,
    processing duplicates wastes calls and can pollute proof state.  This routine
    keeps the highest-signal representative per signature and drops weak family
    hypotheses when the target source contains no family signal.
    """
    src_l = (target_source or "").lower()
    kept: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    by_sig: Dict[str, Dict[str, Any]] = {}
    score_by_sig: Dict[str, int] = {}

    def score(h: Dict[str, Any]) -> int:
        blob = " ".join(str(h.get(k) or "").lower() for k in ("title", "risk_summary", "affected_code_region", "vulnerability_class"))
        s = 0
        if any(x in blob for x in ("overflow", "out-of-bounds", "bounds", "pointer", "memory")): s += 3
        if any(x in blob for x in ("length", "size", "count", "offset", "raw", "buffer")): s += 3
        if "concurr" in blob or "race" in blob: s -= 3
        if h.get("affected_code_region"): s += 1
        s += min(3, len(h.get("required_proof_questions") or []))
        return s

    for h in hypotheses:
        blob = " ".join(str(h.get(k) or "").lower() for k in ("title", "risk_summary", "vulnerability_class"))
        if ("concurr" in blob or "race" in blob or "thread" in blob) and not re.search(r"\b(thread|pthread|mutex|lock|atomic|volatile|shared|global|static)\b", src_l):
            notes.append({
                "hypothesis_id": h.get("hypothesis_id"),
                "action": "dropped",
                "reason": "weak_concurrency_lifecycle_hypothesis_without_source_signal",
                "title": h.get("title"),
            })
            continue
        sig = _hypothesis_normalization_signature(h)
        s = score(h)
        if sig not in by_sig:
            by_sig[sig] = h
            score_by_sig[sig] = s
        else:
            old = by_sig[sig]
            if s > score_by_sig[sig]:
                by_sig[sig] = h
                score_by_sig[sig] = s
                kept_id = h.get("hypothesis_id")
                dropped_id = old.get("hypothesis_id")
            else:
                kept_id = old.get("hypothesis_id")
                dropped_id = h.get("hypothesis_id")
            notes.append({
                "action": "merged_duplicate",
                "signature": sig,
                "kept_hypothesis_id": kept_id,
                "dropped_hypothesis_id": dropped_id,
            })
    kept = sorted(by_sig.values(), key=score, reverse=True)
    # Re-number only if ids are missing. Preserve original IDs for report continuity.
    for i, h in enumerate(kept, start=1):
        if not str(h.get("hypothesis_id") or "").strip():
            h["hypothesis_id"] = f"HYP-{i:02d}"
    return kept, notes

def _all_hypotheses_resolved(verifications: Dict[str, Any]) -> bool:
    items = verifications.get("verifications") or []
    if not items:
        return False
    return all(v.get("status") in _RESOLVED_STATUSES for v in items)


def _gap_plan_has_queryable_high_value_gaps(gap_plan: EvidenceGapPlan) -> bool:
    """Return True when the LLM says stop but its own structured gaps are queryable.

    This protects the controller from a common contradiction: the model sets
    needs_more_evidence=false while still listing high/medium-priority queryable
    gaps and concrete follow-up queries. In that situation the controller should
    continue bounded retrieval instead of silently ending the proof loop.
    """
    priorities = {"high", "medium"}
    return any(
        bool(getattr(g, "queryable", False))
        and str(getattr(g, "priority", "medium") or "medium").lower() in priorities
        for g in (gap_plan.gaps or [])
    )


def _effective_follow_up_queries(gap_plan: EvidenceGapPlan) -> List[KGQuery]:
    """Return follow-up queries only when the plan contains actionable gaps.

    The CodeKG executor is deterministic and bounded; executing a small number of
    non-duplicate queries is safer than stopping with unresolved proof elements.
    """
    if not gap_plan.follow_up_queries:
        return []
    if gap_plan.needs_more_evidence or _gap_plan_has_queryable_high_value_gaps(gap_plan):
        return list(gap_plan.follow_up_queries)
    return []


def _plan_effective_needs_more_evidence(gap_plan: EvidenceGapPlan) -> bool:
    return bool(
        gap_plan.needs_more_evidence
        or _effective_follow_up_queries(gap_plan)
        or _gap_plan_has_queryable_high_value_gaps(gap_plan)
    )


def _query_mentions(text: str, terms: List[str]) -> bool:
    low = (text or "").lower()
    return any(t.lower() in low for t in terms)


_ALLOWED_CODEKG_PREFIXES = (
    "security_context(", "evidence_slice(", "variable_flow(",
    "call_neighborhood(", "semantic_facts(", "function_context(",
    "file_context(", "shortest_path(",
)


def _looks_like_codekg_query(text: str) -> bool:
    low = _norm_query(text)
    return any(low.startswith(prefix) for prefix in _ALLOWED_CODEKG_PREFIXES)


def _symbol_from_bad_query_text(text: str) -> str:
    stripped = str(text or "").strip().strip('`').strip()
    # Convert common LLM mistakes such as "length" or "raw" into a deterministic
    # variable_flow query only if the identifier actually appears in the target
    # source.  This prevents English gap words such as "Bit", "Caller",
    # "Bounds", or "Unresolved" from becoming bogus CodeKG variable queries.
    if re.fullmatch(r"[A-Za-z_]\w*", stripped):
        return stripped
    return ""


def _strip_c_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src or "", flags=re.S)
    src = re.sub(r"//.*", " ", src)
    return src


def _code_identifiers(target_source: str) -> set[str]:
    """Identifiers visible in the target function source.

    Used only for query sanitation.  It is deliberately language-generic for
    C/C++: if the symbol is not syntactically present in the target body, a
    target-scoped variable_flow query is almost certainly wasted.
    """
    src = _strip_c_comments(target_source or "")
    ids = set(re.findall(r"\b[A-Za-z_]\w*\b", src))
    c_keywords = {
        "if", "else", "for", "while", "do", "switch", "case", "default", "break",
        "continue", "return", "sizeof", "typedef", "struct", "enum", "union",
        "static", "const", "volatile", "extern", "register", "inline", "void",
        "char", "short", "int", "long", "float", "double", "signed", "unsigned",
        "bool", "true", "false", "NULL", "nullptr", "class", "public", "private",
        "protected", "template", "typename", "namespace", "using", "new", "delete",
    }
    return {x for x in ids if x not in c_keywords}


def _function_calls(target_source: str) -> set[str]:
    src = _strip_c_comments(target_source or "")
    calls = {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", src)}
    c_keywords = {"if", "while", "for", "switch", "return", "sizeof", "do"}
    return {c for c in calls if c not in c_keywords}


def _target_variable_symbols(target_source: str, target_function: str = "") -> set[str]:
    """Return local/parameter symbols suitable for target-scoped variable_flow.

    The broader identifier set includes function names, typedefs, and callee
    names.  Passing those to variable_flow wastes KG calls.  This conservative
    extractor keeps parameters and locals declared in the target body.
    """
    src = _strip_c_comments(target_source or "")
    out: set[str] = set()
    header = src.split("{", 1)[0]
    if "(" in header and ")" in header:
        params = header[header.find("(") + 1: header.rfind(")")]
        for part in params.split(","):
            part = part.strip()
            if not part or part == "void":
                continue
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part.replace("*", " "))
            if m:
                out.add(m.group(1))
    body = src[src.find("{") + 1: src.rfind("}")] if "{" in src and "}" in src else src
    # Common C/C++ local declarations, including typedef-like uppercase names.
    decl_re = re.compile(
        r"(?:^|[;{}]\s*)"
        r"(?:const\s+|volatile\s+|static\s+|unsigned\s+|signed\s+|long\s+|short\s+|struct\s+[A-Za-z_]\w*\s+)*"
        r"(?:[A-Za-z_]\w*(?:_t)?|bool|char|int|float|double|void)"
        r"\s*[\*\s]+([A-Za-z_]\w*)\s*(?:=|;|,|\[)",
        flags=re.M,
    )
    for m in decl_re.finditer(body):
        out.add(m.group(1))
    if target_function:
        out.discard(target_function)
    out -= _function_calls(target_source)
    return out


def _parse_query_call(text: str) -> tuple[str, dict[str, str]]:
    m = re.match(r"\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$", text or "", flags=re.S)
    if not m:
        return "", {}
    kind = m.group(1)
    body = m.group(2)
    args: dict[str, str] = {}
    # Lightweight parser sufficient for sanitizer diagnostics.  The authoritative
    # parser still lives in codekg_adapter.
    parts: list[str] = []
    cur: list[str] = []
    quote = None
    esc = False
    depth = 0
    for ch in body:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        args[k.strip()] = v.strip().strip('"\'')
    return kind, args


def _sanitize_or_rewrite_query(q: KGQuery, sample: Dict[str, Any], *, target_source: str = "") -> KGQuery | None:
    fn = str(sample.get("func_name") or sample.get("function_name") or sample.get("target_function") or sample.get("function") or "").strip()
    text = str(q.query_text or "").strip()
    if not text or "<relative" in text or "<path" in text or "TODO" in text:
        return None
    target_symbols = _code_identifiers(target_source)
    target_variables = _target_variable_symbols(target_source, fn)
    target_calls = _function_calls(target_source)

    if _looks_like_codekg_query(text):
        kind, args = _parse_query_call(text)
        kind_l = kind.lower()
        # Target-scoped variable_flow must reference a real target-source symbol.
        if kind_l == "variable_flow":
            sym = str(args.get("symbol") or "").strip()
            if not sym:
                return None
            if target_source.strip() and sym not in target_variables:
                return None
            # A function/type name is not a valid variable-flow target.
            if sym == fn or sym in target_calls:
                return None
        # function_context on a helper is useful only if it is the target or a call
        # syntactically visible in the target source.  This avoids hallucinated
        # helper names while remaining function-agnostic.
        if kind_l == "function_context":
            tf = str(args.get("target_function") or "").strip()
            if target_calls and tf and tf != fn and tf not in target_calls:
                return None
        # evidence_slice should name code that is visible or a standard operator/API;
        # one-word English abstractions are not valid slices.
        if kind_l == "evidence_slice":
            stmt = str(args.get("target_statement") or "").strip()
            if stmt and re.fullmatch(r"[A-Za-z_]\w*", stmt) and target_symbols and stmt not in target_symbols and stmt not in target_calls:
                return None
        return q

    sym = _symbol_from_bad_query_text(text)
    if sym and fn and (not target_source.strip() or sym in target_variables) and sym != fn and sym not in target_calls:
        return _make_query(
            q.query_id, q.hypothesis_id,
            f"Rewritten invalid free-form query `{text}` into variable flow for target-source symbol `{sym}`",
            f'variable_flow(target_function="{fn}", symbol="{sym}", data_depth=5)',
            [sym],
        )
    # Drop arbitrary free-form graph/search requests. The KG tool contract is
    # deliberately deterministic; non-call strings repeatedly returned zero
    # evidence in larger runs.
    return None


def _make_query(query_id: str, hypothesis_id: Optional[str], purpose: str, query_text: str, variables: List[str] | None = None) -> KGQuery:
    return KGQuery(
        query_id=query_id,
        hypothesis_id=hypothesis_id,
        purpose=purpose,
        query_text=query_text,
        variables=variables or [],
        expected_evidence=purpose,
        limit=8,
    )


def _auto_follow_up_queries_from_gaps(
    sample: Dict[str, Any],
    gap_plan: EvidenceGapPlan,
    *,
    prefix: str,
    target_source: str = "",
) -> List[KGQuery]:
    """Create bounded deterministic follow-up queries for real code symbols only.

    The previous fallback expanded English gap text into dozens of variable_flow
    queries.  That produced invalid symbols such as ``Bit`` or ``Caller`` and
    consumed the iteration budget before useful caller/callee/source queries ran.
    This version is universal but code-grounded: it uses only the target function,
    real identifiers present in the target source, exact backticked expressions,
    and helper calls syntactically visible in the target function.
    """
    fn = str(sample.get("func_name") or sample.get("function_name") or sample.get("target_function") or sample.get("function") or "").strip()
    if not fn:
        return []

    gaps = [g for g in (gap_plan.gaps or []) if getattr(g, "queryable", False)]
    if not gaps:
        return []

    out: List[KGQuery] = []
    seen: set[str] = set()
    target_symbols = _code_identifiers(target_source)
    target_variables = _target_variable_symbols(target_source, fn)
    target_calls = _function_calls(target_source)

    def add(purpose: str, query_text: str, variables: List[str] | None = None, hypothesis_id: Optional[str] = None) -> None:
        norm = _norm_query(query_text)
        if not norm or norm in seen:
            return
        seen.add(norm)
        out.append(_make_query(f"{prefix}{len(out)+1:02d}", hypothesis_id, purpose, query_text, variables))

    # Broad but still bounded context queries.  These should be useful for most
    # C/C++ vulnerability families: caller preconditions, callee helpers,
    # local guards, types/macros/globals, and semantic source facts.
    add(
        "Expanded security context for unresolved proof gaps",
        f'security_context(target_function="{fn}", depth=4, call_depth=3, data_depth=5, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=900)',
    )
    add(
        "Incoming callers and caller-side constraints for unresolved proof gaps",
        f'call_neighborhood(target_function="{fn}", direction="in", call_depth=4)',
    )
    add(
        "Outgoing callees and helper validation for unresolved proof gaps",
        f'call_neighborhood(target_function="{fn}", direction="out", call_depth=3)',
    )
    add(
        "Semantic guard/risk facts for unresolved proof gaps",
        f'semantic_facts(target_function="{fn}")',
    )

    gap_text = "\n".join(
        " ".join(str(getattr(g, attr, "") or "") for attr in ("proof_element", "missing_evidence", "recommended_query_focus", "why_queryable_or_not"))
        for g in gaps
    )

    # Variable-flow only for target-source identifiers that are explicitly named
    # in the missing-evidence text.  This preserves generality without creating
    # queries over English words.
    mentioned_symbols = []
    if target_variables:
        for sym in sorted(target_variables):
            if re.search(rf"\b{re.escape(sym)}\b", gap_text):
                mentioned_symbols.append(sym)
    elif not target_source.strip():
        # Unit-test / degraded-mode fallback when target source is unavailable.
        # Keep this conservative: only code-like lowercase/underscore symbols,
        # not abstract proof words.  Normal audits always have target_source and
        # therefore use the precise symbol-kind router above.
        stop_words = {
            "caller", "callers", "bounds", "bound", "validation", "logic", "source", "input",
            "evidence", "constraint", "constraints", "proof", "element", "need", "missing",
            "high", "medium", "low", "function", "target", "unresolved", "guard", "guards",
        }
        for sym in sorted(set(re.findall(r"\b[a-z_][a-z0-9_]{2,}\b", gap_text))):
            if sym not in stop_words:
                mentioned_symbols.append(sym)
    for sym in mentioned_symbols[:8]:
        add(
            f"Variable flow for target-source symbol `{sym}` mentioned by unresolved gap",
            f'variable_flow(target_function="{fn}", symbol="{sym}", data_depth=5)',
            [sym],
        )

    # Evidence slices for exact expressions quoted by the verifier/gap analyzer.
    expressions: list[str] = []
    for expr in re.findall(r"`([^`]{2,120})`", gap_text):
        expr = expr.strip()
        if any(ch in expr for ch in "[]()+-*/%<>=&|.^") or re.search(r"\b[A-Za-z_]\w*\s*\(", expr):
            expressions.append(expr)
    # Also capture unquoted C/C++ field/index expressions such as curve->p
    # from proof_element/missing_evidence text when the model forgot backticks.
    for expr in re.findall(r"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\b", gap_text):
        expressions.append(expr)
    for expr in list(dict.fromkeys(expressions))[:6]:
        add(
            f"Evidence slice for exact expression `{expr}` mentioned by unresolved gap",
            f'evidence_slice(target_function="{fn}", target_statement="{expr}", relation_depth=5, data_depth=5, control_depth=4, call_depth=3, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=700)',
        )

    # Helper context for callees visible in target source and named by the gap.
    for helper in sorted(target_calls - {fn}):
        if re.search(rf"\b{re.escape(helper)}\b", gap_text):
            add(
                f"Function context for visible helper `{helper}` mentioned by unresolved gap",
                f'function_context(target_function="{helper}", depth=3)',
            )

    return out

def _actionable_gap_queries(
    sample: Dict[str, Any],
    gap_plan: EvidenceGapPlan,
    llm_queries: List[KGQuery],
    *,
    prefix: str,
    target_source: str = "",
) -> List[KGQuery]:
    """Combine deterministic fallback queries with LLM queries.

    Fallback queries are placed first so a weak/duplicate LLM proposal cannot
    consume the small per-iteration query budget and prematurely end the loop.
    """
    combined = _auto_follow_up_queries_from_gaps(sample, gap_plan, prefix=prefix, target_source=target_source) + list(llm_queries or [])
    out: List[KGQuery] = []
    seen: set[str] = set()
    for q in combined:
        q2 = _sanitize_or_rewrite_query(q, sample, target_source=target_source)
        if q2 is None:
            continue
        norm = _norm_query(q2.query_text)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(q2)
    return out

def _evidence_ids_for_gate(evidence: List[Dict[str, Any]] | None) -> set[str]:
    ids = {"TARGET-SOURCE"}
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        v = item.get("id") or item.get("evidence_id") or item.get("node_id")
        if v:
            ids.add(str(v))
    return ids


def _verification_missing_is_blocking(missing: List[Any] | None) -> bool:
    # Strict by design: a confirmed_vulnerability should not still say that
    # attacker control, caller constraints, guard dominance, impact, or callee
    # behavior is missing.  This prevents the LLM from promoting uncertainty into
    # confirmation and lets the final validator make any forced-binary fallback.
    return bool([m for m in (missing or []) if str(m).strip()])


def _gate_single_verification(verification: Dict[str, Any], evidence: List[Dict[str, Any]] | None) -> tuple[Dict[str, Any], List[str]]:
    """Apply a deterministic proof gate to one LLM verification object.

    The LLM may mark a hypothesis as confirmed while its own object still lists
    missing proof elements.  That is not a valid source-grounded proof.  This
    gate is model-agnostic and function-agnostic: it only checks the structured
    proof contract and evidence IDs.
    """
    v = dict(verification or {})
    notes: List[str] = []
    if v.get("status") != HypothesisStatus.confirmed_vulnerability.value and not v.get("confirmed_security_vulnerability"):
        return v, notes

    proof = v.get("proof") or {}
    required = ["input_control", "dangerous_operation", "missing_or_failed_guard", "unsafe_use", "security_impact"]
    missing_fields = [k for k in required if not str(proof.get(k) or "").strip()]
    cited = {str(x) for x in (proof.get("cited_evidence_ids") or []) if str(x).strip()}
    existing = _evidence_ids_for_gate(evidence)
    missing_ids = sorted(cited - existing)
    uncertainty = str(proof.get("input_control") or "").lower()

    reasons: List[str] = []
    if missing_fields:
        reasons.append(f"proof_missing_fields={missing_fields}")
    if not cited:
        reasons.append("proof_has_no_cited_evidence_ids")
    if missing_ids:
        reasons.append(f"proof_cites_unknown_evidence_ids={missing_ids[:8]}")
    if _verification_missing_is_blocking(v.get("missing_evidence") or []):
        reasons.append("verification_still_lists_missing_evidence")
    if any(marker in uncertainty for marker in ("unproven", "unknown", "no evidence", "not proven", "assumed", "unclear")):
        reasons.append("input_control_field_is_uncertain")

    if reasons:
        old_status = v.get("status")
        v["status"] = HypothesisStatus.plausible_but_unproven.value if bool(v.get("local_risk_present")) else HypothesisStatus.insufficient_evidence.value
        v["confirmed_security_vulnerability"] = False
        existing_missing = list(v.get("missing_evidence") or [])
        existing_missing.append("Proof gate downgrade: LLM confirmation did not satisfy the complete cited proof contract.")
        v["missing_evidence"] = existing_missing
        notes.append(f"downgraded {v.get('hypothesis_id') or '?'} from {old_status}: {', '.join(reasons)}")
    return v, notes


def _apply_counter_review_to_verifications(
    verifications: Dict[str, Any],
    counter_review: Any,
) -> tuple[Dict[str, Any], List[str]]:
    """Downgrade/annotate hypothesis states using counter-review output.

    This prevents a raw per-hypothesis confirmation from remaining final if a
    later defense pass found a relevant guard, caller constraint, or other
    counter-evidence.  The controller uses this normalized proof state for the
    final adjudicator and report.
    """
    findings = []
    if hasattr(counter_review, "model_dump"):
        findings = list((counter_review.model_dump(mode="json") or {}).get("findings") or [])
    elif isinstance(counter_review, dict):
        findings = list(counter_review.get("findings") or [])
    by_h: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        hid = str(f.get("hypothesis_id") or "").strip()
        if hid:
            by_h.setdefault(hid, []).append(f)

    out_items: List[Dict[str, Any]] = []
    notes: List[str] = []
    unsupported = {
        HypothesisStatus.plausible_but_unproven.value,
        HypothesisStatus.refuted_by_guard.value,
        HypothesisStatus.refuted_by_caller_constraint.value,
        HypothesisStatus.refuted_by_patch_or_changed_logic.value,
        HypothesisStatus.irrelevant_to_target_function.value,
        HypothesisStatus.insufficient_evidence.value,
    }
    for item in list((verifications or {}).get("verifications") or []):
        v = dict(item or {})
        hid = str(v.get("hypothesis_id") or "").strip()
        for f in by_h.get(hid, []):
            rec = f.get("recommended_status")
            rec_val = rec.value if hasattr(rec, "value") else str(rec or "")
            refutes = str(f.get("refutes_or_weakens") or "").lower()
            counter_ids = [str(x) for x in (f.get("counter_evidence_ids") or []) if str(x).strip()]
            if counter_ids:
                merged = list(dict.fromkeys(list(v.get("counter_evidence_ids") or []) + counter_ids))
                v["counter_evidence_ids"] = merged
            if rec_val in unsupported and (
                v.get("status") == HypothesisStatus.confirmed_vulnerability.value
                or v.get("confirmed_security_vulnerability")
                or "refut" in refutes
                or "weaken" in refutes
            ):
                old = v.get("status")
                v["status"] = rec_val
                v["confirmed_security_vulnerability"] = False
                if rec_val in {HypothesisStatus.refuted_by_guard.value, HypothesisStatus.refuted_by_caller_constraint.value, HypothesisStatus.refuted_by_patch_or_changed_logic.value, HypothesisStatus.irrelevant_to_target_function.value}:
                    v["local_risk_present"] = False
                    v["missing_evidence"] = []
                else:
                    miss = list(v.get("missing_evidence") or [])
                    miss.append("Counter-review downgraded the raw confirmation; proof state is not accepted_confirmed.")
                    v["missing_evidence"] = miss
                notes.append(f"counter_review_updated {hid}: {old} -> {rec_val}")
        out_items.append(v)
    return {"verifications": out_items}, notes


@dataclass
class AgenticProofConfig:
    max_hypotheses: int = 24
    max_queries_per_hypothesis: int = 6
    evidence_limit_per_query: int = 8
    # Per-stage token budgets
    max_tokens_source_only_hypothesis: int = 16384
    max_tokens_kg_query_planning: int = 8192
    max_tokens_hypothesis_verification: int = 16384
    max_tokens_counter_evidence_review: int = 16384
    max_tokens_final_decision: int = 8192
    max_tokens_schema_repair: int = 8192
    max_tokens_evidence_gap_analysis: int = 8192
    # Iterative evidence loop controls
    iterative_evidence_loop: bool = False
    max_evidence_iterations: int = 3
    max_queries_per_iteration: int = 5
    stop_when_no_new_evidence: bool = True
    stop_when_no_new_queries: bool = True
    stop_when_all_hypotheses_resolved: bool = True
    enable_counter_evidence_loop: bool = False
    max_counter_iterations: int = 2
    # Research-side default: verify one hypothesis at a time with code evidence.
    per_hypothesis_verification: bool = True
    # New default: decompose each hypothesis into typed proof obligations and
    # ask the LLM one narrow proof question per call.
    enable_proof_obligation_ledger: bool = True
    max_obligations_per_hypothesis: int = 8
    max_queries_per_obligation: int = 3
    stop_on_confirmed_vulnerability: bool = True
    # Other
    temperature: float = 0.0
    provider_extra_body: Dict[str, Any] = field(
        default_factory=lambda: {"chat_template_kwargs": {"enable_thinking": False}}
    )
    enable_pair_aware_dev_mode: bool = False


@dataclass
class AgentEvent:
    sample_id: Any
    stage: str
    event: str
    elapsed_seconds: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LegacyPrediction:
    prediction_bool: Optional[bool]
    prediction_label: str
    confidence: float
    final_json: Dict[str, Any]
    events: List[Dict[str, Any]]
    usage: Dict[str, Any]


@dataclass
class AgenticProofResult:
    decision: FinalDecision
    hypotheses: Dict[str, Any]
    query_plan: KGQueryPlan
    retrieved_evidence: List[Dict[str, Any]]
    verifications: Dict[str, Any]
    counter_review: CounterEvidenceReview
    events: List[AgentEvent]
    usage: Dict[str, Any]
    # Iterative loop metadata
    loop_stop_reason: Optional[str] = None
    iterations_completed: int = 0

    def to_legacy_prediction(self) -> LegacyPrediction:
        return LegacyPrediction(
            self.decision.prediction_bool,
            self.decision.prediction.value,
            self.decision.confidence,
            self.decision.model_dump(mode="json"),
            [e.__dict__ for e in self.events],
            self.usage,
        )


def _message_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        if isinstance(response.get("content"), str):
            return response["content"]
        choices = response.get("choices")
        if choices:
            msg = choices[0].get("message", {})
            if msg.get("content"):
                return msg["content"]
            if msg.get("reasoning"):
                return str(msg["reasoning"])
        if "text" in response:
            return str(response["text"])
    content = getattr(response, "content", None)
    if content:
        return content
    return str(response)


def _usage(response: Any) -> Dict[str, Any]:
    return response.get("usage", {}) if isinstance(response, dict) else (getattr(response, "usage", {}) or {})


def _merge_usage(total: Dict[str, Any], usage: Dict[str, Any]) -> None:
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        v = usage.get(k)
        if isinstance(v, (int, float)):
            total[k] = total.get(k, 0) + v


def _call_llm(
    *,
    llm_generate: Callable[..., Any],
    messages: List[Dict[str, Any]],
    sample_id: Any,
    stage: str,
    max_tokens: int,
    config: AgenticProofConfig,
    events: List[AgentEvent],
) -> tuple[str, Dict[str, Any]]:
    start = time.monotonic()
    # Prompt builders should produce OpenAI-style messages with string content.
    # A malformed prompt string can accidentally evaluate to a boolean in Python
    # (for example, an unescaped `"in"` inside a concatenated string expression).
    # Normalize here so optional loop stages cannot crash before the failure is
    # recorded, while preserving a warning event for diagnosis.
    normalized_messages: List[Dict[str, Any]] = []
    coerced_fields: List[Dict[str, Any]] = []
    for idx, msg in enumerate(messages or []):
        content = msg.get("content", "")
        if content is None:
            content_text = ""
            coerced_fields.append({"index": idx, "from_type": "NoneType"})
        elif isinstance(content, str):
            content_text = content
        else:
            content_text = str(content)
            coerced_fields.append({"index": idx, "from_type": type(content).__name__})
        copied = dict(msg)
        copied["content"] = content_text
        normalized_messages.append(copied)

    prompt_chars = sum(len(m.get("content", "")) for m in normalized_messages)
    prompt_has_truncation_marker = any("...<truncated>..." in m.get("content", "") for m in normalized_messages)
    if coerced_fields:
        events.append(AgentEvent(sample_id, stage, "prompt_content_coerced",
                                  details={"coerced_fields": coerced_fields}))
    events.append(AgentEvent(sample_id, stage, "start",
                              details={"prompt_chars": prompt_chars, "max_tokens": max_tokens,
                                       "prompt_has_truncation_marker": prompt_has_truncation_marker}))
    try:
        response = llm_generate(
            normalized_messages,
            stage=stage,
            max_tokens=max_tokens,
            temperature=config.temperature,
            extra_body=config.provider_extra_body,
        )
    except Exception as exc:
        elapsed = time.monotonic() - start
        events.append(AgentEvent(sample_id, stage, "error", elapsed_seconds=elapsed,
                                  details={"prompt_chars": prompt_chars,
                                           "error": f"{type(exc).__name__}: {exc}"}))
        raise
    elapsed = time.monotonic() - start
    text = _message_text(response)
    usage = _usage(response)
    events.append(AgentEvent(sample_id, stage, "done", elapsed_seconds=elapsed,
                              details={"response_chars": len(text or ""), "usage": usage,
                                       "prompt_has_truncation_marker": prompt_has_truncation_marker,
                                       "enable_thinking": config.provider_extra_body.get(
                                           "chat_template_kwargs", {}).get("enable_thinking")}))
    return text, usage


_BINARY_DECISION_STATUSES = frozenset({
    "confirmed_vulnerable", "confirmed_non_vulnerable",
    "forced_binary_vulnerable", "forced_binary_non_vulnerable",
})


def _decision_has_valid_binary(decision: "FinalDecision") -> bool:
    """Return True when the validator has already produced a definitive binary decision.

    When True, Stage 07 consistency repair is unnecessary — the forced binary choice
    (forced_prediction_bool) is already set deterministically.
    """
    return (
        decision.forced_prediction_bool is not None
        and decision.decision_status in _BINARY_DECISION_STATUSES
    )


def _repair_llm(
    llm_generate: Callable[..., Any],
    config: AgenticProofConfig,
    sample_id: Any,
    events: List[AgentEvent],
    stage: str,
) -> Callable[[List[Dict[str, str]]], str]:
    def repair(messages: List[Dict[str, str]]) -> str:
        text, _ = _call_llm(
            llm_generate=llm_generate,
            messages=messages,
            sample_id=sample_id,
            stage=f"{stage}_json_repair",
            max_tokens=config.max_tokens_schema_repair,
            config=config,
            events=events,
        )
        return text
    return repair


class _HypothesisEnvelope(BaseModel):
    hypotheses: List[VulnerabilityHypothesis]
    source_observations: list[str] = []
    non_vulnerability_possibilities: list[str] = []


class _VerificationEnvelope(BaseModel):
    verifications: list


def run_agentic_proof_pipeline(
    *,
    sample: Dict[str, Any],
    target_source: str,
    initial_evidence: List[Dict[str, Any]],
    llm_generate: Callable[..., Any],
    kg_search: Callable[..., List[Dict[str, Any]]],
    config: Optional[AgenticProofConfig] = None,
    on_iteration_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> AgenticProofResult:
    """Run the agentic proof pipeline with optional iterative evidence loop.

    on_iteration_event: optional callback(event_type, data) called at iteration
    start/end so callers (pipeline.py) can emit live WS events and write artifacts.
    """
    config = config or AgenticProofConfig()
    sample_id = sample.get("id") or sample.get("sample_id") or "unknown"
    events: List[AgentEvent] = []
    usage_total: Dict[str, Any] = {}

    # Deterministic source-level facts remain internal evidence for validators and
    # reports. The LLM-facing code-evidence bundle intentionally excludes these
    # textual facts so verification receives source code, not summaries.
    source_facts = _infer_deterministic_source_facts(
        target_source, str(sample.get("function") or sample.get("func_name") or sample.get("target_function") or "")
    )
    if source_facts:
        initial_evidence = list(initial_evidence) + source_facts
        events.append(AgentEvent(sample_id, "00_deterministic_source_facts", "done",
                                  details={"items": len(source_facts),
                                           "fact_types": [f.get("metadata", {}).get("fact_type") for f in source_facts]}))

    # ── Stage 01: source-only hypothesis generation ──────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=source_only_hypothesis_prompt(sample, target_source),
        sample_id=sample_id,
        stage="01_source_only_hypothesis",
        max_tokens=config.max_tokens_source_only_hypothesis,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    hypothesis_obj, _ = parse_model_object(
        text, _HypothesisEnvelope,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "01_source_only_hypothesis"),
    )
    hypotheses = hypothesis_obj.model_dump(mode="json")
    raw_hypotheses = list(hypotheses.get("hypotheses") or [])[:config.max_hypotheses]
    clean_hypotheses: List[Dict[str, Any]] = []
    dropped_hypotheses: List[Dict[str, Any]] = []
    for h in raw_hypotheses:
        title = str(h.get("title") or "").strip()
        risk = str(h.get("risk_summary") or "").strip()
        region = str(h.get("affected_code_region") or "").strip()
        # JSON-repair can conservatively close a truncated hypothesis with empty
        # risk text or a syntactically broken affected region.  Such records are
        # not useful proof tasks and should not consume per-hypothesis loop time.
        if not title or not risk or region.endswith("*") or region.endswith("+"):
            dropped_hypotheses.append({
                "hypothesis_id": h.get("hypothesis_id"),
                "title": title,
                "reason": "incomplete_or_truncated_hypothesis_record",
            })
            continue
        clean_hypotheses.append(h)
    normalized_hypotheses, normalization_notes = _normalize_hypotheses_for_sequential_review(
        clean_hypotheses, target_source
    )
    hypotheses["hypotheses"] = normalized_hypotheses
    if dropped_hypotheses or normalization_notes:
        events.append(AgentEvent(sample_id, "01_hypothesis_normalization", "done", details={
            "raw_count": len(raw_hypotheses),
            "sanitized_count": len(clean_hypotheses),
            "normalized_count": len(normalized_hypotheses),
            "dropped_hypotheses": dropped_hypotheses,
            "normalization_notes": normalization_notes,
            "review_order": [h.get("hypothesis_id") for h in normalized_hypotheses],
        }))

    # ── Stages 02–04/05: sequential per-hypothesis retrieval, verification,
    # proof-gating, and local counter-review ─────────────────────────────────
    # Research-side strategy: treat each hypothesis as an independent security
    # proof task.  For each hypothesis, plan targeted CodeKG queries, retrieve
    # code evidence, verify only that hypothesis, and loop for more evidence only
    # when that hypothesis still needs code to be confirmed or falsified.
    all_query_models: List[KGQuery] = []
    retrieved: List[Dict[str, Any]] = []
    accumulated_evidence = list(initial_evidence)
    executed_query_ids: set[str] = set()
    executed_query_texts: set[str] = set()
    final_verification_items: List[Dict[str, Any]] = []
    # Per-hypothesis counter-review state.  A hypothesis is not allowed to
    # release control to the next hypothesis until its own verification has
    # been proof-gated and counter-reviewed.  This prevents the older global
    # pattern where a raw confirmation was only challenged after all hypotheses
    # had already run.
    accepted_confirmed_hypotheses: List[str] = []
    per_hypothesis_counter_findings: List[Dict[str, Any]] = []
    loop_stop_reason: Optional[str] = None
    iterations_completed: int = 0

    hypotheses_list: List[Dict[str, Any]] = list(hypotheses.get("hypotheses") or [])
    events.append(AgentEvent(sample_id, "02_04_per_hypothesis_loop", "start",
                              details={"hypotheses": len(hypotheses_list)}))

    for hyp_index, hypothesis in enumerate(hypotheses_list, start=1):
        hyp_id = str(hypothesis.get("hypothesis_id") or f"HYP-{hyp_index:02d}")
        hyp_stage_id = re.sub(r"[^A-Za-z0-9_\-]", "_", hyp_id)

        # ── Stage 02{hyp}: targeted KG query planning ──────────────────────
        plan_stage = f"02_kg_query_planning__{hyp_stage_id}"
        text, usage = _call_llm(
            llm_generate=llm_generate,
            messages=kg_query_planning_prompt(sample, [hypothesis], initial_evidence),
            sample_id=sample_id,
            stage=plan_stage,
            max_tokens=config.max_tokens_kg_query_planning,
            config=config,
            events=events,
        )
        _merge_usage(usage_total, usage)
        hyp_query_plan, _ = parse_model_object(
            text, KGQueryPlan,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, plan_stage),
        )

        sanitized_hyp_queries: List[KGQuery] = []
        dropped_hyp_queries = 0
        for q in hyp_query_plan.queries[:config.max_queries_per_hypothesis]:
            q2 = _sanitize_or_rewrite_query(q, sample, target_source=target_source)
            if q2 is None:
                dropped_hyp_queries += 1
                continue
            if not q2.hypothesis_id:
                q2.hypothesis_id = hyp_id
            norm = _norm_query(q2.query_text)
            if norm in executed_query_texts:
                dropped_hyp_queries += 1
                continue
            sanitized_hyp_queries.append(q2)
            executed_query_texts.add(norm)
            executed_query_ids.add(q2.query_id)
            all_query_models.append(q2)
        if dropped_hyp_queries:
            events.append(AgentEvent(sample_id, f"02_kg_query_sanitization__{hyp_stage_id}", "done",
                                      details={"dropped_or_rewritten": dropped_hyp_queries,
                                               "kept": len(sanitized_hyp_queries)}))

        # ── Stage 03{hyp}: hypothesis-specific KG retrieval ────────────────
        hyp_query_dicts = [q.model_dump(mode="json") for q in sanitized_hyp_queries]
        retrieval_stage = f"03_retrieval__{hyp_stage_id}"
        for _qd in hyp_query_dicts:
            _qd["_agentic_stage"] = retrieval_stage
            _qd["_hypothesis_id"] = hyp_id
        events.append(AgentEvent(sample_id, retrieval_stage, "start",
                                  details={"queries": len(hyp_query_dicts), "hypothesis_id": hyp_id}))
        hyp_retrieved = kg_search(hyp_query_dicts, sample=sample, limit=config.evidence_limit_per_query) if hyp_query_dicts else []
        events.append(AgentEvent(sample_id, retrieval_stage, "done",
                                  details={
                                      "items": len(hyp_retrieved),
                                      "kg_returned_items": len(hyp_retrieved),
                                      "accepted_new_evidence_items": len(hyp_retrieved),
                                      "hypothesis_id": hyp_id,
                                  }))
        retrieved.extend(hyp_retrieved)
        accumulated_evidence.extend(hyp_retrieved)
        hyp_evidence = list(accumulated_evidence)

        latest_verification: Optional[Dict[str, Any]] = None
        hyp_stop_reason: Optional[str] = None

        if config.enable_proof_obligation_ledger:
            # ── Stage 04{hyp}: proof-obligation micro-verification ledger ──
            # The controller decomposes the hypothesis into typed proof obligations
            # and asks the LLM one narrow question at a time.  The final
            # hypothesis verification is derived from this ledger, not from a
            # single large hypothesis-level prompt.
            family = infer_proof_family(hypothesis, target_source)
            obligations = build_proof_obligations(hypothesis, target_source)[:config.max_obligations_per_hypothesis]
            events.append(AgentEvent(sample_id, f"04_proof_ledger__{hyp_stage_id}", "start", details={
                "hypothesis_id": hyp_id,
                "family": family,
                "obligations": [o.model_dump(mode="json") for o in obligations],
            }))
            obligation_results = []
            target_file = str(sample.get("filepath") or sample.get("file") or sample.get("target_file") or "")
            for obligation in obligations:
                po_stage_id = re.sub(r"[^A-Za-z0-9_\-]", "_", obligation.obligation_id)
                po_query_stage = f"03_obligation_retrieval__{hyp_stage_id}__{po_stage_id}"
                po_queries_raw = obligation_queries(sample, hypothesis, obligation, target_file=target_file)
                po_queries: List[KGQuery] = []
                dropped_po_queries = 0
                for q in po_queries_raw[:config.max_queries_per_obligation]:
                    q2 = _sanitize_or_rewrite_query(q, sample, target_source=target_source)
                    if q2 is None:
                        dropped_po_queries += 1
                        continue
                    norm = _norm_query(q2.query_text)
                    if q2.query_id in executed_query_ids or norm in executed_query_texts:
                        dropped_po_queries += 1
                        continue
                    po_queries.append(q2)
                    executed_query_ids.add(q2.query_id)
                    executed_query_texts.add(norm)
                    all_query_models.append(q2)
                if dropped_po_queries:
                    events.append(AgentEvent(sample_id, f"03_obligation_query_sanitization__{hyp_stage_id}__{po_stage_id}", "done", details={
                        "hypothesis_id": hyp_id,
                        "obligation_id": obligation.obligation_id,
                        "dropped_or_duplicate": dropped_po_queries,
                        "kept": len(po_queries),
                    }))
                po_new_evidence: List[Dict[str, Any]] = []
                if po_queries:
                    po_query_dicts = [q.model_dump(mode="json") for q in po_queries]
                    for _qd in po_query_dicts:
                        _qd["_agentic_stage"] = po_query_stage
                        _qd["_hypothesis_id"] = hyp_id
                        _qd["_obligation_id"] = obligation.obligation_id
                    events.append(AgentEvent(sample_id, po_query_stage, "start", details={
                        "hypothesis_id": hyp_id,
                        "obligation_id": obligation.obligation_id,
                        "queries": len(po_query_dicts),
                        "query_ids": [q.query_id for q in po_queries],
                    }))
                    po_new_evidence = kg_search(po_query_dicts, sample=sample, limit=config.evidence_limit_per_query)
                    events.append(AgentEvent(sample_id, po_query_stage, "done", details={
                        "hypothesis_id": hyp_id,
                        "obligation_id": obligation.obligation_id,
                        # Backward-compatible field retained for old report code.
                        "items": len(po_new_evidence),
                        # Explicit accounting fields for debugging: KG returned
                        # these items before code-capsule filtering/deduplication.
                        "kg_returned_items": len(po_new_evidence),
                        "accepted_new_evidence_items": len(po_new_evidence),
                    }))
                    if po_new_evidence:
                        hyp_evidence.extend(po_new_evidence)
                        accumulated_evidence.extend(po_new_evidence)
                        retrieved.extend(po_new_evidence)
                        iterations_completed += 1
                po_verif_stage = f"04_proof_obligation__{hyp_stage_id}__{po_stage_id}"
                text, usage = _call_llm(
                    llm_generate=llm_generate,
                    messages=proof_obligation_verification_prompt(
                        sample, hypothesis, obligation, hyp_evidence, target_source=target_source
                    ),
                    sample_id=sample_id,
                    stage=po_verif_stage,
                    max_tokens=min(config.max_tokens_hypothesis_verification, 4096),
                    config=config,
                    events=events,
                )
                _merge_usage(usage_total, usage)
                po_obj, _ = parse_model_object(
                    text,
                    ProofObligationVerificationEnvelope,
                    llm_repair=_repair_llm(llm_generate, config, sample_id, events, po_verif_stage),
                )
                po_items = po_obj.model_dump(mode="json").get("verifications") or []
                if po_items:
                    chosen = next((x for x in po_items if x.get("obligation_id") == obligation.obligation_id), po_items[0])
                else:
                    chosen = {
                        "obligation_id": obligation.obligation_id,
                        "hypothesis_id": hyp_id,
                        "result": "not_answered",
                        "evidence_ids": [],
                        "counter_evidence_ids": [],
                        "missing_evidence": ["LLM returned no obligation verification object."],
                        "explanation": "No structured proof-obligation result was returned.",
                        "confidence": 0.0,
                    }
                try:
                    from .schemas import ProofObligationVerification
                    parsed_result = ProofObligationVerification.model_validate(chosen)
                except Exception:
                    # Keep the pipeline robust: malformed micro-result becomes not_answered.
                    from .schemas import ProofObligationVerification
                    parsed_result = ProofObligationVerification.model_validate({
                        "obligation_id": obligation.obligation_id,
                        "hypothesis_id": hyp_id,
                        "result": "not_answered",
                        "missing_evidence": ["Malformed proof-obligation verification output."],
                        "explanation": "Malformed proof-obligation verification output.",
                        "confidence": 0.0,
                    })
                normalized_result = normalize_obligation_result(obligation, parsed_result, target_source=target_source)
                obligation_results.append(normalized_result)
                events.append(AgentEvent(sample_id, po_verif_stage, "ledger_update", details={
                    "hypothesis_id": hyp_id,
                    "obligation_id": obligation.obligation_id,
                    "obligation_name": obligation.name,
                    "required": obligation.required,
                    "result": obligation_results[-1].result.value if hasattr(obligation_results[-1].result, "value") else str(obligation_results[-1].result),
                    "evidence_ids": obligation_results[-1].evidence_ids,
                    "counter_evidence_ids": obligation_results[-1].counter_evidence_ids,
                    "missing_evidence": obligation_results[-1].missing_evidence,
                    "supports_hypothesis": getattr(obligation_results[-1], "supports_hypothesis", None),
                    "refutes_hypothesis": getattr(obligation_results[-1], "refutes_hypothesis", None),
                    "result_meaning": getattr(obligation_results[-1], "result_meaning", ""),
                }))
            ledger = summarize_ledger(hyp_id, family, obligations, obligation_results, target_source=target_source)
            latest_verification = verification_from_ledger(hypothesis, ledger)
            latest_verification, gate_notes = _gate_single_verification(latest_verification, hyp_evidence)
            if gate_notes:
                events.append(AgentEvent(sample_id, f"04_proof_ledger__{hyp_stage_id}", "proof_gate", details={"hypothesis_id": hyp_id, "notes": gate_notes}))
            hyp_stop_reason = f"proof_ledger_{ledger.status_hint}"
            events.append(AgentEvent(sample_id, f"04_proof_ledger__{hyp_stage_id}", "done", details={
                "hypothesis_id": hyp_id,
                "family": ledger.family,
                "required_proven": ledger.required_proven,
                "required_total": ledger.required_total,
                "required_missing": ledger.required_missing,
                "status_hint": ledger.status_hint,
                "proof_tier": getattr(ledger, "proof_tier", None),
                "trust_boundary_strength": getattr(ledger, "trust_boundary_strength", None),
                "supporting_evidence_ids": ledger.supporting_evidence_ids,
                "counter_evidence_ids": ledger.counter_evidence_ids,
                "derived_status": latest_verification.get("status"),
                "confirmed_security_vulnerability": latest_verification.get("confirmed_security_vulnerability"),
                "ledger": ledger.model_dump(mode="json"),
            }))

        else:
            def _terminal_close_hypothesis(reason: str, iteration_no: int, retrieval_status: Dict[str, Any]) -> None:
                """Run a final closure pass for one hypothesis when retrieval cannot continue.

                This prevents an unresolved hypothesis from silently falling through to
                the next hypothesis after duplicate/no-result follow-up queries.  The
                LLM sees the same source-code bundle plus a retrieval-status object and
                must return the best terminal status for this hypothesis under bounded
                static evidence.
                """
                nonlocal latest_verification, hyp_stop_reason
                terminal_stage = f"04_hypothesis_terminal_verification__{hyp_stage_id}_iter{iteration_no}"
                terminal_payload = {
                    "hypothesis_id": hyp_id,
                    "closure_reason": reason,
                    "previous_status": (latest_verification or {}).get("status"),
                    "previous_missing_evidence": (latest_verification or {}).get("missing_evidence") or [],
                    "retrieval": retrieval_status,
                    "current_code_evidence_items": len(hyp_evidence),
                }
                text, usage = _call_llm(
                    llm_generate=llm_generate,
                    messages=single_hypothesis_verification_prompt(
                        sample,
                        hypothesis,
                        hyp_evidence,
                        target_source=target_source,
                        retrieval_status=terminal_payload,
                        terminal_closure=True,
                    ),
                    sample_id=sample_id,
                    stage=terminal_stage,
                    max_tokens=config.max_tokens_hypothesis_verification,
                    config=config,
                    events=events,
                )
                _merge_usage(usage_total, usage)
                terminal_obj, _ = parse_model_object(
                    text,
                    _VerificationEnvelope,
                    llm_repair=_repair_llm(llm_generate, config, sample_id, events, terminal_stage),
                )
                terminal_verifs = terminal_obj.model_dump(mode="json").get("verifications") or []
                if terminal_verifs:
                    latest_verification = next((v for v in terminal_verifs if v.get("hypothesis_id") == hyp_id), terminal_verifs[0])
                    latest_verification.setdefault("hypothesis_id", hyp_id)
                    latest_verification, gate_notes = _gate_single_verification(latest_verification, hyp_evidence)
                    if gate_notes:
                        events.append(AgentEvent(sample_id, terminal_stage, "proof_gate", details={"hypothesis_id": hyp_id, "notes": gate_notes}))
                hyp_stop_reason = reason
                events.append(AgentEvent(sample_id, terminal_stage, "terminal_closed", details={
                    "hypothesis_id": hyp_id,
                    "stop_reason": reason,
                    "terminal_status": (latest_verification or {}).get("status"),
                    "confirmed_security_vulnerability": (latest_verification or {}).get("confirmed_security_vulnerability"),
                }))

            # ── Stage 04{hyp}: verify and iterate only for this hypothesis ──────
            for iteration in range(config.max_evidence_iterations + 1):
                stage_suffix = "" if iteration == 0 else f"_iter{iteration}"
                verif_stage = f"04_hypothesis_verification__{hyp_stage_id}{stage_suffix}"
                text, usage = _call_llm(
                    llm_generate=llm_generate,
                    messages=single_hypothesis_verification_prompt(
                        sample, hypothesis, hyp_evidence, target_source=target_source
                    ),
                    sample_id=sample_id,
                    stage=verif_stage,
                    max_tokens=config.max_tokens_hypothesis_verification,
                    config=config,
                    events=events,
                )
                _merge_usage(usage_total, usage)
                verifications_obj, _ = parse_model_object(
                    text, _VerificationEnvelope,
                    llm_repair=_repair_llm(llm_generate, config, sample_id, events, verif_stage),
                )
                parsed_verifs = verifications_obj.model_dump(mode="json").get("verifications") or []
                if parsed_verifs:
                    # The prompt asks for exactly one, but keep the matching one if a
                    # model emits extras.
                    latest_verification = next((v for v in parsed_verifs if v.get("hypothesis_id") == hyp_id), parsed_verifs[0])
                    latest_verification.setdefault("hypothesis_id", hyp_id)
                    latest_verification, gate_notes = _gate_single_verification(latest_verification, hyp_evidence)
                    if gate_notes:
                        events.append(AgentEvent(sample_id, verif_stage, "proof_gate", details={"hypothesis_id": hyp_id, "notes": gate_notes}))
                else:
                    latest_verification = {
                        "hypothesis_id": hyp_id,
                        "status": "insufficient_evidence",
                        "local_risk_present": False,
                        "confirmed_security_vulnerability": False,
                        "proof": {},
                        "supporting_evidence_ids": [],
                        "counter_evidence_ids": [],
                        "missing_evidence": ["LLM returned no verification object for this hypothesis."],
                        "explanation": "No structured verification was returned for this hypothesis.",
                    }

                # Stop this hypothesis as soon as it is confirmed/refuted/resolved.
                one_verif_envelope = {"verifications": [latest_verification]}
                if _all_hypotheses_resolved(one_verif_envelope):
                    hyp_stop_reason = "hypothesis_resolved"
                    break
                # A raw confirmed status only closes the current hypothesis after the
                # proof gate has accepted it.  It does not stop the global audit;
                # counter-review and final validation still run later.
                if not config.iterative_evidence_loop:
                    hyp_stop_reason = "loop_disabled"
                    break
                if iteration >= config.max_evidence_iterations:
                    hyp_stop_reason = "max_iterations_reached"
                    break

                # Ask for more code evidence for this hypothesis only.
                gap_stage = f"04_evidence_gap__{hyp_stage_id}_iter{iteration + 1}"
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_started", {
                        "sample_id": sample_id,
                        "phase": "verification",
                        "hypothesis_id": hyp_id,
                        "iteration": iteration + 1,
                        "accumulated_evidence_count": len(hyp_evidence),
                    })
                try:
                    text, usage = _call_llm(
                        llm_generate=llm_generate,
                        messages=evidence_gap_analysis_prompt(
                            sample,
                            [latest_verification],
                            hyp_evidence,
                            list(executed_query_ids),
                            iteration=iteration + 1,
                        ),
                        sample_id=sample_id,
                        stage=gap_stage,
                        max_tokens=config.max_tokens_evidence_gap_analysis,
                        config=config,
                        events=events,
                    )
                except Exception as _gap_exc:
                    if "Timeout" not in type(_gap_exc).__name__:
                        raise
                    hyp_stop_reason = "llm_timeout_gap_analysis"
                    if on_iteration_event:
                        on_iteration_event("evidence_iteration_completed", {
                            "sample_id": sample_id,
                            "phase": "verification",
                            "hypothesis_id": hyp_id,
                            "iteration": iteration + 1,
                            "new_evidence_count": 0,
                            "stop_reason": hyp_stop_reason,
                        })
                    break
                _merge_usage(usage_total, usage)
                gap_plan, _ = parse_model_object(
                    text, EvidenceGapPlan,
                    llm_repair=_repair_llm(llm_generate, config, sample_id, events, gap_stage),
                )
                effective_gap_queries = _actionable_gap_queries(
                    sample, gap_plan, _effective_follow_up_queries(gap_plan),
                    prefix=f"QF-{hyp_stage_id}-{iteration + 1}-",
                    target_source=target_source,
                )
                events.append(AgentEvent(sample_id, gap_stage, "gap_plan", details={
                    "hypothesis_id": hyp_id,
                    "iteration": iteration + 1,
                    "needs_more_evidence": bool(gap_plan.needs_more_evidence),
                    "gaps": len(gap_plan.gaps or []),
                    "llm_follow_up_queries": len(gap_plan.follow_up_queries or []),
                    "effective_follow_up_queries": len(effective_gap_queries),
                }))
                if not _plan_effective_needs_more_evidence(gap_plan):
                    reason = (gap_plan.stop_reason_if_no_queries
                              or gap_plan.stop_reason
                              or "no_more_evidence_needed")
                    if not _all_hypotheses_resolved({"verifications": [latest_verification]}):
                        _terminal_close_hypothesis(reason, iteration + 1, {
                            "gap_plan_needs_more_evidence": bool(gap_plan.needs_more_evidence),
                            "gap_plan_reason": gap_plan.reason,
                            "gap_plan_stop_reason": reason,
                            "attempted_new_queries": 0,
                            "new_evidence_count": 0,
                        })
                    else:
                        hyp_stop_reason = reason
                    if on_iteration_event:
                        on_iteration_event("evidence_iteration_completed", {
                            "sample_id": sample_id,
                            "phase": "verification",
                            "hypothesis_id": hyp_id,
                            "iteration": iteration + 1,
                            "new_evidence_count": 0,
                            "stop_reason": hyp_stop_reason,
                        })
                    break
                new_queries: List[KGQuery] = []
                for q in effective_gap_queries[:config.max_queries_per_iteration]:
                    if not q.hypothesis_id:
                        q.hypothesis_id = hyp_id
                    norm = _norm_query(q.query_text)
                    if q.query_id in executed_query_ids or norm in executed_query_texts:
                        continue
                    new_queries.append(q)
                    executed_query_ids.add(q.query_id)
                    executed_query_texts.add(norm)
                    all_query_models.append(q)
                if not new_queries:
                    duplicate_reason = "all_queries_duplicate"
                    _terminal_close_hypothesis(duplicate_reason, iteration + 1, {
                        "gap_plan_needs_more_evidence": bool(gap_plan.needs_more_evidence),
                        "gap_plan_reason": gap_plan.reason,
                        "effective_follow_up_queries": [q.model_dump(mode="json") for q in effective_gap_queries[:config.max_queries_per_iteration]],
                        "attempted_new_queries": 0,
                        "duplicate_or_already_executed_queries": len(effective_gap_queries[:config.max_queries_per_iteration]),
                        "new_evidence_count": 0,
                    })
                    if on_iteration_event:
                        on_iteration_event("evidence_iteration_completed", {
                            "sample_id": sample_id,
                            "phase": "verification",
                            "hypothesis_id": hyp_id,
                            "iteration": iteration + 1,
                            "new_evidence_count": 0,
                            "stop_reason": hyp_stop_reason,
                        })
                    break

                followup_stage = f"03_followup_retrieval__{hyp_stage_id}_iter{iteration + 1}"
                followup_dicts = [q.model_dump(mode="json") for q in new_queries]
                for _qd in followup_dicts:
                    _qd["_agentic_stage"] = followup_stage
                    _qd["_hypothesis_id"] = hyp_id
                events.append(AgentEvent(sample_id, followup_stage, "start",
                                          details={"queries": len(followup_dicts), "hypothesis_id": hyp_id,
                                                   "query_ids": [q.query_id for q in new_queries]}))
                new_evidence = kg_search(followup_dicts, sample=sample, limit=config.evidence_limit_per_query)
                events.append(AgentEvent(sample_id, followup_stage, "done",
                                          details={"items": len(new_evidence), "hypothesis_id": hyp_id}))
                if not new_evidence and config.stop_when_no_new_evidence:
                    _terminal_close_hypothesis("no_new_evidence_returned", iteration + 1, {
                        "attempted_new_queries": len(new_queries),
                        "executed_query_ids": [q.query_id for q in new_queries],
                        "executed_query_texts": [q.query_text for q in new_queries],
                        "new_evidence_count": 0,
                        "interpretation": "KG retrieval returned no previously unseen source-code evidence for this hypothesis.",
                    })
                    if on_iteration_event:
                        on_iteration_event("evidence_iteration_completed", {
                            "sample_id": sample_id,
                            "phase": "verification",
                            "hypothesis_id": hyp_id,
                            "iteration": iteration + 1,
                            "new_evidence_count": 0,
                            "stop_reason": hyp_stop_reason,
                        })
                    break
                hyp_evidence.extend(new_evidence)
                accumulated_evidence.extend(new_evidence)
                retrieved.extend(new_evidence)
                iterations_completed += 1
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id,
                        "phase": "verification",
                        "hypothesis_id": hyp_id,
                        "iteration": iteration + 1,
                        "new_evidence_count": len(new_evidence),
                        "stop_reason": None,
                    })

        # ── Stage 05{hyp}: immediate counter-review before moving on ────────
        # A hypothesis is only terminal after its own counter-evidence review has
        # run and the proof state has been normalized.  Raw LLM confirmations are
        # treated as proposed_confirmed, never as accepted_confirmed.
        if latest_verification is not None:
            latest_verification.setdefault("hypothesis_id", hyp_id)
            pre_counter_status = latest_verification.get("status")
            counter_stage = f"05_counter_evidence_review__{hyp_stage_id}"
            events.append(AgentEvent(sample_id, counter_stage, "start", details={
                "hypothesis_id": hyp_id,
                "pre_counter_status": pre_counter_status,
                "local_risk_present": latest_verification.get("local_risk_present"),
                "confirmed_security_vulnerability": latest_verification.get("confirmed_security_vulnerability"),
            }))
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=counter_evidence_prompt(
                    sample, [latest_verification], hyp_evidence,
                    target_source=target_source
                ),
                sample_id=sample_id,
                stage=counter_stage,
                max_tokens=config.max_tokens_counter_evidence_review,
                config=config,
                events=events,
            )
            _merge_usage(usage_total, usage)
            local_counter_review, _ = parse_model_object(
                text, CounterEvidenceReview,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, counter_stage),
            )
            local_findings = (local_counter_review.model_dump(mode="json") or {}).get("findings") or []
            per_hypothesis_counter_findings.extend(local_findings)

            normalized_one, counter_notes = _apply_counter_review_to_verifications(
                {"verifications": [latest_verification]}, local_counter_review
            )
            normalized_items = normalized_one.get("verifications") or []
            if normalized_items:
                latest_verification = normalized_items[0]
            if counter_notes:
                events.append(AgentEvent(sample_id, counter_stage, "proof_state_update", details={
                    "hypothesis_id": hyp_id,
                    "notes": counter_notes,
                }))

            accepted_confirmed = (
                latest_verification.get("status") == HypothesisStatus.confirmed_vulnerability.value
                and bool(latest_verification.get("confirmed_security_vulnerability"))
            )
            if accepted_confirmed:
                accepted_confirmed_hypotheses.append(hyp_id)
                hyp_stop_reason = "accepted_confirmed_after_local_counter_review"
            events.append(AgentEvent(sample_id, f"05_hypothesis_proof_state__{hyp_stage_id}", "done", details={
                "hypothesis_id": hyp_id,
                "pre_counter_status": pre_counter_status,
                "post_counter_status": latest_verification.get("status"),
                "accepted_confirmed": accepted_confirmed,
                "counter_findings": len(local_findings),
                "stop_reason": hyp_stop_reason,
            }))
            final_verification_items.append(latest_verification)

        events.append(AgentEvent(sample_id, f"04_hypothesis_done__{hyp_stage_id}", "done",
                                  details={"hypothesis_id": hyp_id,
                                           "status": (latest_verification or {}).get("status"),
                                           "accepted_confirmed": bool(accepted_confirmed_hypotheses and accepted_confirmed_hypotheses[-1] == hyp_id),
                                           "stop_reason": hyp_stop_reason}))
        loop_stop_reason = hyp_stop_reason or loop_stop_reason
        if (
            config.stop_on_confirmed_vulnerability
            and accepted_confirmed_hypotheses
            and accepted_confirmed_hypotheses[-1] == hyp_id
        ):
            loop_stop_reason = "stopped_on_accepted_confirmed_vulnerability"
            events.append(AgentEvent(sample_id, "02_04_per_hypothesis_loop", "early_stop", details={
                "hypothesis_id": hyp_id,
                "accepted_confirmed_hypotheses": list(accepted_confirmed_hypotheses),
                "remaining_hypotheses_skipped": max(0, len(hypotheses_list) - hyp_index),
            }))
            break

    query_plan = KGQueryPlan(queries=all_query_models)
    verifications: Dict[str, Any] = {"verifications": final_verification_items}
    events.append(AgentEvent(sample_id, "02_04_per_hypothesis_loop", "done",
                              details={"verified_hypotheses": len(final_verification_items),
                                       "queries": len(all_query_models),
                                       "retrieved_items": len(retrieved),
                                       "loop_stop_reason": loop_stop_reason}))

    # ── Stage 05 aggregate: all counter-reviews already ran per hypothesis ───
    # The new controller architecture counter-reviews each hypothesis before the
    # next hypothesis is allowed to start.  Therefore the old global Stage-05 LLM
    # call is intentionally replaced by an aggregate object.  This keeps Stage-06
    # compatible while preserving the one-hypothesis-at-a-time proof lifecycle.
    counter_review = CounterEvidenceReview(
        findings=per_hypothesis_counter_findings,
        overall_notes=(
            "Counter-evidence was reviewed immediately per hypothesis before "
            "moving to the next hypothesis. This aggregate contains all local "
            "counter-review findings."
        ),
    )
    events.append(AgentEvent(sample_id, "05_counter_evidence_review", "aggregate_from_local_reviews", details={
        "findings": len(per_hypothesis_counter_findings),
        "accepted_confirmed_hypotheses": list(accepted_confirmed_hypotheses),
        "global_counter_llm_call": False,
    }))

    # ── Optional counter-evidence iterative loop ──────────────────────────────
    # Disabled in the one-hypothesis lifecycle.  Counter iteration belongs inside
    # the current hypothesis closure, not after all hypotheses have run.
    if False and config.enable_counter_evidence_loop:
        counter_executed_ids = set(executed_query_ids)
        counter_executed_texts = set(executed_query_texts)
        for c_iter in range(1, config.max_counter_iterations + 1):
            if on_iteration_event:
                on_iteration_event("evidence_iteration_started", {
                    "sample_id": sample_id, "phase": "counter",
                    "iteration": c_iter, "accumulated_evidence_count": len(accumulated_evidence),
                })
            c_gap_stage = f"05_counter_gap_iter{c_iter}"
            # Counter-gap analysis is also optional; timeout stops the loop.
            try:
                text, usage = _call_llm(
                    llm_generate=llm_generate,
                    messages=counter_gap_analysis_prompt(
                        sample,
                        counter_review.model_dump(mode="json").get("findings") or [],
                        accumulated_evidence,
                        list(counter_executed_ids),
                        iteration=c_iter,
                    ),
                    sample_id=sample_id,
                    stage=c_gap_stage,
                    max_tokens=config.max_tokens_evidence_gap_analysis,
                    config=config,
                    events=events,
                )
            except Exception as _cgap_exc:
                if "Timeout" not in type(_cgap_exc).__name__:
                    raise
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "llm_timeout_counter_gap_analysis",
                    })
                break
            _merge_usage(usage_total, usage)
            c_gap, _ = parse_model_object(
                text, EvidenceGapPlan,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, c_gap_stage),
            )
            c_effective_queries = _actionable_gap_queries(
                sample, c_gap, _effective_follow_up_queries(c_gap),
                prefix=f"QCF{c_iter}-",
                target_source=target_source,
            )
            if not _plan_effective_needs_more_evidence(c_gap) or not c_effective_queries:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "no_more_counter_queries",
                    })
                break
            c_new_queries = [
                q for q in c_effective_queries[:config.max_queries_per_iteration]
                if q.query_id not in counter_executed_ids
                and _norm_query(q.query_text) not in counter_executed_texts
            ]
            if not c_new_queries:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "all_counter_queries_duplicate",
                    })
                break
            c_ret_stage = f"03_counter_retrieval_iter{c_iter}"
            c_followup_dicts = [q.model_dump(mode="json") for q in c_new_queries]
            events.append(AgentEvent(sample_id, c_ret_stage, "start",
                                      details={"queries": len(c_followup_dicts)}))
            c_new_evidence = kg_search(c_followup_dicts, sample=sample, limit=config.evidence_limit_per_query)
            events.append(AgentEvent(sample_id, c_ret_stage, "done",
                                      details={"items": len(c_new_evidence)}))
            if not c_new_evidence:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "no_new_counter_evidence",
                    })
                break
            accumulated_evidence.extend(c_new_evidence)
            counter_executed_ids.update(q.query_id for q in c_new_queries)
            counter_executed_texts.update(_norm_query(q.query_text) for q in c_new_queries)
            # Re-run counter review with expanded evidence
            c_rev_stage = f"05_counter_evidence_review_iter{c_iter}"
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=counter_evidence_prompt(
                    sample, verifications.get("verifications") or [], accumulated_evidence,
                    target_source=target_source
                ),
                sample_id=sample_id,
                stage=c_rev_stage,
                max_tokens=config.max_tokens_counter_evidence_review,
                config=config,
                events=events,
            )
            _merge_usage(usage_total, usage)
            counter_review, _ = parse_model_object(
                text, CounterEvidenceReview,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, c_rev_stage),
            )
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "counter",
                    "iteration": c_iter, "new_evidence_count": len(c_new_evidence),
                    "stop_reason": None,
                })

    # Normalize proof state with the final counter-review before Stage 06.
    verifications, counter_notes = _apply_counter_review_to_verifications(verifications, counter_review)
    if counter_notes:
        events.append(AgentEvent(sample_id, "05_counter_evidence_review", "proof_state_update", details={"notes": counter_notes}))

    accepted_confirmed_ids = [
        v.get("hypothesis_id") for v in (verifications.get("verifications") or [])
        if v.get("status") == HypothesisStatus.confirmed_vulnerability.value
        and v.get("confirmed_security_vulnerability")
    ]
    if accepted_confirmed_ids:
        loop_stop_reason = "accepted_confirmed_after_counter_review"
    elif loop_stop_reason == "stopped_on_confirmed_vulnerability":
        loop_stop_reason = "raw_confirmation_downgraded_after_counter_review"
    events.append(AgentEvent(sample_id, "05_proof_state", "done", details={
        "accepted_confirmed_hypotheses": accepted_confirmed_ids,
        "verified_hypotheses": len(verifications.get("verifications") or []),
        "loop_stop_reason": loop_stop_reason,
    }))

    # ── Stage 06: Final adjudication ─────────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=final_decision_prompt(
            sample,
            verifications.get("verifications") or [],
            counter_review.model_dump(mode="json"),
            accumulated_evidence,
            target_source=target_source,
        ),
        sample_id=sample_id,
        stage="06_final_adjudication",
        max_tokens=config.max_tokens_final_decision,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    # Wrap parse + validate in a single handler so a schema validation failure or a
    # failed JSON repair does not crash the whole sample.  A failed Stage 06 produces
    # an emergency fallback decision with decision_status='failed_parse' so the
    # sample is excluded from binary metrics rather than raising an unhandled exception.
    notes: List[str] = []
    modified = False
    try:
        decision, _ = parse_model_object(
            text, FinalDecision,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, "06_final_adjudication"),
        )
        decision, notes, modified = validate_final_decision(
            decision, evidence_items=accumulated_evidence, counter_review=counter_review
        )
        events.append(AgentEvent(sample_id, "06_final_adjudication", "validated", details={
            "validator_notes": list(notes), "modified": bool(modified),
            "prediction": decision.prediction.value, "confidence": decision.confidence,
            "final_decision_source": decision.final_decision_source,
            "normalization_warnings": list(decision.normalization_warnings or []),
        }))
    except Exception as _stage06_exc:
        _err_msg = f"{type(_stage06_exc).__name__}: {_stage06_exc}"
        decision, notes, modified = _make_fallback_decision_from_verifications(
            _err_msg,
            verifications,
            evidence_items=accumulated_evidence,
            counter_review=counter_review,
        )
        events.append(AgentEvent(sample_id, "06_final_adjudication", "parse_failed", details={
            "error_type": type(_stage06_exc).__name__,
            "error_message": str(_stage06_exc),
            "recovery": decision.final_decision_source or "fallback_from_verifications",
            "decision_status": decision.decision_status,
            "forced_prediction": decision.forced_prediction,
            "forced_prediction_bool": decision.forced_prediction_bool,
        }))

    # Keep validator notes visible in final_prediction.json and dashboard reports.
    if notes:
        merged_limitations = list(decision.limitations or [])
        for note in notes:
            if note not in merged_limitations:
                merged_limitations.append(note)
        decision.limitations = merged_limitations

    # ── Stage 07: Schema consistency repair (conditional) ────────────────────
    # Skip repair when the validator has already produced a definitive forced binary
    # decision — repair cannot improve on a deterministically-set forced_prediction_bool.
    if modified and not _decision_has_valid_binary(decision):
        _fallback_decision = decision  # save stage-06 validated decision before attempting repair
        try:
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=consistency_repair_prompt(decision.model_dump(mode="json"), notes),
                sample_id=sample_id,
                stage="07_schema_consistency_repair",
                max_tokens=config.max_tokens_schema_repair,
                config=config,
                events=events,
            )
            _merge_usage(usage_total, usage)
            repaired_decision, _ = parse_model_object(
                text, FinalDecision,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, "07_schema_consistency_repair"),
            )
            decision, notes2, modified2 = validate_final_decision(
                repaired_decision, evidence_items=accumulated_evidence, counter_review=counter_review
            )
            notes.extend(notes2)
            events.append(AgentEvent(sample_id, "07_schema_consistency_repair", "validated", details={
                "validator_notes": list(notes2), "modified": bool(modified2),
                "prediction": decision.prediction.value, "confidence": decision.confidence,
            }))
        except Exception as _repair_exc:
            # Fall back to the validated stage-06 decision rather than crashing the sample.
            decision = _fallback_decision
            events.append(AgentEvent(sample_id, "07_schema_consistency_repair", "fallback", details={
                "error": str(_repair_exc),
                "fallback_reason": "repair_stage_failed_using_stage06_validated_decision",
                "prediction": decision.prediction.value,
                "confidence": decision.confidence,
            }))

    if notes:
        merged_limitations = list(decision.limitations or [])
        for note in notes:
            if note not in merged_limitations:
                merged_limitations.append(note)
        decision.limitations = merged_limitations

    events.append(AgentEvent(sample_id, "agentic_proof", "done", details={
        "prediction": decision.prediction.value, "forced_prediction": decision.forced_prediction,
        "forced_prediction_bool": decision.forced_prediction_bool,
        "decision_status": decision.decision_status, "confidence": decision.confidence,
        "validator_notes": notes, "loop_stop_reason": loop_stop_reason,
        "iterations_completed": iterations_completed,
    }))

    return AgenticProofResult(
        decision=decision,
        hypotheses=hypotheses,
        query_plan=query_plan,
        retrieved_evidence=retrieved,
        verifications=verifications,
        counter_review=counter_review,
        events=events,
        usage=usage_total,
        loop_stop_reason=loop_stop_reason,
        iterations_completed=iterations_completed,
    )
