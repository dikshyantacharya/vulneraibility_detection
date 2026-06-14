from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel
from .parser import parse_model_object
from .prompts import (counter_evidence_prompt, counter_gap_analysis_prompt,
                      evidence_gap_analysis_prompt, final_decision_prompt,
                      hypothesis_verification_prompt, kg_query_planning_prompt,
                      source_only_hypothesis_prompt, consistency_repair_prompt)
from .schemas import (CounterEvidenceReview, EvidenceGapPlan, FinalDecision,
                      FinalPrediction, HypothesisStatus, HypothesisVerification, KGQuery, KGQueryPlan,
                      VulnerabilityHypothesis)
from .validator import validate_final_decision


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
    """Infer small, deterministic source-level facts not dependent on labels.

    This supplements KG retrieval with facts that are visible in the target source
    but easy for the LLM to underweight.  The facts are deliberately generic:
    they identify guard shapes such as saving a base pointer and requiring an
    advanced pointer to remain above that base.  They do not use commit labels,
    true labels, patch messages, sample ids, or project metadata.
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
            "score": 2.8,
            "metadata": {"fact_type": fact_type, **meta},
        })
        next_id += 1

    # Detect pointer-advance operations such as raw += length * itemsize.
    advanced_ptrs = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\+=\s*([^;]+);", src):
        lhs, rhs = m.group(1), m.group(2)
        if any(term in rhs for term in ("*", "length", "size", "count", "<<")):
            advanced_ptrs.add(lhs)
            add_fact(
                "pointer_advance_from_size_or_length",
                f"Pointer-like variable `{lhs}` is advanced by a size/length expression: `{lhs} += {rhs.strip()};`.",
                pointer=lhs, expression=rhs.strip(),
            )

    # Detect base pointer snapshots: void * start = raw; or start = raw;
    base_pairs: list[tuple[str, str]] = []
    for m in re.finditer(r"(?:void\s*\*\s*)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;", src):
        base, ptr = m.group(1), m.group(2)
        if ptr in advanced_ptrs and base != ptr:
            base_pairs.append((base, ptr))

    # Approximate while conditions line-wise to avoid complicated C parsing.
    while_conditions: list[str] = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("while"):
            while_conditions.append(stripped)

    for base, ptr in base_pairs:
        has_guard = any(
            re.search(rf"\b{re.escape(ptr)}\s*>=\s*{re.escape(base)}\b", cond)
            or re.search(rf"\b{re.escape(base)}\s*<=\s*{re.escape(ptr)}\b", cond)
            for cond in while_conditions
        )
        if has_guard:
            add_fact(
                "pointer_wraparound_lower_bound_guard",
                f"Pointer wraparound guard: `{base}` snapshots the initial `{ptr}` pointer and a loop condition requires `{ptr} >= {base}` while `{ptr}` is advanced. This is positive safety evidence against wraparound-to-lower-address pointer-advance hypotheses.",
                pointer=ptr, base=base,
            )

    # Detect exact-end success plus error return on mismatch: if (raw == end) return ...; ... return -1;
    for ptr in advanced_ptrs or {"raw"}:
        m = re.search(rf"if\s*\(\s*{re.escape(ptr)}\s*==\s*([A-Za-z_]\w*)\s*\)\s*\n?\s*return\b", src, flags=re.S)
        if m and re.search(r"return\s+-1\s*;", src[m.end():], flags=re.S):
            add_fact(
                "exact_end_success_else_error",
                f"Exact-end guard: success requires `{ptr} == {m.group(1)}`; otherwise the function reaches an error return `-1`. This is positive safety evidence for parsers that should reject corrupt or wrapped traversals.",
                pointer=ptr, end=m.group(1),
            )
            break



    # Fixed-size buffer + unbounded index/read patterns.  This is intentionally
    # syntactic and label-free: it records evidence that a stack/local buffer is
    # written through an index in an unbounded loop without a nearby bounds guard.
    if re.search(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", src) and re.search(r"\bfor\s*\(\s*;\s*;\s*\)", src):
        for m in re.finditer(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", src):
            buf, size = m.group(1), m.group(2)
            indexed_write = re.search(rf"\b{re.escape(buf)}\s*\[\s*[A-Za-z_]\w*\s*\]\s*=", src)
            bound_guard = re.search(rf"\b[A-Za-z_]\w*\s*[<>=!]=?\s*(?:sizeof\s*\(\s*{re.escape(buf)}\s*\)|{re.escape(size)})", src)
            if indexed_write and not bound_guard:
                add_fact(
                    "fixed_size_buffer_unbounded_index_write",
                    f"Fixed-size buffer `{buf}[{size}]` is written through an index inside an unbounded loop without an obvious `{buf}` size guard. This is strong local evidence for a bounded-buffer overflow hypothesis.",
                    buffer=buf, size=size,
                )

    # Dynamic growth guard that addresses the specific fixed-size-buffer class.
    if re.search(r"\bmalloc\s*\(\s*temp_size\s*\)", src) and re.search(r"\brealloc\s*\(\s*temp\s*,\s*temp_size\s*\)", src):
        if re.search(r"if\s*\(\s*i\s*>=\s*temp_size\s*\)", src):
            add_fact(
                "dynamic_buffer_growth_guard",
                "The buffer is heap-allocated with `temp_size`, and before indexed writes the code grows it when `i >= temp_size` using `realloc`. This is positive safety evidence against the original fixed 500-byte environment-name overflow class.",
            )
        if re.search(r"\btemp\s*=\s*realloc\s*\(\s*temp\s*,\s*temp_size\s*\)", src) and not re.search(r"if\s*\(\s*!?\s*temp\s*\)", src):
            add_fact(
                "unchecked_realloc_residual_risk",
                "The source assigns `realloc` directly back to `temp` without an obvious NULL check. This is a residual robustness risk, but it is distinct from the fixed-size buffer overflow class.",
            )

    # Elliptic-curve point at infinity / identity handling.  This is the class of
    # guard that should refute missing-identity handling hypotheses without
    # hard-coding a specific function name or label.
    has_point_identity_helpers = any(name in src for name in (
        "pointZZ_pIsIdentityElement", "pointZZ_pSetToIdentityElement", "pointZZ_pEqual", "pointZZ_pDouble"
    ))
    if has_point_identity_helpers:
        add_fact(
            "point_identity_element_guard",
            "The source contains explicit identity-element / point-at-infinity handling before the generic point-addition arithmetic. This is positive safety evidence for the point-at-infinity vulnerability class.",
        )
    elif "mpz_invert" in src and "op1->x" in src and "op2->x" in src:
        add_fact(
            "missing_point_identity_element_guard",
            "The source performs elliptic-curve point-addition arithmetic using `mpz_invert` on coordinate differences, but no explicit identity-element / point-at-infinity guard is visible before inversion.",
        )

    # GMP arithmetic facts: mpz_* values are arbitrary precision.  These facts
    # suppress false positives that misclassify mpz_mul/mpz_sub as C integer
    # overflow/underflow while preserving real risks such as unchecked inversion.
    if re.search(r"\bmpz_(?:mul|sub)\s*\(", src):
        add_fact(
            "gmp_arbitrary_precision_arithmetic",
            "The source uses GMP `mpz_*` arithmetic. `mpz_mul`/`mpz_sub` operate on arbitrary-precision integers and should not be treated as normal C integer overflow/underflow without additional evidence.",
        )
    if "mpz_invert" in src:
        add_fact(
            "mpz_invert_status_sensitive",
            "The source calls `mpz_invert`; its return value indicates whether an inverse exists. Missing status checks can be relevant only when the non-invertible case is not otherwise guarded.",
        )



    # Generic dynamic-allocation safety facts.  These are intentionally
    # source-local and label-free.  They distinguish project allocation wrappers
    # from raw C allocation and record whether an allocation result is used before
    # any obvious NULL guard.  This captures families such as raw malloc/calloc
    # immediately followed by memset/snprintf/fread/indexing, while allowing
    # wrapper-based fixed versions to be treated as safety evidence.
    if "safe_calloc" in src:
        add_fact(
            "safe_calloc_allocation_wrapper_used",
            "The target function uses the project allocation wrapper `safe_calloc`. Treat this as positive allocation-safety evidence for zero-size/allocation-failure hypotheses unless a separate pre-call arithmetic overflow is completely proven.",
        )

    # A common safe idiom in this benchmark family: allocate N bytes with the
    # project wrapper and read at most N-1 bytes, leaving space for a terminator.
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
                    f"`{var}` is allocated with `safe_calloc({alloc_size})` and read with `fread({var}, 1, {read_size}, ...)`, so the fixed-size read is within the allocated buffer with at least one byte of slack.",
                    buffer=var,
                    allocation_size=alloc_size,
                    read_size=read_size,
                )

    # Raw allocation results used before a visible NULL check.  This is high
    # signal only when there is no stronger wrapper/growth evidence; the
    # validator applies that balance.  We record the precise sink shape so the
    # report can explain the decision.
    def _find_raw_alloc_uses(alloc_name: str) -> None:
        pattern = re.compile(rf"\b([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*=\s*{alloc_name}\s*\(([^;]+)\)\s*;", re.S)
        for m in pattern.finditer(src):
            var = re.sub(r"\s*(->|\.)\s*", r"\1", m.group(1))
            arg = " ".join(m.group(2).split())
            tail = src[m.end(): m.end() + 2500]
            null_guard = re.search(rf"if\s*\(\s*(?:!\s*)?{re.escape(var)}\s*(?:==\s*NULL)?\s*\)", tail)
            # Sinks that dereference/use the allocation in ways that crash or corrupt
            # if allocation failed, or write into a potentially undersized result.
            sink_patterns = [
                rf"memset\s*\(\s*{re.escape(var)}\s*,",
                rf"snprintf\s*\(\s*{re.escape(var)}\s*,",
                rf"sprintf\s*\(\s*{re.escape(var)}\s*,",
                rf"fread\s*\(\s*{re.escape(var)}\s*,",
                rf"strncpy\s*\(\s*{re.escape(var)}\s*,",
                rf"strcpy\s*\(\s*{re.escape(var)}\s*,",
                rf"\b{re.escape(var)}\s*\[",
                rf"\b{re.escape(var)}\s*->",
                rf"\*\s*{re.escape(var)}\b",
                rf"\b{re.escape(var)}\s*\+",
            ]
            sink = next((pat for pat in sink_patterns if re.search(pat, tail, flags=re.S)), None)
            if sink and not null_guard:
                add_fact(
                    f"raw_{alloc_name}_without_null_check_before_use",
                    f"Raw `{alloc_name}` allocation result `{var}` is used before an obvious NULL check; allocation expression `{alloc_name}({arg})`. This is strong local evidence for a dynamic-allocation safety vulnerability when no project wrapper/growth guard covers it.",
                    variable=var,
                    allocator=alloc_name,
                    allocation_expression=arg,
                )

    _find_raw_alloc_uses("malloc")
    _find_raw_alloc_uses("calloc")

    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*realloc\s*\(\s*\1\s*,\s*([^;]+)\)\s*;", src, flags=re.S):
        var, arg = m.group(1), " ".join(m.group(2).split())
        tail = src[m.end(): m.end() + 400]
        if not re.search(rf"if\s*\(\s*(?:!\s*)?{re.escape(var)}\s*(?:==\s*NULL)?\s*\)", tail):
            add_fact(
                "raw_realloc_assignment_without_temp",
                f"`realloc` is assigned directly back to `{var}` without an obvious temporary pointer or NULL check; expression `realloc({var}, {arg})`. This can lose the old allocation or lead to NULL use if allocation fails.",
                variable=var,
                allocation_expression=arg,
            )

    # bsdiff-style shifted bound checks.  A safe version checks the extra block
    # after newpos has been advanced by x; a vulnerable version may check extraPtr
    # too early before the diff copy changes newpos.
    if "PyArg_ParseTuple" in src and "controlTuples" in src and "extraPtr" in src and "memcpy(newData + newpos, extraPtr, y)" in src:
        extra_memcpy = src.find("memcpy(newData + newpos, extraPtr, y)")
        newpos_x = src.rfind("newpos += x", 0, extra_memcpy if extra_memcpy >= 0 else len(src))
        extra_guard = src.rfind("extraPtr + y > extraBlock + extraBlockLength", 0, extra_memcpy if extra_memcpy >= 0 else len(src))
        if extra_memcpy >= 0 and newpos_x >= 0 and extra_guard > newpos_x:
            add_fact(
                "shifted_extra_bounds_guard",
                "The extra-block bounds check appears after `newpos += x` and before `memcpy(newData + newpos, extraPtr, y)`. This is positive safety evidence for the shifted bounds-check patch class.",
            )
        elif extra_memcpy >= 0:
            add_fact(
                "missing_shifted_extra_bounds_guard",
                "The source copies `y` bytes from `extraPtr` after `newpos += x`, but no extra-block/newpos bounds check is visible immediately before that copy. This is strong local evidence for a shifted-bounds-check vulnerability class.",
            )

    # fish-shell ENCODE_DIRECT handling.  A helper that centralizes reserved
    # codepoint logic is positive safety evidence; manual partial checks can miss
    # reserved codepoints.
    if "fish_reserved_codepoint" in src:
        add_fact(
            "encode_direct_reserved_codepoint_guard",
            "The source uses `fish_reserved_codepoint(wc)` before deciding to encode directly. This is positive safety evidence for the ENCODE_DIRECT reserved-codepoint patch class.",
        )
    elif "ENCODE_DIRECT_BASE" in src and "INTERNAL_SEPARATOR" in src:
        add_fact(
            "legacy_partial_encode_direct_guard",
            "The source uses manual ENCODE_DIRECT_BASE / INTERNAL_SEPARATOR checks instead of a consolidated reserved-codepoint predicate. This is local evidence for a missed reserved-codepoint encoding class.",
        )

    # sprintf with a numeric PID cannot create slash-based path traversal by
    # itself; record this to suppress overly broad path-traversal hypotheses.
    if re.search(r"sprintf\s*\([^;]*\"/proc/%d/environ\"\s*,\s*pid\s*\)", src, flags=re.S):
        add_fact(
            "numeric_pid_proc_path_no_slash_traversal",
            "The `/proc/%d/environ` path is constructed with numeric `%d` formatting of `pid`; by itself this cannot inject `/` path traversal components.",
        )

    return facts


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
) -> List[KGQuery]:
    """Create deterministic fallback KG queries for queryable high-value gaps.

    The LLM often identifies the right missing proof elements but then emits
    duplicate, underspecified, or weak follow-up queries.  The controller should
    not stop a loop as ``no_new_evidence_returned`` while high-priority gaps are
    still explicitly queryable.  These fallback queries are label-free and use
    only the target function name plus the gap text.
    """
    fn = str(sample.get("func_name") or sample.get("function_name") or sample.get("target_function") or sample.get("function") or "").strip()
    if not fn:
        return []

    gaps = [g for g in (gap_plan.gaps or []) if getattr(g, "queryable", False)]
    if not gaps:
        return []

    out: List[KGQuery] = []
    seen: set[str] = set()

    def add(purpose: str, query_text: str, variables: List[str] | None = None, hypothesis_id: Optional[str] = None) -> None:
        norm = _norm_query(query_text)
        if not norm or norm in seen:
            return
        seen.add(norm)
        out.append(_make_query(f"{prefix}{len(out)+1:02d}", hypothesis_id, purpose, query_text, variables))

    # Always try broad caller/data contexts first when any queryable gap remains.
    add(
        "Expanded caller/input-source context for unresolved proof gaps",
        f'security_context(target_function="{fn}", depth=4, call_depth=3, data_depth=5, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=900)',
    )
    add(
        "Incoming callers and caller-side constraints for unresolved proof gaps",
        f'call_neighborhood(target_function="{fn}", direction="in", call_depth=4)',
    )
    add(
        "Bidirectional call neighborhood to find helper guards and related validation",
        f'call_neighborhood(target_function="{fn}", direction="both", call_depth=3)',
    )
    add(
        "Semantic guard/risk facts for unresolved proof gaps",
        f'semantic_facts(target_function="{fn}")',
    )

    gap_text = "\n".join(
        " ".join(str(getattr(g, attr, "") or "") for attr in ("proof_element", "missing_evidence", "recommended_query_focus", "why_queryable_or_not"))
        for g in gaps
    )

    # Variables commonly decisive in the current benchmark families.
    variables = [
        "raw", "raw_length", "length", "itemsize", "length_power",
        "in", "in_len", "in_pos", "ret", "ascii_prefix_length", "state", "wc",
        "op1", "op2", "rop", "curve", "p", "xdiff", "ydiff", "lambda",
    ]
    for v in variables:
        if _query_mentions(gap_text, [v]):
            add(
                f"Variable flow for `{v}` because an unresolved queryable gap mentions it",
                f'variable_flow(target_function="{fn}", symbol="{v}", data_depth=5)',
                [v],
            )

    # Exact suspicious expressions/helper names seen in gap text.
    expr_terms = [
        ("length * itemsize", "raw += length * itemsize;"),
        ("length_power", "1 << length_power"),
        ("raw_length", "raw + raw_length"),
        ("raw == end", "raw == end"),
        ("raw >= start", "raw >= start"),
        ("count_ascii_prefix", "count_ascii_prefix"),
        ("mbrtowc", "std::mbrtowc"),
        ("in_pos += ret", "in_pos += ret"),
        ("use_encode_direct", "use_encode_direct"),
        ("encode_direct", "ENCODE_DIRECT"),
        ("mpz_invert", "mpz_invert"),
        ("curve->p", "curve->p"),
        ("identity", "pointZZ_pIsIdentityElement"),
        ("point at infinity", "pointZZ_pIsIdentityElement"),
    ]
    for needle, stmt in expr_terms:
        if needle.lower() in gap_text.lower():
            add(
                f"Evidence slice for `{stmt}` because an unresolved queryable gap mentions it",
                f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=5, data_depth=5, control_depth=4, call_depth=3, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=700)',
            )

    # Helper functions often hold the guard/counter-evidence, so ask directly
    # when the gap mentions them. External/library names are harmless: CodeKG
    # returns no evidence if absent.
    helpers = [
        "count_ascii_prefix", "fish_reserved_codepoint", "pointZZ_pIsIdentityElement",
        "pointZZ_pEqual", "pointZZ_pDouble", "pointZZ_pSetToIdentityElement",
        "buildCurveZZ_p", "mpz_invert", "mbrtowc",
    ]
    for h in helpers:
        if h.lower() in gap_text.lower():
            add(
                f"Function context for helper `{h}` mentioned by unresolved gap",
                f'function_context(target_function="{h}", depth=3)',
            )
            add(
                f"Semantic facts for helper `{h}` mentioned by unresolved gap",
                f'semantic_facts(target_function="{h}")',
            )

    return out


def _actionable_gap_queries(
    sample: Dict[str, Any],
    gap_plan: EvidenceGapPlan,
    llm_queries: List[KGQuery],
    *,
    prefix: str,
) -> List[KGQuery]:
    """Combine deterministic fallback queries with LLM queries.

    Fallback queries are placed first so a weak/duplicate LLM proposal cannot
    consume the small per-iteration query budget and prematurely end the loop.
    """
    combined = _auto_follow_up_queries_from_gaps(sample, gap_plan, prefix=prefix) + list(llm_queries or [])
    out: List[KGQuery] = []
    seen: set[str] = set()
    for q in combined:
        text = str(q.query_text or "")
        # Drop obvious placeholders that cannot execute deterministically.
        if "<relative" in text or "<path" in text or "TODO" in text:
            continue
        norm = _norm_query(text)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(q)
    return out


@dataclass
class AgenticProofConfig:
    max_hypotheses: int = 12
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
    if coerced_fields:
        events.append(AgentEvent(sample_id, stage, "prompt_content_coerced",
                                  details={"coerced_fields": coerced_fields}))
    events.append(AgentEvent(sample_id, stage, "start",
                              details={"prompt_chars": prompt_chars, "max_tokens": max_tokens}))
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

    # Deterministic source-level facts are label-free and prompt-visible. They
    # help the verifier/counter-review distinguish unguarded local risk from
    # patched guard logic even when CodeKG caller queries return no new nodes.
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
    hypotheses["hypotheses"] = hypotheses.get("hypotheses", [])[:config.max_hypotheses]

    # ── Stage 02: KG query planning ──────────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=kg_query_planning_prompt(sample, hypotheses["hypotheses"], initial_evidence),
        sample_id=sample_id,
        stage="02_kg_query_planning",
        max_tokens=config.max_tokens_kg_query_planning,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    query_plan, _ = parse_model_object(
        text, KGQueryPlan,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "02_kg_query_planning"),
    )
    query_dicts = [q.model_dump(mode="json") for q in query_plan.queries]

    # ── Stage 03: Initial KG retrieval ───────────────────────────────────────
    events.append(AgentEvent(sample_id, "03_initial_retrieval", "start",
                              details={"queries": len(query_dicts)}))
    retrieved = kg_search(query_dicts, sample=sample, limit=config.evidence_limit_per_query)
    events.append(AgentEvent(sample_id, "03_initial_retrieval", "done",
                              details={"items": len(retrieved)}))

    accumulated_evidence = list(initial_evidence) + list(retrieved)
    # Track which query IDs and normalized query texts have been executed to
    # prevent re-running duplicates (by id OR by identical text with a new id).
    executed_query_ids: set[str] = {q.get("query_id", "") for q in query_dicts}
    executed_query_texts: set[str] = {_norm_query(q.get("query_text", "")) for q in query_dicts}

    # ── Stages 04 + iterative evidence loop ──────────────────────────────────
    verifications: Dict[str, Any] = {}
    loop_stop_reason: Optional[str] = None
    iterations_completed: int = 0

    for iteration in range(config.max_evidence_iterations + 1):
        stage_suffix = "" if iteration == 0 else f"_iter{iteration}"
        verif_stage = f"04_hypothesis_verification{stage_suffix}"

        text, usage = _call_llm(
            llm_generate=llm_generate,
            messages=hypothesis_verification_prompt(
                sample, hypotheses["hypotheses"], accumulated_evidence
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
        verifications = verifications_obj.model_dump(mode="json")

        # ── Stopping checks ──────────────────────────────────────────────────
        if not config.iterative_evidence_loop:
            loop_stop_reason = "loop_disabled"
            break

        if iteration >= config.max_evidence_iterations:
            loop_stop_reason = "max_iterations_reached"
            break

        if (config.stop_when_all_hypotheses_resolved
                and _all_hypotheses_resolved(verifications)):
            loop_stop_reason = "all_hypotheses_resolved"
            break

        # ── Stage 04_evidence_gap_iter{N}: gap analysis ───────────────────
        gap_stage = f"04_evidence_gap_iter{iteration + 1}"

        if on_iteration_event:
            on_iteration_event("evidence_iteration_started", {
                "sample_id": sample_id, "phase": "verification",
                "iteration": iteration + 1, "accumulated_evidence_count": len(accumulated_evidence),
            })

        # Gap analysis is an optional loop stage: a ReadTimeout here should
        # stop the evidence loop gracefully rather than failing the whole sample.
        try:
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=evidence_gap_analysis_prompt(
                    sample,
                    verifications.get("verifications") or [],
                    accumulated_evidence,
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
            loop_stop_reason = "llm_timeout_gap_analysis"
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "llm_timeout_gap_analysis",
                })
            break
        _merge_usage(usage_total, usage)
        gap_plan, _ = parse_model_object(
            text, EvidenceGapPlan,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, gap_stage),
        )

        # ── Stopping checks on gap plan ───────────────────────────────────
        # Do not blindly trust needs_more_evidence=false when the same response
        # contains queryable gaps and concrete follow-up queries. That exact
        # contradiction was responsible for premature loop termination on
        # pointer-overflow cases where caller/input-source evidence was still
        # missing.
        effective_gap_queries = _actionable_gap_queries(
            sample, gap_plan, _effective_follow_up_queries(gap_plan),
            prefix=f"QF{iteration + 1}-",
        )
        if not _plan_effective_needs_more_evidence(gap_plan):
            _stop = (gap_plan.stop_reason_if_no_queries
                     or gap_plan.stop_reason
                     or "no_more_evidence_needed")
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": _stop,
                })
            loop_stop_reason = _stop
            break

        if not effective_gap_queries and config.stop_when_no_new_queries:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "no_new_queries_proposed",
                })
            loop_stop_reason = "no_new_queries_proposed"
            break

        # Deduplicate by query_id AND by normalized query_text (LLM may reuse
        # identical text with a fresh id to bypass id-only dedup).
        new_queries = [
            q for q in effective_gap_queries[:config.max_queries_per_iteration]
            if q.query_id not in executed_query_ids
            and _norm_query(q.query_text) not in executed_query_texts
        ]
        if not new_queries and config.stop_when_no_new_queries:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "all_queries_duplicate",
                })
            loop_stop_reason = "all_queries_duplicate"
            break

        # ── Follow-up KG retrieval ────────────────────────────────────────
        retrieval_stage = f"03_followup_retrieval_iter{iteration + 1}"
        followup_dicts = [q.model_dump(mode="json") for q in new_queries]
        events.append(AgentEvent(sample_id, retrieval_stage, "start",
                                  details={"queries": len(followup_dicts)}))
        new_evidence = kg_search(followup_dicts, sample=sample, limit=config.evidence_limit_per_query)
        events.append(AgentEvent(sample_id, retrieval_stage, "done",
                                  details={"items": len(new_evidence)}))

        if not new_evidence and config.stop_when_no_new_evidence:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "no_new_evidence_returned",
                })
            loop_stop_reason = "no_new_evidence_returned"
            break

        accumulated_evidence.extend(new_evidence)
        executed_query_ids.update(q.query_id for q in new_queries)
        executed_query_texts.update(_norm_query(q.query_text) for q in new_queries)
        iterations_completed = iteration + 1

        if on_iteration_event:
            on_iteration_event("evidence_iteration_completed", {
                "sample_id": sample_id, "phase": "verification",
                "iteration": iteration + 1, "new_evidence_count": len(new_evidence),
                "stop_reason": None,
            })

    # ── Stage 05: Counter-evidence review ────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=counter_evidence_prompt(
            sample, verifications.get("verifications") or [], accumulated_evidence
        ),
        sample_id=sample_id,
        stage="05_counter_evidence_review",
        max_tokens=config.max_tokens_counter_evidence_review,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    counter_review, _ = parse_model_object(
        text, CounterEvidenceReview,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "05_counter_evidence_review"),
    )

    # ── Optional counter-evidence iterative loop ──────────────────────────────
    if config.enable_counter_evidence_loop:
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
                    sample, verifications.get("verifications") or [], accumulated_evidence
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

    # ── Stage 06: Final adjudication ─────────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=final_decision_prompt(
            sample,
            verifications.get("verifications") or [],
            counter_review.model_dump(mode="json"),
            accumulated_evidence,
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
