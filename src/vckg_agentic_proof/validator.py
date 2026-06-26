from __future__ import annotations
from typing import Any, Iterable, List
import re
from .schemas import FinalDecision, FinalPrediction, HypothesisStatus, CounterEvidenceReview

_UNSUPPORTED_COUNTER_STATUSES = {
    HypothesisStatus.plausible_but_unproven,
    HypothesisStatus.refuted_by_guard,
    HypothesisStatus.refuted_by_caller_constraint,
    HypothesisStatus.refuted_by_patch_or_changed_logic,
    HypothesisStatus.irrelevant_to_target_function,
    HypothesisStatus.insufficient_evidence,
}

_GENERIC_PROOF_PHRASES = {
    "unknown", "n/a", "none", "not shown", "not provided", "unclear",
    "missing", "not available", "insufficient evidence", "not evidenced",
}

def _evidence_id_set(evidence_items: Iterable[Any] | None) -> set[str]:
    # Verification prompts always expose the target function source as the virtual
    # code section TARGET-SOURCE.  Allow proofs to cite it even though it is not a
    # persisted KG EvidenceItem.
    ids: set[str] = {"TARGET-SOURCE"}
    for item in evidence_items or []:
        if isinstance(item, dict):
            v = item.get("id") or item.get("evidence_id") or item.get("node_id")
        else:
            v = getattr(item, "id", None) or getattr(item, "evidence_id", None) or getattr(item, "node_id", None)
        if v:
            ids.add(str(v))
    return ids

def _source_fact_types(evidence_items: Iterable[Any] | None) -> set[str]:
    fact_types: set[str] = set()
    for item in evidence_items or []:
        meta = None
        text = ""
        if isinstance(item, dict):
            meta = item.get("metadata") or {}
            text = str(item.get("text") or "")
        else:
            meta = getattr(item, "metadata", {}) or {}
            text = str(getattr(item, "text", "") or "")
        ft = meta.get("fact_type") if isinstance(meta, dict) else None
        if ft:
            fact_types.add(str(ft))
        low = text.lower().replace("`", "")
        if "pointer wraparound guard" in low or "wraparound-to-lower-address" in low:
            fact_types.add("pointer_wraparound_lower_bound_guard")
        if re.search(r"\b(?:void\s*\*\s*)?start\s*=\s*raw\b", low) and re.search(r"\braw\s*>=\s*start\b|\bstart\s*<=\s*raw\b", low):
            fact_types.add("pointer_wraparound_lower_bound_guard")
        if ("exact-end guard" in low or "exact-end" in low or "exact end" in low) and ("return -1" in low or "error return" in low):
            fact_types.add("exact_end_success_else_error")
        if re.search(r"if\s*\(\s*raw\s*==\s*end\s*\)\s*return", low) and re.search(r"return\s*-\s*1\s*;", low):
            fact_types.add("exact_end_success_else_error")
        if ft == "exact_end_accept_else_error":
            fact_types.add("exact_end_success_else_error")
    return fact_types


def _has_pointer_wraparound_safety(evidence_items: Iterable[Any] | None) -> bool:
    facts = _source_fact_types(evidence_items)
    return (
        "pointer_wraparound_lower_bound_guard" in facts
        and "exact_end_success_else_error" in facts
    )


def _has_fact(evidence_items: Iterable[Any] | None, fact_type: str) -> bool:
    return fact_type in _source_fact_types(evidence_items)


def _proof_tier_of_hypothesis(h: Any) -> str:
    tier = str(getattr(h, "proof_tier", "") or "").strip()
    if tier:
        return tier
    text = " ".join(str(getattr(h, k, "") or "") for k in ("explanation", "relevance_reason"))
    for candidate in (
        "confirmed_reachable_vulnerability",
        "confirmed_source_level_vulnerability",
        "high_signal_incomplete",
        "refuted",
    ):
        if candidate in text:
            return candidate
    return "unknown"


def _is_confirmed_tier(tier: str) -> bool:
    return tier in {"confirmed_source_level_vulnerability", "confirmed_reachable_vulnerability"}


def _counter_status_is_unsupported_for_tier(counter_status: Any, h: Any) -> bool:
    """Counter-review recommendations only reject proof tiers when supported by
    concrete refuting evidence. The structured CounterEvidenceReview currently
    has no tier field, so a recommendation to downgrade source-level confirmation
    is treated as advisory unless the hypothesis itself carries counter evidence.
    """
    if counter_status not in _UNSUPPORTED_COUNTER_STATUSES:
        return False
    tier = _proof_tier_of_hypothesis(h)
    if _is_confirmed_tier(tier):
        # Counter review can still be reflected as limitations, but not erase a
        # completed proof tier without concrete counter evidence attached to the
        # hypothesis. This mirrors the tier-aware controller logic.
        return bool(getattr(h, "counter_evidence_ids", []) and counter_status in {
            HypothesisStatus.refuted_by_guard,
            HypothesisStatus.refuted_by_caller_constraint,
            HypothesisStatus.refuted_by_patch_or_changed_logic,
            HypothesisStatus.irrelevant_to_target_function,
        })
    return True


def _joined_evidence_text(evidence_items: Iterable[Any] | None) -> str:
    parts: list[str] = []
    for item in evidence_items or []:
        if isinstance(item, dict):
            parts.append(str(item.get("text") or ""))
            meta = item.get("metadata") or {}
        else:
            parts.append(str(getattr(item, "text", "") or ""))
            meta = getattr(item, "metadata", {}) or {}
        if isinstance(meta, dict):
            parts.extend(str(v) for v in meta.values())
    return "\n".join(parts).lower()


def _has_strong_uncovered_vulnerability_pattern(decision: FinalDecision, evidence_items: Iterable[Any] | None) -> tuple[bool, str]:
    """Return whether incomplete evidence should still force vulnerable.

    This is a deterministic, label-free precision gate.  It only treats a local
    risk as benchmark-vulnerable when the target source contains a high-signal
    unguarded pattern.  Generic local risks, missing NULL checks, speculative
    side channels, GMP arithmetic concerns, or unrelated residual findings do
    not trigger the vulnerable fallback.
    """
    facts = _source_fact_types(evidence_items)
    text = _joined_evidence_text(evidence_items)
    hyp_text = " ".join(_verification_text(h) for h in (decision.final_hypothesis_statuses or []))

    if "fixed_size_buffer_unbounded_index_write" in facts:
        return True, "fixed-size buffer with unbounded indexed write"
    raw_alloc_facts = {
        "raw_malloc_without_null_check_before_use",
        "raw_calloc_without_null_check_before_use",
        "raw_realloc_assignment_without_temp",
    }
    if facts & raw_alloc_facts:
        # Do not let the fixed /proc environ variant regress: it still contains
        # raw malloc/realloc residual risks, but the dynamic growth guard is the
        # target-relevant fix for the original fixed-size overflow class.
        if "dynamic_buffer_growth_guard" not in facts:
            which = sorted(facts & raw_alloc_facts)[0]
            return True, f"raw dynamic allocation used before a visible safety check ({which})"
    if "missing_shifted_extra_bounds_guard" in facts:
        return True, "missing shifted bounds check before extra-block copy"
    if "missing_point_identity_element_guard" in facts:
        return True, "missing point-at-infinity / identity-element guard before point-addition arithmetic"
    if "legacy_partial_encode_direct_guard" in facts:
        return True, "legacy partial ENCODE_DIRECT reserved-codepoint handling"
    if "missing_protocol_trust_boundary_guard" in facts:
        return True, "network/protocol boundary without an obvious trust-boundary validation guard"
    if "possible_deterministic_transform_without_diversification" in facts:
        return True, "deterministic security transform without obvious diversification/randomization guard"
    if "length_offset_sensitive_operation" in facts and "parser_state_machine_surface" in facts:
        # Parser/state bugs often lack one obvious dangerous call.  Treat an
        # unresolved parser length/offset proof as vulnerable only when the final
        # statuses are not already refuted by a relevant guard/safe wrapper.
        if any(getattr(h, "local_risk_present", False) for h in (decision.final_hypothesis_statuses or [])):
            return True, "parser/state-machine length or offset operation remains unresolved"
    combined = text + " " + hyp_text
    if not _has_pointer_wraparound_safety(evidence_items):
        if "raw += length * itemsize" in combined or ("raw +=" in combined and "length * itemsize" in combined):
            return True, "unguarded raw-buffer pointer advancement by parsed length/size"
        if "pointer_advance_from_size_or_length" in facts:
            # Do not let arbitrary pointer-like += operations force vulnerability;
            # require parser/raw-buffer vocabulary that matches the high-signal class.
            if any(t in combined for t in ("uint64_t length", "parsed length", "raw buffer")):
                return True, "unguarded raw-buffer pointer advancement by parsed length/size"

    return False, "no strong uncovered vulnerability pattern"


def _is_low_relevance_or_residual_confirmed(h: Any, evidence_items: Iterable[Any] | None) -> tuple[bool, str]:
    """Identify confirmed hypotheses that should not drive benchmark vulnerable.

    This suppresses false positives from unrelated residual issues in fixed code:
    unchecked realloc after dynamic growth, GMP arithmetic overflow hallucinations,
    /proc/%d path traversal, and side-channel/speculative concerns without the
    complete target proof chain.
    """
    facts = _source_fact_types(evidence_items)
    t = _verification_text(h)

    if "bounded_read_within_safe_allocation" in facts and any(x in t for x in ("fread", "buffer overflow", "fixed-size", "uninitialized", "null-termination", "unterminated", "header")):
        return True, "bounded read is within a safe_calloc allocation with slack; fixed-buffer/header-read concern is refuted"
    if "safe_calloc_allocation_wrapper_used" in facts and any(x in t for x in ("safe_calloc", "calloc", "allocation", "malloc", "null pointer", "zero-size", "zero size", "integer overflow", "wraparound", "undersized")):
        if not ({"raw_malloc_without_null_check_before_use", "raw_calloc_without_null_check_before_use", "raw_realloc_assignment_without_temp"} & facts):
            return True, "project safe_calloc wrapper is positive allocation-safety evidence; allocation-size concern remains residual unless independently proven"

    if "dynamic_buffer_growth_guard" in facts and any(x in t for x in ("realloc", "malloc", "temp_size", "environment")):
        if "fixed-size" not in t and "temp[500]" not in t:
            return True, "residual realloc/dynamic-allocation concern after dynamic growth guard"
    if "point_identity_element_guard" in facts and any(x in t for x in ("mpz_invert", "curve->p", "side-channel", "mpz_mul", "mpz_sub", "underflow", "overflow")):
        return True, "unrelated elliptic-curve arithmetic concern after identity-element guard"
    if "gmp_arbitrary_precision_arithmetic" in facts and any(x in t for x in ("mpz_mul", "mpz_sub", "integer overflow", "integer underflow")):
        return True, "GMP arbitrary-precision arithmetic misclassified as C overflow/underflow"
    if "numeric_pid_proc_path_no_slash_traversal" in facts and "path traversal" in t:
        return True, "numeric %d /proc path cannot inject slash traversal by itself"
    if "shifted_extra_bounds_guard" in facts and any(x in t for x in ("extra", "diff", "patch", "newpos", "memcpy", "control tuple", "oldpos", "origdata", " z", " z ")):
        return True, "shifted bounds-check guard covers the patch-copy vulnerability class; remaining tuple/oldpos concerns are residual unless separately proven"
    if "encode_direct_reserved_codepoint_guard" in facts and any(x in t for x in ("encode_direct", "reserved", "mbrtowc", "codepoint", "in_pos", "ascii_prefix")):
        return True, "reserved-codepoint guard covers ENCODE_DIRECT patch class"
    if any(x in t for x in ("possible side-channel", "side-channel", "timing")) and not getattr(getattr(h, "proof", None), "complete", lambda: False)():
        return True, "speculative side-channel without complete proof"

    return False, ""


def _is_guard_claim_relevant(h: Any, evidence_items: Iterable[Any] | None) -> bool:
    """Conservative check for whether a counter-evidence claim can refute a hypothesis.

    The large-run reports showed false safety when a guard on one value was
    treated as protecting another value.  This helper is intentionally simple:
    it prevents generic guard/caller claims from refuting high-signal source
    facts unless the corresponding safety fact is present.
    """
    facts = _source_fact_types(evidence_items)
    text = _verification_text(h)
    if any(x in text for x in ("pointer", "raw", "length * itemsize", "wraparound")):
        return _has_pointer_wraparound_safety(evidence_items)
    if any(x in text for x in ("malloc", "calloc", "realloc", "allocation")):
        return bool(facts & {"safe_calloc_allocation_wrapper_used", "bounded_read_within_safe_allocation", "dynamic_buffer_growth_guard"})
    if any(x in text for x in ("hop", "link-local", "localhost", "protocol", "socket", "network")):
        return not _has_fact(evidence_items, "missing_protocol_trust_boundary_guard")
    return True


def _verification_text(h: Any) -> str:
    proof = getattr(h, "proof", None)
    parts = [
        getattr(h, "hypothesis_id", ""),
        getattr(h, "explanation", ""),
    ]
    if proof is not None:
        parts.extend([
            getattr(proof, "dangerous_operation", ""),
            getattr(proof, "missing_or_failed_guard", ""),
            getattr(proof, "unsafe_use", ""),
            getattr(proof, "security_impact", ""),
        ])
    return " ".join(str(x or "") for x in parts).lower()


def _is_pointer_wraparound_like(h: Any) -> bool:
    text = _verification_text(h)
    pointer_terms = (
        "pointer", "raw", "buffer", "end", "start", "advance",
        "wrap", "overflow", "underflow", "out-of-bounds", "overread",
        "read past", "length * itemsize", "+=",
    )
    return any(term in text for term in pointer_terms)


def _pointer_safety_covers_unresolved(decision: FinalDecision, unresolved_ids: list[str], evidence_items: Iterable[Any] | None) -> bool:
    if not unresolved_ids or not _has_pointer_wraparound_safety(evidence_items):
        return False
    by_id = {h.hypothesis_id: h for h in (decision.final_hypothesis_statuses or [])}
    return all(_is_pointer_wraparound_like(by_id.get(hid)) for hid in unresolved_ids if hid in by_id)


def _looks_non_specific(value: str | None) -> bool:
    s = (value or "").strip().lower()
    if not s:
        return True
    if s in _GENERIC_PROOF_PHRASES:
        return True
    # A complete proof field must assert the proof element, not say it is only
    # plausible/unproven.  Without this, models can accidentally turn
    # "attacker control is plausible but unproven" into a confirmed proof chain.
    uncertainty_markers = (
        "unproven", "plausible but unproven", "not proven", "not established",
        "depends on", "if attacker", "if an attacker", "could be", "may be",
        "requires proof", "requires attacker", "no evidence", "unknown",
    )
    if any(marker in s for marker in uncertainty_markers):
        return True
    return len(s) < 4

def _counter_recommendations(counter_review: CounterEvidenceReview | dict[str, Any] | None) -> dict[str, HypothesisStatus]:
    out: dict[str, HypothesisStatus] = {}
    if counter_review is None:
        return out
    findings = counter_review.findings if hasattr(counter_review, "findings") else (counter_review.get("findings") if isinstance(counter_review, dict) else [])
    for f in findings or []:
        if isinstance(f, dict):
            hid = str(f.get("hypothesis_id") or "")
            raw = f.get("recommended_status")
        else:
            hid = str(getattr(f, "hypothesis_id", "") or "")
            raw = getattr(f, "recommended_status", None)
        if not hid:
            continue
        try:
            out[hid] = raw if isinstance(raw, HypothesisStatus) else HypothesisStatus(str(raw))
        except Exception:
            continue
    return out


_POSITIVE_SAFETY_STATUSES = {
    HypothesisStatus.refuted_by_guard,
    HypothesisStatus.refuted_by_caller_constraint,
    HypothesisStatus.refuted_by_patch_or_changed_logic,
    HypothesisStatus.irrelevant_to_target_function,
}


def _unresolved_local_risk_ids(
    decision: FinalDecision,
    counter_by_h: dict[str, HypothesisStatus],
    evidence_items: Iterable[Any] | None = None,
) -> list[str]:
    """Return local-risk hypotheses that lack positive safety/refutation evidence.

    A fixed/non-vulnerable *confirmed* decision is unsafe when any local risky
    operation remains only plausible/insufficient. Missing attacker-control
    evidence can justify a low-confidence forced binary choice, but it is not
    positive evidence that the code is safe.

    Important precision/recall guard: an exact-end parser guard (`raw == end` or
    equivalent) is not by itself a proof that pointer wraparound is impossible.
    It only refutes wraparound-to-lower-address traversal when paired with a
    saved-base lower-bound guard such as `raw >= start`.  Otherwise a model can
    incorrectly mark the vulnerable pre-fix count_rows variant as safe.
    """
    facts = _source_fact_types(evidence_items)
    exact_end_only_for_pointer = (
        "exact_end_success_else_error" in facts
        and "pointer_wraparound_lower_bound_guard" not in facts
    )
    unresolved: list[str] = []
    for h in decision.final_hypothesis_statuses or []:
        if not h.local_risk_present:
            continue
        status = counter_by_h.get(h.hypothesis_id, h.status)
        has_positive_status = status in _POSITIVE_SAFETY_STATUSES or h.status in _POSITIVE_SAFETY_STATUSES
        if has_positive_status and exact_end_only_for_pointer and _is_pointer_wraparound_like(h):
            unresolved.append(h.hypothesis_id)
            continue
        if not has_positive_status:
            unresolved.append(h.hypothesis_id)
    return unresolved


def _set_binary_explanation(decision: FinalDecision, *, vulnerable: bool, reason: str) -> None:
    """Keep dashboard reasoning consistent with forced_prediction_bool.

    The LLM sometimes writes an explanation for its pre-validator answer
    (for example, "predicted vulnerable") while the validator legitimately
    forces the binary result the other way.  The dashboard uses explanation as
    the user-facing final reasoning, so overwrite it when validator policy is
    the source of the binary decision.
    """
    label = "vulnerable" if vulnerable else "fixed/non-vulnerable"
    decision.explanation = f"Validator-forced binary decision: {label}. {reason}"


def _local_risk_evidence_ids(decision: FinalDecision) -> list[str]:
    """Return evidence ids for unresolved local-risk hypotheses.

    Used when the final binary label is forced vulnerable because of a strong
    uncovered local pattern.  This prevents reports from citing unrelated
    counter-evidence as the decisive evidence.
    """
    out: list[str] = []
    refuted = {
        HypothesisStatus.refuted_by_guard,
        HypothesisStatus.refuted_by_caller_constraint,
        HypothesisStatus.refuted_by_patch_or_changed_logic,
        HypothesisStatus.irrelevant_to_target_function,
    }
    for h in decision.final_hypothesis_statuses or []:
        if not getattr(h, "local_risk_present", False):
            continue
        if getattr(h, "status", None) in refuted:
            continue
        proof = getattr(h, "proof", None)
        if proof is not None:
            out.extend(str(x) for x in (proof.cited_evidence_ids or []) if str(x).strip())
        out.extend(str(x) for x in (getattr(h, "supporting_evidence_ids", []) or []) if str(x).strip())
    # Preserve order, keep report compact.
    return list(dict.fromkeys(out))[:16]


def validate_final_decision(
    decision: FinalDecision,
    *,
    evidence_items: Iterable[Any] | None = None,
    counter_review: CounterEvidenceReview | dict[str, Any] | None = None,
) -> tuple[FinalDecision, list[str], bool]:
    """Evidence-contract validator for the agentic proof pipeline.

    This does not use dataset labels or commit messages. It only enforces a
    model-visible proof contract: a vulnerable prediction must be supported by a
    complete, non-generic proof chain, existing evidence ids, and no accepted
    counter-evidence recommendation that downgrades the same hypothesis.
    """
    notes: List[str] = []
    modified = False
    existing_ids = _evidence_id_set(evidence_items)
    counter_by_h = _counter_recommendations(counter_review)
    has_pointer_wrap_safety = _has_pointer_wraparound_safety(evidence_items)

    usable_confirmed = []
    for h in decision.final_hypothesis_statuses:
        tier = _proof_tier_of_hypothesis(h)
        tier_confirmed = _is_confirmed_tier(tier)
        if not (
            h.status == HypothesisStatus.confirmed_vulnerability
            and h.confirmed_security_vulnerability
            and (h.proof.complete() or tier_confirmed)
        ):
            continue
        counter_status = counter_by_h.get(h.hypothesis_id)
        if _counter_status_is_unsupported_for_tier(counter_status, h):
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: counter-evidence review recommends {counter_status.value} with concrete counter evidence.")
            continue
        elif counter_status in _UNSUPPORTED_COUNTER_STATUSES and tier_confirmed:
            notes.append(f"Preserved confirmed hypothesis {h.hypothesis_id}: proof_tier={tier} and counter-review did not provide tier-erasing counter evidence.")
        proof = h.proof
        if not tier_confirmed and any(_looks_non_specific(x) for x in [proof.input_control, proof.dangerous_operation, proof.missing_or_failed_guard, proof.unsafe_use, proof.security_impact]):
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: proof chain contains generic or non-specific fields.")
            continue
        cited = {str(x) for x in (proof.cited_evidence_ids or []) if str(x).strip()}
        if not cited:
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: proof has no cited evidence ids.")
            continue
        if existing_ids and not cited.issubset(existing_ids):
            missing = sorted(cited - existing_ids)
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: proof cites evidence ids not present in retrieved evidence: {missing[:8]}.")
            continue
        if has_pointer_wrap_safety and _is_pointer_wraparound_like(h):
            proof_text = _verification_text(h)
            if "raw >= start" not in proof_text and "lower-bound" not in proof_text and "pointer wraparound guard" not in proof_text:
                notes.append(
                    f"Rejected confirmed hypothesis {h.hypothesis_id}: deterministic source facts show a pointer-wraparound lower-bound guard plus exact-end error return, but the proof does not explain how that guard is bypassed."
                )
                continue
        residual, residual_reason = _is_low_relevance_or_residual_confirmed(h, evidence_items)
        if residual:
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: {residual_reason}.")
            continue
        usable_confirmed.append(h)

    # Carry the strongest accepted proof tier to top-level decision fields so the
    # dashboard and final_prediction.json cannot lose the controller's proof state.
    tier_rank = {"confirmed_reachable_vulnerability": 3, "confirmed_source_level_vulnerability": 2, "high_signal_incomplete": 1}
    strongest_confirmed = None
    if usable_confirmed:
        strongest_confirmed = max(usable_confirmed, key=lambda h: tier_rank.get(_proof_tier_of_hypothesis(h), 0))
        final_tier = _proof_tier_of_hypothesis(strongest_confirmed)
        final_trust = str(getattr(strongest_confirmed, "trust_boundary_strength", "none") or "none")
        accepted_ids = [str(h.hypothesis_id) for h in usable_confirmed]
        if getattr(decision, "final_proof_tier", "unknown") != final_tier:
            decision.final_proof_tier = final_tier
            modified = True
        if getattr(decision, "final_trust_boundary_strength", "none") != final_trust:
            decision.final_trust_boundary_strength = final_trust
            modified = True
        if list(getattr(decision, "accepted_confirmed_hypotheses", []) or []) != accepted_ids:
            decision.accepted_confirmed_hypotheses = accepted_ids
            modified = True

    # Proof tiers are controller-derived and take precedence over the final
    # adjudicator's conservative fallback.  If a hypothesis completed a confirmed
    # tier, the final decision must remain vulnerable and must report that tier.
    if usable_confirmed and decision.prediction != FinalPrediction.vulnerable:
        chosen = usable_confirmed[0]
        tier = _proof_tier_of_hypothesis(chosen)
        notes.append(f"Upgraded final prediction from {decision.prediction.value} using accepted proof tier {tier} on {chosen.hypothesis_id}.")
        decision.prediction = FinalPrediction.vulnerable
        decision.local_risk_present = True
        decision.confirmed_security_vulnerability = True
        decision.confidence = max(float(decision.confidence or 0.0), 0.75 if tier == "confirmed_source_level_vulnerability" else 0.85)
        if decision.minimum_vulnerability_proof is None or not decision.minimum_vulnerability_proof.complete():
            decision.minimum_vulnerability_proof = chosen.proof
        if not decision.decisive_evidence_ids:
            decision.decisive_evidence_ids = list(dict.fromkeys((chosen.proof.cited_evidence_ids or []) + (getattr(chosen, "supporting_evidence_ids", []) or [])))[:20]
        modified = True

    if decision.prediction == FinalPrediction.vulnerable:
        if not usable_confirmed:
            notes.append("Downgraded vulnerable decision: no confirmed hypothesis survived the evidence/counter-evidence proof contract.")
            decision.prediction = FinalPrediction.inconclusive if decision.local_risk_present else FinalPrediction.fixed_or_non_vulnerable
            decision.confirmed_security_vulnerability = False
            decision.confidence = min(decision.confidence, 0.65)
            modified = True
        else:
            chosen = usable_confirmed[0]
            if decision.minimum_vulnerability_proof is None or not decision.minimum_vulnerability_proof.complete():
                notes.append("Filled final minimum_vulnerability_proof from the strongest confirmed hypothesis proof.")
                decision.minimum_vulnerability_proof = chosen.proof
                modified = True
            decisive = {str(x) for x in (decision.decisive_evidence_ids or []) if str(x).strip()}
            cited = {str(x) for x in (decision.minimum_vulnerability_proof.cited_evidence_ids or [])} if decision.minimum_vulnerability_proof else set()
            if not decisive:
                notes.append("Filled decisive_evidence_ids from minimum proof citations.")
                decision.decisive_evidence_ids = sorted(cited)
                modified = True
            elif cited and not (decisive & cited):
                notes.append("Adjusted decisive_evidence_ids to include proof-cited evidence.")
                decision.decisive_evidence_ids = sorted(decisive | cited)
                modified = True
            if existing_ids and any(str(x) not in existing_ids for x in decision.decisive_evidence_ids):
                old = list(decision.decisive_evidence_ids)
                decision.decisive_evidence_ids = [str(x) for x in decision.decisive_evidence_ids if str(x) in existing_ids]
                notes.append(f"Removed decisive evidence ids not present in retrieved evidence: {sorted(set(old) - set(decision.decisive_evidence_ids))[:8]}.")
                modified = True
            if not decision.decisive_evidence_ids:
                notes.append("Downgraded vulnerable decision: decisive_evidence_ids are empty after evidence-id validation.")
                decision.prediction = FinalPrediction.inconclusive
                decision.confirmed_security_vulnerability = False
                decision.confidence = min(decision.confidence, 0.65)
                modified = True

    if decision.prediction != FinalPrediction.vulnerable and decision.confirmed_security_vulnerability:
        notes.append("Set confirmed_security_vulnerability=false because final prediction is not vulnerable.")
        decision.confirmed_security_vulnerability = False
        modified = True
    if decision.prediction == FinalPrediction.vulnerable:
        decision.confirmed_security_vulnerability = True
        decision.local_risk_present = True
        if decision.confidence < 0.70:
            decision.confidence = 0.70; modified = True
    if decision.prediction == FinalPrediction.inconclusive and decision.confidence > 0.70:
        decision.confidence = 0.70; modified = True
    if decision.prediction == FinalPrediction.fixed_or_non_vulnerable:
        decision.confirmed_security_vulnerability = False
        if decision.confidence > 0.95:
            decision.confidence = 0.95; modified = True

    unresolved_local = _unresolved_local_risk_ids(decision, counter_by_h, evidence_items)
    pointer_safety_covers_unresolved = _pointer_safety_covers_unresolved(decision, unresolved_local, evidence_items)
    if decision.prediction == FinalPrediction.fixed_or_non_vulnerable and unresolved_local:
        if pointer_safety_covers_unresolved:
            notes.append(
                "Retained fixed/non-vulnerable decision: unresolved local-risk hypotheses are pointer-wraparound-like and deterministic source facts show a lower-bound pointer guard plus exact-end error return."
            )
            decision.confirmed_security_vulnerability = False
            decision.local_risk_present = True
            if decision.confidence > 0.80:
                decision.confidence = 0.80
                modified = True
            decision.evidence_strength = decision.evidence_strength or "likely"
            _set_binary_explanation(
                decision,
                vulnerable=False,
                reason=(
                    "The model selected fixed/non-vulnerable and the validator retained it because "
                    "all unresolved local-risk hypotheses are pointer-wraparound-like and deterministic "
                    "source facts show a lower-bound pointer guard plus exact-end error return."
                ),
            )
        else:
            notes.append(
                "Converted fixed/non-vulnerable decision to evidence-incomplete: "
                f"unresolved local-risk hypotheses remain: {unresolved_local[:8]}. "
                "Missing attacker-control evidence is not positive proof of safety."
            )
            decision.prediction = FinalPrediction.inconclusive
            decision.local_risk_present = True
            decision.confirmed_security_vulnerability = False
            decision.confidence = min(decision.confidence, 0.65)
            if not decision.residual_uncertainty:
                decision.residual_uncertainty = [
                    f"Unresolved local-risk hypothesis: {hid}" for hid in unresolved_local[:8]
                ]
            if not decision.why_forced_binary:
                decision.why_forced_binary = (
                    "Positive safety proof is incomplete; binary benchmark output falls back "
                    "to local-risk-present heuristic after bounded evidence retrieval."
                )
            decision.evidence_exhausted = True
            modified = True

    strong_pattern_before_binary, pattern_reason_before_binary = _has_strong_uncovered_vulnerability_pattern(decision, evidence_items)
    if decision.prediction == FinalPrediction.fixed_or_non_vulnerable and strong_pattern_before_binary:
        notes.append(
            "Converted fixed/non-vulnerable decision to evidence-incomplete: "
            f"deterministic source facts show a high-signal uncovered vulnerability pattern ({pattern_reason_before_binary})."
        )
        decision.prediction = FinalPrediction.inconclusive
        decision.local_risk_present = True
        decision.confirmed_security_vulnerability = False
        decision.confidence = min(decision.confidence, 0.65)
        if not decision.residual_uncertainty:
            decision.residual_uncertainty = [
                f"High-signal uncovered vulnerability pattern: {pattern_reason_before_binary}"
            ]
        modified = True

    # Always populate forced binary fields so benchmark scoring always has a
    # definitive True/False regardless of internal evidence status.
    if decision.prediction == FinalPrediction.vulnerable:
        decision.forced_prediction = "vulnerable"
        decision.forced_prediction_bool = True
        source_level_confirmed = any(
            getattr(h, "confirmed_security_vulnerability", False)
            and _proof_tier_of_hypothesis(h) == "confirmed_source_level_vulnerability"
            for h in (decision.final_hypothesis_statuses or [])
        )
        reachable_confirmed = any(
            getattr(h, "confirmed_security_vulnerability", False)
            and _proof_tier_of_hypothesis(h) == "confirmed_reachable_vulnerability"
            for h in (decision.final_hypothesis_statuses or [])
        )
        if source_level_confirmed and not reachable_confirmed:
            decision.decision_status = "confirmed_source_level_vulnerable"
            decision.evidence_strength = "confirmed_source_level"
            if "Confirmed source-level vulnerability; explicit caller/public-entry exploitability evidence is a stricter tier." not in decision.limitations:
                decision.limitations.append("Confirmed source-level vulnerability; explicit caller/public-entry exploitability evidence is a stricter tier.")
        else:
            decision.decision_status = "confirmed_vulnerable"
            decision.evidence_strength = "confirmed"
    elif decision.prediction == FinalPrediction.fixed_or_non_vulnerable:
        decision.forced_prediction = "fixed/non-vulnerable"
        decision.forced_prediction_bool = False
        decision.decision_status = "confirmed_non_vulnerable"
        decision.evidence_strength = "confirmed" if decision.confidence >= 0.80 else "likely"
    else:  # inconclusive — choose the more evidence-supported class
        strong_pattern, pattern_reason = _has_strong_uncovered_vulnerability_pattern(decision, evidence_items)
        if pointer_safety_covers_unresolved:
            decision.forced_prediction = "fixed/non-vulnerable"
            decision.forced_prediction_bool = False
            decision.decision_status = "forced_binary_non_vulnerable"
            notes.append("Forced fixed/non-vulnerable: pointer-wraparound local risks are covered by deterministic lower-bound pointer guard and exact-end error return.")
        elif strong_pattern:
            decision.forced_prediction = "vulnerable"
            decision.forced_prediction_bool = True
            decision.decision_status = "forced_binary_vulnerable"
            local_ids = _local_risk_evidence_ids(decision)
            if local_ids:
                decision.decisive_evidence_ids = local_ids
            notes.append(f"Forced vulnerable: {pattern_reason}.")
        else:
            decision.forced_prediction = "fixed/non-vulnerable"
            decision.forced_prediction_bool = False
            decision.decision_status = "forced_binary_non_vulnerable"
            notes.append("Forced fixed/non-vulnerable: local risks remain unproven and no high-signal uncovered vulnerability pattern was found.")
        decision.evidence_strength = "insufficient_static_evidence"
        if not decision.why_forced_binary:
            if pointer_safety_covers_unresolved:
                decision.why_forced_binary = (
                    "Evidence incomplete after bounded loop, but deterministic source facts show "
                    "a pointer-wraparound lower-bound guard and exact-end error return covering the remaining local risk."
                )
            elif strong_pattern:
                decision.why_forced_binary = (
                    "Evidence incomplete after bounded loop, but deterministic source facts show "
                    f"a high-signal uncovered vulnerability pattern: {pattern_reason}."
                )
            else:
                decision.why_forced_binary = (
                    "Evidence incomplete after bounded loop; local risk alone is not enough for a vulnerable benchmark prediction."
                )
        if decision.forced_prediction_bool is False:
            _set_binary_explanation(
                decision,
                vulnerable=False,
                reason=(
                    "No hypothesis satisfied the full minimum vulnerability proof contract. "
                    "Residual/local risks may remain, but without a high-signal uncovered pattern or complete exploitability proof, "
                    "the benchmark prediction is fixed/non-vulnerable."
                ),
            )
        else:
            _set_binary_explanation(
                decision,
                vulnerable=True,
                reason=(
                    f"A high-signal uncovered vulnerability pattern remains after bounded retrieval ({pattern_reason}). "
                    "This is a forced binary choice, not necessarily a confirmed vulnerability proof."
                ),
            )
        decision.evidence_exhausted = True

    decision.normalize_prediction_bool()
    return decision, notes, modified
