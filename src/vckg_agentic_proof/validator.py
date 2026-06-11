from __future__ import annotations
from typing import Any, Iterable, List
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
    ids: set[str] = set()
    for item in evidence_items or []:
        if isinstance(item, dict):
            v = item.get("id") or item.get("evidence_id") or item.get("node_id")
        else:
            v = getattr(item, "id", None) or getattr(item, "evidence_id", None) or getattr(item, "node_id", None)
        if v:
            ids.add(str(v))
    return ids

def _looks_non_specific(value: str | None) -> bool:
    s = (value or "").strip().lower()
    if not s:
        return True
    if s in _GENERIC_PROOF_PHRASES:
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

    usable_confirmed = []
    for h in decision.final_hypothesis_statuses:
        if not (h.status == HypothesisStatus.confirmed_vulnerability and h.confirmed_security_vulnerability and h.proof.complete()):
            continue
        counter_status = counter_by_h.get(h.hypothesis_id)
        if counter_status in _UNSUPPORTED_COUNTER_STATUSES:
            notes.append(f"Rejected confirmed hypothesis {h.hypothesis_id}: counter-evidence review recommends {counter_status.value}.")
            continue
        proof = h.proof
        if any(_looks_non_specific(x) for x in [proof.input_control, proof.dangerous_operation, proof.missing_or_failed_guard, proof.unsafe_use, proof.security_impact]):
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
        usable_confirmed.append(h)

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

    # Always populate forced binary fields so benchmark scoring always has a
    # definitive True/False regardless of internal evidence status.
    if decision.prediction == FinalPrediction.vulnerable:
        decision.forced_prediction = "vulnerable"
        decision.forced_prediction_bool = True
        decision.decision_status = "confirmed_vulnerable"
        decision.evidence_strength = "confirmed"
    elif decision.prediction == FinalPrediction.fixed_or_non_vulnerable:
        decision.forced_prediction = "fixed/non-vulnerable"
        decision.forced_prediction_bool = False
        decision.decision_status = "confirmed_non_vulnerable"
        decision.evidence_strength = "confirmed" if decision.confidence >= 0.80 else "likely"
    else:  # inconclusive — choose the more evidence-supported class
        if decision.local_risk_present:
            decision.forced_prediction = "vulnerable"
            decision.forced_prediction_bool = True
            decision.decision_status = "forced_binary_vulnerable"
        else:
            decision.forced_prediction = "fixed/non-vulnerable"
            decision.forced_prediction_bool = False
            decision.decision_status = "forced_binary_non_vulnerable"
        decision.evidence_strength = "insufficient_static_evidence"
        if not decision.why_forced_binary:
            decision.why_forced_binary = (
                "Evidence incomplete after bounded loop; forced binary chosen by "
                "local_risk_present heuristic."
            )
        decision.evidence_exhausted = True

    decision.normalize_prediction_bool()
    return decision, notes, modified
