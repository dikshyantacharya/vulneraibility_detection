from vckg_agentic_proof.adapter import _apply_counter_review_to_verifications
from vckg_agentic_proof.schemas import CounterEvidenceReview, CounterEvidenceFinding, FinalDecision, FinalPrediction, HypothesisStatus, HypothesisVerification, MinimumVulnerabilityProof
from vckg_agentic_proof.validator import validate_final_decision


def _confirmed_source_verification():
    return {
        "hypothesis_id": "HYP-01",
        "status": "confirmed_vulnerability",
        "local_risk_present": True,
        "confirmed_security_vulnerability": True,
        "proof_tier": "confirmed_source_level_vulnerability",
        "trust_boundary_strength": "source_level",
        "accepted_confirmed": True,
        "proof": {
            "input_control": "source-level parser input from loads comment",
            "dangerous_operation": "raw += length * itemsize",
            "missing_or_failed_guard": "no remaining-space/product-overflow guard",
            "unsafe_use": "raw reused in next parser loop iteration",
            "security_impact": "out-of-bounds read or crash",
            "cited_evidence_ids": ["TARGET-SOURCE"],
        },
        "supporting_evidence_ids": ["TARGET-SOURCE"],
        "counter_evidence_ids": [],
        "missing_evidence": [],
        "explanation": "Proof tier: confirmed_source_level_vulnerability; trust boundary: source_level.",
    }


def test_counter_review_preserves_source_level_tier_without_concrete_counter_evidence():
    v = _confirmed_source_verification()
    review = CounterEvidenceReview(findings=[CounterEvidenceFinding(
        hypothesis_id="HYP-01",
        strongest_counterargument="Missing concrete caller code and int_readers targets; this weakens reachable exploitability but does not show a guard.",
        counter_evidence_ids=[],
        refutes_or_weakens="weakens",
        recommended_status=HypothesisStatus.plausible_but_unproven,
    )])
    normalized, notes = _apply_counter_review_to_verifications({"verifications": [v]}, review)
    out = normalized["verifications"][0]
    assert out["status"] == "confirmed_vulnerability"
    assert out["confirmed_security_vulnerability"] is True
    assert out["accepted_confirmed"] is True
    assert any("counter_review_preserved" in n for n in notes)


def test_final_validator_maps_source_level_tier_to_confirmed_source_level_status():
    h = HypothesisVerification.model_validate(_confirmed_source_verification())
    decision = FinalDecision(
        prediction=FinalPrediction.inconclusive,
        prediction_bool=None,
        confidence=0.5,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[h],
        explanation="LLM was conservative.",
    )
    decision, notes, modified = validate_final_decision(decision, evidence_items=[{"id": "TARGET-SOURCE", "text": "raw += length * itemsize;"}], counter_review={"findings": []})
    assert decision.prediction == FinalPrediction.vulnerable
    assert decision.decision_status == "confirmed_source_level_vulnerable"
    assert decision.evidence_strength == "confirmed_source_level"
    assert decision.forced_prediction_bool is True
    assert decision.confirmed_security_vulnerability is True
