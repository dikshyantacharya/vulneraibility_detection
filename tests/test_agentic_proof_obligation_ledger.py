from vckg_agentic_proof.proof_obligations import (
    build_proof_obligations,
    infer_proof_family,
    summarize_ledger,
    verification_from_ledger,
)
from vckg_agentic_proof.schemas import ProofObligationVerification


def test_parser_scaled_pointer_family_builds_specific_obligations():
    src = """
    int f(void *raw, int raw_length, int itemsize) {
      uint64_t length = read(raw);
      raw += length * itemsize;
      return 0;
    }
    """
    hyp = {
        "hypothesis_id": "HYP-01",
        "title": "unchecked parsed length advances raw",
        "affected_code_region": "raw += length * itemsize;",
        "risk_summary": "length * itemsize can overflow pointer traversal",
    }
    assert infer_proof_family(hyp, src) == "parser_scaled_pointer_traversal"
    names = [o.name for o in build_proof_obligations(hyp, src)]
    assert "parsed_value_origin" in names
    assert "missing_remaining_bound_guard" in names
    assert "unsafe_continuation_or_accept_path" in names


def test_complete_required_ledger_derives_confirmed_hypothesis():
    hyp = {
        "hypothesis_id": "HYP-01",
        "title": "unchecked parsed length advances raw",
        "affected_code_region": "raw += length * itemsize;",
        "risk_summary": "length * itemsize can overflow pointer traversal",
    }
    obligations = build_proof_obligations(hyp, "raw += length * itemsize;")
    results = [
        ProofObligationVerification(
            obligation_id=o.obligation_id,
            hypothesis_id="HYP-01",
            result="proven",
            evidence_ids=["TARGET-SOURCE"],
            explanation=o.name,
            confidence=0.8,
        )
        for o in obligations
        if o.required
    ]
    ledger = summarize_ledger("HYP-01", "parser_scaled_pointer_traversal", obligations, results)
    verification = verification_from_ledger(hyp, ledger)
    assert ledger.status_hint == "complete"
    assert verification["status"] == "confirmed_vulnerability"
    assert verification["confirmed_security_vulnerability"] is True
    assert verification["proof"]["security_impact"]
