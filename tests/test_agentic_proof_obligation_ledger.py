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
    assert "parsed_value_from_buffer" in names
    assert "trust_boundary_or_external_input" in names
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



def test_missing_guard_absence_supports_vulnerability_not_refutation():
    hyp = {
        "hypothesis_id": "HYP-01",
        "title": "unchecked parsed length advances raw",
        "affected_code_region": "raw += length * itemsize;",
        "risk_summary": "length * itemsize can overflow pointer traversal",
    }
    src = """
    while (raw <= end - (1 << length_power)) {
      uint64_t length = read(raw);
      raw += (1 << length_power);
      raw += length * itemsize;
    }
    """
    obligations = build_proof_obligations(hyp, src)
    missing_guard = next(o for o in obligations if o.name == "missing_remaining_bound_guard")
    result = ProofObligationVerification(
        obligation_id=missing_guard.obligation_id,
        hypothesis_id="HYP-01",
        result="refuted",
        evidence_ids=["TARGET-SOURCE"],
        explanation="The loop guard only checks space for the length field. No guard ensures length * itemsize <= remaining space and no overflow check exists.",
        confidence=0.95,
    )
    ledger = summarize_ledger("HYP-01", "parser_scaled_pointer_traversal", obligations, [result], target_source=src)
    normalized = ledger.obligation_results[0]
    assert normalized.result == "proven"
    assert normalized.supports_hypothesis is True
    assert ledger.status_hint != "refuted"


def test_atomic_scaled_advance_and_loop_continuation_are_deterministically_proven():
    hyp = {
        "hypothesis_id": "HYP-01",
        "title": "unchecked parsed length advances raw",
        "affected_code_region": "raw += length * itemsize;",
        "risk_summary": "length * itemsize can overflow pointer traversal",
    }
    src = """
    while (raw <= end - (1 << length_power)) {
      uint64_t length = read(raw);
      raw += (1 << length_power);
      raw += length * itemsize;
      rows++;
    }
    """
    obligations = build_proof_obligations(hyp, src)
    advance = next(o for o in obligations if o.name == "scaled_state_advance")
    continuation = next(o for o in obligations if o.name == "unsafe_continuation_or_accept_path")
    results = [
        ProofObligationVerification(
            obligation_id=advance.obligation_id,
            hypothesis_id="HYP-01",
            result="partially_proven",
            evidence_ids=["TARGET-SOURCE"],
            missing_evidence=["bounds checking belongs elsewhere"],
            explanation="The code directly shows raw += length * itemsize but lacks bounds checks.",
        ),
        ProofObligationVerification(
            obligation_id=continuation.obligation_id,
            hypothesis_id="HYP-01",
            result="partially_proven",
            evidence_ids=["TARGET-SOURCE"],
            missing_evidence=["post-loop dereference"],
            explanation="The advanced raw participates in loop continuation.",
        ),
    ]
    ledger = summarize_ledger("HYP-01", "parser_scaled_pointer_traversal", obligations, results, target_source=src)
    by_name = {o.name: r for o, r in zip([advance, continuation], ledger.obligation_results)}
    assert by_name["scaled_state_advance"].result == "proven"
    assert by_name["unsafe_continuation_or_accept_path"].result == "proven"


def test_parser_context_trust_boundary_gives_source_level_confirmation_without_caller_proof():
    hyp = {
        "hypothesis_id": "HYP-01",
        "title": "unchecked parsed length advances raw",
        "affected_code_region": "raw += length * itemsize;",
        "risk_summary": "length * itemsize can overflow pointer traversal",
    }
    src = """
    int count_rows(void *raw, int raw_length, int itemsize) {
      /* Pre-parse data fed to `RaggedArray.loads()`.
         Returns -1 for corrupt data. */
      while (raw <= end - 8) {
        uint64_t length = read(raw);
        raw += length * itemsize;
      }
      return -1;
    }
    """
    obligations = build_proof_obligations(hyp, src)
    results = []
    for o in obligations:
        if not o.required:
            continue
        result = "proven"
        missing = []
        explanation = o.name
        if o.name == "trust_boundary_or_external_input":
            result = "partially_proven"
            missing = ["explicit caller code showing raw buffer originates from external serialized/file/network/user input"]
            explanation = "The comment states the buffer is data fed to RaggedArray.loads(), but direct caller code is missing."
        results.append(ProofObligationVerification(
            obligation_id=o.obligation_id,
            hypothesis_id="HYP-01",
            result=result,
            evidence_ids=["TARGET-SOURCE"],
            missing_evidence=missing,
            explanation=explanation,
            confidence=0.8,
        ))
    ledger = summarize_ledger("HYP-01", "parser_scaled_pointer_traversal", obligations, results, target_source=src)
    verification = verification_from_ledger(hyp, ledger)
    assert ledger.status_hint == "source_level_complete"
    assert ledger.proof_tier == "confirmed_source_level_vulnerability"
    assert ledger.trust_boundary_strength == "source_level"
    assert ledger.required_missing == []
    assert verification["status"] == "confirmed_vulnerability"
    assert verification["confirmed_security_vulnerability"] is True
    assert "confirmed_source_level_vulnerability" in verification["explanation"]


def test_family_assignment_uses_hypothesis_not_target_source_for_secondary_issues():
    src = """
    int count_rows(void * raw, int length_power, int itemsize) {
      uint64_t length = read(raw);
      raw += length * itemsize;
      while (raw <= end - (1 << length_power)) {}
    }
    """
    signed_hyp = {
        "hypothesis_id": "HYP-02",
        "title": "Signed integer misinterpretation in read leading to negative length",
        "affected_code_region": "uint64_t length = read(raw);",
        "risk_summary": "If read returns a signed negative value, conversion to uint64_t yields a huge length.",
    }
    selector_hyp = {
        "hypothesis_id": "HYP-03",
        "title": "Insufficient bounds checking for length_power leading to out-of-bounds read",
        "affected_code_region": "while (raw <= end - (1 << length_power))",
        "risk_summary": "length_power controls a shift and dispatch width without a domain guard.",
    }
    assert infer_proof_family(signed_hyp, src) == "callee_return_signedness_or_value_range"
    assert infer_proof_family(selector_hyp, src) == "selector_shift_domain_or_dispatch_bounds"
    assert "return_signedness_or_value_range" in [o.name for o in build_proof_obligations(signed_hyp, src)]
    assert "shift_or_dispatch_expression" in [o.name for o in build_proof_obligations(selector_hyp, src)]


def test_missing_guard_inversion_is_fixed_even_when_llm_says_refuted():
    hyp = {
        "hypothesis_id": "HYP-02",
        "title": "signed read value later used unsafely",
        "affected_code_region": "uint64_t length = read(raw);",
        "risk_summary": "returned length is converted and later used without a post-read range check",
    }
    src = """
    uint64_t length = read(raw);
    raw += length * itemsize;
    """
    obligations = build_proof_obligations(hyp, src)
    missing = next(o for o in obligations if o.name == "missing_post_read_range_check")
    result = ProofObligationVerification(
        obligation_id=missing.obligation_id,
        hypothesis_id="HYP-02",
        result="refuted",
        evidence_ids=["TARGET-SOURCE"],
        missing_evidence=["guard ensuring length * itemsize <= remaining_space", "overflow check for length * itemsize"],
        explanation="No dominating guard exists after read(raw); the code does not validate length before pointer arithmetic.",
    )
    ledger = summarize_ledger("HYP-02", missing.family, obligations, [result], target_source=src)
    normalized = ledger.obligation_results[0]
    assert normalized.result == "proven"
    assert normalized.supports_hypothesis is True
    assert normalized.refutes_hypothesis is False
