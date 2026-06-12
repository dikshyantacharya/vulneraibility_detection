from vckg_agentic_proof.adapter import _effective_follow_up_queries, _plan_effective_needs_more_evidence
from vckg_agentic_proof.schemas import (
    EvidenceGapPlan,
    FinalDecision,
    FinalPrediction,
    GapItem,
    HypothesisStatus,
    HypothesisVerification,
    KGQuery,
    VulnerabilityHypothesis,
)
from vckg_agentic_proof.validator import validate_final_decision


def test_gap_plan_does_not_stop_when_queryable_gaps_and_queries_exist():
    plan = EvidenceGapPlan(
        needs_more_evidence=False,
        stop_reason_if_no_queries="no_queryable_gaps",
        gaps=[
            GapItem(
                gap_id="G1",
                hypothesis_id="HYP-01",
                proof_element="input_control",
                missing_evidence="caller/source evidence",
                queryable=True,
                priority="high",
            )
        ],
        follow_up_queries=[
            KGQuery(
                query_id="Q99",
                hypothesis_id="HYP-01",
                purpose="Find callers and source of untrusted buffer",
                query_text='call_neighborhood(target_function="count_rows", direction="in", call_depth=2)',
                expected_evidence="caller constraints and input source",
            )
        ],
    )

    assert _plan_effective_needs_more_evidence(plan) is True
    assert [q.query_id for q in _effective_follow_up_queries(plan)] == ["Q99"]


def test_fixed_prediction_with_unresolved_local_risk_defaults_safe_without_strong_pattern():
    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.85,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.plausible_but_unproven,
                local_risk_present=True,
                explanation="Unguarded length multiplication remains unresolved.",
            )
        ],
        explanation="The risk is unproven.",
    )

    out, notes, modified = validate_final_decision(decision, evidence_items=[], counter_review=None)

    assert modified is True
    assert out.prediction == FinalPrediction.inconclusive
    assert out.forced_prediction_bool is False
    assert out.forced_prediction == "fixed/non-vulnerable"
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("unresolved local-risk" in note for note in notes)
    assert any("local risks remain unproven" in note for note in notes)


def test_hypotheses_id_alias_is_normalized():
    h = VulnerabilityHypothesis.model_validate(
        {
            "hypotheses_id": "HYP-04",
            "title": "Alias typo",
            "risk_summary": "Should still be kept.",
        }
    )
    assert h.hypothesis_id == "HYP-04"

from vckg_agentic_proof.adapter import AgentEvent, AgenticProofConfig, _call_llm
from vckg_agentic_proof.prompts import counter_gap_analysis_prompt


def test_counter_gap_prompt_content_is_string_not_boolean():
    messages = counter_gap_analysis_prompt(
        {"target_function": "count_rows"},
        counter_findings=[{"hypothesis_id": "HYP-01", "refutes_or_weakens": "weakens"}],
        evidence=[{"id": "E1", "kind": "target_statement"}],
        executed_query_ids=["Q01"],
        iteration=1,
    )

    assert messages
    assert all(isinstance(m.get("content"), str) for m in messages)
    assert 'call_neighborhood(direction="in")' in messages[-1]["content"]


def test_call_llm_coerces_non_string_message_content_before_generation():
    captured = {}

    def fake_generate(messages, **kwargs):
        captured["messages"] = messages
        return {"content": "<answer>{}</answer>", "usage": {}}

    events = []
    text, _usage = _call_llm(
        llm_generate=fake_generate,
        messages=[{"role": "user", "content": True}],
        sample_id="S1",
        stage="unit_stage",
        max_tokens=128,
        config=AgenticProofConfig(),
        events=events,
    )

    assert text == "<answer>{}</answer>"
    assert captured["messages"][0]["content"] == "True"
    assert any(e.event == "prompt_content_coerced" for e in events)


def test_codekg_query_direction_aliases_are_normalized():
    q = KGQuery(
        query_id="Q1",
        purpose="callers",
        query_text='call_neighborhood(target_function="f", direction="incoming", call_depth=3)',
        expected_evidence="callers",
    )
    assert 'direction="in"' in q.query_text


def test_pointer_wraparound_guard_changes_incomplete_local_risk_to_forced_safe():
    decision = FinalDecision(
        prediction=FinalPrediction.inconclusive,
        confidence=0.6,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.plausible_but_unproven,
                local_risk_present=True,
                explanation="raw pointer may wrap due to length * itemsize pointer advancement",
                proof={
                    "dangerous_operation": "raw += length * itemsize",
                    "missing_or_failed_guard": "No direct multiplication overflow check",
                    "unsafe_use": "raw may wrap below start or past end",
                    "security_impact": "buffer overread",
                    "cited_evidence_ids": ["E1"],
                },
            )
        ],
        explanation="Incomplete proof but local pointer risk remains.",
    )
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "Pointer wraparound guard", "metadata": {"fact_type": "pointer_wraparound_lower_bound_guard"}},
        {"id": "AUTO-SF-2", "kind": "deterministic_source_fact", "text": "Exact-end guard: success requires `raw == end`; otherwise the function reaches an error return `-1`.", "metadata": {"fact_type": "exact_end_success_else_error"}},
    ]

    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)

    assert out.forced_prediction_bool is False
    assert out.forced_prediction == "fixed/non-vulnerable"
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("pointer-wraparound" in note for note in notes)


def test_confirmed_pointer_vulnerability_rejected_when_source_guard_unaddressed():
    decision = FinalDecision(
        prediction=FinalPrediction.vulnerable,
        confidence=0.8,
        local_risk_present=True,
        confirmed_security_vulnerability=True,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.confirmed_vulnerability,
                local_risk_present=True,
                confirmed_security_vulnerability=True,
                explanation="raw pointer overflow in parser",
                proof={
                    "input_control": "length is read from raw parser buffer",
                    "dangerous_operation": "raw += length * itemsize",
                    "missing_or_failed_guard": "no multiplication overflow check",
                    "unsafe_use": "overflowed raw may advance before buffer start",
                    "security_impact": "out-of-bounds read",
                    "cited_evidence_ids": ["E1"],
                },
            )
        ],
        explanation="Vulnerable because raw may wrap.",
    )
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "Pointer wraparound guard", "metadata": {"fact_type": "pointer_wraparound_lower_bound_guard"}},
        {"id": "AUTO-SF-2", "kind": "deterministic_source_fact", "text": "Exact-end guard: success requires `raw == end`; otherwise the function reaches an error return `-1`.", "metadata": {"fact_type": "exact_end_success_else_error"}},
    ]

    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)

    assert out.forced_prediction_bool is False
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("does not explain how that guard is bypassed" in note for note in notes)


def test_unproven_input_control_rejects_confirmed_vulnerability_proof():
    decision = FinalDecision(
        prediction=FinalPrediction.vulnerable,
        confidence=0.8,
        local_risk_present=True,
        confirmed_security_vulnerability=True,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.confirmed_vulnerability,
                local_risk_present=True,
                confirmed_security_vulnerability=True,
                explanation="raw pointer overflow in parser",
                proof={
                    "input_control": "Attacker control is plausible but unproven.",
                    "dangerous_operation": "raw += length * itemsize",
                    "missing_or_failed_guard": "no multiplication overflow check",
                    "unsafe_use": "raw may overflow",
                    "security_impact": "out-of-bounds read",
                    "cited_evidence_ids": ["E1"],
                },
            )
        ],
        explanation="Vulnerable because raw may wrap.",
    )

    out, notes, modified = validate_final_decision(
        decision, evidence_items=[{"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"}], counter_review=None
    )

    assert out.decision_status == "forced_binary_vulnerable"
    assert any("generic or non-specific" in note for note in notes)


def test_stage06_fallback_from_verifications_forces_vulnerable_without_pointer_guard():
    from vckg_agentic_proof.adapter import _make_fallback_decision_from_verifications

    verifications = {"verifications": [
        {
            "hypothesis_id": "HYP-01",
            "status": "plausible_but_unproven",
            "local_risk_present": True,
            "confirmed_security_vulnerability": False,
            "proof": {
                "dangerous_operation": "raw += length * itemsize",
                "missing_or_failed_guard": "no overflow check",
                "unsafe_use": "raw may wrap",
                "security_impact": "buffer overread",
                "cited_evidence_ids": ["E1"],
            },
            "supporting_evidence_ids": ["E1"],
            "counter_evidence_ids": [],
            "missing_evidence": ["caller constraints"],
            "explanation": "local raw pointer risk remains",
        }
    ]}
    decision, notes, modified = _make_fallback_decision_from_verifications(
        "TaggedJsonParseError: truncated",
        verifications,
        evidence_items=[{"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"}],
        counter_review=None,
    )

    assert decision.final_decision_source == "stage06_fallback_from_verifications"
    assert decision.decision_status == "forced_binary_vulnerable"
    assert decision.forced_prediction_bool is True
    assert any("stage06_fallback_from_verifications" in n for n in notes)


def test_stage06_fallback_from_verifications_forces_safe_when_pointer_guard_covers_risk():
    from vckg_agentic_proof.adapter import _make_fallback_decision_from_verifications

    verifications = {"verifications": [
        {
            "hypothesis_id": "HYP-01",
            "status": "plausible_but_unproven",
            "local_risk_present": True,
            "confirmed_security_vulnerability": False,
            "proof": {
                "dangerous_operation": "raw += length * itemsize",
                "missing_or_failed_guard": "no direct overflow check",
                "unsafe_use": "raw may wrap below start",
                "security_impact": "buffer overread",
                "cited_evidence_ids": ["E1"],
            },
            "supporting_evidence_ids": ["E1"],
            "counter_evidence_ids": ["AUTO-SF-1", "AUTO-SF-2"],
            "missing_evidence": [],
            "explanation": "pointer wraparound-like risk",
        }
    ]}
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "Pointer wraparound guard", "metadata": {"fact_type": "pointer_wraparound_lower_bound_guard"}},
        {"id": "AUTO-SF-2", "kind": "deterministic_source_fact", "text": "Exact-end guard", "metadata": {"fact_type": "exact_end_success_else_error"}},
    ]
    decision, notes, modified = _make_fallback_decision_from_verifications(
        "TaggedJsonParseError: truncated", verifications, evidence_items=evidence, counter_review=None
    )

    assert decision.final_decision_source == "stage06_fallback_from_verifications"
    assert decision.decision_status == "forced_binary_non_vulnerable"
    assert decision.forced_prediction_bool is False
    assert "fixed/non-vulnerable" in decision.explanation


def test_exact_end_guard_alone_does_not_refute_count_rows_pointer_wraparound():
    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.9,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.refuted_by_guard,
                local_risk_present=True,
                confirmed_security_vulnerability=False,
                explanation="Exact-end guard refutes raw += length * itemsize pointer wraparound.",
                proof={
                    "dangerous_operation": "raw += length * itemsize",
                    "missing_or_failed_guard": "no multiplication overflow check",
                    "unsafe_use": "raw may wrap below buffer start",
                    "security_impact": "out-of-bounds read",
                    "cited_evidence_ids": ["E1", "AUTO-SF-1"],
                },
                counter_evidence_ids=["AUTO-SF-1"],
            )
        ],
        explanation="Exact-end guard is enough.",
    )
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "raw += length * itemsize;"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "Exact-end guard: success requires `raw == end`; otherwise the function reaches an error return `-1`.", "metadata": {"fact_type": "exact_end_success_else_error"}},
    ]

    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)

    assert modified is True
    assert out.forced_prediction_bool is True
    assert out.decision_status == "forced_binary_vulnerable"
    assert any("Forced vulnerable: unguarded raw-buffer pointer advancement" in note for note in notes)


def test_fixed_size_buffer_pattern_overrides_overconfident_safe_decision():
    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.95,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.refuted_by_guard,
                local_risk_present=True,
                confirmed_security_vulnerability=False,
                explanation="Kernel-managed environ is bounded, so temp[500] write is safe.",
                proof={
                    "dangerous_operation": "temp[i]=fgetc(fp)",
                    "missing_or_failed_guard": "no i < 500 check",
                    "unsafe_use": "indexed stack buffer write",
                    "security_impact": "stack buffer overflow",
                    "cited_evidence_ids": ["E1", "AUTO-SF-1"],
                },
            )
        ],
        explanation="Safe due to environment delimiters.",
    )
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "char temp[500]; temp[i]=fgetc(fp);"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "Fixed-size buffer `temp[500]` is written through an index inside an unbounded loop without an obvious `temp` size guard.", "metadata": {"fact_type": "fixed_size_buffer_unbounded_index_write"}},
    ]

    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)

    assert modified is True
    assert out.forced_prediction_bool is True
    assert out.decision_status == "forced_binary_vulnerable"
    assert any("fixed-size buffer" in note for note in notes)


def test_shifted_extra_bounds_guard_suppresses_oldpos_residual_false_positive():
    decision = FinalDecision(
        prediction=FinalPrediction.vulnerable,
        confidence=0.95,
        local_risk_present=True,
        confirmed_security_vulnerability=True,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-01",
                status=HypothesisStatus.confirmed_vulnerability,
                local_risk_present=True,
                confirmed_security_vulnerability=True,
                explanation="oldpos += z advances oldpos without bounds validation",
                proof={
                    "input_control": "control tuple z comes from input",
                    "dangerous_operation": "oldpos += z",
                    "missing_or_failed_guard": "no explicit z bounds guard",
                    "unsafe_use": "origData[oldpos + j] may be reached",
                    "security_impact": "out-of-bounds read",
                    "cited_evidence_ids": ["E1", "E2"],
                },
                supporting_evidence_ids=["E1", "E2"],
            )
        ],
        explanation="Vulnerable due to oldpos residual concern.",
    )
    evidence = [
        {"id": "E1", "kind": "target_statement", "text": "oldpos += z;"},
        {"id": "E2", "kind": "target_statement", "text": "if ((oldpos + j >= 0) && (oldpos + j < origDataLength))"},
        {"id": "AUTO-SF-1", "kind": "deterministic_source_fact", "text": "The extra-block bounds check appears after `newpos += x` and before `memcpy(newData + newpos, extraPtr, y)`.", "metadata": {"fact_type": "shifted_extra_bounds_guard"}},
    ]

    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)

    assert modified is True
    assert out.forced_prediction_bool is False
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("proof chain contains generic or non-specific" in note or "Forced fixed/non-vulnerable" in note for note in notes)
