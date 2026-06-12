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


def test_fixed_prediction_with_unresolved_local_risk_becomes_forced_binary_vulnerable():
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
    assert out.forced_prediction_bool is True
    assert out.forced_prediction == "vulnerable"
    assert out.decision_status == "forced_binary_vulnerable"
    assert any("unresolved local-risk" in note for note in notes)


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
