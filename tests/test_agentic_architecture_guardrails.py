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


def test_raw_malloc_immediate_use_forces_vulnerable_when_no_growth_guard():
    from vckg_agentic_proof.adapter import _infer_deterministic_source_facts

    src = '''
    void f(const char *name, const char *dirname) {
        char *new_fname = malloc(strlen(name) + strlen(dirname) + 16);
        snprintf(new_fname, strlen(name) + strlen(dirname) + 16, "%s/%s", dirname, name);
    }
    '''
    evidence = _infer_deterministic_source_facts(src, "f")
    assert any(e["metadata"]["fact_type"] == "raw_malloc_without_null_check_before_use" for e in evidence)

    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.9,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-ALLOC",
                status=HypothesisStatus.plausible_but_unproven,
                local_risk_present=True,
                explanation="malloc result is used by snprintf before a visible NULL check",
            )
        ],
        explanation="model thought local risk was unproven",
    )
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.forced_prediction_bool is True
    assert out.decision_status == "forced_binary_vulnerable"
    assert any("raw dynamic allocation" in note for note in notes)


def test_raw_calloc_then_fread_forces_vulnerable_when_no_wrapper_guard():
    from vckg_agentic_proof.adapter import _infer_deterministic_source_facts

    src = '''
    static char *get_header(FILE *fp) {
        char *header;
        header = calloc(1, 1024);
        SAFE_E(fread(header, 1, 1023, fp), 1023, "fail");
        return header;
    }
    '''
    evidence = _infer_deterministic_source_facts(src, "get_header")
    assert any(e["metadata"]["fact_type"] == "raw_calloc_without_null_check_before_use" for e in evidence)

    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.8,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-CALLOC",
                status=HypothesisStatus.plausible_but_unproven,
                local_risk_present=True,
                explanation="calloc result may be NULL before fread uses it",
            )
        ],
        explanation="unproven",
    )
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.forced_prediction_bool is True
    assert out.decision_status == "forced_binary_vulnerable"


def test_safe_calloc_bounded_fread_refutes_header_false_positive():
    from vckg_agentic_proof.adapter import _infer_deterministic_source_facts

    src = '''
    static char *get_header(FILE *fp) {
        char *header = safe_calloc(1024);
        SAFE_E(fread(header, 1, 1023, fp), 1023, "fail");
        return header;
    }
    '''
    evidence = _infer_deterministic_source_facts(src, "get_header")
    fact_types = {e["metadata"]["fact_type"] for e in evidence}
    assert "safe_calloc_allocation_wrapper_used" in fact_types
    assert "bounded_read_within_safe_allocation" in fact_types

    decision = FinalDecision(
        prediction=FinalPrediction.vulnerable,
        confidence=0.95,
        local_risk_present=True,
        confirmed_security_vulnerability=True,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-FREAD",
                status=HypothesisStatus.confirmed_vulnerability,
                local_risk_present=True,
                confirmed_security_vulnerability=True,
                explanation="fread may overflow header buffer",
                proof={
                    "input_control": "file contents are attacker supplied",
                    "dangerous_operation": "fread(header, 1, 1023, fp)",
                    "missing_or_failed_guard": "no explicit file size check",
                    "unsafe_use": "header buffer may be overrun or unterminated",
                    "security_impact": "memory corruption",
                    "cited_evidence_ids": ["AUTO-SF-01"],
                },
            )
        ],
        explanation="confirmed vulnerable",
    )
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.forced_prediction_bool is False
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("Downgraded vulnerable decision" in note or "bounded read" in note or "safe_calloc" in note for note in notes)


def test_safe_calloc_wrapper_suppresses_allocation_overflow_false_positive():
    from vckg_agentic_proof.adapter import _infer_deterministic_source_facts

    src = '''
    static void load_xref_from_plaintext(xref_t *xref) {
        xref->n_entries = atoi(buf + strlen("ize "));
        xref->entries = safe_calloc(xref->n_entries * sizeof(struct _xref_entry));
        xref->entries[0].obj_id = 1;
    }
    '''
    evidence = _infer_deterministic_source_facts(src, "load_xref_from_plaintext")
    assert any(e["metadata"]["fact_type"] == "safe_calloc_allocation_wrapper_used" for e in evidence)

    decision = FinalDecision(
        prediction=FinalPrediction.vulnerable,
        confidence=0.95,
        local_risk_present=True,
        confirmed_security_vulnerability=True,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-SAFE-CALLOC",
                status=HypothesisStatus.confirmed_vulnerability,
                local_risk_present=True,
                confirmed_security_vulnerability=True,
                explanation="safe_calloc allocation may wrap around",
                proof={
                    "input_control": "xref n_entries is parsed from PDF input",
                    "dangerous_operation": "safe_calloc(xref->n_entries * sizeof(struct _xref_entry))",
                    "missing_or_failed_guard": "no explicit multiplication overflow check",
                    "unsafe_use": "xref entries are written after allocation",
                    "security_impact": "heap overflow",
                    "cited_evidence_ids": ["AUTO-SF-01"],
                },
            )
        ],
        explanation="confirmed vulnerable",
    )
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.forced_prediction_bool is False
    assert out.decision_status == "forced_binary_non_vulnerable"
    assert any("safe_calloc" in note for note in notes)


def test_dynamic_growth_guard_prevents_raw_malloc_residual_from_forcing_vulnerable():
    from vckg_agentic_proof.adapter import _infer_deterministic_source_facts

    src = '''
    static char *get_pid_environ_val(pid_t pid,char *val){
      int temp_size = 500;
      char *temp = malloc(temp_size);
      int i = 0;
      sprintf(temp,"/proc/%d/environ",pid);
      for(;;){
        if (i >= temp_size) {
          temp_size *= 2;
          temp = realloc(temp, temp_size);
        }
        temp[i]=fgetc(fp);
        i++;
      }
    }
    '''
    evidence = _infer_deterministic_source_facts(src, "get_pid_environ_val")
    fact_types = {e["metadata"]["fact_type"] for e in evidence}
    assert "dynamic_buffer_growth_guard" in fact_types
    assert "raw_malloc_without_null_check_before_use" in fact_types

    decision = FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.8,
        local_risk_present=True,
        confirmed_security_vulnerability=False,
        final_hypothesis_statuses=[
            HypothesisVerification(
                hypothesis_id="HYP-REALLOC",
                status=HypothesisStatus.plausible_but_unproven,
                local_risk_present=True,
                explanation="realloc result is unchecked residual risk",
            )
        ],
        explanation="local residual risk only",
    )
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.forced_prediction_bool is False
    assert out.decision_status == "forced_binary_non_vulnerable"


def test_single_hypothesis_terminal_prompt_includes_retrieval_status():
    from vckg_agentic_proof.prompts import single_hypothesis_verification_prompt

    messages = single_hypothesis_verification_prompt(
        {"target_function": "count_rows", "filepath": "x.c"},
        {"hypothesis_id": "HYP-01", "title": "t", "risk_summary": "r"},
        evidence=[{"id": "E1", "kind": "target_statement", "function": "count_rows", "text": "raw += length * itemsize;"}],
        target_source="int count_rows(){ return 0; }",
        retrieval_status={"closure_reason": "no_new_evidence_returned", "attempted_new_queries": 3},
        terminal_closure=True,
    )

    text = "\n".join(m["content"] for m in messages)
    assert "RETRIEVAL STATUS FOR THIS HYPOTHESIS" in text
    assert "terminal verification object" in text
    assert "no_new_evidence_returned" in text


def test_variable_flow_sanitizer_rejects_english_gap_words():
    from vckg_agentic_proof.adapter import _actionable_gap_queries

    plan = EvidenceGapPlan(
        needs_more_evidence=True,
        gaps=[
            GapItem(
                gap_id="G1",
                hypothesis_id="HYP-01",
                proof_element="caller_constraints",
                missing_evidence="Bit width and Caller constraints remain unresolved",
                queryable=True,
                priority="high",
            )
        ],
        follow_up_queries=[
            KGQuery(
                query_id="BAD1",
                hypothesis_id="HYP-01",
                purpose="bad abstract variable",
                query_text='variable_flow(target_function="count_rows", symbol="Bit", data_depth=5)',
                expected_evidence="bad",
            ),
            KGQuery(
                query_id="OK1",
                hypothesis_id="HYP-01",
                purpose="real target symbol",
                query_text='variable_flow(target_function="count_rows", symbol="raw_length", data_depth=5)',
                expected_evidence="ok",
            ),
        ],
    )
    src = "int count_rows(void *raw, int raw_length) { void *end = raw + raw_length; return 0; }"
    out = _actionable_gap_queries({"function": "count_rows"}, plan, plan.follow_up_queries, prefix="QF-", target_source=src)
    texts = [q.query_text for q in out]

    assert not any('symbol="Bit"' in t for t in texts)
    assert any('symbol="raw_length"' in t for t in texts)


def test_confirmed_verification_with_missing_evidence_is_downgraded_by_proof_gate():
    from vckg_agentic_proof.adapter import _gate_single_verification

    v = {
        "hypothesis_id": "HYP-01",
        "status": "confirmed_vulnerability",
        "local_risk_present": True,
        "confirmed_security_vulnerability": True,
        "proof": {
            "input_control": "length is read from raw",
            "dangerous_operation": "raw += length * itemsize",
            "missing_or_failed_guard": "no overflow guard",
            "unsafe_use": "raw may wrap",
            "security_impact": "out-of-bounds read",
            "cited_evidence_ids": ["TARGET-SOURCE"],
        },
        "missing_evidence": ["Caller constraints on length_power are still missing"],
        "explanation": "claimed confirmed",
    }

    out, notes = _gate_single_verification(v, evidence=[])

    assert out["status"] == "plausible_but_unproven"
    assert out["confirmed_security_vulnerability"] is False
    assert any("verification_still_lists_missing_evidence" in n for n in notes)


def test_variable_flow_rejects_function_and_type_symbols_after_symbol_kind_routing():
    from vckg_agentic_proof.adapter import _sanitize_or_rewrite_query

    src = '''
    int count_rows(void * raw, int raw_length, int length_power, int big_endian, int itemsize) {
        IntRead read = choose_int_read(length_power, big_endian);
        uint64_t length = read(raw);
        raw += length * itemsize;
        return 0;
    }
    '''
    sample = {"function": "count_rows"}
    valid = KGQuery(query_id="Q1", purpose="p", query_text='variable_flow(target_function="count_rows", symbol="length", data_depth=4)', expected_evidence="e")
    bad_fn = KGQuery(query_id="Q2", purpose="p", query_text='variable_flow(target_function="count_rows", symbol="choose_int_read", data_depth=4)', expected_evidence="e")
    bad_type = KGQuery(query_id="Q3", purpose="p", query_text='variable_flow(target_function="count_rows", symbol="IntRead", data_depth=4)', expected_evidence="e")
    bad_target = KGQuery(query_id="Q4", purpose="p", query_text='variable_flow(target_function="count_rows", symbol="count_rows", data_depth=4)', expected_evidence="e")

    assert _sanitize_or_rewrite_query(valid, sample, target_source=src) is not None
    assert _sanitize_or_rewrite_query(bad_fn, sample, target_source=src) is None
    assert _sanitize_or_rewrite_query(bad_type, sample, target_source=src) is None
    assert _sanitize_or_rewrite_query(bad_target, sample, target_source=src) is None


def test_counter_review_downgrades_raw_confirmed_before_final_adjudication():
    from vckg_agentic_proof.adapter import _apply_counter_review_to_verifications

    verifications = {"verifications": [
        {
            "hypothesis_id": "HYP-02",
            "status": "confirmed_vulnerability",
            "local_risk_present": True,
            "confirmed_security_vulnerability": True,
            "proof": {"input_control": "x", "dangerous_operation": "y", "missing_or_failed_guard": "z", "unsafe_use": "u", "security_impact": "i", "cited_evidence_ids": ["E1"]},
            "supporting_evidence_ids": ["E1"],
            "counter_evidence_ids": [],
            "missing_evidence": [],
            "explanation": "raw confirmed",
        }
    ]}
    counter = {
        "findings": [
            {
                "hypothesis_id": "HYP-02",
                "strongest_counterargument": "dominating guard",
                "counter_evidence_ids": ["C1"],
                "refutes_or_weakens": "refutes",
                "recommended_status": "refuted_by_guard",
            }
        ]
    }
    out, notes = _apply_counter_review_to_verifications(verifications, counter)
    v = out["verifications"][0]
    assert v["status"] == "refuted_by_guard"
    assert v["confirmed_security_vulnerability"] is False
    assert v["local_risk_present"] is False
    assert v["counter_evidence_ids"] == ["C1"]
    assert notes and "counter_review_updated HYP-02" in notes[0]


def test_forced_vulnerable_decisive_ids_use_local_risk_evidence_not_counter_only():
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
                explanation="raw pointer local risk",
                proof={
                    "dangerous_operation": "raw += length * itemsize",
                    "missing_or_failed_guard": "no overflow guard",
                    "unsafe_use": "raw may traverse beyond end",
                    "security_impact": "out-of-bounds read",
                    "cited_evidence_ids": ["E_LOCAL"],
                },
                supporting_evidence_ids=["E_LOCAL"],
                counter_evidence_ids=["C_GUARD"],
            )
        ],
        decisive_evidence_ids=["C_GUARD"],
        explanation="inconclusive",
    )
    evidence = [
        {"id": "E_LOCAL", "kind": "target_statement", "text": "raw += length * itemsize;"},
        {"id": "C_GUARD", "kind": "target_statement", "text": "if (ordinal < 0 || ordinal > 8) return 0;"},
    ]
    out, notes, modified = validate_final_decision(decision, evidence_items=evidence, counter_review=None)
    assert out.decision_status == "forced_binary_vulnerable"
    assert "E_LOCAL" in out.decisive_evidence_ids
    assert out.decisive_evidence_ids != ["C_GUARD"]
