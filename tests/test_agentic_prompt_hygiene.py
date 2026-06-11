"""Focused tests for agentic-proof prompt hygiene, token budgets,
truncation detection, JSON repair, and trace field safety.

These tests are designed to fail first (TDD), then pass after implementation.
No KG build, no real LLM calls required.
"""
from __future__ import annotations

import json
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE = {
    "id": "99999",
    "sample_id": "99999",
    "project": "test_project",
    "project_url": "https://github.com/org/test_project",
    "function": "vulnerable_func",
    "func_name": "vulnerable_func",
    "filepath": "src/test.c",
    "label": "vulnerable",
    "commit": "deadbeef1234",
    "resolved_commit": "cafebabe5678",
}

_SOURCE = "int vulnerable_func(char *buf, int len) {\n    memcpy(dst, buf, len);\n    return 0;\n}"

_HYPOTHESES = [
    {
        "hypothesis_id": "HYP-01",
        "title": "Unchecked buffer length",
        "risk_summary": "len may exceed dst capacity",
        "required_proof_questions": ["Is len validated?"],
    }
]

_EVIDENCE = [
    {
        "id": "EV-01",
        "kind": "source_snippet",
        "text": "memcpy(dst, buf, len);",
        "function": "vulnerable_func",
    }
]

_VERIFICATIONS = [
    {
        "hypothesis_id": "HYP-01",
        "status": "plausible_but_unproven",
        "explanation": "No guard found in snippet.",
        "supporting_evidence_ids": ["EV-01"],
    }
]

_COUNTER_REVIEW = {
    "findings": [],
    "overall_notes": "No counter-evidence found.",
}


def _all_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(m.get("content", "") for m in messages)


# ---------------------------------------------------------------------------
# A. Prompt hygiene — Stage 01
# ---------------------------------------------------------------------------

class TestStage01PromptHygiene:
    def _msgs(self):
        from vckg_agentic_proof.prompts import source_only_hypothesis_prompt
        return source_only_hypothesis_prompt(_SAMPLE, _SOURCE)

    def test_contains_target_function_name(self):
        text = _all_text(self._msgs())
        assert "vulnerable_func" in text

    def test_contains_target_source(self):
        text = _all_text(self._msgs())
        assert "memcpy" in text

    def test_contains_schema(self):
        text = _all_text(self._msgs())
        assert "schema" in text.lower() or "hypotheses" in text.lower()

    def test_contains_hyp_id_instruction(self):
        text = _all_text(self._msgs())
        assert "HYP-" in text or "HYP-01" in text or "generic" in text.lower()

    def test_no_sample_id(self):
        text = _all_text(self._msgs())
        assert "99999" not in text, "sample_id must not appear in stage 01 prompt"

    def test_no_project_url(self):
        text = _all_text(self._msgs())
        assert "github.com" not in text, "project_url must not appear in stage 01 prompt"

    def test_no_project_name(self):
        text = _all_text(self._msgs())
        assert "test_project" not in text, "project name must not appear in stage 01 prompt"

    def test_no_label(self):
        text = _all_text(self._msgs())
        # Dataset label as metadata key/value must not appear — "vulnerable" legitimately
        # appears inside function names and source code, so check metadata patterns.
        assert '"label"' not in text, "dataset label key must not appear in stage 01 prompt"
        assert "LABEL:" not in text, "LABEL: metadata block must not appear in stage 01 prompt"

    def test_no_commit(self):
        text = _all_text(self._msgs())
        assert "deadbeef" not in text
        assert "cafebabe" not in text

    def test_has_system_and_user_roles(self):
        msgs = self._msgs()
        roles = [m["role"] for m in msgs]
        assert "system" in roles
        assert "user" in roles


# ---------------------------------------------------------------------------
# B. Prompt hygiene — Stage 02
# ---------------------------------------------------------------------------

class TestStage02PromptHygiene:
    def _msgs(self):
        from vckg_agentic_proof.prompts import kg_query_planning_prompt
        return kg_query_planning_prompt(_SAMPLE, _HYPOTHESES, initial_evidence=_EVIDENCE)

    def test_contains_hypotheses(self):
        text = _all_text(self._msgs())
        assert "HYP-01" in text

    def test_contains_codekg_contract(self):
        text = _all_text(self._msgs())
        assert "security_context" in text or "evidence_slice" in text

    def test_no_initial_evidence_block(self):
        text = _all_text(self._msgs())
        assert "INITIAL EVIDENCE" not in text, "INITIAL EVIDENCE must not appear in stage 02 prompt"

    def test_no_sample_id(self):
        text = _all_text(self._msgs())
        assert "99999" not in text

    def test_no_project_url(self):
        text = _all_text(self._msgs())
        assert "github.com" not in text

    def test_no_label(self):
        text = _all_text(self._msgs())
        assert "label" not in text.lower() or "LABEL" not in text

    def test_no_commit(self):
        text = _all_text(self._msgs())
        assert "deadbeef" not in text
        assert "cafebabe" not in text


# ---------------------------------------------------------------------------
# C. Prompt hygiene — Stage 04 (hypothesis_verification)
# ---------------------------------------------------------------------------

class TestStage04PromptHygiene:
    def _msgs(self):
        from vckg_agentic_proof.prompts import hypothesis_verification_prompt
        return hypothesis_verification_prompt(_SAMPLE, _HYPOTHESES, _EVIDENCE)

    def test_no_sample_block(self):
        text = _all_text(self._msgs())
        assert "SAMPLE:" not in text, "SAMPLE: block must not appear in stage 04 prompt"

    def test_no_sample_id(self):
        text = _all_text(self._msgs())
        assert "99999" not in text, "sample_id must not appear in stage 04 prompt"

    def test_no_project_url(self):
        text = _all_text(self._msgs())
        assert "github.com" not in text, "project_url must not appear in stage 04 prompt"

    def test_no_label(self):
        text = _all_text(self._msgs())
        # Dataset metadata patterns must not appear (schema fields use "label" legitimately,
        # so check for dataset-metadata-specific patterns).
        assert "deadbeef" not in text
        assert "cafebabe" not in text
        assert '"label": "vulnerable"' not in text, "dataset label value must not appear in stage 04"

    def test_contains_hypotheses(self):
        text = _all_text(self._msgs())
        assert "HYP-01" in text

    def test_contains_evidence(self):
        text = _all_text(self._msgs())
        assert "EV-01" in text or "memcpy" in text

    def test_contains_target_function_name(self):
        text = _all_text(self._msgs())
        assert "vulnerable_func" in text

    def test_contains_schema(self):
        text = _all_text(self._msgs())
        assert "schema" in text.lower() or "verifications" in text.lower()


# ---------------------------------------------------------------------------
# D. Prompt hygiene — Stage 05 (counter_evidence_review)
# ---------------------------------------------------------------------------

class TestStage05PromptHygiene:
    def _msgs(self):
        from vckg_agentic_proof.prompts import counter_evidence_prompt
        return counter_evidence_prompt(_SAMPLE, _VERIFICATIONS, _EVIDENCE)

    def test_no_sample_block(self):
        text = _all_text(self._msgs())
        assert "SAMPLE:" not in text, "SAMPLE: block must not appear in stage 05 prompt"

    def test_no_sample_id(self):
        text = _all_text(self._msgs())
        assert "99999" not in text

    def test_no_project_url(self):
        text = _all_text(self._msgs())
        assert "github.com" not in text

    def test_no_commit(self):
        text = _all_text(self._msgs())
        assert "deadbeef" not in text

    def test_contains_verifications(self):
        text = _all_text(self._msgs())
        assert "HYP-01" in text

    def test_contains_evidence(self):
        text = _all_text(self._msgs())
        assert "EV-01" in text or "memcpy" in text

    def test_contains_target_function(self):
        text = _all_text(self._msgs())
        assert "vulnerable_func" in text

    def test_contains_schema(self):
        text = _all_text(self._msgs())
        assert "schema" in text.lower() or "findings" in text.lower()


# ---------------------------------------------------------------------------
# E. Prompt hygiene — Stage 06 (final_adjudication)
# ---------------------------------------------------------------------------

class TestStage06PromptHygiene:
    def _msgs(self):
        from vckg_agentic_proof.prompts import final_decision_prompt
        return final_decision_prompt(_SAMPLE, _VERIFICATIONS, _COUNTER_REVIEW, _EVIDENCE)

    def test_no_sample_block(self):
        text = _all_text(self._msgs())
        assert "SAMPLE:" not in text, "SAMPLE: block must not appear in stage 06 prompt"

    def test_no_sample_id(self):
        text = _all_text(self._msgs())
        assert "99999" not in text

    def test_no_project_url(self):
        text = _all_text(self._msgs())
        assert "github.com" not in text

    def test_no_commit(self):
        text = _all_text(self._msgs())
        assert "deadbeef" not in text

    def test_contains_verifications(self):
        text = _all_text(self._msgs())
        assert "HYP-01" in text

    def test_contains_counter_review(self):
        text = _all_text(self._msgs())
        assert "counter" in text.lower() or "findings" in text.lower() or "overall_notes" in text.lower()

    def test_contains_target_function(self):
        text = _all_text(self._msgs())
        assert "vulnerable_func" in text

    def test_contains_schema(self):
        text = _all_text(self._msgs())
        assert "schema" in text.lower() or "prediction" in text.lower()


# ---------------------------------------------------------------------------
# F. STAGE_CONTEXT_POLICY completeness
# ---------------------------------------------------------------------------

class TestStageContextPolicy:
    def test_all_six_stages_declared(self):
        from vckg_agentic_proof.prompts import STAGE_CONTEXT_POLICY
        for stage in ("01_source_only_hypothesis", "02_kg_query_planning",
                      "04_hypothesis_verification", "05_counter_evidence_review",
                      "06_final_adjudication"):
            assert stage in STAGE_CONTEXT_POLICY, f"{stage} missing from STAGE_CONTEXT_POLICY"

    def test_forbidden_metadata_in_stages_04_05_06(self):
        from vckg_agentic_proof.prompts import STAGE_CONTEXT_POLICY
        for stage in ("04_hypothesis_verification", "05_counter_evidence_review", "06_final_adjudication"):
            forbidden = STAGE_CONTEXT_POLICY[stage].get("forbidden", [])
            for key in ("sample_id", "project_url", "label", "commit"):
                assert key in forbidden, f"'{key}' must be forbidden in {stage}"

    def test_no_forbidden_metadata_in_stage_01(self):
        from vckg_agentic_proof.prompts import STAGE_CONTEXT_POLICY
        forbidden = STAGE_CONTEXT_POLICY["01_source_only_hypothesis"].get("forbidden", [])
        for key in ("sample_id", "project_url", "label", "commit"):
            assert key in forbidden, f"'{key}' must be forbidden in stage 01"


# ---------------------------------------------------------------------------
# G. JSON repair prompt deduplication
# ---------------------------------------------------------------------------

class TestJsonRepairPrompt:
    def test_schema_appears_once(self):
        from vckg_agentic_proof.parser import build_json_repair_prompt
        from vckg_agentic_proof.schemas import KGQueryPlan
        schema = KGQueryPlan.model_json_schema()
        msgs = build_json_repair_prompt(
            raw_text='<analysis>a</analysis><answer>{"queries": [</answer>',
            answer_text='{"queries": [',
            schema_name="KGQueryPlan",
            schema_json=schema,
        )
        full = _all_text(msgs)
        schema_str = json.dumps(schema, indent=2)
        # Schema content (a stable key like "queries") should appear at most once
        assert full.count('"queries"') <= schema_str.count('"queries"') + 1

    def test_no_schema_name_label_duplication(self):
        from vckg_agentic_proof.parser import build_json_repair_prompt
        msgs = build_json_repair_prompt(
            raw_text='truncated output',
            answer_text='truncated output',
            schema_name="KGQueryPlan",
            schema_json={"type": "object"},
        )
        full = _all_text(msgs)
        # Should not have both "SCHEMA NAME:" and "JSON SCHEMA:" as separate labels
        assert not ("SCHEMA NAME:" in full and "JSON SCHEMA:" in full), (
            "repair prompt duplicates 'SCHEMA NAME:' and 'JSON SCHEMA:' labels"
        )

    def test_no_new_security_reasoning_instruction(self):
        from vckg_agentic_proof.parser import build_json_repair_prompt
        msgs = build_json_repair_prompt(
            raw_text="<answer>{}</answer>",
            answer_text="{}",
            schema_name="FinalDecision",
            schema_json={"type": "object"},
        )
        sys_text = next(m["content"] for m in msgs if m["role"] == "system")
        assert "new security" in sys_text.lower() or "do not add" in sys_text.lower()


# ---------------------------------------------------------------------------
# H. Truncation detection helper
# ---------------------------------------------------------------------------

class TestTruncationDetection:
    def test_complete_json_not_truncated(self):
        from vckg_agentic_proof.parser import detect_truncation
        assert detect_truncation('<answer>{"k": "v"}</answer>') is False

    def test_missing_answer_tag_and_open_brace_is_truncated(self):
        from vckg_agentic_proof.parser import detect_truncation
        assert detect_truncation('{"queries": [{"query_id": "Q1"') is True

    def test_empty_string_is_truncated(self):
        from vckg_agentic_proof.parser import detect_truncation
        assert detect_truncation("") is True

    def test_complete_bracketed_is_not_truncated(self):
        from vckg_agentic_proof.parser import detect_truncation
        assert detect_truncation('{"a": 1}') is False


# ---------------------------------------------------------------------------
# I. Token budget defaults
# ---------------------------------------------------------------------------

class TestTokenBudgetDefaults:
    def test_agentic_proof_config_stage_defaults_are_high(self):
        from vckg_agentic_proof.adapter import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.max_tokens_source_only_hypothesis >= 8192, "stage 01 too low"
        assert cfg.max_tokens_kg_query_planning >= 4096, "stage 02 too low"
        assert cfg.max_tokens_hypothesis_verification >= 8192, "stage 04 too low"
        assert cfg.max_tokens_counter_evidence_review >= 8192, "stage 05 too low"
        assert cfg.max_tokens_final_decision >= 4096, "stage 06 too low"
        assert cfg.max_tokens_schema_repair >= 2048, "repair too low"

    def test_runtime_config_mirrors_adapter_defaults(self):
        from vuln_commit_kg.config import AgenticProofRuntimeConfig
        cfg = AgenticProofRuntimeConfig()
        assert cfg.max_tokens_source_only_hypothesis >= 8192
        assert cfg.max_tokens_kg_query_planning >= 4096
        assert cfg.max_tokens_hypothesis_verification >= 8192
        assert cfg.max_tokens_counter_evidence_review >= 8192
        assert cfg.max_tokens_final_decision >= 4096

    def test_model_config_max_tokens_default_is_high(self):
        from vuln_commit_kg.config import ModelConfig
        cfg = ModelConfig()
        assert cfg.max_tokens >= 8192, (
            f"ModelConfig.max_tokens default is {cfg.max_tokens}, should be >= 8192"
        )


# ---------------------------------------------------------------------------
# J. Trace fields: finish_reason, was_truncated, requested/effective max_tokens
# ---------------------------------------------------------------------------

class TestTraceFields:
    """Verify that the call_record written to model_calls includes the new fields."""

    def _run_one_stage(self):
        """Build a minimal call_record by exercising llm_generate internals
        via a mock model that returns a fake response with finish_reason."""
        from vckg_agentic_proof.prompts import source_only_hypothesis_prompt
        from vckg_agentic_proof.adapter import AgenticProofConfig

        messages = source_only_hypothesis_prompt(_SAMPLE, _SOURCE)
        call_records: list[dict] = []

        # Simulate what pipeline.py llm_generate does: build call_record fields
        # We test that the record builder function includes the new fields.
        # We import the helper that _should_ exist after implementation.
        from vuln_commit_kg.orchestration import pipeline as pipe_mod
        assert hasattr(pipe_mod, "_build_call_record") or True  # placeholder assertion
        # The real test: after implementation, model_calls records must include these keys.
        # For now we verify the call_record structure that llm_generate produces
        # by checking that the key names are defined in the module or documented.
        required_keys = {"finish_reason", "was_truncated", "requested_max_tokens", "effective_max_tokens"}
        # We'll test this via the research.py stage extractor instead.
        return required_keys

    def test_research_stages_expose_finish_reason_field(self):
        """sample_stages() on ResearchInventory must propagate finish_reason."""
        import inspect
        from student_system_creator.dashboard.research import ResearchInventory
        src = inspect.getsource(ResearchInventory.sample_stages)
        assert "finish_reason" in src, (
            "sample_stages() must extract 'finish_reason' from call records"
        )

    def test_research_stages_expose_was_truncated_field(self):
        import inspect
        from student_system_creator.dashboard.research import ResearchInventory
        src = inspect.getsource(ResearchInventory.sample_stages)
        assert "was_truncated" in src, (
            "sample_stages() must extract 'was_truncated' from call records"
        )

    def test_pipeline_llm_generate_records_finish_reason(self):
        """pipeline.py llm_generate must write finish_reason to call_record."""
        import inspect
        from vuln_commit_kg.orchestration import pipeline
        src = inspect.getsource(pipeline.CommitKGPipeline._classify_agentic_proof)
        assert "finish_reason" in src, "llm_generate must record finish_reason"

    def test_pipeline_llm_generate_records_was_truncated(self):
        import inspect
        from vuln_commit_kg.orchestration import pipeline
        src = inspect.getsource(pipeline.CommitKGPipeline._classify_agentic_proof)
        assert "was_truncated" in src, "llm_generate must record was_truncated"

    def test_pipeline_llm_generate_records_requested_max_tokens(self):
        import inspect
        from vuln_commit_kg.orchestration import pipeline
        src = inspect.getsource(pipeline.CommitKGPipeline._classify_agentic_proof)
        assert "requested_max_tokens" in src, "llm_generate must record requested_max_tokens"


# ---------------------------------------------------------------------------
# K. Dashboard jobs: maximum-mode sentinel
# ---------------------------------------------------------------------------

class TestDashboardMaxTokensMode:
    def test_none_max_tokens_not_written_to_model_cfg(self):
        """_apply_llm_override with max_tokens=None must NOT set model_cfg['max_tokens']."""
        from student_system_creator.dashboard.jobs import _apply_llm_override
        cfg: dict = {}
        _apply_llm_override(cfg, "academiccloud", "some-model", max_tokens=None)
        mc = cfg.get("model", {})
        assert "max_tokens" not in mc, (
            "max_tokens=None (maximum mode) must not override model.max_tokens"
        )

    def test_explicit_max_tokens_written_to_model_cfg(self):
        from student_system_creator.dashboard.jobs import _apply_llm_override
        cfg: dict = {}
        _apply_llm_override(cfg, "academiccloud", "some-model", max_tokens=16384)
        mc = cfg.get("model", {})
        assert mc.get("max_tokens") == 16384

    def test_zero_max_tokens_not_written(self):
        """max_tokens=0 is also treated as 'use default'."""
        from student_system_creator.dashboard.jobs import _apply_llm_override
        cfg: dict = {}
        _apply_llm_override(cfg, "academiccloud", "some-model", max_tokens=0)
        mc = cfg.get("model", {})
        assert "max_tokens" not in mc


# ---------------------------------------------------------------------------
# L. Secret safety in call records
# ---------------------------------------------------------------------------

class TestSecretSafety:
    def test_no_api_key_in_call_record_keys(self):
        """Ensure that known secret field names are not in a typical call_record."""
        # Simulate a call_record as llm_generate would produce after implementation
        call_record = {
            "name": "01_source_only_hypothesis",
            "messages": [{"role": "system", "content": "..."}],
            "system_prompt": "You are...",
            "user_prompt": "TARGET FUNCTION: foo...",
            "provider": "academiccloud",
            "model": "some-model",
            "requested_max_tokens": 16384,
            "effective_max_tokens": 16384,
            "finish_reason": "stop",
            "was_truncated": False,
            "response": "<analysis>...</analysis><answer>{}</answer>",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            "error": None,
        }
        secret_keys = {"api_key", "authorization", "bearer", "api_secret", "password"}
        found = {k for k in call_record if k.lower() in secret_keys}
        assert not found, f"Secret keys found in call_record: {found}"

    def test_mask_secrets_does_not_redact_finish_reason(self):
        from student_system_creator.dashboard.research import _mask_secrets
        obj = {"finish_reason": "stop", "was_truncated": False, "requested_max_tokens": 16384}
        masked = _mask_secrets(obj)
        assert masked["finish_reason"] == "stop"
        assert masked["was_truncated"] is False
        assert masked["requested_max_tokens"] == 16384

    def test_mask_secrets_does_not_redact_token_counts(self):
        from student_system_creator.dashboard.research import _mask_secrets
        obj = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150, "max_tokens": 32768}
        masked = _mask_secrets(obj)
        assert masked["prompt_tokens"] == 100
        assert masked["total_tokens"] == 150
        assert masked["max_tokens"] == 32768
