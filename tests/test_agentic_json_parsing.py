"""TDD tests for Agentic Flow JSON parsing, parse_status propagation, and full-flow report.

RED phase: these tests are written FIRST and must fail before any fix is applied.
GREEN phase: all tests must pass after the fixes in Phases A-F.

Bug: valid JSON inside <answer>...</answer> is shown as 'JSON invalid' because
  sample_stages() computes json_valid = (parsed is not None) where parsed is the
  result of _read_json(parsed_response_XX_name.json). Those files are never written,
  so parsed=None, (None is not None)=False, and json_valid=False triggers the badge.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run(tmp_path: Path, run_id: str, sample_id: str, func_name: str = "myfunc") -> Path:
    run_dir = tmp_path / "runs" / run_id
    sample_dir = run_dir / "agent_demos" / f"sample_{sample_id}_{func_name}"
    sample_dir.mkdir(parents=True)
    return sample_dir


def _make_inventory(tmp_path: Path):
    from student_system_creator.dashboard.research import ResearchInventory
    return ResearchInventory(project_root=tmp_path, runs_root="runs", jobs_root="jobs")


def _write_jsonl(path: Path, rows: list) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


_VALID_ANSWER_RESPONSE = """\
<analysis>
The function allocates memory using malloc. The size argument comes from an
untrusted integer that could overflow.
</analysis>
<answer>
{
  "hypotheses": [
    {
      "hypothesis_id": "HYP-01",
      "title": "Integer overflow in malloc size",
      "risk_summary": "size * n could overflow",
      "required_proof_questions": ["Is size validated?"]
    }
  ],
  "source_observations": ["malloc called with user-controlled size"],
  "non_vulnerability_possibilities": ["size might be bounded upstream"]
}
</answer>
"""


# ---------------------------------------------------------------------------
# A. Parser: <answer> extraction
# ---------------------------------------------------------------------------

class TestAnswerExtraction:
    """Parser must correctly extract the JSON inside <answer>...</answer>."""

    def test_extract_answer_with_analysis_prefix(self):
        """extract_answer_text must return only the <answer> content, not the
        <analysis> section, even when both tags are present."""
        from vckg_agentic_proof.parser import extract_answer_text
        analysis, answer = extract_answer_text(_VALID_ANSWER_RESPONSE)
        assert answer.strip().startswith("{"), "answer_text must start with '{'"
        assert "hypotheses" in answer, "answer_text must contain JSON payload"
        # analysis should not bleed into answer_text
        assert "<analysis>" not in answer
        assert "allocates memory" in analysis

    def test_parse_json_answer_succeeds_on_valid_answer_tag(self):
        """parse_json_answer must parse valid JSON from <answer>...</answer> without raising."""
        from vckg_agentic_proof.parser import parse_json_answer
        result = parse_json_answer(_VALID_ANSWER_RESPONSE)
        assert result.parsed is not None
        assert "hypotheses" in result.parsed
        assert len(result.parsed["hypotheses"]) == 1

    def test_parse_json_answer_no_repair_for_valid_response(self):
        """parse_model_object must NOT call llm_repair when the original <answer> is valid."""
        from vckg_agentic_proof.parser import parse_model_object
        from vckg_agentic_proof.adapter import _HypothesisEnvelope

        repair_called = []

        def mock_repair(messages):
            repair_called.append(messages)
            return _VALID_ANSWER_RESPONSE

        result, parsed = parse_model_object(
            _VALID_ANSWER_RESPONSE,
            _HypothesisEnvelope,
            llm_repair=mock_repair,
        )
        assert not repair_called, "llm_repair must NOT be called when the original <answer> is valid JSON"
        assert result is not None
        assert len(result.hypotheses) == 1

    def test_parse_json_answer_captures_analysis_text(self):
        """ParsedTaggedJson.analysis must contain the <analysis> text."""
        from vckg_agentic_proof.parser import parse_json_answer
        result = parse_json_answer(_VALID_ANSWER_RESPONSE)
        assert "allocates memory" in result.analysis or "malloc" in result.analysis

    def test_answer_text_field_set_on_valid_parse(self):
        """ParsedTaggedJson.answer_text must be set to the extracted JSON string."""
        from vckg_agentic_proof.parser import parse_json_answer
        result = parse_json_answer(_VALID_ANSWER_RESPONSE)
        assert result.answer_text, "answer_text must not be empty"
        assert "hypotheses" in result.answer_text


# ---------------------------------------------------------------------------
# B. sample_stages(): json_valid must be None, not False, when parse file absent
# ---------------------------------------------------------------------------

class TestJsonValidNotFalseWhenFileAbsent:
    """Core regression test for the 'JSON invalid' false-positive bug.

    Before the fix: json_valid = (parsed is not None) => False => red badge.
    After the fix:  json_valid = True if parsed is not None else None => None => gray badge.
    """

    def test_json_valid_is_none_not_false_for_structured_stage_no_parse_file(self, tmp_path):
        """sample_stages() must return json_valid=None (not False) when the
        parsed_response_XX_name.json file does not exist."""
        sd = _make_run(tmp_path, "run_a", "101")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                "elapsed_seconds": 1.5,
                "json_status": "raw_agentic_proof_pending_parse",
            }
        ])
        inv = _make_inventory(tmp_path)
        stages = inv.sample_stages("run_a", "101")
        assert len(stages) == 1
        stage = stages[0]
        # The critical assertion: must be None, not False
        assert stage["json_valid"] is not False, (
            f"json_valid must be None (unknown) when parsed_response file is absent, "
            f"got {stage['json_valid']!r}. This was the root cause of the 'JSON invalid' "
            f"false-positive badge."
        )

    def test_json_valid_is_none_for_all_structured_stages_without_parse_files(self, tmp_path):
        """All structured stages (01..06) must show json_valid=None, not False."""
        sd = _make_run(tmp_path, "run_b", "102")
        structured = [
            "01_source_only_hypothesis",
            "02_kg_query_planning",
            "04_hypothesis_verification",
            "05_counter_evidence_review",
            "06_final_adjudication",
        ]
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": name, "system_prompt": "s", "user_prompt": "u",
             "messages": [], "response": "<answer>{}</answer>",
             "usage": {}, "json_status": "raw_agentic_proof_pending_parse"}
            for name in structured
        ])
        inv = _make_inventory(tmp_path)
        stages = inv.sample_stages("run_b", "102")
        assert len(stages) == len(structured)
        for s in stages:
            assert s["json_valid"] is not False, (
                f"Stage {s['stage']} must have json_valid=None, not False. "
                f"json_invalid badge must never fire for a stage that simply hasn't "
                f"been verified yet (file missing ≠ parse failed)."
            )

    def test_json_valid_true_when_parse_status_valid_in_model_calls(self, tmp_path):
        """After Phase B+C: if model_calls entry has parse_status='valid', json_valid must be True."""
        sd = _make_run(tmp_path, "run_c", "103")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {},
                "json_status": "json_ok",
                "parse_status": "valid",
                "parsed_answer": {"hypotheses": [], "source_observations": [], "non_vulnerability_possibilities": []},
                "answer_text": '{"hypotheses": [], ...}',
            }
        ])
        inv = _make_inventory(tmp_path)
        stages = inv.sample_stages("run_c", "103")
        assert len(stages) == 1
        assert stages[0]["json_valid"] is True, (
            f"json_valid must be True when parse_status='valid' in model_calls, "
            f"got {stages[0]['json_valid']!r}"
        )

    def test_json_valid_false_when_parse_status_invalid(self, tmp_path):
        """If model_calls entry has parse_status='invalid', json_valid must be False."""
        sd = _make_run(tmp_path, "run_d", "104")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": "<analysis>stuff</analysis>BROKEN JSON {{{{",
                "usage": {},
                "json_status": "json_invalid",
                "parse_status": "invalid",
                "parse_error": "Expecting ',' delimiter",
            }
        ])
        inv = _make_inventory(tmp_path)
        stages = inv.sample_stages("run_d", "104")
        assert len(stages) == 1
        assert stages[0]["json_valid"] is False, (
            f"json_valid must be False when parse_status='invalid', "
            f"got {stages[0]['json_valid']!r}"
        )

    def test_final_decision_synthetic_stage_not_json_invalid(self, tmp_path):
        """final_decision is a synthetic validator-only stage and must never show JSON invalid."""
        sd = _make_run(tmp_path, "run_e", "105")
        final_json = {"prediction": "inconclusive", "confidence": 0.4,
                      "explanation": "test", "limitations": []}
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "final_decision",
                "prompt": "[accepted parsed final JSON produced by agentic-proof validator]",
                "response": json.dumps(final_json, indent=2),
                "parsed": final_json,
                "json_status": "json_ok",
                "parse_status": "valid",
                "elapsed_seconds": 0.0,
                "usage": {},
            }
        ])
        inv = _make_inventory(tmp_path)
        stages = inv.sample_stages("run_e", "105")
        assert len(stages) == 1
        stage = stages[0]
        # Must not be False
        assert stage["json_valid"] is not False, (
            f"final_decision synthetic stage must not show JSON invalid (json_valid={stage['json_valid']!r})"
        )


# ---------------------------------------------------------------------------
# C. flow(): parsed_answer and parse_status must be preserved
# ---------------------------------------------------------------------------

class TestFlowPreservesParseFields:
    """flow() must pass parsed_answer, answer_text, parse_status, parse_error through
    from model_calls.jsonl to the FlowStage dict. This feeds the frontend detail panel."""

    def test_flow_passes_parsed_answer_from_model_calls(self, tmp_path):
        """flow() stages must include parsed_answer from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run_f", "106")
        expected_parsed = {"hypotheses": [{"id": "H1"}], "source_observations": [], "non_vulnerability_possibilities": []}
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {},
                "parse_status": "valid",
                "parsed_answer": expected_parsed,
                "answer_text": json.dumps(expected_parsed),
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_f", "106")
        assert result is not None
        stage = result["stages"][0]
        assert stage.get("parsed_answer") is not None, (
            "flow() must include parsed_answer in stage dict so the frontend "
            "detail panel can show the parsed JSON tab."
        )
        assert stage["parsed_answer"].get("hypotheses") is not None

    def test_flow_passes_parse_status_from_model_calls(self, tmp_path):
        """flow() stages must include parse_status from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run_g", "107")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {},
                "parse_status": "valid",
                "parsed_answer": {"hypotheses": []},
                "answer_text": '{"hypotheses": []}',
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_g", "107")
        stage = result["stages"][0]
        assert stage.get("parse_status") == "valid", (
            f"flow() must pass parse_status='valid' through to stage dict, "
            f"got {stage.get('parse_status')!r}"
        )

    def test_flow_passes_answer_text_from_model_calls(self, tmp_path):
        """flow() stages must include answer_text from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run_h", "108")
        answer_text = '{"hypotheses": [], "source_observations": [], "non_vulnerability_possibilities": []}'
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": f"<analysis>brief</analysis><answer>{answer_text}</answer>",
                "usage": {},
                "parse_status": "valid",
                "parsed_answer": {},
                "answer_text": answer_text,
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_h", "108")
        stage = result["stages"][0]
        assert stage.get("answer_text") is not None, (
            "flow() must include answer_text in stage dict so the frontend can show "
            "the extracted <answer> content separately from the full response."
        )

    def test_flow_passes_parse_error_from_model_calls(self, tmp_path):
        """flow() must include parse_error when present."""
        sd = _make_run(tmp_path, "run_i", "109")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": "BROKEN <<<",
                "usage": {},
                "parse_status": "invalid",
                "parse_error": "Could not parse <answer> JSON: Expecting value",
                "parsed_answer": None,
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_i", "109")
        stage = result["stages"][0]
        assert stage.get("parse_error") is not None, (
            "flow() must include parse_error in stage dict so the frontend can show "
            "why parsing failed."
        )

    def test_flow_does_not_overwrite_parsed_answer_with_null(self, tmp_path):
        """flow() with agent_flow.json present must not overwrite a non-null parsed_answer
        from model_calls.jsonl with null from the compact agent_flow.json summary."""
        sd = _make_run(tmp_path, "run_j", "110")
        # agent_flow.json has compact summary (no parsed_answer)
        agent_flow = {
            "sample_id": "110",
            "loop_stop_reason": "loop_disabled",
            "iterations_completed": 0,
            "iterative_loop_enabled": False,
            "stages": [
                {"stage": "01_source_only_hypothesis", "status": "completed",
                 "elapsed_seconds": 1.0, "usage": {}}
            ],
            "iterations": [],
        }
        (sd / "agent_flow.json").write_text(json.dumps(agent_flow), encoding="utf-8")
        # model_calls.jsonl has full parse results
        expected_parsed = {"hypotheses": [{"hypothesis_id": "H1"}], "source_observations": [], "non_vulnerability_possibilities": []}
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys", "user_prompt": "user", "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {},
                "parse_status": "valid",
                "parsed_answer": expected_parsed,
                "answer_text": json.dumps(expected_parsed),
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_j", "110")
        stage = result["stages"][0]
        # parsed_answer from model_calls must survive the merge
        assert stage.get("parsed_answer") is not None, (
            "Merging agent_flow.json with model_calls.jsonl must not overwrite "
            "non-null parsed_answer with null from the compact summary."
        )


# ---------------------------------------------------------------------------
# D. Pipeline post-parse enrichment
# ---------------------------------------------------------------------------

class TestPipelinePostParseEnrichment:
    """After run_agentic_proof_pipeline() returns, pipeline.py must enrich each
    model_calls entry with parsed_answer, answer_text, parse_status, json_status.

    These tests verify the helper function(s) used for post-parse enrichment.
    We test them independently without running the full pipeline.
    """

    def test_enrich_call_record_valid_answer(self):
        """A call record with a valid <answer>JSON</answer> response must get
        parse_status='valid' and parsed_answer set after enrichment."""
        from vuln_commit_kg.orchestration.pipeline import _enrich_call_parse_result
        call = {
            "name": "01_source_only_hypothesis",
            "response": _VALID_ANSWER_RESPONSE,
            "json_status": "raw_agentic_proof_pending_parse",
        }
        _enrich_call_parse_result(call)
        assert call.get("parse_status") == "valid", (
            f"Expected parse_status='valid', got {call.get('parse_status')!r}"
        )
        assert call.get("parsed_answer") is not None
        assert "hypotheses" in call["parsed_answer"]
        assert call.get("json_status") == "json_ok"

    def test_enrich_call_record_no_answer_tag(self):
        """A response with no <answer> tag on a structured stage must get
        parse_status='text_only' or 'invalid'."""
        from vuln_commit_kg.orchestration.pipeline import _enrich_call_parse_result
        call = {
            "name": "01_source_only_hypothesis",
            "response": "Here is my analysis but I forgot to wrap it in answer tags.",
            "json_status": "raw_agentic_proof_pending_parse",
        }
        _enrich_call_parse_result(call)
        assert call.get("parse_status") in ("text_only", "invalid"), (
            f"Expected 'text_only' or 'invalid' for missing <answer> tag, "
            f"got {call.get('parse_status')!r}"
        )

    def test_enrich_call_record_broken_json_in_answer(self):
        """A response with malformed JSON inside <answer> must get parse_status='invalid'."""
        from vuln_commit_kg.orchestration.pipeline import _enrich_call_parse_result
        call = {
            "name": "01_source_only_hypothesis",
            "response": "<analysis>brief</analysis><answer>{ BROKEN }</answer>",
            "json_status": "raw_agentic_proof_pending_parse",
        }
        _enrich_call_parse_result(call)
        assert call.get("parse_status") == "invalid", (
            f"Expected parse_status='invalid' for malformed JSON, got {call.get('parse_status')!r}"
        )
        assert call.get("parse_error") is not None

    def test_enrich_call_record_final_decision(self):
        """The final_decision synthetic stage (json_status='json_ok') must keep
        parse_status='valid' and not be re-parsed."""
        from vuln_commit_kg.orchestration.pipeline import _enrich_call_parse_result
        final_json = {"prediction": "inconclusive", "confidence": 0.4,
                      "explanation": "test", "limitations": []}
        call = {
            "name": "final_decision",
            "response": json.dumps(final_json, indent=2),
            "parsed": final_json,
            "json_status": "json_ok",
        }
        _enrich_call_parse_result(call)
        assert call.get("parse_status") == "valid"
        assert call.get("parsed_answer") == final_json

    def test_enrich_call_record_error_stage(self):
        """A call record with error set must get parse_status='failed'."""
        from vuln_commit_kg.orchestration.pipeline import _enrich_call_parse_result
        call = {
            "name": "01_source_only_hypothesis",
            "response": "",
            "error": "ReadTimeout: timed out after 300s",
            "json_status": "provider_error",
        }
        _enrich_call_parse_result(call)
        assert call.get("parse_status") == "failed"


# ---------------------------------------------------------------------------
# E. Flow report
# ---------------------------------------------------------------------------

class TestFlowReport:
    """flow_report() must generate a sanitized, human-readable text report."""

    def test_flow_report_returns_nonempty_string(self, tmp_path):
        """flow_report() must return a non-empty string when artifacts exist."""
        sd = _make_run(tmp_path, "run_k", "111")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "You are a security analyst.",
                "user_prompt": "Analyse this function.",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                "elapsed_seconds": 1.5,
                "parse_status": "valid",
                "parsed_answer": {"hypotheses": [], "source_observations": [], "non_vulnerability_possibilities": []},
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_k", "111")
        assert report, "flow_report() must return a non-empty string when artifacts exist"
        assert isinstance(report, str)

    def test_flow_report_contains_stage_names(self, tmp_path):
        """flow_report() must include all stage names in order."""
        sd = _make_run(tmp_path, "run_l", "112")
        stages = ["01_source_only_hypothesis", "02_kg_query_planning", "06_final_adjudication"]
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": s, "system_prompt": "sys", "user_prompt": "user",
             "messages": [], "response": f"<answer>{{\"stage\": \"{s}\"}}</answer>",
             "usage": {}, "parse_status": "valid", "parsed_answer": {"stage": s}}
            for s in stages
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_l", "112")
        for stage_name in stages:
            assert stage_name in report, (
                f"flow_report() must include stage name '{stage_name}' in the report"
            )

    def test_flow_report_contains_system_and_user_prompts(self, tmp_path):
        """flow_report() must include system and user prompts for LLM stages."""
        sd = _make_run(tmp_path, "run_m", "113")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "You are a security expert. UNIQUE_SYS_MARKER",
                "user_prompt": "Analyse the following function. UNIQUE_USER_MARKER",
                "messages": [],
                "response": _VALID_ANSWER_RESPONSE,
                "usage": {},
                "parse_status": "valid",
                "parsed_answer": {},
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_m", "113")
        assert "UNIQUE_SYS_MARKER" in report, "flow_report must include system prompt text"
        assert "UNIQUE_USER_MARKER" in report, "flow_report must include user prompt text"

    def test_flow_report_contains_parsed_json(self, tmp_path):
        """flow_report() must include pretty-printed parsed JSON for each stage."""
        sd = _make_run(tmp_path, "run_n", "114")
        parsed = {"hypotheses": [{"id": "H1", "title": "UNIQUE_HYPOTHESIS_TITLE"}],
                  "source_observations": [], "non_vulnerability_possibilities": []}
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys", "user_prompt": "user",
                "messages": [], "response": _VALID_ANSWER_RESPONSE, "usage": {},
                "parse_status": "valid",
                "parsed_answer": parsed,
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_n", "114")
        assert "UNIQUE_HYPOTHESIS_TITLE" in report, (
            "flow_report must include parsed JSON content so readers can see "
            "what the LLM actually returned"
        )

    def test_flow_report_masks_secrets(self, tmp_path):
        """flow_report() must redact api_key, authorization, secret values."""
        sd = _make_run(tmp_path, "run_o", "115")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys", "user_prompt": "user",
                "messages": [],
                "response": "<answer>{}</answer>",
                "usage": {"api_key": "sk-SECRET-SHOULD-BE-MASKED"},
                "authorization": "Bearer sk-ANOTHER-SECRET",
                "parse_status": "valid",
                "parsed_answer": {},
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_o", "115")
        assert "sk-SECRET-SHOULD-BE-MASKED" not in report
        assert "sk-ANOTHER-SECRET" not in report

    def test_flow_report_returns_none_when_sample_not_found(self, tmp_path):
        """flow_report() must return None when the sample directory does not exist."""
        inv = _make_inventory(tmp_path)
        result = inv.flow_report("nonexistent_run", "999")
        assert result is None, (
            "flow_report() must return None for a non-existent run/sample so the "
            "backend can return a 404."
        )

    def test_flow_report_includes_raw_response(self, tmp_path):
        """flow_report() must include the raw LLM response (full text with analysis+answer)."""
        sd = _make_run(tmp_path, "run_p", "116")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "sys", "user_prompt": "user",
                "messages": [], "response": _VALID_ANSWER_RESPONSE, "usage": {},
                "parse_status": "valid", "parsed_answer": {},
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_p", "116")
        # The raw response contains "allocates memory" in the <analysis> section
        assert "allocates memory" in report or "malloc" in report, (
            "flow_report must include the raw LLM response text"
        )


# ---------------------------------------------------------------------------
# F. Frontend TypeScript build safety (structural check only)
# ---------------------------------------------------------------------------

class TestFrontendTypeStructure:
    """Structural checks on frontend source files (no browser required)."""

    def test_flow_stage_type_has_parse_status_field(self):
        """FlowStage in research.ts must include parse_status field."""
        ts_file = Path(__file__).parents[1] / "frontend" / "src" / "api" / "research.ts"
        content = ts_file.read_text(encoding="utf-8")
        assert "parse_status" in content, (
            "FlowStage in research.ts must declare parse_status field so the "
            "frontend can render the correct badge"
        )

    def test_flow_stage_type_has_answer_text_field(self):
        """FlowStage in research.ts must include answer_text field."""
        ts_file = Path(__file__).parents[1] / "frontend" / "src" / "api" / "research.ts"
        content = ts_file.read_text(encoding="utf-8")
        assert "answer_text" in content, (
            "FlowStage in research.ts must declare answer_text field for the Answer Text tab"
        )

    def test_agent_flow_page_has_download_button(self):
        """AgentFlowPage.tsx must contain a Download full flow report button."""
        tsx_file = Path(__file__).parents[1] / "frontend" / "src" / "pages" / "AgentFlowPage.tsx"
        content = tsx_file.read_text(encoding="utf-8")
        assert "Download" in content and "report" in content.lower(), (
            "AgentFlowPage.tsx must contain a Download full flow report button"
        )

    def test_agent_flow_page_has_parse_status_badge_logic(self):
        """AgentFlowPage.tsx must reference parse_status for badge rendering."""
        tsx_file = Path(__file__).parents[1] / "frontend" / "src" / "pages" / "AgentFlowPage.tsx"
        content = tsx_file.read_text(encoding="utf-8")
        assert "parse_status" in content, (
            "AgentFlowPage.tsx must use parse_status to render correct JSON valid/invalid badges"
        )

    def test_research_ts_has_flow_report_method(self):
        """research.ts must have a flowReport method for the download endpoint."""
        ts_file = Path(__file__).parents[1] / "frontend" / "src" / "api" / "research.ts"
        content = ts_file.read_text(encoding="utf-8")
        assert "flowReport" in content or "flow_report" in content or "flow/report" in content, (
            "research.ts must have a flowReport method calling GET .../flow/report"
        )
