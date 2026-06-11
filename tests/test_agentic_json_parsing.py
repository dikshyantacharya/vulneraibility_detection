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


# ---------------------------------------------------------------------------
# G. flow() on-read parse inference for unenriched records (failed/partial runs)
# ---------------------------------------------------------------------------

class TestFlowInfersParseStatusOnRead:
    """flow() must infer parse_status from raw response when the post-pipeline
    enrichment pass was skipped (e.g., the run failed before the bulk rewrite).
    """

    def test_flow_infers_valid_when_answer_tag_has_valid_json(self, tmp_path):
        """flow() must return parse_status='valid' for a call with valid <answer> JSON
        even when the stored parse_status is absent (unenriched failed-run record)."""
        sd = _make_run(tmp_path, "run_inf1", "200")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "response": '<analysis>brief</analysis><answer>{"hypotheses": []}</answer>',
                "json_status": "raw_agentic_proof_pending_parse",
                # No parse_status — simulates a failed run
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_inf1", "200")
        assert result is not None
        stage = result["stages"][0]
        assert stage.get("parse_status") == "valid", (
            f"flow() must infer parse_status='valid' from raw response when stored "
            f"value absent. Got {stage.get('parse_status')!r}"
        )

    def test_flow_infers_invalid_when_answer_tag_has_bad_json(self, tmp_path):
        """flow() must return parse_status='invalid' when <answer> has malformed JSON."""
        sd = _make_run(tmp_path, "run_inf2", "201")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "response": "<answer>{ BROKEN JSON }</answer>",
                "json_status": "raw_agentic_proof_pending_parse",
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_inf2", "201")
        assert result is not None
        stage = result["stages"][0]
        assert stage.get("parse_status") == "invalid", (
            f"flow() must infer parse_status='invalid' when <answer> contains bad JSON. "
            f"Got {stage.get('parse_status')!r}"
        )

    def test_flow_infers_text_only_when_no_answer_tag(self, tmp_path):
        """flow() must infer parse_status='text_only' when response has no <answer> tag."""
        sd = _make_run(tmp_path, "run_inf3", "202")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "response": "Here is my analysis without any answer tag.",
                "json_status": "raw_agentic_proof_pending_parse",
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_inf3", "202")
        stage = result["stages"][0]
        assert stage.get("parse_status") == "text_only", (
            f"Expected text_only for no-answer-tag response, got {stage.get('parse_status')!r}"
        )

    def test_flow_preserves_stored_parse_status_when_present(self, tmp_path):
        """flow() must not overwrite an existing stored parse_status with an inferred one."""
        sd = _make_run(tmp_path, "run_inf4", "203")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "response": "<answer>{}</answer>",
                "parse_status": "invalid",
                "parse_error": "Schema validation failed",
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run_inf4", "203")
        stage = result["stages"][0]
        assert stage.get("parse_status") == "invalid", (
            f"Stored parse_status must not be overwritten by inference. "
            f"Got {stage.get('parse_status')!r}"
        )

    def test_flow_report_shows_valid_not_dash_for_unenriched_records(self, tmp_path):
        """flow_report() must show 'valid' not '—' for unenriched records with parseable response."""
        sd = _make_run(tmp_path, "run_inf5", "204")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "06_final_adjudication",
                "system_prompt": "sys",
                "user_prompt": "user",
                "messages": [],
                "response": '<analysis>a</analysis><answer>{"prediction": "vulnerable", "confidence": 0.8, "explanation": "x", "limitations": []}</answer>',
                "json_status": "raw_agentic_proof_pending_parse",
                "elapsed_seconds": 2.1,
                "usage": {"prompt_tokens": 200, "completion_tokens": 80},
            }
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_inf5", "204")
        assert report is not None
        assert "parse=valid" in report or "parse_status: valid" in report or "valid" in report, (
            f"flow_report must show parse_status=valid for unenriched but parseable record. "
            f"Got report excerpt: {report[:400]!r}"
        )
        assert "parse=—" not in report and "parse_status: —" not in report, (
            "flow_report must NOT show '—' for a stage that has a parseable <answer> response."
        )


# ---------------------------------------------------------------------------
# H. Forced binary prediction schema fields
# ---------------------------------------------------------------------------

class TestForcedBinaryPredictionSchema:
    """FinalDecision.forced_prediction, forced_prediction_bool, decision_status,
    evidence_strength must be set by validate_final_decision() for all outcomes."""

    def _make_minimal_decision(self, prediction: str, local_risk: bool = False) -> dict:
        return {
            "prediction": prediction,
            "confidence": 0.4,
            "local_risk_present": local_risk,
            "confirmed_security_vulnerability": False,
            "final_hypothesis_statuses": [],
            "minimum_vulnerability_proof": None,
            "decisive_evidence_ids": [],
            "decisive_counter_evidence_ids": [],
            "explanation": "test",
            "limitations": [],
        }

    def test_inconclusive_with_local_risk_gets_forced_binary_vulnerable(self):
        """Inconclusive prediction with local_risk_present=True must yield
        forced_prediction='vulnerable', forced_prediction_bool=True."""
        from vckg_agentic_proof.schemas import FinalDecision
        from vckg_agentic_proof.validator import validate_final_decision
        decision = FinalDecision(**self._make_minimal_decision("inconclusive", local_risk=True))
        decision, _, _ = validate_final_decision(decision)
        assert decision.forced_prediction == "vulnerable", (
            f"Expected forced_prediction='vulnerable' for inconclusive+local_risk, "
            f"got {decision.forced_prediction!r}"
        )
        assert decision.forced_prediction_bool is True
        assert decision.decision_status == "forced_binary_vulnerable"
        assert decision.evidence_strength == "insufficient_static_evidence"

    def test_inconclusive_without_local_risk_gets_forced_binary_non_vulnerable(self):
        """Inconclusive prediction without local_risk must yield
        forced_prediction='fixed/non-vulnerable', forced_prediction_bool=False."""
        from vckg_agentic_proof.schemas import FinalDecision
        from vckg_agentic_proof.validator import validate_final_decision
        decision = FinalDecision(**self._make_minimal_decision("inconclusive", local_risk=False))
        decision, _, _ = validate_final_decision(decision)
        assert decision.forced_prediction == "fixed/non-vulnerable"
        assert decision.forced_prediction_bool is False
        assert decision.decision_status == "forced_binary_non_vulnerable"

    def test_vulnerable_prediction_gets_confirmed_status(self):
        """Vulnerable prediction with complete proof gets confirmed_vulnerable status."""
        from vckg_agentic_proof.schemas import FinalDecision, HypothesisVerification, HypothesisStatus, MinimumVulnerabilityProof
        proof = MinimumVulnerabilityProof(
            input_control="user input flows to malloc",
            dangerous_operation="malloc(user_size)",
            missing_or_failed_guard="no bounds check",
            unsafe_use="heap overflow via size control",
            security_impact="arbitrary write",
            cited_evidence_ids=["EV-1"],
        )
        hyp = HypothesisVerification(
            hypothesis_id="HYP-01",
            status=HypothesisStatus.confirmed_vulnerability,
            local_risk_present=True,
            confirmed_security_vulnerability=True,
            proof=proof,
            supporting_evidence_ids=["EV-1"],
            counter_evidence_ids=[],
            missing_evidence=[],
            explanation="confirmed",
        )
        decision = FinalDecision(
            prediction="vulnerable",
            confidence=0.9,
            local_risk_present=True,
            confirmed_security_vulnerability=True,
            final_hypothesis_statuses=[hyp],
            minimum_vulnerability_proof=proof,
            decisive_evidence_ids=["EV-1"],
            decisive_counter_evidence_ids=[],
            explanation="confirmed vuln",
            limitations=[],
        )
        from vckg_agentic_proof.validator import validate_final_decision
        decision, _, _ = validate_final_decision(decision, evidence_items=[{"id": "EV-1"}])
        assert decision.forced_prediction == "vulnerable"
        assert decision.forced_prediction_bool is True
        assert decision.decision_status == "confirmed_vulnerable"
        assert decision.evidence_strength == "confirmed"

    def test_non_vulnerable_prediction_gets_confirmed_non_vulnerable_status(self):
        """fixed/non-vulnerable prediction must get confirmed_non_vulnerable status."""
        from vckg_agentic_proof.schemas import FinalDecision
        from vckg_agentic_proof.validator import validate_final_decision
        decision = FinalDecision(
            prediction="fixed/non-vulnerable",
            confidence=0.85,
            local_risk_present=False,
            confirmed_security_vulnerability=False,
            final_hypothesis_statuses=[],
            minimum_vulnerability_proof=None,
            decisive_evidence_ids=[],
            decisive_counter_evidence_ids=[],
            explanation="safe",
            limitations=[],
        )
        decision, _, _ = validate_final_decision(decision)
        assert decision.forced_prediction == "fixed/non-vulnerable"
        assert decision.forced_prediction_bool is False
        assert decision.decision_status == "confirmed_non_vulnerable"


class TestParseModelObjectRepairRouting:
    """parse_model_object must trigger JSON repair ONLY for malformed JSON,
    not for valid JSON that fails Pydantic schema validation."""

    def test_json_repair_not_triggered_for_schema_validation_failure(self):
        """When <answer> contains valid JSON that fails schema validation,
        llm_repair must NOT be called — only TaggedJsonParseError triggers repair."""
        from vckg_agentic_proof.parser import parse_model_object
        from pydantic import BaseModel

        class StrictModel(BaseModel):
            required_str: str
            required_int: int

        repair_called = {"count": 0}

        def mock_repair(messages):
            repair_called["count"] += 1
            return '<answer>{"required_str": "fixed", "required_int": 1}</answer>'

        # Valid JSON but missing required fields → ValidationError should propagate,
        # NOT trigger llm_repair.
        raw = '<answer>{"unrelated_field": "value"}</answer>'
        try:
            parse_model_object(raw, StrictModel, llm_repair=mock_repair)
        except Exception:
            pass  # exception is expected after fix; before fix it succeeds via repair

        assert repair_called["count"] == 0, (
            "parse_model_object must NOT call llm_repair for Pydantic schema validation "
            "failures on valid JSON. Got repair_called=%d" % repair_called["count"]
        )

    def test_json_repair_triggered_for_malformed_json(self):
        """When <answer> contains malformed JSON, llm_repair IS called."""
        from vckg_agentic_proof.parser import parse_model_object
        from pydantic import BaseModel

        class SimpleModel(BaseModel):
            field: str

        repair_called = {"count": 0}

        def mock_repair(messages):
            repair_called["count"] += 1
            return '<answer>{"field": "repaired"}</answer>'

        raw = '<answer>{field: malformed json</answer>'
        result, _ = parse_model_object(raw, SimpleModel, llm_repair=mock_repair)
        assert repair_called["count"] == 1, (
            "parse_model_object must call llm_repair exactly once for malformed JSON"
        )
        assert result.field == "repaired"

    def test_schema_failure_propagates_even_with_repair_callback(self):
        """Valid JSON that fails schema validation must raise even when llm_repair is provided.
        The repair callback must not be called."""
        from vckg_agentic_proof.parser import parse_model_object
        from pydantic import BaseModel, ValidationError

        class StrictModel(BaseModel):
            required_str: str

        repair_called = {"count": 0}

        def mock_repair(messages):
            repair_called["count"] += 1
            return '<answer>{"required_str": "ok"}</answer>'

        raw = '<answer>{"unrelated_field": 123}</answer>'
        with pytest.raises(Exception):
            parse_model_object(raw, StrictModel, llm_repair=mock_repair)

        assert repair_called["count"] == 0, (
            "llm_repair must not be invoked for schema validation failures"
        )

    def test_no_json_repair_stage_for_valid_json_schema_failure_in_adapter(self):
        """When Stage 06 returns valid JSON that fails FinalDecision schema,
        no '06_final_adjudication_json_repair' event must appear."""
        from vckg_agentic_proof.adapter import run_agentic_proof_pipeline, AgenticProofConfig

        config = AgenticProofConfig(
            max_tokens_source_only_hypothesis=512,
            max_tokens_kg_query_planning=256,
            max_tokens_hypothesis_verification=512,
            max_tokens_counter_evidence_review=256,
            max_tokens_final_decision=512,
            max_tokens_schema_repair=256,
            iterative_evidence_loop=False,
        )
        json_repair_stages = []

        stage_responses = {
            "01_source_only_hypothesis": json.dumps({
                "hypotheses": [{"hypothesis_id": "HYP-01", "title": "t",
                                "risk_summary": "r", "required_proof_questions": []}]
            }),
            "02_kg_query_planning": json.dumps({"queries": []}),
            "04_hypothesis_verification": json.dumps({"verifications": [
                {"hypothesis_id": "HYP-01", "status": "insufficient_evidence",
                 "local_risk_present": False, "confirmed_security_vulnerability": False,
                 "proof": {"input_control": "", "dangerous_operation": "",
                           "missing_or_failed_guard": "", "unsafe_use": "",
                           "security_impact": "", "cited_evidence_ids": []},
                 "supporting_evidence_ids": [], "counter_evidence_ids": [],
                 "missing_evidence": [], "explanation": "none"}
            ]}),
            "05_counter_evidence_review": json.dumps({"findings": [], "overall_notes": ""}),
            "06_final_adjudication": json.dumps({"wrong_field": "not a FinalDecision"}),
        }

        def mock_llm(messages, *, stage, max_tokens, temperature, extra_body=None):
            if "_json_repair" in stage:
                json_repair_stages.append(stage)
            base = stage.split("_json_repair")[0]
            resp = stage_responses.get(stage) or stage_responses.get(base)
            if resp is None:
                return json.dumps({"findings": [], "overall_notes": ""})
            return resp

        result = run_agentic_proof_pipeline(
            sample={"function": "fn", "filepath": "f.c", "func_body": "int fn(){}"},
            target_source="int fn(){}",
            initial_evidence=[],
            llm_generate=mock_llm,
            kg_search=lambda queries, **kw: [],
            config=config,
        )
        assert result is not None, "Pipeline must return a result even when Stage 06 schema-fails"
        assert "06_final_adjudication_json_repair" not in json_repair_stages, (
            "JSON repair must NOT fire for valid-JSON schema failures. "
            f"Got json_repair_stages={json_repair_stages}"
        )

    def test_stage06_schema_failure_gives_failed_parse_decision_status(self):
        """When Stage 06 returns schema-invalid JSON, decision_status must be 'failed_parse'."""
        from vckg_agentic_proof.adapter import run_agentic_proof_pipeline, AgenticProofConfig

        config = AgenticProofConfig(
            max_tokens_source_only_hypothesis=512,
            max_tokens_kg_query_planning=256,
            max_tokens_hypothesis_verification=512,
            max_tokens_schema_repair=256,
            iterative_evidence_loop=False,
        )

        stage_responses = {
            "01_source_only_hypothesis": json.dumps({
                "hypotheses": [{"hypothesis_id": "HYP-01", "title": "t",
                                "risk_summary": "r", "required_proof_questions": []}]
            }),
            "02_kg_query_planning": json.dumps({"queries": []}),
            "04_hypothesis_verification": json.dumps({"verifications": [
                {"hypothesis_id": "HYP-01", "status": "insufficient_evidence",
                 "local_risk_present": False, "confirmed_security_vulnerability": False,
                 "proof": {"input_control": "", "dangerous_operation": "",
                           "missing_or_failed_guard": "", "unsafe_use": "",
                           "security_impact": "", "cited_evidence_ids": []},
                 "supporting_evidence_ids": [], "counter_evidence_ids": [],
                 "missing_evidence": [], "explanation": "none"}
            ]}),
            "05_counter_evidence_review": json.dumps({"findings": [], "overall_notes": ""}),
            "06_final_adjudication": json.dumps({"not_a_final_decision": True}),
        }

        def mock_llm(messages, *, stage, max_tokens, temperature, extra_body=None):
            base = stage.split("_json_repair")[0]
            resp = stage_responses.get(stage) or stage_responses.get(base)
            if resp is None:
                return json.dumps({"findings": [], "overall_notes": ""})
            return resp

        result = run_agentic_proof_pipeline(
            sample={"function": "fn", "filepath": "f.c", "func_body": "int fn(){}"},
            target_source="int fn(){}",
            initial_evidence=[],
            llm_generate=mock_llm,
            kg_search=lambda queries, **kw: [],
            config=config,
        )
        assert result is not None
        assert result.decision is not None
        assert result.decision.decision_status == "failed_parse", (
            f"Expected decision_status='failed_parse' for schema-invalid Stage 06, "
            f"got {result.decision.decision_status!r}"
        )
