"""TDD tests for Agentic Flow dashboard endpoint and pipeline artifact writes.

RED phase: all tests must fail before the fix is applied.
GREEN phase: all tests must pass after the fix.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from student_system_creator.dashboard.research import ResearchInventory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run(tmp_path: Path, run_id: str, sample_id: str, func_name: str = "myfunc") -> Path:
    run_dir = tmp_path / "runs" / run_id
    sample_dir = run_dir / "agent_demos" / f"sample_{sample_id}_{func_name}"
    sample_dir.mkdir(parents=True)
    return sample_dir


def _make_inventory(tmp_path: Path) -> ResearchInventory:
    return ResearchInventory(
        project_root=tmp_path,
        runs_root="runs",
        jobs_root="jobs",
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# 1. flow() returns stages from model_calls.jsonl even without agent_flow.json
# ---------------------------------------------------------------------------

class TestFlowFromModelCallsJsonl:
    def test_returns_non_empty_stages_from_model_calls_jsonl(self, tmp_path):
        """flow() must return stages during a live run (no agent_flow.json yet)."""
        sd = _make_run(tmp_path, "run1", "42")
        _write_jsonl(sd / "model_calls.jsonl", [
            {
                "name": "01_source_only_hypothesis",
                "system_prompt": "You are a security analyst.",
                "user_prompt": "Analyse this function.",
                "messages": [
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": "Analyse this function."},
                ],
                "response": '{"hypotheses": []}',
                "elapsed_seconds": 1.2,
                "finish_reason": "stop",
                "was_truncated": False,
                "requested_max_tokens": 16384,
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
        ])
        inv = _make_inventory(tmp_path)
        result = inv.flow("run1", "42")
        assert result is not None, "flow() must not return None"
        assert len(result["stages"]) == 1, "should have 1 stage from model_calls.jsonl"
        stage = result["stages"][0]
        assert stage["stage"] == "01_source_only_hypothesis"

    def test_stage_includes_system_prompt(self, tmp_path):
        """Stages must include system_prompt from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run2", "43")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "You are a security analyst.",
             "user_prompt": "Analyse.", "messages": [], "response": "{}", "usage": {}}
        ])
        result = _make_inventory(tmp_path).flow("run2", "43")
        stage = result["stages"][0]
        assert stage.get("system_prompt") == "You are a security analyst."

    def test_stage_includes_user_prompt_and_response(self, tmp_path):
        """Stages must include user_prompt and response from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run3", "44")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "02_kg_query_planning", "system_prompt": "sys",
             "user_prompt": "Plan queries.", "messages": [], "response": '{"queries": []}', "usage": {}}
        ])
        result = _make_inventory(tmp_path).flow("run3", "44")
        stage = result["stages"][0]
        assert stage.get("user_prompt") == "Plan queries."
        assert stage.get("response") == '{"queries": []}'

    def test_fallback_flag_set_when_no_agent_flow_json(self, tmp_path):
        """flow() must set fallback=True when agent_flow.json is absent."""
        sd = _make_run(tmp_path, "run4", "45")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "s", "user_prompt": "u",
             "messages": [], "response": "{}", "usage": {}}
        ])
        result = _make_inventory(tmp_path).flow("run4", "45")
        assert result["fallback"] is True


# ---------------------------------------------------------------------------
# 2. flow() returns explicit diagnostic when no artifacts exist
# ---------------------------------------------------------------------------

class TestFlowNoArtifacts:
    def test_returns_data_not_none_when_sample_dir_exists_but_empty(self, tmp_path):
        """flow() must not return None when sample dir exists but has no artifacts."""
        _make_run(tmp_path, "run5", "46")
        result = _make_inventory(tmp_path).flow("run5", "46")
        assert result is not None
        assert "stages" in result
        assert result["stages"] == []

    def test_no_artifacts_diagnostic_field(self, tmp_path):
        """flow() should indicate there are no artifacts yet."""
        _make_run(tmp_path, "run6", "47")
        result = _make_inventory(tmp_path).flow("run6", "47")
        assert result is not None
        # Either explicit flag or just empty stages — never a 404 or None
        assert isinstance(result.get("stages"), list)


# ---------------------------------------------------------------------------
# 3. flow() enriches agent_flow.json stages with model_calls content
# ---------------------------------------------------------------------------

class TestFlowEnrichesAgentFlowJson:
    def test_agent_flow_json_stages_enriched_with_prompts(self, tmp_path):
        """When agent_flow.json exists, its summary stages must be enriched with
        full content from model_calls.jsonl."""
        sd = _make_run(tmp_path, "run7", "48")
        # Write agent_flow.json (summary only - as written by pipeline)
        agent_flow = {
            "sample_id": "48",
            "loop_stop_reason": "loop_disabled",
            "iterations_completed": 0,
            "iterative_loop_enabled": False,
            "stages": [
                {"stage": "01_source_only_hypothesis", "status": "completed",
                 "elapsed_seconds": 1.5, "finish_reason": "stop", "was_truncated": False,
                 "requested_max_tokens": 16384, "prompt_chars": 200, "usage": {}},
            ],
            "iterations": [],
            "total_evidence_items": 5,
            "initial_evidence_items": 5,
        }
        (sd / "agent_flow.json").write_text(json.dumps(agent_flow), encoding="utf-8")
        # Write model_calls.jsonl with full content
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "Be a security analyst.",
             "user_prompt": "Find vulnerabilities.", "messages": [{"role": "system", "content": "Be a security analyst."}],
             "response": '{"hypotheses": ["buffer overflow"]}', "usage": {"total_tokens": 200}}
        ])
        result = _make_inventory(tmp_path).flow("run7", "48")
        assert result is not None
        stage = result["stages"][0]
        assert stage.get("system_prompt") == "Be a security analyst."
        assert stage.get("user_prompt") == "Find vulnerabilities."
        assert "buffer overflow" in (stage.get("response") or "")

    def test_agent_flow_json_iterations_merged_from_jsonl(self, tmp_path):
        """evidence_iterations.jsonl should be merged when agent_flow.json has empty iterations."""
        sd = _make_run(tmp_path, "run8", "49")
        agent_flow = {
            "sample_id": "49", "loop_stop_reason": None, "iterations_completed": 1,
            "iterative_loop_enabled": True, "stages": [], "iterations": [],
            "total_evidence_items": 8, "initial_evidence_items": 5,
        }
        (sd / "agent_flow.json").write_text(json.dumps(agent_flow), encoding="utf-8")
        _write_jsonl(sd / "evidence_iterations.jsonl", [
            {"iteration": 1, "phase": "hypothesis", "new_evidence_count": 3, "stop_reason": None}
        ])
        result = _make_inventory(tmp_path).flow("run8", "49")
        assert len(result["iterations"]) == 1
        assert result["iterations"][0]["iteration"] == 1


# ---------------------------------------------------------------------------
# 4. flow() secret masking
# ---------------------------------------------------------------------------

class TestFlowSecretMasking:
    def test_api_key_in_prompt_is_redacted(self, tmp_path):
        """api_key values in model call content must be masked."""
        sd = _make_run(tmp_path, "run9", "50")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis",
             "system_prompt": "Call with api_key=SECRET123",
             "user_prompt": "normal user prompt",
             "messages": [{"role": "system", "content": "Call with api_key=SECRET123"}],
             "response": "{}",
             "usage": {"api_key": "SHOULD_BE_MASKED"},  # api_key in nested usage
            }
        ])
        result = _make_inventory(tmp_path).flow("run9", "50")
        result_str = json.dumps(result)
        # api_key values in dict keys should be redacted
        assert "SHOULD_BE_MASKED" not in result_str

    def test_authorization_header_not_exposed(self, tmp_path):
        """authorization values must never appear in flow() output."""
        sd = _make_run(tmp_path, "run10", "51")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis",
             "system_prompt": "sys",
             "user_prompt": "user",
             "messages": [],
             "response": "{}",
             "usage": {},
             "authorization": "Bearer sk-secret-token",
            }
        ])
        result = _make_inventory(tmp_path).flow("run10", "51")
        result_str = json.dumps(result)
        assert "sk-secret-token" not in result_str

    def test_token_counts_not_redacted(self, tmp_path):
        """Token counts (prompt_tokens, completion_tokens, total_tokens) must NOT be redacted."""
        sd = _make_run(tmp_path, "run11", "52")
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis",
             "system_prompt": "sys", "user_prompt": "user", "messages": [], "response": "{}",
             "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
        ])
        result = _make_inventory(tmp_path).flow("run11", "52")
        usage = result["stages"][0].get("usage") or {}
        assert usage.get("total_tokens") == 150, "total_tokens must not be redacted"
        assert usage.get("prompt_tokens") == 100


# ---------------------------------------------------------------------------
# 5. Route path consistency check
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 6. Dashboard job loop defaults — RED phase tests
# ---------------------------------------------------------------------------

class TestDashboardJobLoopDefaults:
    """_research_argv() must inject agentic_proof loop defaults into effective config
    so dashboard Research Audit runs enable the bounded iterative evidence loop
    by default without requiring the base YAML to set it explicitly.
    """

    def _build_base_config(self, tmp_path: Path) -> Path:
        """Write a minimal valid base config (agent.mode=agentic_proof) and return its path."""
        cfg = {
            "experiment": {"name": "test_run"},
            "agent": {"mode": "agentic_proof"},
            "agentic_proof": {"enabled": True},
            "dataset": {"path": "data/raw/fake.arrow"},
        }
        p = tmp_path / "base.yaml"
        import yaml
        p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return p

    def _call_research_argv(self, tmp_path: Path, *, loop_params: dict | None = None) -> dict:
        """Call _research_argv and return the effective_config as a parsed dict."""
        import yaml
        from student_system_creator.dashboard.jobs import _research_argv, JobContext

        cfg_path = self._build_base_config(tmp_path)
        job_dir = tmp_path / "job1"
        job_dir.mkdir()
        ctx = JobContext(project_root=tmp_path, default_config=str(cfg_path), default_challenge="challenge")
        params: dict = {"config_path": str(cfg_path)}
        if loop_params is not None:
            params["loop"] = loop_params
        try:
            _research_argv(params, job_dir, ctx)
        except Exception:
            pass  # may fail on missing vckg validate — we only care about the written config
        effective = job_dir / "effective_config.yaml"
        if not effective.exists():
            return {}
        return yaml.safe_load(effective.read_text(encoding="utf-8")) or {}

    def test_iterative_evidence_loop_enabled_by_default(self, tmp_path):
        """Dashboard Research Audit effective config must have iterative_evidence_loop=True."""
        cfg = self._call_research_argv(tmp_path)
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("iterative_evidence_loop") is True, (
            f"iterative_evidence_loop must be True in effective config; got {ap}"
        )

    def test_enable_counter_evidence_loop_enabled_by_default(self, tmp_path):
        """Dashboard Research Audit effective config must have enable_counter_evidence_loop=True."""
        cfg = self._call_research_argv(tmp_path)
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("enable_counter_evidence_loop") is True, (
            f"enable_counter_evidence_loop must be True in effective config; got {ap}"
        )

    def test_max_evidence_iterations_in_effective_config(self, tmp_path):
        """Effective config must record max_evidence_iterations >= 2."""
        cfg = self._call_research_argv(tmp_path)
        ap = cfg.get("agentic_proof") or {}
        assert (ap.get("max_evidence_iterations") or 0) >= 2, (
            f"max_evidence_iterations must be >= 2; got {ap}"
        )

    def test_loop_can_be_disabled_via_ui_param(self, tmp_path):
        """Passing loop={loop_enabled: False} must disable the loop."""
        cfg = self._call_research_argv(tmp_path, loop_params={"loop_enabled": False})
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("iterative_evidence_loop") is False, (
            f"iterative_evidence_loop must be False when UI disables it; got {ap}"
        )

    def test_ui_can_override_max_iterations(self, tmp_path):
        """Passing loop={max_evidence_iterations: 5} must be reflected in effective config."""
        cfg = self._call_research_argv(tmp_path, loop_params={"max_evidence_iterations": 5})
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("max_evidence_iterations") == 5, (
            f"max_evidence_iterations override not applied; got {ap}"
        )

    def test_stop_when_no_new_evidence_enabled_by_default(self, tmp_path):
        """stop_when_no_new_evidence must be True in effective config."""
        cfg = self._call_research_argv(tmp_path)
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("stop_when_no_new_evidence") is True

    def test_stop_when_no_new_queries_enabled_by_default(self, tmp_path):
        """stop_when_no_new_queries must be True in effective config."""
        cfg = self._call_research_argv(tmp_path)
        ap = cfg.get("agentic_proof") or {}
        assert ap.get("stop_when_no_new_queries") is True


# ---------------------------------------------------------------------------
# 7. EvidenceGapPlan richer schema — RED phase tests
# ---------------------------------------------------------------------------

class TestEvidenceGapPlanRicherSchema:
    """EvidenceGapPlan must include structured gaps list and stop_reason_if_no_queries."""

    def test_evidence_gap_plan_has_gaps_field(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        plan = EvidenceGapPlan(needs_more_evidence=False, reason="all resolved")
        assert hasattr(plan, "gaps"), "EvidenceGapPlan must have 'gaps' field"
        assert plan.gaps == []

    def test_evidence_gap_plan_has_stop_reason_if_no_queries(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        plan = EvidenceGapPlan(
            needs_more_evidence=False,
            reason="no queryable gaps",
            stop_reason_if_no_queries="no_queryable_gaps",
        )
        assert plan.stop_reason_if_no_queries == "no_queryable_gaps"

    def test_evidence_gap_plan_has_reason_field(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        plan = EvidenceGapPlan(needs_more_evidence=False, reason="evidence sufficient")
        assert plan.reason == "evidence sufficient"

    def test_gap_item_has_queryable_field(self):
        from vckg_agentic_proof.schemas import GapItem
        g = GapItem(
            gap_id="GAP-01",
            hypothesis_id="HYP-01",
            proof_element="input_control",
            missing_evidence="no caller evidence",
            queryable=False,
            why_queryable_or_not="static KG has no callers indexed",
        )
        assert g.queryable is False

    def test_gap_item_has_priority_field(self):
        from vckg_agentic_proof.schemas import GapItem
        g = GapItem(
            gap_id="GAP-01",
            hypothesis_id="HYP-01",
            proof_element="dangerous_operation",
            missing_evidence="no malloc size bound",
            priority="high",
        )
        assert g.priority == "high"

    def test_evidence_gap_plan_with_gaps_parses(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan, GapItem
        data = {
            "needs_more_evidence": True,
            "reason": "input control path unclear",
            "gaps": [
                {
                    "gap_id": "GAP-01",
                    "hypothesis_id": "HYP-01",
                    "proof_element": "input_control",
                    "missing_evidence": "caller origin unknown",
                    "queryable": True,
                    "why_queryable_or_not": "call_neighborhood can find callers",
                    "priority": "high",
                    "recommended_query_focus": "call_neighborhood",
                }
            ],
            "follow_up_queries": [],
            "stop_reason_if_no_queries": None,
        }
        plan = EvidenceGapPlan.model_validate(data)
        assert plan.needs_more_evidence is True
        assert len(plan.gaps) == 1
        assert plan.gaps[0].queryable is True

    def test_old_schema_without_gaps_still_parses(self):
        """Backward compat: old gap plans without 'gaps' must still parse."""
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        data = {
            "needs_more_evidence": True,
            "gap_summary": "missing guard check",
            "follow_up_queries": [],
            "stop_reason": None,
        }
        plan = EvidenceGapPlan.model_validate(data)
        assert plan.needs_more_evidence is True
        assert plan.gaps == []  # default empty list


# ---------------------------------------------------------------------------
# 8. Query-text deduplication — RED phase test
# ---------------------------------------------------------------------------

class TestQueryTextDedup:
    """Follow-up queries with the same query_text (normalized) as an executed query
    must be filtered even if they have a different query_id."""

    def test_same_text_different_id_is_deduped(self):
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline

        import json

        def _xml(data):
            return f"<analysis>brief</analysis><answer>{json.dumps(data)}</answer>"

        hyp = [{"hypothesis_id": "HYP-01", "title": "OOB", "risk_summary": "r",
                "required_proof_questions": []}]
        initial_q_text = 'security_context(target_function="foo", depth=3)'
        stage_responses = {
            "01_source_only_hypothesis": {"hypotheses": hyp, "source_observations": [],
                                          "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [
                {"query_id": "Q1", "hypothesis_id": "HYP-01", "purpose": "p",
                 "query_text": initial_q_text, "variables": [], "expected_evidence": "e", "limit": 8}
            ]},
            "04_hypothesis_verification": {
                "verifications": [{
                    "hypothesis_id": "HYP-01", "status": "plausible_but_unproven",
                    "local_risk_present": False, "confirmed_security_vulnerability": False,
                    "proof": {"input_control": "", "dangerous_operation": "",
                              "missing_or_failed_guard": "", "unsafe_use": "",
                              "security_impact": "", "cited_evidence_ids": []},
                    "supporting_evidence_ids": [], "counter_evidence_ids": [],
                    "missing_evidence": ["guard"], "explanation": "needs more",
                }]
            },
            "04_evidence_gap_iter1": {
                "needs_more_evidence": True,
                "reason": "guard missing",
                "gaps": [],
                "follow_up_queries": [
                    # SAME query_text as Q1, DIFFERENT id → must be deduped
                    {"query_id": "NEWID-99", "hypothesis_id": "HYP-01",
                     "purpose": "find guard",
                     "query_text": initial_q_text,  # identical text
                     "variables": [], "expected_evidence": "guard", "limit": 8}
                ],
                "stop_reason_if_no_queries": None,
            },
            "05_counter_evidence_review": {"findings": [], "overall_notes": ""},
            "06_final_adjudication": {
                "prediction": "inconclusive", "prediction_bool": None, "confidence": 0.4,
                "local_risk_present": False, "confirmed_security_vulnerability": False,
                "final_hypothesis_statuses": [], "minimum_vulnerability_proof": None,
                "decisive_evidence_ids": [], "decisive_counter_evidence_ids": [],
                "explanation": "insufficient", "limitations": [],
            },
        }

        kg_call_count = [0]

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                raise ValueError(f"Unexpected mock stage: {stage!r}")
            return {"content": _xml(data), "usage": {}}

        def kg_search(queries, *, sample=None, limit=8):
            kg_call_count[0] += 1
            return [{"id": f"EV-{kg_call_count[0]}", "kind": "source", "text": "x"}]

        cfg = AgenticProofConfig(iterative_evidence_loop=True, max_evidence_iterations=2,
                                 stop_when_no_new_queries=True)
        run_agentic_proof_pipeline(
            sample={"function": "foo"},
            target_source="int foo(void){ return 0; }",
            initial_evidence=[],
            llm_generate=llm_generate,
            kg_search=kg_search,
            config=cfg,
        )
        # Only 1 kg_search call (initial Q1). The follow-up NEWID-99 has the same
        # text → should be deduped so stop_when_no_new_queries fires.
        assert kg_call_count[0] == 1, (
            f"Expected 1 kg_search call (follow-up deduped by text); got {kg_call_count[0]}"
        )

class TestRoutePathConsistency:
    def test_frontend_flow_api_path_matches_backend(self, tmp_path):
        """The API path used by frontend research.flow() must match the backend route."""
        frontend_api = Path(__file__).parents[1] / "frontend" / "src" / "api" / "research.ts"
        assert frontend_api.exists(), "research.ts not found"
        content = frontend_api.read_text(encoding="utf-8")
        # Frontend: http<AgentFlow>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/flow`)
        assert "/flow`" in content or "/flow`)" in content, \
            "frontend research.flow() must use /flow path"
        # Backend uses /api/research/runs/{run_id}/samples/{sample_id}/flow
        backend_app = Path(__file__).parents[1] / "src" / "student_system_creator" / "dashboard" / "app.py"
        app_content = backend_app.read_text(encoding="utf-8")
        assert "/flow" in app_content, "backend must have /flow endpoint"

    def test_agent_flow_page_download_button_label_is_full(self):
        """AgentFlowPage download button must be labelled 'Download full flow report'."""
        tsx = Path(__file__).parents[1] / "frontend" / "src" / "pages" / "AgentFlowPage.tsx"
        assert tsx.exists(), "AgentFlowPage.tsx not found"
        content = tsx.read_text(encoding="utf-8")
        assert "Download full flow report" in content, (
            "AgentFlowPage.tsx must contain the text 'Download full flow report' "
            "on the download anchor so users can find it easily"
        )


# ---------------------------------------------------------------------------
# Generic /research/flow landing page — RED tests
# ---------------------------------------------------------------------------

class TestAgentFlowLandingPage:
    """The generic /research/flow route must not be blank."""

    def _app_tsx(self) -> str:
        p = Path(__file__).parents[1] / "frontend" / "src" / "App.tsx"
        assert p.exists(), "App.tsx not found"
        return p.read_text(encoding="utf-8")

    def _sidebar_tsx(self) -> str:
        p = Path(__file__).parents[1] / "frontend" / "src" / "components" / "Sidebar.tsx"
        assert p.exists(), "Sidebar.tsx not found"
        return p.read_text(encoding="utf-8")

    def _flow_tsx(self) -> str:
        p = Path(__file__).parents[1] / "frontend" / "src" / "pages" / "AgentFlowPage.tsx"
        assert p.exists(), "AgentFlowPage.tsx not found"
        return p.read_text(encoding="utf-8")

    def test_app_tsx_has_generic_flow_route(self):
        """App.tsx must register a /research/flow route with no required params
        so the sidebar link does not render a blank page."""
        content = self._app_tsx()
        # Must have path="/research/flow" without :runId/:sampleId
        assert '"/research/flow"' in content or "'/research/flow'" in content, (
            "App.tsx must include a <Route path=\"/research/flow\"> "
            "(no :runId/:sampleId) so the sidebar link is not blank"
        )

    def test_app_tsx_still_has_specific_flow_route(self):
        """App.tsx must still have the specific /research/flow/:runId/:sampleId route."""
        content = self._app_tsx()
        assert "/research/flow/:runId/:sampleId" in content, (
            "App.tsx must keep the /research/flow/:runId/:sampleId route "
            "for the detailed per-sample flow view"
        )

    def test_sidebar_links_to_generic_flow(self):
        """Sidebar Agentic Flow link must point to /research/flow."""
        content = self._sidebar_tsx()
        assert '"/research/flow"' in content or "'/research/flow'" in content, (
            "Sidebar must link to /research/flow for the Agentic Flow entry"
        )

    def test_flow_page_has_landing_title(self):
        """AgentFlowPage must show 'Agentic Flow' as a page title in landing mode."""
        content = self._flow_tsx()
        assert "Agentic Flow" in content, (
            "AgentFlowPage.tsx must contain 'Agentic Flow' title for the landing mode"
        )

    def test_flow_page_has_run_audit_link(self):
        """AgentFlowPage landing mode must include a link/button to Run Audit (/research)."""
        content = self._flow_tsx()
        # Check for navigation to /research (the Run Audit page)
        assert '"/research"' in content or "'/research'" in content, (
            "AgentFlowPage.tsx landing mode must include a link to /research (Run Audit) "
            "so users can start a new audit when no runs exist"
        )

    def test_flow_page_has_empty_state_text(self):
        """AgentFlowPage must show a non-blank empty state when no runs exist."""
        content = self._flow_tsx()
        assert "No agentic audit runs" in content or "no runs" in content.lower() or \
               "Start one from" in content or "Run Audit" in content, (
            "AgentFlowPage.tsx must contain empty-state text explaining "
            "there are no runs and how to start one"
        )

    def test_flow_page_open_flow_link_uses_run_and_sample(self):
        """AgentFlowPage landing mode must build 'Open flow' links with runId and sampleId."""
        content = self._flow_tsx()
        # The landing page must construct URLs like /research/flow/${run.run_id}/${s.sample_id}
        assert "/research/flow/" in content, (
            "AgentFlowPage.tsx must contain /research/flow/ URL fragments "
            "to build per-sample Open flow links"
        )

    def test_flow_page_view_runs_link(self):
        """AgentFlowPage landing must include a link to /research/runs (View audit runs)."""
        content = self._flow_tsx()
        assert '"/research/runs"' in content or "'/research/runs'" in content or \
               "/research/runs" in content, (
            "AgentFlowPage.tsx must link to /research/runs so users can browse all runs"
        )


# ---------------------------------------------------------------------------
# New: flow_report() must include commit message and target function source
# ---------------------------------------------------------------------------

class TestFlowReportCommitMessage:
    """flow_report() must include commit_message when sample.json has it."""

    def test_flow_report_includes_commit_message(self, tmp_path):
        """flow_report() must include the commit message from sample.json in the report text."""
        sd = _make_run(tmp_path, "run_cm1", "200", "myfunc")
        sd.joinpath("sample.json").write_text(
            json.dumps({
                "func_name": "myfunc",
                "filepath": "src/foo.c",
                "commit_message": "fix: prevent buffer overflow in myfunc by adding bounds check",
                "is_vulnerable": True,
            }),
            encoding="utf-8",
        )
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({"is_vulnerable": True, "confidence": 0.9,
                        "resolved_commit_id": "abc123", "reasoning_summary": "r"}),
            encoding="utf-8",
        )
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "s", "user_prompt": "u",
             "response": "{}", "parse_status": "valid", "parsed_answer": {"hypotheses": []}}
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_cm1", "200")
        assert report is not None, "flow_report() must return a string"
        assert "prevent buffer overflow" in report, (
            "flow_report() must include commit_message text from sample.json"
        )

    def test_flow_report_shows_commit_unavailable_when_missing(self, tmp_path):
        """flow_report() must handle missing commit_message gracefully."""
        sd = _make_run(tmp_path, "run_cm2", "201", "bar")
        sd.joinpath("sample.json").write_text(
            json.dumps({"func_name": "bar", "filepath": "bar.c"}),
            encoding="utf-8",
        )
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({"is_vulnerable": False, "confidence": 0.8,
                        "resolved_commit_id": "def456", "reasoning_summary": "r"}),
            encoding="utf-8",
        )
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "s", "user_prompt": "u",
             "response": "{}", "parse_status": "valid", "parsed_answer": {}}
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_cm2", "201")
        assert report is not None
        # Must not crash; should show unavailable marker
        assert "unavailable" in report.lower() or "commit_message" in report.lower(), (
            "flow_report() must mention commit_message or 'unavailable' when it is absent"
        )


class TestFlowReportFuncBody:
    """flow_report() must include target function source (func_body) from sample.json."""

    def test_flow_report_includes_target_function_source(self, tmp_path):
        """flow_report() must include the target function source in the report."""
        sd = _make_run(tmp_path, "run_fb1", "202", "count_rows")
        sd.joinpath("sample.json").write_text(
            json.dumps({
                "func_name": "count_rows",
                "filepath": "db/query.c",
                "func_body": "int count_rows(DB *db) { return db->rows; }",
            }),
            encoding="utf-8",
        )
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({"is_vulnerable": False, "confidence": 0.7,
                        "resolved_commit_id": "fe3f", "reasoning_summary": "r"}),
            encoding="utf-8",
        )
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "s", "user_prompt": "u",
             "response": "{}", "parse_status": "valid", "parsed_answer": {}}
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_fb1", "202")
        assert report is not None
        assert "count_rows" in report, (
            "flow_report() must include the function name from func_body in the report"
        )
        assert "db->rows" in report, (
            "flow_report() must include target function source (func_body) text in the report"
        )

    def test_flow_report_includes_target_source_section_header(self, tmp_path):
        """flow_report() must include a TARGET FUNCTION SOURCE section header."""
        sd = _make_run(tmp_path, "run_fb2", "203", "do_something")
        sd.joinpath("sample.json").write_text(
            json.dumps({
                "func_name": "do_something",
                "filepath": "lib/util.c",
                "func_body": "void do_something(void) {}",
            }),
            encoding="utf-8",
        )
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({"is_vulnerable": False, "confidence": 0.6,
                        "resolved_commit_id": "aa01", "reasoning_summary": "r"}),
            encoding="utf-8",
        )
        _write_jsonl(sd / "model_calls.jsonl", [
            {"name": "01_source_only_hypothesis", "system_prompt": "s", "user_prompt": "u",
             "response": "{}", "parse_status": "valid", "parsed_answer": {}}
        ])
        inv = _make_inventory(tmp_path)
        report = inv.flow_report("run_fb2", "203")
        assert report is not None
        assert "TARGET FUNCTION SOURCE" in report, (
            "flow_report() must have a 'TARGET FUNCTION SOURCE' section header"
        )


# ---------------------------------------------------------------------------
# New: trace_normalized() must expose commit_message + target_function_source
# ---------------------------------------------------------------------------

class TestTraceNormalizedNewFields:
    """trace_normalized() must return commit_message and target_function_source."""

    def _make_trace_run(self, tmp_path: Path, run_id: str, sample_id: str,
                        func_name: str = "myfunc",
                        commit_message: str | None = None,
                        func_body: str | None = None) -> Path:
        run_dir = tmp_path / "runs" / run_id
        (run_dir / "agent_demos" / f"sample_{sample_id}_{func_name}").mkdir(parents=True)
        sd = run_dir / "agent_demos" / f"sample_{sample_id}_{func_name}"
        sample_data: dict = {"func_name": func_name, "filepath": "src/f.c",
                             "is_vulnerable": True}
        if commit_message is not None:
            sample_data["commit_message"] = commit_message
        if func_body is not None:
            sample_data["func_body"] = func_body
        sd.joinpath("sample.json").write_text(json.dumps(sample_data), encoding="utf-8")
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({"is_vulnerable": True, "confidence": 0.9,
                        "resolved_commit_id": "cafecafe", "reasoning_summary": "text"}),
            encoding="utf-8",
        )
        (run_dir / "run_meta.json").write_text(
            json.dumps({"llm": {}, "kg": {}, "status": "completed"}), encoding="utf-8"
        )
        return sd

    def test_trace_normalized_returns_commit_message_in_admin_mode(self, tmp_path):
        """trace_normalized() must return commit_message when mode='admin'."""
        self._make_trace_run(
            tmp_path, "run_tn1", "300",
            commit_message="fix: null deref in parser",
        )
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_tn1", "300", mode="admin")
        assert result is not None, "trace_normalized must return a dict"
        assert "commit_message" in result, (
            "trace_normalized() must include 'commit_message' key in admin mode"
        )
        assert result["commit_message"] == "fix: null deref in parser", (
            "commit_message must match the value from sample.json"
        )

    def test_trace_normalized_commit_message_hidden_in_student_mode(self, tmp_path):
        """trace_normalized() must hide commit_message when mode='student'."""
        self._make_trace_run(
            tmp_path, "run_tn2", "301",
            commit_message="fix: null deref in parser",
        )
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_tn2", "301", mode="student")
        assert result is not None
        # commit_message must either be absent or None in student mode
        assert result.get("commit_message") is None, (
            "commit_message must be None/absent in student mode (same gate as true_label)"
        )

    def test_trace_normalized_commit_message_none_when_missing(self, tmp_path):
        """trace_normalized() must return None for commit_message when sample.json lacks it."""
        self._make_trace_run(tmp_path, "run_tn3", "302")  # no commit_message
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_tn3", "302", mode="admin")
        assert result is not None
        assert "commit_message" in result, (
            "commit_message key must always be present in the response"
        )
        assert result["commit_message"] is None, (
            "commit_message must be None when not in sample.json"
        )

    def test_trace_normalized_returns_target_function_source(self, tmp_path):
        """trace_normalized() must return target_function_source from sample.json func_body."""
        self._make_trace_run(
            tmp_path, "run_tn4", "303",
            func_body="int myfunc(void) { return 42; }",
        )
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_tn4", "303", mode="admin")
        assert result is not None
        assert "target_function_source" in result, (
            "trace_normalized() must include 'target_function_source' key"
        )
        assert result["target_function_source"] == "int myfunc(void) { return 42; }", (
            "target_function_source must match func_body from sample.json"
        )

    def test_trace_normalized_target_function_source_none_when_missing(self, tmp_path):
        """trace_normalized() must return None for target_function_source when func_body absent."""
        self._make_trace_run(tmp_path, "run_tn5", "304")  # no func_body
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_tn5", "304", mode="admin")
        assert result is not None
        assert "target_function_source" in result, (
            "target_function_source key must always be present in the response"
        )
        assert result["target_function_source"] is None, (
            "target_function_source must be None when sample.json has no func_body"
        )


# ---------------------------------------------------------------------------
# RED: canonical prediction mapping (Bug 1 — dashboard side)
# ---------------------------------------------------------------------------

class TestCanonicalPredictionMapping:
    """trace_normalized() must use forced_prediction_bool/decision_status when
    is_vulnerable is stale (False) but decision_status=forced_binary_vulnerable."""

    def _make_forced_binary_run(self, tmp_path: Path, run_id: str, sample_id: str,
                                 decision_status: str, forced_prediction_bool: bool,
                                 stale_is_vulnerable: bool) -> None:
        sd = _make_run(tmp_path, run_id, sample_id, "count_rows")
        sd.joinpath("sample.json").write_text(
            json.dumps({"func_name": "count_rows", "filepath": "db.c", "is_vulnerable": True}),
            encoding="utf-8",
        )
        sd.joinpath("final_prediction.json").write_text(
            json.dumps({
                "is_vulnerable": stale_is_vulnerable,  # stale/wrong value
                "forced_prediction_bool": forced_prediction_bool,
                "decision_status": decision_status,
                "confidence": 0.55,
                "reasoning_summary": "forced binary chosen",
            }),
            encoding="utf-8",
        )
        (tmp_path / "runs" / run_id / "run_meta.json").write_text(
            json.dumps({"llm": {}, "kg": {}, "status": "completed"}), encoding="utf-8"
        )

    def test_trace_normalized_uses_forced_bool_not_stale_is_vulnerable(self, tmp_path):
        """When is_vulnerable=False but forced_prediction_bool=True+forced_binary_vulnerable,
        trace_normalized() must return prediction='vulnerable', not 'safe'."""
        self._make_forced_binary_run(
            tmp_path, "run_fp1", "400",
            decision_status="forced_binary_vulnerable",
            forced_prediction_bool=True,
            stale_is_vulnerable=False,  # the stale/wrong value on disk
        )
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_fp1", "400")
        assert result is not None
        assert result.get("prediction") == "vulnerable", (
            f"trace_normalized() must return prediction='vulnerable' when "
            f"decision_status=forced_binary_vulnerable even if is_vulnerable=False on disk. "
            f"Got prediction={result.get('prediction')!r}. "
            f"This is the root cause of the contradictory Trace card display."
        )

    def test_trace_normalized_forced_non_vuln_shows_safe(self, tmp_path):
        """forced_binary_non_vulnerable + forced_prediction_bool=False → prediction='safe'."""
        self._make_forced_binary_run(
            tmp_path, "run_fp2", "401",
            decision_status="forced_binary_non_vulnerable",
            forced_prediction_bool=False,
            stale_is_vulnerable=False,
        )
        inv = _make_inventory(tmp_path)
        result = inv.trace_normalized("run_fp2", "401")
        assert result is not None
        assert result.get("prediction") == "safe"

    def test_classify_sample_forced_binary_vulnerable_is_tp(self, tmp_path):
        """_classify_sample with forced_binary_vulnerable + true_label=vulnerable must be TP."""
        from student_system_creator.dashboard.research import _classify_sample
        fp = {
            "is_vulnerable": False,  # stale wrong value
            "forced_prediction_bool": True,
            "decision_status": "forced_binary_vulnerable",
            "confidence": 0.55,
        }
        sample = {"is_vulnerable": True}
        result, error_type, outcome = _classify_sample(fp, sample)
        assert result == "correct" and error_type == "tp" and outcome == "TP", (
            f"forced_binary_vulnerable with true_label=vulnerable must be TP. "
            f"Got result={result!r}, error_type={error_type!r}, outcome={outcome!r}. "
            f"This mismatch is caused by _is_inconclusive_status() not matching 'forced_binary_*'."
        )

    def test_classify_sample_forced_binary_non_vuln_is_tn(self, tmp_path):
        """_classify_sample with forced_binary_non_vulnerable + true_label=non-vuln must be TN."""
        from student_system_creator.dashboard.research import _classify_sample
        fp = {
            "is_vulnerable": False,
            "forced_prediction_bool": False,
            "decision_status": "forced_binary_non_vulnerable",
            "confidence": 0.45,
        }
        sample = {"is_vulnerable": False}
        result, error_type, outcome = _classify_sample(fp, sample)
        assert result == "correct" and error_type == "tn" and outcome == "TN", (
            f"forced_binary_non_vulnerable with true_label=non-vuln must be TN. "
            f"Got result={result!r}, error_type={error_type!r}, outcome={outcome!r}."
        )

    def test_list_samples_forced_binary_shows_vulnerable(self, tmp_path):
        """list_samples() must show prediction='vulnerable' for forced_binary_vulnerable samples."""
        self._make_forced_binary_run(
            tmp_path, "run_fp3", "402",
            decision_status="forced_binary_vulnerable",
            forced_prediction_bool=True,
            stale_is_vulnerable=False,
        )
        inv = _make_inventory(tmp_path)
        samples = inv.list_samples("run_fp3")
        assert len(samples) == 1
        s = samples[0]
        assert s.get("prediction") == "vulnerable", (
            f"list_samples() must show prediction='vulnerable' for forced_binary_vulnerable. "
            f"Got {s.get('prediction')!r}."
        )


# ---------------------------------------------------------------------------
# RED: consistency repair policy (Bug 2 — adapter.py Stage 07)
# ---------------------------------------------------------------------------

class TestConsistencyRepairPolicy:
    """Stage 07 consistency repair must NOT run when the validator has already
    produced a definitive forced binary decision (forced_prediction_bool is set).

    The real-world trigger: Stage 06 returns 'vulnerable' but validator downgrades
    to 'inconclusive' because proof is incomplete. modified=True fires Stage 07.
    But the forced binary (forced_binary_vulnerable/non_vulnerable) is already
    deterministically set — Stage 07 should be skipped.
    """

    def _run_pipeline_downgraded_vulnerable(self, local_risk: bool) -> tuple:
        """Stage 06 returns 'vulnerable' → validator downgrades to inconclusive.
        Returns (result, repair_stages_called)."""
        import json
        from vckg_agentic_proof.adapter import run_agentic_proof_pipeline, AgenticProofConfig

        def _xml(data):
            return f"<analysis>brief</analysis><answer>{json.dumps(data)}</answer>"

        hyp = [{"hypothesis_id": "HYP-01", "title": "OOB", "risk_summary": "r",
                "required_proof_questions": []}]
        verifications = [{
            "hypothesis_id": "HYP-01", "status": "insufficient_evidence",
            "local_risk_present": local_risk, "confirmed_security_vulnerability": False,
            "proof": {"input_control": "", "dangerous_operation": "",
                      "missing_or_failed_guard": "", "unsafe_use": "",
                      "security_impact": "", "cited_evidence_ids": []},
            "supporting_evidence_ids": [], "counter_evidence_ids": [],
            "missing_evidence": [], "explanation": "none",
        }]
        # Stage 06 claims 'vulnerable' but provides no proof → validator downgrades
        stage_responses = {
            "01_source_only_hypothesis": {"hypotheses": hyp, "source_observations": [],
                                          "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": []},
            "04_hypothesis_verification": {"verifications": verifications},
            "05_counter_evidence_review": {"findings": [], "overall_notes": ""},
            "06_final_adjudication": {
                "prediction": "vulnerable", "confidence": 0.8,
                "local_risk_present": local_risk, "confirmed_security_vulnerability": True,
                "final_hypothesis_statuses": verifications,
                "minimum_vulnerability_proof": None,  # no proof → validator downgrades
                "decisive_evidence_ids": [], "decisive_counter_evidence_ids": [],
                "explanation": "looks vulnerable", "limitations": [],
            },
        }
        repair_stages_called = []

        def mock_llm(messages, *, stage, max_tokens, temperature, extra_body=None):
            if "07_schema_consistency_repair" in stage:
                repair_stages_called.append(stage)
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                return _xml({"findings": [], "overall_notes": ""})
            return _xml(data)

        cfg = AgenticProofConfig(iterative_evidence_loop=False)
        result = run_agentic_proof_pipeline(
            sample={"function": "fn", "filepath": "f.c", "func_body": "int fn(){}"},
            target_source="int fn(){}",
            initial_evidence=[],
            llm_generate=mock_llm,
            kg_search=lambda queries, **kw: [],
            config=cfg,
        )
        return result, repair_stages_called

    def test_stage07_not_called_when_downgraded_to_forced_binary_vulnerable(self):
        """When Stage 06 returns vulnerable → validator downgrades to forced_binary_vulnerable,
        Stage 07 must NOT be called (forced binary is already definitively set)."""
        result, repair_stages = self._run_pipeline_downgraded_vulnerable(local_risk=True)
        assert result.decision.decision_status in (
            "forced_binary_vulnerable", "forced_binary_non_vulnerable",
            "confirmed_non_vulnerable",
        ), f"Expected forced binary status, got {result.decision.decision_status!r}"
        assert len(repair_stages) == 0, (
            f"Stage 07 consistency repair must NOT be called when the validator already "
            f"produces a definitive forced binary decision. Got: {repair_stages}. "
            f"Bug 2: modified=True fires Stage 07 even when forced_prediction_bool is set."
        )

    def test_stage07_not_called_when_downgraded_to_forced_binary_non_vulnerable(self):
        """Stage 06 returns vulnerable, validator downgrades, local_risk=False →
        forced_binary_non_vulnerable. Stage 07 must NOT run."""
        result, repair_stages = self._run_pipeline_downgraded_vulnerable(local_risk=False)
        assert len(repair_stages) == 0, (
            f"Stage 07 must not run for forced_binary_non_vulnerable downgrade. "
            f"Got: {repair_stages}"
        )

# ---------------------------------------------------------------------------
# Forced-binary artifacts with missing forced_prediction_bool
# ---------------------------------------------------------------------------

class TestForcedBinaryStatusInference:
    def test_classify_sample_infers_forced_bool_from_status_when_field_missing(self):
        from student_system_creator.dashboard.research import _classify_sample
        fp = {"is_vulnerable": True, "decision_status": "forced_binary_vulnerable", "confidence": 0.65}
        sample = {"is_vulnerable": False}
        result, error_type, outcome = _classify_sample(fp, sample)
        assert (result, error_type, outcome) == ("incorrect", "fp", "FP")

    def test_classify_sample_infers_forced_non_vulnerable_from_status_when_field_missing(self):
        from student_system_creator.dashboard.research import _classify_sample
        fp = {"is_vulnerable": False, "decision_status": "forced_binary_non_vulnerable", "confidence": 0.65}
        sample = {"is_vulnerable": False}
        result, error_type, outcome = _classify_sample(fp, sample)
        assert (result, error_type, outcome) == ("correct", "tn", "TN")
