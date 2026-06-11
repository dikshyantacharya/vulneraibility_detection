"""
TDD tests for the iterative evidence loop, stopping conditions, prompt hygiene,
artifact writing, and event emission. All tests run without a real LLM or KG.

RED → GREEN → REFACTOR: this file was written before implementation.
"""
from __future__ import annotations

import importlib
import inspect
import json
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _make_sample() -> dict:
    return {
        "function": "count_rows",
        "filepath": "src/db.c",
        # These must NEVER appear in gap-analysis prompts
        "sample_id": "18452",
        "project": "rockhopper",
        "project_url": "https://github.com/x/rockhopper",
        "label": 1,
        "commit": "deadbeef",
        "resolved_commit": "cafebabe",
    }


def _make_hypotheses() -> list:
    return [{"hypothesis_id": "HYP-01", "title": "OOB write", "risk_summary": "r",
             "required_proof_questions": ["q1"], "status": "plausible_but_unproven"}]


def _make_evidence(n: int = 2) -> list:
    return [{"id": f"EV-{i}", "kind": "source", "text": f"evidence {i}"} for i in range(n)]


def _hypothesis_verification_json(statuses: list[str]) -> dict:
    """Build a mock verifications envelope JSON."""
    return {
        "verifications": [
            {
                "hypothesis_id": f"HYP-0{i+1}",
                "status": s,
                "local_risk_present": False,
                "confirmed_security_vulnerability": False,
                "proof": {"input_control": "", "dangerous_operation": "", "missing_or_failed_guard": "",
                          "unsafe_use": "", "security_impact": "", "cited_evidence_ids": []},
                "supporting_evidence_ids": [],
                "counter_evidence_ids": [],
                "missing_evidence": ["missing_guard_check"],
                "explanation": "needs more evidence",
            }
            for i, s in enumerate(statuses)
        ]
    }


def _counter_review_json() -> dict:
    return {
        "findings": [
            {"hypothesis_id": "HYP-01", "strongest_counterargument": "none",
             "counter_evidence_ids": [], "refutes_or_weakens": "weakens",
             "recommended_status": "plausible_but_unproven"}
        ],
        "overall_notes": "",
    }


def _final_decision_json(prediction: str = "inconclusive") -> dict:
    return {
        "prediction": prediction,
        "prediction_bool": None,
        "confidence": 0.4,
        "local_risk_present": False,
        "confirmed_security_vulnerability": False,
        "final_hypothesis_statuses": [],
        "minimum_vulnerability_proof": None,
        "decisive_evidence_ids": [],
        "decisive_counter_evidence_ids": [],
        "explanation": "insufficient evidence",
        "limitations": [],
    }


def _gap_plan_json(needs: bool = True, queries: list | None = None) -> dict:
    return {
        "needs_more_evidence": needs,
        "gap_summary": "missing guard check",
        "follow_up_queries": queries or (
            [{"query_id": "FUQ-01", "hypothesis_id": "HYP-01",
              "purpose": "find guard", "query_text": 'evidence_slice(target_function="count_rows", target_statement="len")',
              "variables": [], "expected_evidence": "guard check", "limit": 8}]
            if needs else []
        ),
        "stop_reason": None,
    }


def _xml_wrap(schema_cls_name: str, data: dict) -> str:
    return f"<analysis>brief</analysis><answer>{json.dumps(data)}</answer>"


# ---------------------------------------------------------------------------
# Build a mock run_agentic_proof_pipeline call sequence
# ---------------------------------------------------------------------------

def _build_llm_generate(stage_responses: dict[str, dict]) -> Any:
    """Return a mock llm_generate callable that returns preset JSON per stage."""
    def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
        data = stage_responses.get(stage)
        if data is None:
            raise ValueError(f"Unexpected stage in mock: {stage!r}")
        return {"content": _xml_wrap(stage, data), "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
    return llm_generate


def _build_kg_search(new_items_per_call: list[list[dict]]) -> Any:
    """Return a mock kg_search that returns successive pre-set evidence lists."""
    call_idx = {"n": 0}
    def kg_search(queries, *, sample=None, limit=8):
        idx = call_idx["n"]
        call_idx["n"] += 1
        if idx < len(new_items_per_call):
            return new_items_per_call[idx]
        return []
    return kg_search


# ---------------------------------------------------------------------------
# A. Tests: iterative loop disabled preserves linear behavior
# ---------------------------------------------------------------------------

class TestIterativeLoopDisabled:
    def _run_linear(self):
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline

        stages = {
            "01_source_only_hypothesis": {"hypotheses": _make_hypotheses(),
                                          "source_observations": [], "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01",
                                                   "purpose": "p", "query_text": 'security_context(target_function="count_rows")',
                                                   "variables": [], "expected_evidence": "e", "limit": 8}]},
            "04_hypothesis_verification": _hypothesis_verification_json(["plausible_but_unproven"]),
            "05_counter_evidence_review": _counter_review_json(),
            "06_final_adjudication": _final_decision_json(),
        }
        cfg = AgenticProofConfig(iterative_evidence_loop=False)
        called_stages = []

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            called_stages.append(stage)
            data = stages.get(stage) or stages.get(stage.split("_json_repair")[0])
            if data is None:
                raise ValueError(f"Unexpected stage: {stage!r}")
            return {"content": _xml_wrap(stage, data), "usage": {}}

        result = run_agentic_proof_pipeline(
            sample=_make_sample(),
            target_source="int count_rows(void){ return 0; }",
            initial_evidence=_make_evidence(2),
            llm_generate=llm_generate,
            kg_search=_build_kg_search([[{"id": "EV-10", "kind": "source", "text": "x"}]]),
            config=cfg,
        )
        return result, called_stages

    def test_no_gap_stages_called(self):
        _, called = self._run_linear()
        gap_stages = [s for s in called if "evidence_gap" in s or "counter_gap" in s]
        assert gap_stages == [], f"Gap stages should not be called when loop is disabled: {gap_stages}"

    def test_stages_01_02_04_05_06_present(self):
        _, called = self._run_linear()
        base_stages = {"01_source_only_hypothesis", "02_kg_query_planning",
                       "04_hypothesis_verification", "05_counter_evidence_review", "06_final_adjudication"}
        for s in base_stages:
            assert any(s in c for c in called), f"Expected stage {s!r} not called; got {called}"

    def test_result_has_decision(self):
        result, _ = self._run_linear()
        from vckg_agentic_proof import AgenticProofResult
        assert isinstance(result, AgenticProofResult)
        assert result.decision is not None


# ---------------------------------------------------------------------------
# B. Tests: iterative loop enabled, gap analysis triggers follow-up
# ---------------------------------------------------------------------------

class TestIterativeLoopEnabled:
    def _run_with_loop(self, *, gap_needs=True, kg_new_items=None, max_iters=2):
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline

        if kg_new_items is None:
            kg_new_items = [
                [{"id": "EV-10", "kind": "source", "text": "initial result"}],  # initial retrieval
                [{"id": "EV-99", "kind": "source", "text": "guard found"}],      # follow-up retrieval iter1
            ]

        stage_responses = {
            "01_source_only_hypothesis": {"hypotheses": _make_hypotheses(),
                                          "source_observations": [], "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01",
                                                   "purpose": "p", "query_text": 'security_context(target_function="count_rows")',
                                                   "variables": [], "expected_evidence": "e", "limit": 8}]},
            "04_hypothesis_verification":      _hypothesis_verification_json(["plausible_but_unproven"]),
            "04_hypothesis_verification_iter1": _hypothesis_verification_json(["plausible_but_unproven"]),
            "04_hypothesis_verification_iter2": _hypothesis_verification_json(["plausible_but_unproven"]),
            "04_evidence_gap_iter1": _gap_plan_json(needs=gap_needs),
            "04_evidence_gap_iter2": _gap_plan_json(needs=False),  # stops second time
            "05_counter_evidence_review": _counter_review_json(),
            "06_final_adjudication": _final_decision_json(),
        }
        cfg = AgenticProofConfig(iterative_evidence_loop=True, max_evidence_iterations=max_iters,
                                 max_queries_per_iteration=5, stop_when_no_new_evidence=True,
                                 stop_when_no_new_queries=True)
        called_stages = []

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            called_stages.append(stage)
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                raise ValueError(f"Unexpected stage in mock: {stage!r}")
            return {"content": _xml_wrap(stage, data), "usage": {}}

        # Initial KG call + one follow-up call
        kg_calls = []
        def kg_search(queries, *, sample=None, limit=8):
            idx = len(kg_calls)
            kg_calls.append(queries)
            return kg_new_items[idx] if idx < len(kg_new_items) else []

        result = run_agentic_proof_pipeline(
            sample=_make_sample(),
            target_source="int count_rows(void){ return 0; }",
            initial_evidence=_make_evidence(2),
            llm_generate=llm_generate,
            kg_search=kg_search,
            config=cfg,
        )
        return result, called_stages, kg_calls

    def test_gap_stage_called_when_loop_enabled(self):
        _, called, _ = self._run_with_loop(gap_needs=True)
        assert any("evidence_gap_iter" in s for s in called), \
            f"Expected gap stage to be called; got {called}"

    def test_followup_kg_search_called(self):
        _, _, kg_calls = self._run_with_loop(gap_needs=True)
        assert len(kg_calls) >= 2, \
            f"Expected at least 2 kg_search calls (initial + follow-up); got {len(kg_calls)}"

    def test_verification_reruns_after_followup(self):
        _, called, _ = self._run_with_loop(gap_needs=True)
        iter_verifs = [s for s in called if "hypothesis_verification_iter" in s]
        assert len(iter_verifs) >= 1, f"Expected re-verification after follow-up; stages={called}"

    def test_no_loop_when_gap_returns_false(self):
        _, called, kg_calls = self._run_with_loop(gap_needs=False)
        # Gap stage called but returns needs_more_evidence=False → no follow-up retrieval
        assert any("evidence_gap_iter" in s for s in called)
        iter_verifs = [s for s in called if "hypothesis_verification_iter" in s]
        assert len(iter_verifs) == 0, f"Verification should not rerun if gap returns False; stages={called}"


# ---------------------------------------------------------------------------
# C. Tests: loop stopping rules
# ---------------------------------------------------------------------------

class TestLoopStoppingRules:
    def _run_loop(self, *, max_iters, gap_always_needs=True,
                  kg_returns_empty=False, all_resolved_after=None):
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline

        # Build enough responses for however many iterations we might run
        stage_responses: dict = {
            "01_source_only_hypothesis": {"hypotheses": _make_hypotheses(),
                                          "source_observations": [], "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01",
                                                   "purpose": "p", "query_text": 'security_context(target_function="count_rows")',
                                                   "variables": [], "expected_evidence": "e", "limit": 8}]},
            "05_counter_evidence_review": _counter_review_json(),
            "06_final_adjudication": _final_decision_json(),
        }
        # Add verification + gap responses for each possible iteration
        for i in range(max_iters + 2):
            suffix = "" if i == 0 else f"_iter{i}"
            if all_resolved_after is not None and i >= all_resolved_after:
                statuses = ["refuted_by_guard"]
            else:
                statuses = ["plausible_but_unproven"]
            stage_responses[f"04_hypothesis_verification{suffix}"] = _hypothesis_verification_json(statuses)
            if i > 0:
                stage_responses[f"04_evidence_gap_iter{i}"] = _gap_plan_json(needs=gap_always_needs)

        called_stages = []
        kg_call_count = [0]

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            called_stages.append(stage)
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                raise ValueError(f"Unexpected mock stage: {stage!r}")
            return {"content": _xml_wrap(stage, data), "usage": {}}

        def kg_search(queries, *, sample=None, limit=8):
            kg_call_count[0] += 1
            if kg_returns_empty:
                return []
            return [{"id": f"EV-{kg_call_count[0]}-x", "kind": "source", "text": "x"}]

        cfg = AgenticProofConfig(
            iterative_evidence_loop=True,
            max_evidence_iterations=max_iters,
            max_queries_per_iteration=5,
            stop_when_no_new_evidence=kg_returns_empty,
            stop_when_no_new_queries=True,
            stop_when_all_hypotheses_resolved=all_resolved_after is not None,
        )
        result = run_agentic_proof_pipeline(
            sample=_make_sample(),
            target_source="int f(void){ return 0; }",
            initial_evidence=_make_evidence(1),
            llm_generate=llm_generate,
            kg_search=kg_search,
            config=cfg,
        )
        return result, called_stages, kg_call_count[0]

    def test_stops_at_max_iterations(self):
        """Loop should not exceed max_evidence_iterations rounds."""
        _, called, _ = self._run_loop(max_iters=2, gap_always_needs=True)
        iter_gaps = [s for s in called if "evidence_gap_iter" in s]
        # At most max_iters gap analyses
        assert len(iter_gaps) <= 2, f"Expected ≤2 gap stages; got {iter_gaps}"

    def test_stops_when_no_new_evidence(self):
        """stop_when_no_new_evidence=True + empty kg_search → loop stops after 1 follow-up attempt."""
        _, called, kg_count = self._run_loop(max_iters=3, gap_always_needs=True, kg_returns_empty=True)
        # Should attempt the gap + follow-up once, then stop
        iter_gaps = [s for s in called if "evidence_gap_iter" in s]
        assert len(iter_gaps) <= 1, f"Expected loop to stop early on empty evidence; got {iter_gaps}"

    def test_stops_when_all_resolved(self):
        """stop_when_all_hypotheses_resolved: all hypotheses refuted → no further iterations."""
        _, called, _ = self._run_loop(max_iters=3, all_resolved_after=1)
        # After the first re-verification (iter1) all are resolved → no gap_iter2
        iter_gaps = [s for s in called if "evidence_gap_iter2" in s or "evidence_gap_iter3" in s]
        assert iter_gaps == [], f"Expected no further gaps after all resolved; got {iter_gaps}"

    def test_final_adjudication_always_runs(self):
        """06_final_adjudication must run regardless of how loop stopped."""
        _, called, _ = self._run_loop(max_iters=1)
        assert any("06_final_adjudication" in s for s in called), \
            f"final adjudication missing; stages={called}"

    def test_final_decision_not_extra_llm_call(self):
        """final_decision is parsed from 06 output, not a new LLM stage."""
        _, called, _ = self._run_loop(max_iters=1)
        final_decision_calls = [s for s in called if s == "final_decision"]
        assert final_decision_calls == [], \
            f"final_decision should not be a separate LLM call; got {final_decision_calls}"


# ---------------------------------------------------------------------------
# D. Tests: duplicate query deduplication
# ---------------------------------------------------------------------------

class TestDuplicateQueryDedup:
    def test_already_executed_queries_skipped(self):
        """Follow-up queries with IDs already in executed_query_ids are not re-sent to kg_search."""
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline

        # Gap returns a follow-up query with the SAME id as the initial query (Q1)
        stage_responses = {
            "01_source_only_hypothesis": {"hypotheses": _make_hypotheses(),
                                          "source_observations": [], "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01",
                                                   "purpose": "p", "query_text": 'security_context(target_function="count_rows")',
                                                   "variables": [], "expected_evidence": "e", "limit": 8}]},
            "04_hypothesis_verification": _hypothesis_verification_json(["plausible_but_unproven"]),
            "04_evidence_gap_iter1": {
                "needs_more_evidence": True,
                "gap_summary": "duplicate query",
                "follow_up_queries": [
                    # Q1 is ALREADY executed — should be deduped
                    {"query_id": "Q1", "hypothesis_id": "HYP-01", "purpose": "dup",
                     "query_text": 'security_context(target_function="count_rows")',
                     "variables": [], "expected_evidence": "e", "limit": 8},
                ],
                "stop_reason": None,
            },
            "05_counter_evidence_review": _counter_review_json(),
            "06_final_adjudication": _final_decision_json(),
        }
        kg_query_sets = []

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                raise ValueError(f"Unexpected mock stage: {stage!r}")
            return {"content": _xml_wrap(stage, data), "usage": {}}

        def kg_search(queries, *, sample=None, limit=8):
            kg_query_sets.append([q.get("query_id") or q.get("id") for q in queries])
            return [{"id": "EV-new", "kind": "source", "text": "new"}]

        cfg = AgenticProofConfig(iterative_evidence_loop=True, max_evidence_iterations=2,
                                 stop_when_no_new_queries=True)
        run_agentic_proof_pipeline(
            sample=_make_sample(),
            target_source="int f(void){ return 0; }",
            initial_evidence=[],
            llm_generate=llm_generate,
            kg_search=kg_search,
            config=cfg,
        )
        # Only the initial call (Q1). The follow-up call with duplicate Q1 should NOT happen.
        followup_calls = kg_query_sets[1:]  # all calls after initial
        dup_q1_calls = [qs for qs in followup_calls if "Q1" in qs]
        assert dup_q1_calls == [], f"Duplicate Q1 should be filtered; kg calls were {kg_query_sets}"


# ---------------------------------------------------------------------------
# E. Tests: gap prompt hygiene
# ---------------------------------------------------------------------------

class TestGapPromptHygiene:
    def _build_gap_prompt_text(self):
        from vckg_agentic_proof.prompts import evidence_gap_analysis_prompt
        sample = _make_sample()
        verifications = _hypothesis_verification_json(["plausible_but_unproven"])["verifications"]
        evidence = _make_evidence(3)
        executed_ids = ["Q1", "Q2"]
        msgs = evidence_gap_analysis_prompt(sample, verifications, evidence, executed_ids, iteration=1)
        return msgs, "\n".join(m["content"] for m in msgs)

    def test_gap_prompt_contains_target_function(self):
        _, text = self._build_gap_prompt_text()
        assert "count_rows" in text

    def test_gap_prompt_contains_verification_status(self):
        _, text = self._build_gap_prompt_text()
        assert "plausible_but_unproven" in text or "HYP-01" in text

    def test_gap_prompt_contains_missing_evidence(self):
        _, text = self._build_gap_prompt_text()
        assert "missing_guard_check" in text or "missing" in text.lower()

    def test_gap_prompt_contains_executed_query_ids(self):
        _, text = self._build_gap_prompt_text()
        assert "Q1" in text or "Q2" in text or "already executed" in text.lower()

    def test_gap_prompt_no_sample_id(self):
        _, text = self._build_gap_prompt_text()
        assert "18452" not in text

    def test_gap_prompt_no_project_url(self):
        _, text = self._build_gap_prompt_text()
        assert "github.com" not in text

    def test_gap_prompt_no_label(self):
        _, text = self._build_gap_prompt_text()
        assert '"label": 1' not in text
        assert '"label": "vulnerable"' not in text

    def test_gap_prompt_no_commit(self):
        _, text = self._build_gap_prompt_text()
        assert "deadbeef" not in text
        assert "cafebabe" not in text

    def test_gap_prompt_has_system_message(self):
        msgs, _ = self._build_gap_prompt_text()
        assert any(m["role"] == "system" for m in msgs)

    def test_gap_prompt_in_stage_context_policy(self):
        from vckg_agentic_proof.prompts import STAGE_CONTEXT_POLICY
        # The gap stage must be declared in STAGE_CONTEXT_POLICY
        assert "04_evidence_gap" in STAGE_CONTEXT_POLICY or \
               any("gap" in k for k in STAGE_CONTEXT_POLICY), \
            f"Gap stage not found in STAGE_CONTEXT_POLICY; keys={list(STAGE_CONTEXT_POLICY)}"


# ---------------------------------------------------------------------------
# F. Tests: AgenticProofConfig new fields
# ---------------------------------------------------------------------------

class TestAgenticProofConfigFields:
    def test_iterative_loop_defaults_false(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.iterative_evidence_loop is False

    def test_max_evidence_iterations_default(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.max_evidence_iterations >= 2

    def test_max_queries_per_iteration_default(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.max_queries_per_iteration >= 3

    def test_stop_when_no_new_evidence_default_true(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.stop_when_no_new_evidence is True

    def test_stop_when_no_new_queries_default_true(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.stop_when_no_new_queries is True

    def test_max_tokens_evidence_gap_default(self):
        from vckg_agentic_proof import AgenticProofConfig
        cfg = AgenticProofConfig()
        assert cfg.max_tokens_evidence_gap_analysis >= 4096


# ---------------------------------------------------------------------------
# G. Tests: EvidenceGapPlan schema
# ---------------------------------------------------------------------------

class TestEvidenceGapPlanSchema:
    def test_schema_importable(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        assert EvidenceGapPlan is not None

    def test_schema_parses_valid_json(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        data = _gap_plan_json(needs=True)
        plan = EvidenceGapPlan.model_validate(data)
        assert plan.needs_more_evidence is True
        assert len(plan.follow_up_queries) == 1

    def test_schema_parses_stop_false(self):
        from vckg_agentic_proof.schemas import EvidenceGapPlan
        data = _gap_plan_json(needs=False, queries=[])
        plan = EvidenceGapPlan.model_validate(data)
        assert plan.needs_more_evidence is False
        assert plan.follow_up_queries == []


# ---------------------------------------------------------------------------
# H. Tests: AgenticProofResult has iteration metadata
# ---------------------------------------------------------------------------

class TestAgenticProofResultIterationMetadata:
    def _run_once(self, iterative=False):
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline
        stage_responses = {
            "01_source_only_hypothesis": {"hypotheses": _make_hypotheses(),
                                          "source_observations": [], "non_vulnerability_possibilities": []},
            "02_kg_query_planning": {"queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01",
                                                   "purpose": "p", "query_text": 'security_context(target_function="count_rows")',
                                                   "variables": [], "expected_evidence": "e", "limit": 8}]},
            "04_hypothesis_verification": _hypothesis_verification_json(["plausible_but_unproven"]),
            "04_evidence_gap_iter1": _gap_plan_json(needs=False),  # immediately stops
            "05_counter_evidence_review": _counter_review_json(),
            "06_final_adjudication": _final_decision_json(),
        }

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            base = stage.split("_json_repair")[0]
            data = stage_responses.get(stage) or stage_responses.get(base)
            if data is None:
                raise ValueError(f"Unexpected: {stage!r}")
            return {"content": _xml_wrap(stage, data), "usage": {}}

        cfg = AgenticProofConfig(iterative_evidence_loop=iterative, max_evidence_iterations=2)
        return run_agentic_proof_pipeline(
            sample=_make_sample(),
            target_source="int f(void){ return 0; }",
            initial_evidence=_make_evidence(1),
            llm_generate=llm_generate,
            kg_search=_build_kg_search([[]]),
            config=cfg,
        )

    def test_result_has_loop_stop_reason(self):
        result = self._run_once(iterative=True)
        assert hasattr(result, "loop_stop_reason"), \
            "AgenticProofResult must have loop_stop_reason field"

    def test_result_has_iterations_completed(self):
        result = self._run_once(iterative=True)
        assert hasattr(result, "iterations_completed"), \
            "AgenticProofResult must have iterations_completed field"

    def test_linear_result_stop_reason_is_loop_disabled(self):
        result = self._run_once(iterative=False)
        assert result.loop_stop_reason in (None, "loop_disabled", ""), \
            f"Non-iterative run should have loop_disabled stop reason; got {result.loop_stop_reason!r}"


# ---------------------------------------------------------------------------
# I. Tests: ResearchInventory.flow() graceful fallback for old artifacts
# ---------------------------------------------------------------------------

class TestResearchInventoryFlow:
    def test_flow_method_exists(self):
        from student_system_creator.dashboard.research import ResearchInventory
        assert hasattr(ResearchInventory, "flow"), \
            "ResearchInventory must have a .flow() method"

    def test_flow_returns_fallback_for_missing_artifact(self, tmp_path):
        from student_system_creator.dashboard.research import ResearchInventory

        # Set up a minimal run directory structure without iterative artifacts
        runs = tmp_path / "runs"
        run_dir = runs / "2025_test_run"
        sample_dir = run_dir / "agent_demos" / "sample_18452_count_rows"
        sample_dir.mkdir(parents=True)
        # Write a minimal final_prediction.json
        (sample_dir / "final_prediction.json").write_text(
            json.dumps({"sample_id": "18452", "is_vulnerable": False,
                        "confidence": 0.5, "decision_status": "inconclusive"}),
            encoding="utf-8",
        )

        inv = ResearchInventory(project_root=str(tmp_path), runs_root="runs", jobs_root="jobs")
        flow = inv.flow("2025_test_run", "18452")

        assert flow is not None
        assert "fallback" in flow or "stages" in flow, \
            f"flow() should return a dict with 'stages' or 'fallback'; got keys={list((flow or {}).keys())}"

    def test_flow_no_secrets_in_output(self, tmp_path):
        from student_system_creator.dashboard.research import ResearchInventory

        runs = tmp_path / "runs"
        run_dir = runs / "2025_secret_run"
        sample_dir = run_dir / "agent_demos" / "sample_99_fn"
        sample_dir.mkdir(parents=True)
        # Write agent_flow.json with a secret that must be redacted
        (sample_dir / "agent_flow.json").write_text(
            json.dumps({"api_key": "sk-supersecret", "stages": [],
                        "loop_stop_reason": "max_iterations_reached"}),
            encoding="utf-8",
        )

        inv = ResearchInventory(project_root=str(tmp_path), runs_root="runs", jobs_root="jobs")
        flow = inv.flow("2025_secret_run", "99")

        assert flow is not None
        text = json.dumps(flow)
        assert "sk-supersecret" not in text, "API key must be redacted in flow() output"


# ---------------------------------------------------------------------------
# J. Tests: pipeline.py emits iteration events (inspect source for event types)
# ---------------------------------------------------------------------------

class TestPipelineIterationEvents:
    def _get_pipeline_source(self):
        import vuln_commit_kg.orchestration.pipeline as pipeline_mod
        return inspect.getsource(pipeline_mod)

    def test_pipeline_emits_evidence_iteration_started(self):
        src = self._get_pipeline_source()
        assert "evidence_iteration_started" in src, \
            "pipeline.py must emit 'evidence_iteration_started' event"

    def test_pipeline_emits_evidence_iteration_completed(self):
        src = self._get_pipeline_source()
        assert "evidence_iteration_completed" in src, \
            "pipeline.py must emit 'evidence_iteration_completed' event"

    def test_pipeline_writes_evidence_iterations_jsonl(self):
        src = self._get_pipeline_source()
        assert "evidence_iterations.jsonl" in src, \
            "pipeline.py must write evidence_iterations.jsonl artifact"

    def test_pipeline_writes_agent_flow_json(self):
        src = self._get_pipeline_source()
        assert "agent_flow.json" in src, \
            "pipeline.py must write agent_flow.json artifact"


# ---------------------------------------------------------------------------
# K. Tests: AgenticProofRuntimeConfig mirrors new fields
# ---------------------------------------------------------------------------

class TestRuntimeConfigMirror:
    def test_runtime_config_has_iterative_loop(self):
        from vuln_commit_kg.config import AgenticProofRuntimeConfig
        cfg = AgenticProofRuntimeConfig()
        assert hasattr(cfg, "iterative_evidence_loop"), \
            "AgenticProofRuntimeConfig must have iterative_evidence_loop field"
        assert cfg.iterative_evidence_loop is False

    def test_runtime_config_has_max_evidence_iterations(self):
        from vuln_commit_kg.config import AgenticProofRuntimeConfig
        cfg = AgenticProofRuntimeConfig()
        assert hasattr(cfg, "max_evidence_iterations")
        assert cfg.max_evidence_iterations >= 2

    def test_runtime_config_has_max_queries_per_iteration(self):
        from vuln_commit_kg.config import AgenticProofRuntimeConfig
        cfg = AgenticProofRuntimeConfig()
        assert hasattr(cfg, "max_queries_per_iteration")


# ---------------------------------------------------------------------------
# L. Tests: frontend build check (TypeScript interface completeness)
# ---------------------------------------------------------------------------

class TestFrontendAgentFlowTypes:
    def _read_research_ts(self):
        root = Path(__file__).resolve().parents[1]
        return (root / "frontend" / "src" / "api" / "research.ts").read_text(encoding="utf-8")

    def _read_app_tsx(self):
        root = Path(__file__).resolve().parents[1]
        return (root / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")

    def _read_sidebar(self):
        root = Path(__file__).resolve().parents[1]
        return (root / "frontend" / "src" / "components" / "Sidebar.tsx").read_text(encoding="utf-8")

    def test_research_ts_has_agent_flow_interface(self):
        src = self._read_research_ts()
        assert "AgentFlow" in src or "FlowStage" in src, \
            "research.ts must define AgentFlow or FlowStage interface"

    def test_research_ts_has_flow_endpoint_call(self):
        src = self._read_research_ts()
        assert "flow" in src and "/flow" in src, \
            "research.ts must have a flow() API call pointing to /flow endpoint"

    def test_app_tsx_has_flow_route(self):
        src = self._read_app_tsx()
        assert "/research/flow/" in src or "research/flow" in src, \
            "App.tsx must have a /research/flow route"

    def test_sidebar_has_flow_link(self):
        src = self._read_sidebar()
        # Accept either "Agentic Flow" label or the route path
        assert "flow" in src.lower() or "Agentic Flow" in src, \
            "Sidebar must include a link to the Agentic Flow page"

    def test_agent_flow_page_exists(self):
        root = Path(__file__).resolve().parents[1]
        page = root / "frontend" / "src" / "pages" / "AgentFlowPage.tsx"
        assert page.exists(), "frontend/src/pages/AgentFlowPage.tsx must exist"


# ---------------------------------------------------------------------------
# M. Tests: stage-07 fallback, partial agent_flow.json on failure
# ---------------------------------------------------------------------------

class TestStage07FallbackAndPartialArtifacts:
    """Stage-07 schema consistency repair must fall back to stage-06 validated
    decision on failure, not crash the whole sample."""

    def _make_sample_dict(self):
        return {
            "function": "vuln_fn",
            "filepath": "src/vuln.c",
            "func_body": "int vuln_fn(int x) { return x; }",
        }

    def _run_adapter_with_stage07_failure(self):
        """Run adapter where stage-07 repair throws, verify fallback to stage-06."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
        from vckg_agentic_proof.adapter import run_agentic_proof_pipeline, AgenticProofConfig

        sample = self._make_sample_dict()
        config = AgenticProofConfig(
            max_tokens_source_only_hypothesis=512,
            max_tokens_kg_query_planning=256,
            max_tokens_hypothesis_verification=512,
            max_tokens_counter_evidence_review=256,
            max_tokens_final_decision=512,
            max_tokens_schema_repair=256,
            iterative_evidence_loop=False,
        )

        repair_attempt = {"triggered": False}

        stage_responses = {
            "01_source_only_hypothesis": json.dumps({
                "hypotheses": [{"hypothesis_id": "HYP-01", "title": "t",
                                "risk_summary": "r", "required_proof_questions": []}]
            }),
            "02_kg_query_planning": json.dumps({"queries": []}),
            "04_hypothesis_verification": json.dumps({"verifications": [
                {"hypothesis_id": "HYP-01", "status": "insufficient_evidence",
                 "local_risk_present": True, "confirmed_security_vulnerability": False,
                 "proof": {"input_control": "", "dangerous_operation": "",
                           "missing_or_failed_guard": "", "unsafe_use": "",
                           "security_impact": "", "cited_evidence_ids": []},
                 "supporting_evidence_ids": [], "counter_evidence_ids": [],
                 "missing_evidence": [], "explanation": "insufficient"}
            ]}),
            "05_counter_evidence_review": json.dumps({"findings": [], "overall_notes": ""}),
            # Vulnerable without proof triggers validator downgrade → modified=True → stage 07
            "06_final_adjudication": json.dumps({
                "prediction": "vulnerable",
                "confidence": 0.9,
                "local_risk_present": True,
                "confirmed_security_vulnerability": True,
                "final_hypothesis_statuses": [],
                "minimum_vulnerability_proof": None,
                "decisive_evidence_ids": [],
                "decisive_counter_evidence_ids": [],
                "explanation": "test",
                "limitations": [],
            }),
        }

        def mock_llm(messages, *, stage, max_tokens, temperature, extra_body=None):
            if stage.startswith("07_schema_consistency_repair"):
                repair_attempt["triggered"] = True
                raise RuntimeError("Simulated repair LLM failure")
            base = stage.split("_json_repair")[0]
            resp = stage_responses.get(stage) or stage_responses.get(base)
            if resp is None:
                raise ValueError(f"Unexpected stage in mock: {stage!r}")
            return resp

        result = run_agentic_proof_pipeline(
            sample=sample,
            target_source="int vuln_fn(int x) { return x; }",
            initial_evidence=[],
            llm_generate=mock_llm,
            kg_search=lambda queries, **kw: [],
            config=config,
        )
        return result, repair_attempt

    def test_stage07_fallback_returns_result_not_exception(self):
        """run_agentic_proof_pipeline must return a result (not raise) when stage-07 fails."""
        result, _ = self._run_adapter_with_stage07_failure()
        assert result is not None, "Pipeline must return a result even when stage-07 repair fails"
        assert result.decision is not None, "Decision must not be None after stage-07 fallback"

    def test_stage07_fallback_decision_is_binary(self):
        """After stage-07 fallback, the returned decision must have a binary forced_prediction."""
        result, _ = self._run_adapter_with_stage07_failure()
        d = result.decision
        assert d.forced_prediction in ("vulnerable", "fixed/non-vulnerable"), (
            f"forced_prediction must be binary after fallback, got {d.forced_prediction!r}"
        )
        assert d.forced_prediction_bool is not None, (
            "forced_prediction_bool must not be None after fallback"
        )

    def test_stage07_fallback_event_recorded(self):
        """After stage-07 fallback, the events list must contain a fallback event."""
        result, repair_attempt = self._run_adapter_with_stage07_failure()
        fallback_events = [
            e for e in result.events
            if getattr(e, "stage", None) == "07_schema_consistency_repair"
            and getattr(e, "event", None) == "fallback"
        ]
        if repair_attempt["triggered"]:
            assert fallback_events, (
                "A fallback AgentEvent must be recorded when stage-07 fails. "
                f"Found events: {[(getattr(e,'stage',None), getattr(e,'event_type',None)) for e in result.events]}"
            )


class TestForcedBinarySchemaFields:
    """FinalDecision schema must contain all forced binary fields."""

    def test_final_decision_has_forced_prediction_field(self):
        from vckg_agentic_proof.schemas import FinalDecision
        import inspect
        fields = FinalDecision.model_fields if hasattr(FinalDecision, "model_fields") else {}
        assert "forced_prediction" in fields or hasattr(FinalDecision(
            prediction="fixed/non-vulnerable", confidence=0.5, explanation="x"
        ), "forced_prediction"), "FinalDecision must have forced_prediction field"

    def test_final_decision_has_decision_status_field(self):
        from vckg_agentic_proof.schemas import FinalDecision
        fd = FinalDecision(prediction="fixed/non-vulnerable", confidence=0.5, explanation="x")
        assert hasattr(fd, "decision_status"), "FinalDecision must have decision_status field"

    def test_final_decision_has_evidence_strength_field(self):
        from vckg_agentic_proof.schemas import FinalDecision
        fd = FinalDecision(prediction="fixed/non-vulnerable", confidence=0.5, explanation="x")
        assert hasattr(fd, "evidence_strength"), "FinalDecision must have evidence_strength field"

    def test_final_decision_has_why_forced_binary_field(self):
        from vckg_agentic_proof.schemas import FinalDecision
        fd = FinalDecision(prediction="fixed/non-vulnerable", confidence=0.5, explanation="x")
        assert hasattr(fd, "why_forced_binary"), "FinalDecision must have why_forced_binary field"


class TestPromptNoBinaryForbidden:
    """Final adjudication prompt must not instruct the model to prefer inconclusive."""

    def _get_prompt_text(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
        from vckg_agentic_proof import prompts
        import inspect
        return inspect.getsource(prompts)

    def test_final_adjudication_prompt_no_prefer_inconclusive(self):
        src = self._get_prompt_text()
        assert "prefer inconclusive" not in src, (
            "final_decision_prompt must not instruct the model to 'prefer inconclusive'. "
            "Binary prediction is required."
        )

    def test_final_adjudication_prompt_requires_binary(self):
        src = self._get_prompt_text()
        assert "binary prediction" in src.lower() or "MUST produce" in src, (
            "final_decision_prompt must instruct the model to produce a binary prediction."
        )

    def test_consistency_repair_prompt_no_choose_inconclusive(self):
        src = self._get_prompt_text()
        assert "choose inconclusive" not in src, (
            "consistency_repair_prompt must not suggest choosing inconclusive. "
            "Binary prediction is required."
        )


class TestStage06RecoveryAndRepairRouting:
    """Stage 06 must not crash the pipeline when JSON parse or schema validation fails.
    JSON repair must only fire for malformed JSON, not for schema failures."""

    def _base_stage_responses(self, stage06_response: str) -> dict:
        return {
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
            "06_final_adjudication": stage06_response,
        }

    def _run_pipeline(self, stage06_response: str):
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
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
        stage_responses = self._base_stage_responses(stage06_response)
        json_repair_stages = []

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
        return result, json_repair_stages

    def test_stage06_schema_failure_does_not_crash_pipeline(self):
        """Pipeline must return a result (not raise) when Stage 06 output fails schema."""
        result, _ = self._run_pipeline(
            json.dumps({"completely_wrong_schema": "this is not a FinalDecision"})
        )
        assert result is not None, "Pipeline must not raise when Stage 06 schema validation fails"
        assert result.decision is not None, "Decision must not be None after Stage 06 schema failure"

    def test_stage06_schema_failure_sets_failed_parse_status(self):
        """decision_status must be 'failed_parse' when Stage 06 schema validation fails."""
        result, _ = self._run_pipeline(
            json.dumps({"completely_wrong_schema": True})
        )
        assert result.decision.decision_status == "failed_parse", (
            f"Expected 'failed_parse', got {result.decision.decision_status!r}"
        )

    def test_stage06_schema_failure_produces_no_json_repair_stage(self):
        """Valid JSON with schema failure must NOT produce a '06_final_adjudication_json_repair' stage."""
        result, json_repair_stages = self._run_pipeline(
            json.dumps({"wrong_schema": "valid json, bad schema"})
        )
        assert "06_final_adjudication_json_repair" not in json_repair_stages, (
            "json_repair must not fire for schema validation failures. "
            f"Fired stages: {json_repair_stages}"
        )

    def test_stage06_malformed_json_triggers_json_repair(self):
        """Malformed JSON in Stage 06 must trigger '06_final_adjudication_json_repair'."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
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

        valid_final_decision = json.dumps({
            "prediction": "fixed/non-vulnerable",
            "confidence": 0.8,
            "local_risk_present": False,
            "confirmed_security_vulnerability": False,
            "final_hypothesis_statuses": [],
            "minimum_vulnerability_proof": None,
            "decisive_evidence_ids": [],
            "decisive_counter_evidence_ids": [],
            "explanation": "repaired",
            "limitations": [],
        })

        stage_responses = self._base_stage_responses("<answer>{prediction: malformed</answer>")
        json_repair_stages = []

        def mock_llm(messages, *, stage, max_tokens, temperature, extra_body=None):
            if "_json_repair" in stage:
                json_repair_stages.append(stage)
                return f"<answer>{valid_final_decision}</answer>"
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
        assert "06_final_adjudication_json_repair" in json_repair_stages, (
            "Malformed JSON in Stage 06 must trigger json_repair. "
            f"Got json_repair_stages={json_repair_stages}"
        )

    def test_stage06_fallback_decision_is_not_counted_as_valid_binary(self):
        """An emergency fallback decision from a failed Stage 06 must have
        decision_status='failed_parse' so it is excluded from binary metrics."""
        result, _ = self._run_pipeline(
            json.dumps({"garbage": "not a FinalDecision"})
        )
        d = result.decision
        assert d.decision_status == "failed_parse", (
            f"Emergency fallback must set decision_status='failed_parse', got {d.decision_status!r}"
        )
        assert d.confidence == 0.0, (
            f"Emergency fallback must have confidence=0.0, got {d.confidence!r}"
        )
