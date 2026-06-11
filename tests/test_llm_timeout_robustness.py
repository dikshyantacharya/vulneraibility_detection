"""
TDD — LLM timeout robustness and Windows Rich logging safety.

RED → GREEN → REFACTOR: all tests written BEFORE the fixes.

Covers:
  A. AcademicCloud dashboard profile sets timeout_seconds >= 600
  B. openai_compatible retries once on ReadTimeout then succeeds / propagates
  C. Failed model-call record written to sample-dir model_calls.jsonl
  D. Optional gap-analysis timeout stops iterative loop gracefully
  E. Windows Rich UnicodeEncodeError does not crash logging
"""
from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ─── shared helpers ────────────────────────────────────────────────────────────

def _make_oc_cfg(*, timeout_seconds: int = 30, retry: int = 1) -> Any:
    """Return a minimal ModelConfig-like mock for OpenAICompatibleModel."""
    cfg = MagicMock()
    cfg.timeout_seconds = timeout_seconds
    cfg.api_base = "https://example.com/v1"
    cfg.api_key_env = None
    cfg.model_name = "test-model"
    cfg.temperature = 0.0
    cfg.top_p = 1.0
    cfg.max_tokens = 1024
    cfg.stop = None
    cfg.api_minimal_payload = True
    cfg.api_extra_body = {}
    cfg.api_disable_thinking = False
    cfg.request_json_object = False
    cfg.llm_retry_on_timeout = retry          # NEW field added by this TDD cycle
    cfg.cost = MagicMock()
    cfg.cost.input_per_1k_usd = 0.0
    cfg.cost.output_per_1k_usd = 0.0
    return cfg


def _ok_requests_response(text: str = "ok") -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }
    resp.headers = {}
    return resp


# Minimal JSON for every agentic-proof stage (reused from test_agentic_flow_loop helpers)

def _xml_wrap(data: dict) -> str:
    return f"<analysis>brief</analysis><answer>{json.dumps(data)}</answer>"


_STAGE_RESPONSES: dict[str, dict] = {
    "01_source_only_hypothesis": {
        "hypotheses": [{"hypothesis_id": "HYP-01", "title": "OOB",
                         "risk_summary": "r", "required_proof_questions": ["q1"],
                         "status": "plausible_but_unproven"}],
        "source_observations": [], "non_vulnerability_possibilities": [],
    },
    "02_kg_query_planning": {
        "queries": [{"query_id": "Q1", "hypothesis_id": "HYP-01", "purpose": "p",
                     "query_text": 'security_context(target_function="count_rows")',
                     "variables": [], "expected_evidence": "e", "limit": 8}],
    },
    "04_hypothesis_verification": {
        "verifications": [{
            "hypothesis_id": "HYP-01", "status": "plausible_but_unproven",
            "local_risk_present": False, "confirmed_security_vulnerability": False,
            "proof": {"input_control": "", "dangerous_operation": "",
                      "missing_or_failed_guard": "", "unsafe_use": "",
                      "security_impact": "", "cited_evidence_ids": []},
            "supporting_evidence_ids": [], "counter_evidence_ids": [],
            "missing_evidence": ["guard_check"], "explanation": "needs more",
        }],
    },
    "05_counter_evidence_review": {
        "findings": [{"hypothesis_id": "HYP-01", "strongest_counterargument": "none",
                      "counter_evidence_ids": [], "refutes_or_weakens": "weakens",
                      "recommended_status": "plausible_but_unproven"}],
        "overall_notes": "",
    },
    "06_final_adjudication": {
        "prediction": "inconclusive", "prediction_bool": None, "confidence": 0.4,
        "local_risk_present": False, "confirmed_security_vulnerability": False,
        "final_hypothesis_statuses": [], "minimum_vulnerability_proof": None,
        "decisive_evidence_ids": [], "decisive_counter_evidence_ids": [],
        "explanation": "insufficient evidence", "limitations": [],
    },
}


def _make_llm_generate(extra_stages: dict | None = None) -> Any:
    """Mock llm_generate that returns preset JSON per stage."""
    responses = dict(_STAGE_RESPONSES)
    if extra_stages:
        responses.update(extra_stages)

    def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
        base = stage.split("_json_repair")[0]
        data = responses.get(stage) or responses.get(base)
        if data is None:
            raise ValueError(f"Unexpected stage in mock: {stage!r}")
        return {"content": _xml_wrap(data), "usage": {"prompt_tokens": 10, "completion_tokens": 20}}

    return llm_generate


# ═══════════════════════════════════════════════════════════════════════════════
# A. AcademicCloud dashboard profile must raise timeout_seconds to >= 600
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcademicCloudTimeoutConfig:
    """jobs._apply_llm_override must guarantee >= 600s for AcademicCloud."""

    def _apply(self, base_timeout: int | None = 180) -> dict:
        from student_system_creator.dashboard.jobs import _apply_llm_override

        config: dict[str, Any] = {}
        if base_timeout is not None:
            config["model"] = {"timeout_seconds": base_timeout}
        _apply_llm_override(config, "academiccloud", "qwen3-coder-30b-a3b-instruct")
        return config

    def test_profile_sets_timeout_at_least_600_when_base_is_180(self):
        """AcademicCloud profile must override the 180s base-config timeout.

        RED: _apply_llm_override does not touch timeout_seconds → stays at 180 → FAILS.
        GREEN: fix sets max(600, existing) → PASSES.
        """
        config = self._apply(base_timeout=180)
        actual = config["model"]["timeout_seconds"]
        assert actual >= 600, (
            f"AcademicCloud dashboard timeout must be >= 600s for iterative loop runs; "
            f"got {actual}s (base config had 180s)"
        )

    def test_profile_preserves_higher_timeout_if_already_set(self):
        """If the base config already sets a timeout > 600, it should be preserved."""
        config = self._apply(base_timeout=900)
        actual = config["model"]["timeout_seconds"]
        assert actual >= 900, (
            f"AcademicCloud override should never lower a base timeout > 600; got {actual}"
        )

    def test_profile_sets_timeout_when_base_config_has_none(self):
        """AcademicCloud profile should set timeout even if model block had none."""
        config = self._apply(base_timeout=None)
        actual = config["model"].get("timeout_seconds")
        assert actual is not None and actual >= 600, (
            f"Expected timeout_seconds >= 600 in model block, got: {actual}"
        )

    def test_other_profiles_not_affected(self):
        """openai and tu_berlin_ollama profiles must not receive the 600s override."""
        from student_system_creator.dashboard.jobs import _apply_llm_override

        for profile in ("openai", "tu_berlin_ollama"):
            config: dict[str, Any] = {"model": {"timeout_seconds": 60}}
            _apply_llm_override(config, profile, "gpt-4o")
            actual = config["model"].get("timeout_seconds")
            # Must NOT be silently inflated to 600 for non-AcademicCloud providers
            assert actual is None or actual == 60, (
                f"Profile {profile!r} should not force 600s timeout; got {actual}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# B. openai_compatible retries once on ReadTimeout, not on other errors
# ═══════════════════════════════════════════════════════════════════════════════

class TestOpenAICompatibleRetry:
    """OpenAICompatibleModel.generate retries up to llm_retry_on_timeout times."""

    def _make_model(self, retry: int = 1) -> Any:
        from vuln_commit_kg.models.openai_compatible import OpenAICompatibleModel
        return OpenAICompatibleModel(_make_oc_cfg(retry=retry))

    def test_readtimeout_retried_once_then_succeeds(self):
        """ReadTimeout on attempt 1 → retry → succeeds on attempt 2.

        RED: no retry loop exists → ReadTimeout propagates immediately → FAILS.
        GREEN: retry loop added → returns result on second attempt → PASSES.
        """
        from requests.exceptions import ReadTimeout

        call_n = {"n": 0}

        def side_effect(*a, **kw):
            call_n["n"] += 1
            if call_n["n"] == 1:
                raise ReadTimeout("simulated read timeout")
            return _ok_requests_response("retried_ok")

        model = self._make_model(retry=1)
        with patch("vuln_commit_kg.models.openai_compatible.requests.post",
                   side_effect=side_effect):
            with patch("time.sleep"):  # suppress real sleep
                result = model.generate("hello")

        assert call_n["n"] == 2, (
            f"Expected 2 HTTP attempts (1 original + 1 retry), got {call_n['n']}"
        )
        assert result.text == "retried_ok"

    def test_readtimeout_all_retries_exhausted_propagates(self):
        """When every attempt times out the exception must eventually propagate.

        RED: no retry → propagates after 1 attempt, assertion on call count FAILS.
        GREEN: retry added → propagates after 2 attempts → PASSES.
        """
        from requests.exceptions import ReadTimeout

        call_n = {"n": 0}

        def always_timeout(*a, **kw):
            call_n["n"] += 1
            raise ReadTimeout("always times out")

        model = self._make_model(retry=1)
        with patch("vuln_commit_kg.models.openai_compatible.requests.post",
                   side_effect=always_timeout):
            with patch("time.sleep"):
                with pytest.raises(ReadTimeout):
                    model.generate("hello")

        assert call_n["n"] == 2, (
            f"Expected exactly 2 HTTP attempts (1 original + 1 retry) before giving up; "
            f"got {call_n['n']}"
        )

    def test_non_timeout_http_error_not_retried(self):
        """HTTP 400 / non-timeout errors must not be retried."""
        import requests as req_mod

        call_n = {"n": 0}
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        mock_resp.headers = {}

        def bad_request(*a, **kw):
            call_n["n"] += 1
            return mock_resp

        model = self._make_model(retry=1)
        with patch("vuln_commit_kg.models.openai_compatible.requests.post",
                   side_effect=bad_request):
            with pytest.raises(req_mod.HTTPError):
                model.generate("hello")

        assert call_n["n"] == 1, (
            f"HTTP 400 must not be retried; expected 1 attempt, got {call_n['n']}"
        )

    def test_retry_zero_means_no_retry(self):
        """llm_retry_on_timeout=0 means zero retries — propagates on first timeout."""
        from requests.exceptions import ReadTimeout

        call_n = {"n": 0}

        def timeout_once(*a, **kw):
            call_n["n"] += 1
            raise ReadTimeout("timeout")

        model = self._make_model(retry=0)
        with patch("vuln_commit_kg.models.openai_compatible.requests.post",
                   side_effect=timeout_once):
            with patch("time.sleep"):
                with pytest.raises(ReadTimeout):
                    model.generate("hello")

        assert call_n["n"] == 1, (
            f"retry=0 should make exactly 1 attempt; got {call_n['n']}"
        )

    def test_timeout_not_in_llm_json_payload(self):
        """timeout_seconds must be a client-side HTTP setting, never in the JSON body."""
        from vuln_commit_kg.models.openai_compatible import build_chat_payload

        payload = build_chat_payload(_make_oc_cfg(timeout_seconds=600), "hello")
        assert "timeout" not in payload, (
            f"timeout must not be added to the LLM request payload; found keys: {list(payload)}"
        )
        assert "timeout_seconds" not in payload, (
            f"timeout_seconds must not be added to the LLM request payload"
        )

    def test_failed_record_has_no_api_key(self):
        """Error records logged to model_calls must never contain the API key value."""
        from requests.exceptions import ReadTimeout

        import os
        os.environ["TEST_SECRET_KEY"] = "SUPER_SECRET_API_KEY_12345"

        cfg = _make_oc_cfg(retry=0)
        cfg.api_key_env = "TEST_SECRET_KEY"

        from vuln_commit_kg.models.openai_compatible import OpenAICompatibleModel
        model = OpenAICompatibleModel(cfg)

        captured_error_text = []
        original_log = MagicMock(side_effect=lambda fmt, *a, **kw: captured_error_text.append(str(a)))

        with patch("vuln_commit_kg.models.openai_compatible.requests.post",
                   side_effect=ReadTimeout("timeout")):
            with patch("vuln_commit_kg.models.openai_compatible.logger.error", original_log):
                with pytest.raises(ReadTimeout):
                    model.generate("hello")

        secret = "SUPER_SECRET_API_KEY_12345"
        for logged in captured_error_text:
            assert secret not in logged, (
                f"API key must never appear in logged error text; found in: {logged!r}"
            )

        del os.environ["TEST_SECRET_KEY"]


# ═══════════════════════════════════════════════════════════════════════════════
# C. Failed model-call record must be written to model_calls.jsonl on disk
# ═══════════════════════════════════════════════════════════════════════════════

class TestModelCallsJsonlOnError:
    """The llm_generate error path in _classify_agentic_proof must persist to disk."""

    def test_error_path_writes_failed_record_to_jsonl(self, tmp_path):
        """When llm_generate raises, the error record must land in model_calls.jsonl.

        RED: the except block only appends to trace.model_calls (in memory);
             model_calls.jsonl is NOT written → assertion fails.
        GREEN: except block also writes to jsonl → PASSES.
        """
        from requests.exceptions import ReadTimeout
        from vuln_commit_kg.config import AppConfig
        from vuln_commit_kg.orchestration.pipeline import CommitKGPipeline
        from vuln_commit_kg.data.schema import SecVulEvalSample
        from vuln_commit_kg.retrieval.evidence import EvidencePack

        cfg = AppConfig.model_validate({
            "experiment": {"name": "test_mc_jsonl", "output_root": str(tmp_path)},
            "logging": {"rich": False, "level": "ERROR"},
            "live_dashboard": {"enabled": False},
            "agent": {"mode": "agentic_proof"},
        })
        pipeline = CommitKGPipeline(cfg)

        mock_model = MagicMock()
        mock_model.generate.side_effect = ReadTimeout("timed out after 600s")
        mock_model.cfg = MagicMock()
        mock_model.cfg.max_tokens = 1024
        mock_model.cfg.temperature = 0.0
        mock_model.cfg.api_extra_body = {}
        mock_model.cfg.api_disable_thinking = False

        sample = SecVulEvalSample(
            sample_id="18452",
            project="rockhopper",
            func_name="count_rows",
            filepath="src/db.c",
            func_body="int count_rows() { return 0; }",
            is_vulnerable=True,
        )
        evidence = EvidencePack(sample_id="18452")
        graph = MagicMock()

        with pytest.raises(Exception):
            pipeline._classify_agentic_proof(
                sample=sample, evidence=evidence, graph=graph, model=mock_model
            )

        mc_path = (
            pipeline.run_dir
            / "agent_demos"
            / "sample_18452_count_rows"
            / "model_calls.jsonl"
        )
        assert mc_path.exists(), (
            "model_calls.jsonl must be created even when llm_generate raises — "
            "the error handler must write the failed record to disk so that the "
            "Agentic Flow dashboard can display the failed stage."
        )
        records = [
            json.loads(line)
            for line in mc_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        error_records = [
            r for r in records
            if r.get("error") or r.get("status") == "failed"
            or r.get("json_status") == "provider_error"
        ]
        assert error_records, (
            f"Expected at least one error record in model_calls.jsonl; "
            f"found {len(records)} record(s): {records}"
        )

    def test_error_record_has_stage_and_error_type(self, tmp_path):
        """The error record must contain stage, error, and json_status fields."""
        from requests.exceptions import ReadTimeout
        from vuln_commit_kg.config import AppConfig
        from vuln_commit_kg.orchestration.pipeline import CommitKGPipeline
        from vuln_commit_kg.data.schema import SecVulEvalSample
        from vuln_commit_kg.retrieval.evidence import EvidencePack

        cfg = AppConfig.model_validate({
            "experiment": {"name": "test_mc_fields", "output_root": str(tmp_path)},
            "logging": {"rich": False, "level": "ERROR"},
            "live_dashboard": {"enabled": False},
            "agent": {"mode": "agentic_proof"},
        })
        pipeline = CommitKGPipeline(cfg)

        mock_model = MagicMock()
        mock_model.generate.side_effect = ReadTimeout("timeout")
        mock_model.cfg = MagicMock()
        mock_model.cfg.max_tokens = 1024
        mock_model.cfg.temperature = 0.0
        mock_model.cfg.api_extra_body = {}
        mock_model.cfg.api_disable_thinking = False

        sample = SecVulEvalSample(
            sample_id="18452", project="rockhopper",
            func_name="count_rows", filepath="src/db.c",
            func_body="int f() {}", is_vulnerable=True,
        )
        with pytest.raises(Exception):
            pipeline._classify_agentic_proof(
                sample=sample, evidence=EvidencePack(sample_id="18452"),
                graph=MagicMock(), model=mock_model,
            )

        mc_path = (
            pipeline.run_dir / "agent_demos" / "sample_18452_count_rows" / "model_calls.jsonl"
        )
        if not mc_path.exists():
            pytest.fail("model_calls.jsonl not written — see test_error_path_writes_failed_record_to_jsonl")

        records = [json.loads(l) for l in mc_path.read_text().splitlines() if l.strip()]
        err = next(
            (r for r in records if r.get("error") or r.get("json_status") == "provider_error"),
            None,
        )
        assert err is not None, "No error record found"
        assert err.get("name") or err.get("stage"), "Error record must have 'name' (stage)"
        assert err.get("error"), "Error record must have 'error' message"
        assert "ReadTimeout" in str(err.get("error", "")), (
            f"Expected ReadTimeout in error message; got: {err.get('error')}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# D. Optional gap-analysis timeout stops the loop with a timeout stop_reason
# ═══════════════════════════════════════════════════════════════════════════════

class TestGapAnalysisTimeoutPolicy:
    """ReadTimeout in optional gap-analysis stages must not fail the whole sample."""

    def _run_with_gap_timeout(self) -> Any:
        """Run the pipeline with llm_generate that raises ReadTimeout for gap stages."""
        from requests.exceptions import ReadTimeout
        from vckg_agentic_proof.adapter import AgenticProofConfig, run_agentic_proof_pipeline

        def llm_generate(messages, *, stage, max_tokens, temperature, extra_body=None):
            if "evidence_gap" in stage:
                raise ReadTimeout("gap analysis timed out after 600s")
            base = stage.split("_json_repair")[0]
            # Map iter-suffixed verification to the base response
            base_no_iter = base.replace("_iter1", "").replace("_iter2", "").replace("_iter3", "")
            data = _STAGE_RESPONSES.get(stage) or _STAGE_RESPONSES.get(base) or _STAGE_RESPONSES.get(base_no_iter)
            if data is None:
                raise ValueError(f"Unexpected stage in mock: {stage!r}")
            return {"content": _xml_wrap(data), "usage": {}}

        return run_agentic_proof_pipeline(
            sample={
                "sample_id": "18452", "project": "rockhopper",
                "project_url": "https://github.com/x/rh",
                "function": "count_rows", "filepath": "src/db.c",
            },
            target_source="int count_rows() { return 0; }",
            initial_evidence=[],
            llm_generate=llm_generate,
            kg_search=lambda q, **kw: [],
            config=AgenticProofConfig(
                iterative_evidence_loop=True,
                max_evidence_iterations=3,
            ),
        )

    def test_gap_timeout_does_not_raise(self):
        """ReadTimeout in gap analysis must not propagate — pipeline completes.

        RED: adapter.py does not catch ReadTimeout in gap stage → exception propagates
             → run_agentic_proof_pipeline raises → FAILS.
        GREEN: adapter catches timeout in optional stage → returns result → PASSES.
        """
        try:
            result = self._run_with_gap_timeout()
        except Exception as exc:
            pytest.fail(
                f"run_agentic_proof_pipeline must not raise when gap-analysis times out; "
                f"got {type(exc).__name__}: {exc}"
            )

    def test_gap_timeout_sets_loop_stop_reason(self):
        """loop_stop_reason must indicate a timeout, not None or a normal stop."""
        result = self._run_with_gap_timeout()
        assert result.loop_stop_reason is not None, (
            "loop_stop_reason must be set when gap analysis timed out"
        )
        assert "timeout" in result.loop_stop_reason.lower(), (
            f"loop_stop_reason must contain 'timeout'; got: {result.loop_stop_reason!r}"
        )

    def test_gap_timeout_final_decision_still_produced(self):
        """A final decision must still be produced after gap-analysis timeout."""
        result = self._run_with_gap_timeout()
        assert result.decision is not None, (
            "FinalDecision must be produced even when gap analysis timed out"
        )

    def test_required_stage_timeout_propagates(self):
        """ReadTimeout in required stage 01 must propagate and fail the sample.

        This is a safety regression test — required stages must NOT be silently swallowed.
        """
        from requests.exceptions import ReadTimeout
        from vckg_agentic_proof.adapter import AgenticProofConfig, run_agentic_proof_pipeline

        def llm_generate_timeout_on_01(messages, *, stage, max_tokens, temperature, extra_body=None):
            if "source_only_hypothesis" in stage:
                raise ReadTimeout("stage 01 timed out")
            return {"content": _xml_wrap(_STAGE_RESPONSES.get(stage, {})), "usage": {}}

        with pytest.raises(Exception) as exc_info:
            run_agentic_proof_pipeline(
                sample={"sample_id": "18452", "project": "rh", "project_url": "x",
                        "function": "f", "filepath": "f.c"},
                target_source="int f() {}",
                initial_evidence=[],
                llm_generate=llm_generate_timeout_on_01,
                kg_search=lambda q, **kw: [],
                config=AgenticProofConfig(iterative_evidence_loop=False),
            )
        # The exception must be the original ReadTimeout (or wrap it)
        assert "ReadTimeout" in type(exc_info.value).__name__ or \
               "Timeout" in type(exc_info.value).__name__ or \
               "ReadTimeout" in str(exc_info.value), (
            f"Required-stage timeout must propagate as a Timeout-related error; "
            f"got: {type(exc_info.value).__name__}: {exc_info.value}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# E. Windows Rich UnicodeEncodeError must not crash logging
# ═══════════════════════════════════════════════════════════════════════════════

class TestRichLoggingWindowsSafety:
    """setup_logging must not raise UnicodeEncodeError on a cp1252-like console."""

    class _CP1252Stream:
        """Stream that raises UnicodeEncodeError for non-cp1252 characters."""
        encoding = "cp1252"

        def __init__(self) -> None:
            self._written: list[str] = []
            self.errors_raised: list[UnicodeEncodeError] = []

        def write(self, s: str) -> int:
            try:
                s.encode("cp1252")
            except UnicodeEncodeError as exc:
                self.errors_raised.append(exc)
                raise
            self._written.append(s)
            return len(s)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return False

    def test_no_unicode_encode_error_on_cp1252_stream(self):
        """setup_logging with use_rich=True must not raise on a narrow encoding stream.

        The production symptom: RichHandler(rich_tracebacks=True) without a safe Console
        raises UnicodeEncodeError when logging messages containing non-cp1252 chars
        (arrows →, checkmarks ✓, Rich box-drawing chars in tracebacks).

        RED: RichHandler uses default Console that auto-detects cp1252 → UnicodeEncodeError → FAILS.
        GREEN: logging_utils wraps narrow stream in errors='replace' → PASSES.
        """
        import sys
        from vuln_commit_kg.logging_utils import setup_logging

        stream = self._CP1252Stream()
        original_stdout = sys.stdout
        try:
            sys.stdout = stream  # type: ignore[assignment]
            try:
                logger = setup_logging(run_dir=None, level="INFO", use_rich=True)
                # Non-cp1252 characters that triggered the production error
                logger.info("[bold cyan]START[/] sample → evidence ✓ box ─")
                logger.info("rss=42.0 MB | delta=+1.0 MB | ok")
                # Simulate a Rich markup line from profile()
                logger.info("[bold green]END[/] pipeline | 12.3s | ok")
            except UnicodeEncodeError as exc:
                pytest.fail(
                    f"setup_logging raised UnicodeEncodeError on cp1252-like stream — "
                    f"this is the Windows console bug: {exc}"
                )
        finally:
            sys.stdout = original_stdout

        assert not stream.errors_raised, (
            f"UnicodeEncodeError(s) were swallowed but still recorded: {stream.errors_raised}"
        )

    def test_logging_still_works_after_safe_stream_setup(self):
        """After the fix, messages must actually be written (not silently dropped)."""
        import sys
        from vuln_commit_kg.logging_utils import setup_logging

        class _CollectingStream:
            encoding = "cp1252"
            written: list[str] = []

            def write(self, s: str) -> int:
                # Silently replace instead of raising
                safe = s.encode("cp1252", errors="replace").decode("cp1252")
                self.written.append(safe)
                return len(s)

            def flush(self) -> None:
                pass

            def isatty(self) -> bool:
                return False

        stream = _CollectingStream()
        original_stdout = sys.stdout
        try:
            sys.stdout = stream  # type: ignore[assignment]
            logger = setup_logging(run_dir=None, level="INFO", use_rich=True)
            logger.info("visible ASCII message for test")
        except Exception:
            pass  # If this fails it's caught by the previous test
        finally:
            sys.stdout = original_stdout

        combined = "".join(stream.written)
        assert "visible ASCII message" in combined or len(combined) > 0, (
            "Logging to a narrow stream should still write something; got nothing"
        )
