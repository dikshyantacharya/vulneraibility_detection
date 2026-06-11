"""Tests for the research agentic-audit dashboard layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from student_system_creator.dashboard.app import create_app  # noqa: E402
from student_system_creator.dashboard.jobs import JobContext, _research_argv  # noqa: E402
from student_system_creator.dashboard.log_parser import parse_line  # noqa: E402
from student_system_creator.dashboard.settings import DashboardSettings  # noqa: E402


def _make_research_tree(root: Path) -> None:
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "46_demo.yaml").write_text(
        "experiment:\n  output_root: outputs/runs\n"
        "dataset:\n  path: data/x.arrow\n  sample_selection: standard\n"
        "model:\n  backend: openai_compatible\n  model_name: demo-model\n  api_key: SECRET123\n"
        "kg:\n  backend: auto\n  require_joern: true\n",
        encoding="utf-8",
    )
    # candidate cache
    cc = root / "cache" / "repo_inventory"
    cc.mkdir(parents=True)
    (cc / "pair_candidates_smallest_first.jsonl").write_text(
        json.dumps({
            "vulnerable_sample_id": "900", "fixed_sample_id": "901",
            "project": "demoproj", "func_name": "do_thing", "filepath": "x.c",
            "repo_key": "demoproj__abc", "usable_repo": True,
        }) + "\n",
        encoding="utf-8",
    )
    # a fake completed run
    sd = root / "outputs" / "runs" / "20260101_000000__demo" / "agent_demos" / "sample_900_do_thing"
    sd.mkdir(parents=True)
    (sd / "final_prediction.json").write_text(
        json.dumps({"sample_id": "900", "is_vulnerable": True, "confidence": 0.83,
                    "decision_status": "confident", "model_backend": "openai_compatible",
                    "raw_response": "It is vulnerable because...", "reasoning_summary": "bounds issue"}),
        encoding="utf-8",
    )
    (sd / "agent_trace.json").write_text(
        json.dumps({"sample_id": "900", "resolved_commit_id": "abc123",
                    "model_calls": [{"stage": "01_source_only_hypothesis", "prompt": "PROMPT TEXT",
                                     "response": "RESPONSE TEXT", "completion_tokens": 42}],
                    "kg_queries": [{"kind": "security_context", "reason": "check guards",
                                    "retrieved_node_count": 10, "retrieved_edge_count": 20,
                                    "params": {"depth": 3}}]}),
        encoding="utf-8",
    )
    (sd / "index.html").write_text("<!doctype html><html><body>KG dashboard</body></html>", encoding="utf-8")
    (root / "outputs" / "runs" / "20260101_000000__demo" / "metrics.json").write_text(
        json.dumps({"f1": 1.0, "accuracy": 1.0}), encoding="utf-8")


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    _make_research_tree(tmp_path)
    s = DashboardSettings()
    s.project_root = str(tmp_path)
    s.jobs_root = str(tmp_path / "outputs" / "dashboard" / "jobs")
    s.frontend_dist = str(tmp_path / "no_frontend")
    return TestClient(create_app(s, None))


def test_research_health(client: TestClient):
    r = client.get("/api/research/health").json()
    assert r["ok"] is True
    assert r["configs"] == 1
    assert r["runs"] == 1


def test_config_meta_redacts_secret(client: TestClient):
    m = client.get("/api/research/configs/46_demo.yaml").json()
    assert m["model_backend"] == "openai_compatible"
    assert m["kg_backend"] == "auto"
    assert "SECRET123" not in json.dumps(m)
    assert "***redacted***" in json.dumps(m["full"])


def test_candidates(client: TestClient):
    cands = client.get("/api/research/candidates").json()
    sids = {c["sample_id"] for c in cands}
    assert {"900", "901"} <= sids
    assert any(c["label"] == "vulnerable" for c in cands)


def test_runs_and_samples(client: TestClient):
    runs = client.get("/api/research/runs").json()
    assert len(runs) == 1
    rid = runs[0]["run_id"]
    samples = client.get(f"/api/research/runs/{rid}/samples").json()
    assert samples[0]["sample_id"] == "900"
    assert samples[0]["prediction"] == "vulnerable"


def test_trace_and_calls(client: TestClient):
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    trace = client.get(f"/api/research/runs/{rid}/samples/900/agent-trace").json()
    assert trace["resolved_commit_id"] == "abc123"
    calls = client.get(f"/api/research/runs/{rid}/samples/900/llm-calls").json()
    assert calls[0]["prompt"] == "PROMPT TEXT"
    assert calls[0]["response"] == "RESPONSE TEXT"
    queries = client.get(f"/api/research/runs/{rid}/samples/900/kg-queries").json()
    assert queries[0]["kind"] == "security_context"
    assert queries[0]["retrieved_node_count"] == 10


def test_static_dashboard_file(client: TestClient):
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    r = client.get(f"/api/research/dash/{rid}/900/index.html")
    assert r.status_code == 200
    assert "KG dashboard" in r.text


def test_static_dashboard_traversal_guarded(client: TestClient):
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    r = client.get(f"/api/research/dash/{rid}/900/../../../../metrics.json")
    assert r.status_code in (404, 400)


# --------------------------------------------------------------------------
# Old CodeKG static dashboard discovery + secure serving
# --------------------------------------------------------------------------

def _make_codekg_dashboard(tmp_path: Path, repo_key: str = "rockhopper__249d7d9b9217",
                           commit: str = "a971948ca5191e1c84335c646be5d5d554ca9a80") -> Path:
    gdir = tmp_path / "cache" / "kg" / repo_key / commit / "project_v6" / "85b3bd63b04c"
    dash = gdir / "dashboard"
    dash.mkdir(parents=True)
    (dash / "index.html").write_text("<html><body>CodeKG Explorer OLD</body></html>", encoding="utf-8")
    (dash / "graph_data.json").write_text(json.dumps({"graph": {"nodes": [], "edges": []}}), encoding="utf-8")
    return gdir


def _set_final_prediction_graph_dir(tmp_path: Path, gdir: Path) -> None:
    sd = tmp_path / "outputs" / "runs" / "20260101_000000__demo" / "agent_demos" / "sample_900_do_thing"
    fp = json.loads((sd / "final_prediction.json").read_text())
    fp["graph_dir"] = str(gdir)
    (sd / "final_prediction.json").write_text(json.dumps(fp), encoding="utf-8")


def test_kg_dashboard_found_from_graph_dir(client: TestClient, tmp_path: Path):
    gdir = _make_codekg_dashboard(tmp_path)
    _set_final_prediction_graph_dir(tmp_path, gdir)
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    assert info["exists"] is True
    assert info["iframe_url"]
    assert "dashboard" in info["dashboard_index"].replace("\\", "/")


def test_kg_dashboard_found_from_log(client: TestClient, tmp_path: Path):
    gdir = _make_codekg_dashboard(tmp_path, repo_key="logproj__deadbeef")
    run_dir = tmp_path / "outputs" / "runs" / "20260101_000000__demo"
    (run_dir / "run.log").write_text(
        f"2026-01-01 INFO Dashboard written: {gdir / 'dashboard' / 'index.html'}\n",
        encoding="utf-8",
    )
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    assert info["exists"] is True
    assert any("logproj__deadbeef" in c["dashboard_index"].replace("\\", "/") for c in info["candidates"])


def test_kg_dashboard_static_serves_index(client: TestClient, tmp_path: Path):
    gdir = _make_codekg_dashboard(tmp_path)
    _set_final_prediction_graph_dir(tmp_path, gdir)
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    r = client.get(info["iframe_url"])
    assert r.status_code == 200
    assert "CodeKG Explorer OLD" in r.text


def test_kg_dashboard_static_serves_graph_data(client: TestClient, tmp_path: Path):
    gdir = _make_codekg_dashboard(tmp_path)
    _set_final_prediction_graph_dir(tmp_path, gdir)
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    asset = info["iframe_url"].replace("index.html", "graph_data.json")
    r = client.get(asset)
    assert r.status_code == 200
    assert "graph" in r.text


def test_kg_dashboard_static_blocks_traversal(client: TestClient, tmp_path: Path):
    gdir = _make_codekg_dashboard(tmp_path)
    _set_final_prediction_graph_dir(tmp_path, gdir)
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    token = info["candidates"][0]["token"]
    # path traversal out of the dashboard dir must not serve metrics.json
    r = client.get(f"/api/research/kg-dashboard/{token}/../../../../../../metrics.json")
    assert r.status_code in (400, 404)


def test_kg_dashboard_token_outside_safe_root_blocked(client: TestClient, tmp_path: Path):
    import base64
    # A crafted token pointing at an arbitrary file outside safe roots is rejected.
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret", encoding="utf-8")
    token = base64.urlsafe_b64encode(str(secret.parent).encode()).decode().rstrip("=")
    r = client.get(f"/api/research/kg-dashboard/{token}/secret.txt")
    assert r.status_code in (400, 404)


def test_kg_dashboard_missing_reports_searched_paths(client: TestClient):
    rid = client.get("/api/research/runs").json()[0]["run_id"]
    info = client.get(f"/api/research/runs/{rid}/samples/900/kg-dashboard").json()
    assert info["exists"] is False
    assert "searched" in info and isinstance(info["searched"], list)


# --------------------------------------------------------------------------
# Run summary / live metrics / normalized sample / inventory (display layer)
# --------------------------------------------------------------------------

def _make_job_run(tmp_path: Path) -> tuple[str, str]:
    """A dashboard-job-style run with llm/kg artifacts + a FN sample (vuln→safe)."""
    job = tmp_path / "outputs" / "dashboard" / "jobs" / "20260610_144251_f081b8"
    run = job / "runs" / "20260610_164252__dashboard_audit_academiccloud"
    sd = run / "agent_demos" / "sample_18452_count_rows"
    sd.mkdir(parents=True)
    (job / "llm_profile_used.json").write_text(json.dumps({
        "profile_id": "academiccloud", "model": "qwen3-coder-30b-a3b-instruct",
        "effective_model_name": "qwen3-coder-30b-a3b-instruct",
        "api_base": "https://chat-ai.academiccloud.de/v1",
        "api_minimal_payload": True, "temperature": 0.0, "max_tokens": 2048,
    }), encoding="utf-8")
    (job / "kg_builder_used.json").write_text(json.dumps({
        "preset": "joern_plus", "display_name": "Joern plus / semantic overlay",
        "effective_backend": "joern", "reuse_cache": True, "force_rebuild": False,
    }), encoding="utf-8")
    (job / "selection.json").write_text(json.dumps({"sample_ids": ["18452"]}), encoding="utf-8")
    (job / "job.json").write_text(json.dumps({
        "job_id": "20260610_144251_f081b8", "status": "completed",
        "params": {"config_path": "configs/46_demo.yaml", "selection": {"sample_ids": ["18452"], "exact_sample_ids_only": True, "include_pairs": False}},
    }), encoding="utf-8")
    (run / "usage_summary.json").write_text(json.dumps({"total_tokens": 5000, "cost_total_usd": 0.02}), encoding="utf-8")
    (run / "metrics.json").write_text(json.dumps({
        "binary": {"n": 1, "tp": 0, "tn": 0, "fp": 0, "fn": 1, "accuracy": 0.0,
                   "precision": 0.0, "recall": 0.0, "f1": 0.0, "specificity": 0.0,
                   "rows": [{"sample_id": "18452", "true": True, "pred": False, "outcome": "FN", "confidence": 0.95, "decision_status": "fixed/non-vulnerable"}]},
        "prediction_correctness": {"per_sample_correctness": [{"sample_id": "18452", "project": "rockhopper", "function": "count_rows"}]},
    }), encoding="utf-8")
    (sd / "sample.json").write_text(json.dumps({
        "sample_id": "18452", "project": "rockhopper", "func_name": "count_rows",
        "filepath": "rockhopper/src/ragged_array.c", "is_vulnerable": True,
    }), encoding="utf-8")
    (sd / "final_prediction.json").write_text(json.dumps({
        "sample_id": "18452", "is_vulnerable": False, "confidence": 0.95,
        "decision_status": "fixed/non-vulnerable", "model_backend": "openai_compatible",
        "resolved_commit_id": "a971948ca5191e", "reasoning_summary": "All vulns refuted by guards.",
        "usage": {"total_tokens": 5000},
    }), encoding="utf-8")
    (sd / "agent_trace.json").write_text(json.dumps({
        "sample_id": "18452",
        "model_calls": [
            {"name": "01_source_only_hypothesis", "prompt": "P1", "response": "R1", "prompt_chars": 2, "usage": {"total_tokens": 100}, "elapsed_seconds": 1.0, "json_status": "ok"},
            {"name": "04_hypothesis_verification_json_repair", "prompt": "P2", "response": "bad json", "json_status": "repaired", "usage": {"total_tokens": 50}},
        ],
        "kg_queries": [{"query_type": "security_context", "query": {"target_function": "count_rows"}, "reason": "check guards", "items": [{"node": "n1"}]}],
    }), encoding="utf-8")
    return run.name, "18452"


def test_run_summary_shows_provider_and_model(client: TestClient, tmp_path: Path):
    run_id, _ = _make_job_run(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["llm"]["provider_name"] == "AcademicCloud"
    assert s["llm"]["model"] == "qwen3-coder-30b-a3b-instruct"
    assert s["kg"]["effective_backend"] == "joern"
    assert s["samples_completed"] == 1
    assert s["metrics"]["fn"] == 1


def test_live_metrics_admin_vs_student(client: TestClient, tmp_path: Path):
    run_id, _ = _make_job_run(tmp_path)
    admin = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert admin["available"] is True
    assert admin["fn"] == 1 and admin["tp"] == 0
    assert admin["single_sample"] is True
    assert admin["per_sample"][0]["correct"] is False
    student = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=student").json()
    assert student["available"] is False  # labels hidden in student mode


def test_normalized_sample_marks_incorrect(client: TestClient, tmp_path: Path):
    run_id, sid = _make_job_run(tmp_path)
    n = client.get(f"/api/research/runs/{run_id}/samples/{sid}/normalized?mode=admin").json()
    assert n["true_label"] == "vulnerable"
    assert n["prediction"] == "safe"
    assert n["correct"] is False
    assert n["confidence"] == 0.95
    assert n["llm"]["provider_name"] == "AcademicCloud"


def test_normalized_sample_hides_label_in_student_mode(client: TestClient, tmp_path: Path):
    run_id, sid = _make_job_run(tmp_path)
    n = client.get(f"/api/research/runs/{run_id}/samples/{sid}/normalized?mode=student").json()
    assert n["true_label"] is None
    assert n["correct"] is None
    assert n["prediction"] == "safe"  # prediction itself is not a private label


def test_sample_stages_parse_all_stages(client: TestClient, tmp_path: Path):
    run_id, sid = _make_job_run(tmp_path)
    stages = client.get(f"/api/research/runs/{run_id}/samples/{sid}/stages").json()
    assert len(stages) == 2
    assert stages[0]["stage"] == "01_source_only_hypothesis"
    assert stages[0]["prompt"] == "P1" and stages[0]["response"] == "R1"
    assert stages[1]["is_repair"] is True


def test_inventory_summary_separates_dataset_and_challenge(client: TestClient, tmp_path: Path):
    inv = client.get("/api/dashboard/inventory-summary?mode=admin").json()
    assert "dataset" in inv and "repos" in inv and "functions" in inv
    assert "challenge" in inv and "research" in inv
    # challenge inventory is its own object, not mixed into dataset counts
    assert isinstance(inv["challenge"], dict)


def test_job_file_viewer_allowlist_and_traversal(client: TestClient, tmp_path: Path):
    _make_job_run(tmp_path)
    jid = "20260610_144251_f081b8"
    ok = client.get(f"/api/dashboard/jobs/{jid}/file?name=llm_profile_used.json")
    assert ok.status_code == 200
    assert "academiccloud" in ok.json()["content"]
    bad = client.get(f"/api/dashboard/jobs/{jid}/file?name=../../../secret.txt")
    assert bad.status_code == 400


# --------------------------------------------------------------------------
# Failed / partial run recovery (no model_calls; placeholder prediction)
# --------------------------------------------------------------------------

def _make_failed_run(tmp_path: Path) -> tuple[str, str]:
    job = tmp_path / "outputs" / "dashboard" / "jobs" / "20260610_183451_774b43"
    run = job / "runs" / "20260610_203452__dashboard_audit_academiccloud_mistral"
    sd = run / "agent_demos" / "sample_18452_count_rows"
    sd.mkdir(parents=True)
    (job / "llm_profile_used.json").write_text(json.dumps({
        "profile_id": "academiccloud", "model": "mistral-large-3-675b-instruct-2512",
        "effective_model_name": "mistral-large-3-675b-instruct-2512",
        "api_base": "https://chat-ai.academiccloud.de/v1",
    }), encoding="utf-8")
    (job / "job.json").write_text(json.dumps({
        "job_id": "20260610_183451_774b43", "status": "failed",
        "params": {"selection": {"sample_ids": ["18452"], "exact_sample_ids_only": True}},
    }), encoding="utf-8")
    # Empty per-sample model_calls + placeholder final_prediction (failed run).
    (sd / "agent_trace.json").write_text(json.dumps({"sample_id": "18452", "model_calls": [], "kg_queries": []}), encoding="utf-8")
    (sd / "model_calls.jsonl").write_text("", encoding="utf-8")
    (sd / "kg_tool_calls.jsonl").write_text("", encoding="utf-8")
    (sd / "sample.json").write_text(json.dumps({"sample_id": "18452", "project": "rockhopper", "func_name": "count_rows", "is_vulnerable": True}), encoding="utf-8")
    (sd / "final_prediction.json").write_text(json.dumps({
        "sample_id": "18452", "is_vulnerable": False, "confidence": 0.0,
        "decision_status": "running", "model_backend": "openai_compatible",
    }), encoding="utf-8")
    # metrics with zero valid predictions
    (run / "metrics.json").write_text(json.dumps({"binary": {"n": 0, "valid_predictions": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0, "rows": []}}), encoding="utf-8")
    # run.log with partial stage events + kg_tools summary + Sample failed
    (run / "run.log").write_text(
        "20:34:56 | INFO | model.generate_start | sample=18452 | stage=01_source_only_hypothesis | attempt=primary | prompt_chars=3064\n"
        "20:36:04 | INFO | model.generate_done | sample=18452 | stage=01_source_only_hypothesis | attempt=primary | elapsed=68.0s | response_chars=6356 | completion_tokens=1535 | enable_thinking=False\n"
        "20:36:50 | INFO | agent.kg_tools | sample=18452 | round=agentic_proof | queries=8 | returned_items=256 | evidence_items=268\n"
        "20:36:50 | INFO | model.generate_start | sample=18452 | stage=04_hypothesis_verification | attempt=primary | prompt_chars=30097\n"
        "20:38:50 | ERROR | Sample failed: 18452 18452:rockhopper:rockhopper/src/ragged_array.c:count_rows:vulnerable\n",
        encoding="utf-8",
    )
    return run.name, "18452"


def test_failed_run_no_fake_safe_prediction(client: TestClient, tmp_path: Path):
    run_id, sid = _make_failed_run(tmp_path)
    n = client.get(f"/api/research/runs/{run_id}/samples/{sid}/trace-normalized?mode=admin").json()
    assert n["status"] == "failed"
    assert n["failed"] is True
    assert n["prediction_available"] is False
    assert n["prediction"] is None  # NOT "safe"
    assert n["confidence"] is None
    assert n["correct"] is None
    assert n["true_label"] == "vulnerable"


def test_failed_run_partial_stage_timeline_from_logs(client: TestClient, tmp_path: Path):
    run_id, sid = _make_failed_run(tmp_path)
    n = client.get(f"/api/research/runs/{run_id}/samples/{sid}/trace-normalized?mode=admin").json()
    stages = n["stages"]
    assert len(stages) >= 2  # not zero
    assert stages[0]["stage"] == "01_source_only_hypothesis"
    assert stages[0]["status"] == "completed"
    assert stages[0]["source"] == "log"
    assert stages[0]["tokens"]["completion"] == 1535
    # the started-but-not-done stage is the failure point
    assert n["failed_stage"] in ("04_hypothesis_verification", "01_source_only_hypothesis")
    assert n["kg_loaded"] in (True, False)


def test_failed_run_metrics_unavailable(client: TestClient, tmp_path: Path):
    run_id, _ = _make_failed_run(tmp_path)
    m = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert m["available"] is False
    assert "no completed predictions" in m["reason"]
    assert m["completed_predictions"] == 0
    assert m["failed_samples"] >= 1
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["metrics_available"] is False
    assert s["metrics_reason"] == "no completed predictions"


def test_failed_run_kg_query_summary_fallback(client: TestClient, tmp_path: Path):
    run_id, sid = _make_failed_run(tmp_path)
    qs = client.get(f"/api/research/runs/{run_id}/samples/{sid}/kg-queries").json()
    assert len(qs) == 1
    assert qs[0]["_summary_only"] is True
    assert qs[0]["queries"] == 8
    assert "unavailable" in qs[0]["reason"].lower()


def test_token_counts_not_redacted():
    from student_system_creator.dashboard.research import _mask_secrets
    obj = {"usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
           "max_tokens": 8000, "api_key": "sk-secret"}
    masked = _mask_secrets(obj)
    assert masked["usage"]["prompt_tokens"] == 100
    assert masked["usage"]["total_tokens"] == 300
    assert masked["max_tokens"] == 8000
    assert masked["api_key"] == "***redacted***"


def test_frontend_academiccloud_default_model_and_max_tokens():
    root = Path(__file__).resolve().parents[1]
    page = (root / "frontend" / "src" / "pages" / "ResearchRunPage.tsx").read_text(encoding="utf-8")
    assert "mistral-large-3-675b-instruct-2512" in page
    # Default changed from "8000" to maximum-mode with "32768" as manual override default
    assert 'useState("8000")' not in page
    assert 'useState("32768")' in page or 'llmMaxTokensMode' in page


# --------------------------------------------------------------------------
# Prompt context hygiene (stage 01 / 02) + system/user prompt visibility
# --------------------------------------------------------------------------

_FORBIDDEN_META = ["18452", "project_url", "github.com", "SAMPLE METADATA", "INITIAL EVIDENCE"]


def test_stage01_source_only_prompt_excludes_metadata_and_evidence():
    from vckg_agentic_proof.prompts import source_only_hypothesis_prompt
    sample = {"sample_id": "18452", "project": "rockhopper", "project_url": "https://github.com/x/rockhopper",
              "filepath": "rockhopper/src/secret_file.c", "function": "count_rows", "label": 1, "commit": "abc123"}
    msgs = source_only_hypothesis_prompt(sample, "int count_rows(void){ return 0; }")
    assert any(m["role"] == "system" for m in msgs)
    user = next(m["content"] for m in msgs if m["role"] == "user")
    for bad in _FORBIDDEN_META + ["secret_file.c", "abc123"]:
        assert bad not in user, bad
    assert "SCHEMA" in user
    assert "TARGET FUNCTION SOURCE" in user
    assert "count_rows" in user  # function name allowed for readability
    assert "plausible vulnerability hypotheses" in user


def test_stage02_kg_query_planning_prompt_excludes_evidence_and_metadata():
    from vckg_agentic_proof.prompts import kg_query_planning_prompt
    sample = {"sample_id": "18452", "project": "rockhopper", "project_url": "https://github.com/x/rockhopper",
              "filepath": "rockhopper/src/ragged_array.c", "function": "count_rows", "label": 1,
              "commit": "abc123", "resolved_commit": "def456"}
    hyps = [{"hypothesis_id": "HYP-01", "title": "potential oob read"}]
    msgs = kg_query_planning_prompt(sample, hyps, [{"id": "ev1", "text": "SECRET_EVIDENCE_BLOB"}])
    user = next(m["content"] for m in msgs if m["role"] == "user")
    for bad in _FORBIDDEN_META + ["SECRET_EVIDENCE_BLOB", "abc123", "def456"]:
        assert bad not in user, bad
    assert "CODEKG QUERY CONTRACT" in user
    assert "ANSWER JSON SCHEMA" in user
    assert "HYP-01" in user
    assert "count_rows" in user
    assert "ragged_array.c" in user  # optional target file is allowed


def test_stage_context_policy_declares_forbidden_for_01_and_02():
    from vckg_agentic_proof.prompts import STAGE_CONTEXT_POLICY
    assert "initial_evidence" in STAGE_CONTEXT_POLICY["01_source_only_hypothesis"]["forbidden"]
    assert "initial_evidence" in STAGE_CONTEXT_POLICY["02_kg_query_planning"]["forbidden"]
    assert "sample_id" in STAGE_CONTEXT_POLICY["02_kg_query_planning"]["forbidden"]


def _make_run_with_calls(tmp_path: Path, calls: list) -> tuple[str, str]:
    run = tmp_path / "outputs" / "runs" / "20260611_000000__prompt_demo"
    sd = run / "agent_demos" / "sample_18452_count_rows"
    sd.mkdir(parents=True)
    (sd / "sample.json").write_text(json.dumps({"sample_id": "18452", "project": "rockhopper", "func_name": "count_rows", "is_vulnerable": True}), encoding="utf-8")
    (sd / "final_prediction.json").write_text(json.dumps({"sample_id": "18452", "is_vulnerable": False, "confidence": 0.9, "decision_status": "fixed/non-vulnerable"}), encoding="utf-8")
    (sd / "agent_trace.json").write_text(json.dumps({"sample_id": "18452", "model_calls": calls, "kg_queries": []}), encoding="utf-8")
    return run.name, "18452"


def test_stages_expose_system_and_user_prompt_separately(client: TestClient, tmp_path: Path):
    run_id, sid = _make_run_with_calls(tmp_path, [{
        "name": "01_source_only_hypothesis",
        "messages": [{"role": "system", "content": "SYS HYP"}, {"role": "user", "content": "USER HYP"}],
        "system_prompt": "SYS HYP", "user_prompt": "USER HYP",
        "request_payload_keys": ["model", "messages", "temperature", "max_tokens"],
        "prompt": "USER HYP", "system": "SYS HYP", "response": "R",
    }])
    stages = client.get(f"/api/research/runs/{run_id}/samples/{sid}/stages").json()
    st = stages[0]
    assert st["system_prompt"] == "SYS HYP"
    assert st["user_prompt"] == "USER HYP"
    assert {m["role"] for m in st["messages"]} == {"system", "user"}
    assert st["legacy_prompt_only"] is False
    assert st["request_payload_keys"] == ["model", "messages", "temperature", "max_tokens"]


def test_stages_backward_compat_legacy_prompt_only(client: TestClient, tmp_path: Path):
    run_id, sid = _make_run_with_calls(tmp_path, [{
        "name": "01_source_only_hypothesis", "prompt": "LEGACY USER PROMPT", "response": "R",
    }])
    stages = client.get(f"/api/research/runs/{run_id}/samples/{sid}/stages").json()
    st = stages[0]
    assert st["legacy_prompt_only"] is True
    assert st["user_prompt"] == "LEGACY USER PROMPT"
    assert st["system_prompt"] in (None, "")
    # synthesized messages still contain the legacy prompt as a user message
    assert any(m["role"] == "user" and m["content"] == "LEGACY USER PROMPT" for m in st["messages"])


def test_prompt_artifacts_contain_no_api_keys(client: TestClient, tmp_path: Path):
    run_id, sid = _make_run_with_calls(tmp_path, [{
        "name": "01_source_only_hypothesis",
        "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}],
        "system_prompt": "sys", "user_prompt": "user", "prompt": "user", "response": "R",
    }])
    import json as _json
    blob = _json.dumps(client.get(f"/api/research/runs/{run_id}/samples/{sid}/stages").json())
    for bad in ("Authorization", "Bearer ", "api_key", "sk-"):
        assert bad not in blob


def test_frontend_agenttrace_has_prompt_tabs():
    root = Path(__file__).resolve().parents[1]
    page = (root / "frontend" / "src" / "pages" / "AgentTracePage.tsx").read_text(encoding="utf-8")
    for label in ("System Prompt", "User Prompt", "Full Messages", "Response", "Parsed JSON", "Error"):
        assert label in page
    assert "Legacy Prompt" in page  # backward-compat label


def test_research_job_selection_enforced(tmp_path: Path):
    _make_research_tree(tmp_path)
    import yaml

    ctx = JobContext(tmp_path, "x", "y")
    jd = tmp_path / "job1"
    jd.mkdir()
    argv = _research_argv(
        {"config_path": str(tmp_path / "configs" / "46_demo.yaml"),
         "selection": {"sample_ids": ["900"], "limit": 1},
         "kg": {"force_rebuild": True}},
        jd, ctx,
    )
    assert argv[0] == "run"
    eff = yaml.safe_load((jd / "effective_config.yaml").read_text())
    assert eff["dataset"]["only_sample_ids"] == ["900"]
    assert eff["dataset"]["sample_limit"] == 1
    assert eff["kg"]["force_rebuild"] is True
    sel = json.loads((jd / "selection.json").read_text())
    assert sel["sample_ids"] == ["900"]


@pytest.mark.parametrize(
    "line,etype",
    [
        ("23:07:44 | INFO    | model.generate_start | sample=18452 | stage=01_source_only_hypothesis | prompt_chars=3064", "llm_prompt"),
        ("23:07:45 | INFO    | model.generate_done | sample=18452 | stage=01_source_only_hypothesis | response_chars=7351 | completion_tokens=1763", "llm_response"),
        ("23:08:01 | INFO    | agent.kg_tools | sample=18452 | round=agentic_proof | queries=5 | returned_items=106", "kg_query"),
        ("23:07:40 | INFO    | sample.start | id=18452 | project=rockhopper | label=vulnerable", "sample_start"),
    ],
)
def test_research_log_parsing_with_prefix(line: str, etype: str):
    parsed = parse_line(line)
    assert parsed is not None, line
    assert parsed["type"] == etype


def test_research_log_parsing_fields():
    parsed = parse_line("23:07:45 | INFO | model.generate_done | sample=18452 | stage=02_kg_query_planning | completion_tokens=1204")
    assert parsed["data"]["sample"] == 18452
    assert parsed["data"]["stage"] == "02_kg_query_planning"
    assert parsed["data"]["completion_tokens"] == 1204


def test_select_samples_filter():
    from vuln_commit_kg.config import DatasetConfig
    from vuln_commit_kg.data.sample_selector import select_samples
    from vuln_commit_kg.data.schema import SecVulEvalSample as S

    rows = [S(idx=i, sample_id=str(10 + i), project="p", project_url="u", filepath="f.c",
              func_name=("a" if i % 2 else "b"), func_body="x", commit_id="c", is_vulnerable=bool(i % 2))
            for i in range(6)]
    cfg = DatasetConfig(sample_limit=None, sample_selection="standard", require_project_url=False)
    cfg.only_sample_ids = ["11", "13"]
    assert {s.sample_id for s in select_samples(rows, cfg)} == {"11", "13"}
