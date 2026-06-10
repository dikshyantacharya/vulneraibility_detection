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
