"""Tests for the student_system_creator dashboard control-plane.

These build a tiny synthetic challenge folder in a tmp dir so they do not depend
on a real (large) built challenge.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import yaml  # noqa: E402

from student_system_creator.dashboard.app import create_app  # noqa: E402
from student_system_creator.dashboard.inventory import ChallengeInventory  # noqa: E402
from student_system_creator.dashboard.jobs import JobContext, _research_argv  # noqa: E402
from student_system_creator.dashboard.kg_presets import (  # noqa: E402
    ALLOWED_BACKEND_VALUES,
    kg_overrides_for,
    preset_options,
)
from student_system_creator.dashboard.log_parser import parse_line  # noqa: E402
from student_system_creator.dashboard.settings import DashboardSettings  # noqa: E402


def _make_challenge(root: Path) -> Path:
    """Create a minimal but realistic challenge folder."""
    challenge = root / "outputs" / "student_challenge" / "demo"
    private = challenge / "private"
    public = challenge / "public"
    private.mkdir(parents=True)
    public.mkdir(parents=True)
    # Anonymized kg ids (no vuln/safe tokens) -> leakage check must pass.
    registry = {
        "schema": "v1",
        "entries": {
            "kg_aaaa1111": {
                "knowledge_graph_id": "kg_aaaa1111",
                "sample_id": "101",
                "project": "demo",
                "filepath": "a.c",
                "function_name": "foo",
                "split": "train",
                "label": 1,
                "repo_key": "demo__abc",
                "graph_dir": "kg_store/kg_aaaa1111",
                "resolved_commit": "deadbeef0000",
            },
            "kg_bbbb2222": {
                "knowledge_graph_id": "kg_bbbb2222",
                "sample_id": "102",
                "project": "demo",
                "filepath": "b.c",
                "function_name": "bar",
                "split": "test",
                "label": 0,
                "repo_key": "demo__abc",
                "graph_dir": "kg_store/kg_bbbb2222",
                "resolved_commit": "feedface1111",
            },
        },
    }
    (private / "kg_registry_private.json").write_text(json.dumps(registry), encoding="utf-8")
    (private / "validation_report.json").write_text(
        json.dumps({"ok": True, "checked_rows": 2, "errors": [], "warnings": [],
                    "registry_entries": 2, "train_rows": 1, "test_rows": 1}),
        encoding="utf-8",
    )
    # one graph.json so the explorer endpoint can return a subgraph
    gdir = private / "kg_store" / "kg_aaaa1111"
    gdir.mkdir(parents=True)
    (gdir / "graph.json").write_text(
        json.dumps({
            "nodes": [
                {"id": "n1", "type": "Function", "name": "foo", "degree": 3},
                {"id": "n2", "type": "Variable", "name": "x", "degree": 1},
            ],
            "edges": [{"source": "n1", "target": "n2", "type": "USES"}],
        }),
        encoding="utf-8",
    )
    return challenge


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    challenge = _make_challenge(tmp_path)
    s = DashboardSettings()
    s.project_root = str(tmp_path)
    s.challenge_root = str(challenge)
    s.outputs_root = str(tmp_path / "outputs" / "student_challenge")
    s.jobs_root = str(tmp_path / "outputs" / "dashboard" / "jobs")
    s.frontend_dist = str(tmp_path / "no_frontend")  # force fallback HTML
    return TestClient(create_app(s, None))


def test_health(client: TestClient):
    r = client.get("/api/dashboard/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_status_has_counts(client: TestClient):
    data = client.get("/api/dashboard/status?mode=admin").json()
    assert data["challenge_exists"] is True
    assert data["projects"] == 1
    assert data["functions"] == 2
    assert data["label_balance"] == {"1": 1, "0": 1}


def test_projects_and_functions(client: TestClient):
    projects = client.get("/api/dashboard/projects?mode=admin").json()
    assert len(projects) == 1
    assert projects[0]["function_count"] == 2
    funcs = client.get("/api/dashboard/functions?mode=admin").json()
    assert {f["function_name"] for f in funcs} == {"foo", "bar"}


def test_student_mode_hides_labels(client: TestClient):
    admin = client.get("/api/dashboard/functions?mode=admin").json()
    student = client.get("/api/dashboard/functions?mode=student").json()
    assert all("label" in f for f in admin)
    assert all("label" not in f for f in student)


def test_no_public_id_leakage(client: TestClient):
    r = client.get("/api/dashboard/leakage").json()
    assert r["ok"] is True
    assert r["flagged"] == []


def test_leakage_flags_bad_ids(tmp_path: Path):
    challenge = _make_challenge(tmp_path)
    reg = challenge / "private" / "kg_registry_private.json"
    data = json.loads(reg.read_text())
    data["entries"]["kg_vuln_leak"] = {"project": "demo", "function_name": "z", "split": "test"}
    reg.write_text(json.dumps(data), encoding="utf-8")
    inv = ChallengeInventory(challenge)
    check = inv.leakage_check()
    assert check["ok"] is False
    assert any("vuln" in f["tokens"] for f in check["flagged"])


def test_kg_graph_endpoint(client: TestClient):
    g = client.get("/api/dashboard/kgs/kg_aaaa1111/graph?limit=10").json()
    assert g["node_count"] == 2
    assert g["edge_count"] == 1
    assert "Function" in g["node_type_distribution"]


def test_validation_report_loads(client: TestClient):
    r = client.get("/api/dashboard/reports/validation").json()
    assert r["ok"] is True
    assert r["checked_rows"] == 2


def test_create_mock_job_writes_events(client: TestClient):
    job = client.post("/api/dashboard/jobs", json={"type": "inspect_inventory"}).json()
    jid = job["job_id"]
    # wait for the in-process job to finish
    for _ in range(50):
        st = client.get(f"/api/dashboard/jobs/{jid}").json()["status"]
        if st in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert st == "completed"
    events = client.get(f"/api/dashboard/jobs/{jid}/events").json()
    assert len(events) >= 1
    assert all("type" in e and "timestamp" in e for e in events)


def test_unknown_job_type_rejected(client: TestClient):
    r = client.post("/api/dashboard/jobs", json={"type": "nope"})
    assert r.status_code == 400


def test_anonymized_kg_id_accepted(client: TestClient):
    r = client.get("/api/dashboard/kgs/kg_aaaa1111?mode=student").json()
    assert r["function_name"] == "foo"
    assert "label" not in r  # student mode


def test_missing_frontend_serves_fallback(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    assert "Dashboard backend is running" in r.text


@pytest.mark.parametrize(
    "line,expected_type",
    [
        ("student_challenge.progress | processed=5/10 | ready=4 | skipped=1 | failed=0", "progress"),
        ("eval.query.done | sample=1 | kind=evidence_slice | nodes=3 | edges=2 | time=0.1", "agent_query"),
        ("challenge.kg_ready | sample=1 | project=demo | label=1", "kg_ready"),
    ],
)
def test_log_parser(line: str, expected_type: str):
    parsed = parse_line(line)
    assert parsed is not None
    assert parsed["type"] == expected_type


# --------------------------------------------------------------------------
# KG backend preset mapping (the joern_plus -> joern fix)
# --------------------------------------------------------------------------

pytest.importorskip("vuln_commit_kg.config")


def _write_base_config(root: Path) -> Path:
    """A minimal but schema-valid AppConfig YAML used as the research base."""
    cfg = {
        "experiment": {"name": "test_research"},
        "model": {"backend": "mock"},
        "kg": {"backend": "auto"},
    }
    p = root / "base_config.yaml"
    p.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return p


def _run_research_argv(tmp_path: Path, kg: dict, llm: dict | None = None):
    base_cfg = _write_base_config(tmp_path)
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    ctx = JobContext(tmp_path, "default_config", "default_challenge")
    params = {
        "config_path": str(base_cfg),
        "selection": {"sample_ids": ["18452"]},
        "kg": kg,
    }
    if llm:
        params["llm"] = llm
    argv = _research_argv(params, job_dir, ctx)
    return job_dir, argv


def test_all_preset_backends_are_allowed():
    opts = preset_options()
    assert set(opts["allowed_backend_values"]) == set(ALLOWED_BACKEND_VALUES)
    for o in opts["options"]:
        assert o["effective_backend"] in ALLOWED_BACKEND_VALUES


def test_kg_overrides_for_maps_joern_plus():
    ov = kg_overrides_for("joern_plus")
    assert ov["backend"] == "joern"
    assert ov["semantic_enrichment_enabled"] is True


def test_kg_overrides_for_aliases():
    assert kg_overrides_for("simple_heuristic")["backend"] == "heuristic"
    assert kg_overrides_for("syntax")["backend"] == "tree_sitter"


def test_kg_overrides_for_rejects_unknown():
    with pytest.raises(ValueError) as exc:
        kg_overrides_for("not_a_backend")
    assert "Allowed backend values" in str(exc.value)


def test_joern_plus_never_writes_invalid_backend(tmp_path: Path):
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus", "backend": "joern", "reuse_cache": True, "force_rebuild": False},
    )
    text = (job_dir / "effective_config.yaml").read_text(encoding="utf-8")
    assert "backend: joern_plus" not in text
    cfg = yaml.safe_load(text)
    assert cfg["kg"]["backend"] == "joern"
    assert cfg["kg"]["backend"] in ALLOWED_BACKEND_VALUES
    assert cfg["kg"]["semantic_enrichment_enabled"] is True


def test_effective_config_passes_appconfig_validation(tmp_path: Path):
    # _research_argv validates internally; an invalid config would have raised.
    job_dir, _ = _run_research_argv(tmp_path, kg={"preset": "joern_plus"})
    from vuln_commit_kg.config import load_config

    cfg = load_config(job_dir / "effective_config.yaml")
    assert cfg.kg.backend == "joern"


def test_kg_builder_used_records_preset_and_effective_backend(tmp_path: Path):
    job_dir, _ = _run_research_argv(
        tmp_path, kg={"preset": "joern_plus", "reuse_cache": True}
    )
    used = json.loads((job_dir / "kg_builder_used.json").read_text(encoding="utf-8"))
    assert used["preset"] == "joern_plus"
    assert used["effective_backend"] == "joern"
    assert used["display_name"] == "Joern plus / semantic overlay"
    assert used["semantic_enrichment_enabled"] is True


def test_research_argv_rejects_unsupported_backend(tmp_path: Path):
    with pytest.raises(ValueError):
        _run_research_argv(tmp_path, kg={"preset": "joern_plus_DOES_NOT_EXIST"})


def test_tu_berlin_ollama_config_is_openai_compatible(tmp_path: Path):
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus"},
        llm={"profile_id": "tu_berlin_ollama", "model": "qwen3-coder:30b"},
    )
    cfg = yaml.safe_load((job_dir / "effective_config.yaml").read_text(encoding="utf-8"))
    assert cfg["model"]["backend"] == "openai_compatible"
    assert cfg["model"]["model_name"] == "qwen3-coder:30b"
    assert "gpu1.mlsec.de" in cfg["model"]["api_base"]


def test_kg_backends_endpoint(client: TestClient):
    r = client.get("/api/kg/backends")
    assert r.status_code == 200
    data = r.json()
    jp = next(o for o in data["options"] if o["id"] == "joern_plus")
    assert jp["effective_backend"] == "joern"
    assert "joern_plus" not in data["allowed_backend_values"]


def test_log_parser_progress_fields():
    parsed = parse_line("student_challenge.progress | processed=277/1178 | ready=237 | eta=37m42s | rate=23.9/min")
    assert parsed["data"]["processed"] == 277
    assert parsed["data"]["total"] == 1178
    assert parsed["data"]["ready"] == 237
    assert parsed["data"]["eta_seconds"] == pytest.approx(2262.0)
    assert parsed["data"]["rate_per_minute"] == pytest.approx(23.9)
