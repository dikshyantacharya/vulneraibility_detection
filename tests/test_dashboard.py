"""Tests for the student_system_creator dashboard control-plane.

These build a tiny synthetic challenge folder in a tmp dir so they do not depend
on a real (large) built challenge.
"""

from __future__ import annotations

import json
import logging
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


def _write_pair_config(root: Path) -> Path:
    """A config 46-like base with validation-aware pair selection + AcademicCloud
    model extras, used to test that exact selection / model override neutralise it."""
    cfg = {
        "experiment": {"name": "curriculum_..._academiccloud_qwen397b_live"},
        "dataset": {
            "sample_selection": "smallest_vuln_fixed_pairs_by_project",
            "validation_aware_pair_selection": True,
            "validated_pair_limit": 1,
            "candidate_pair_limit": 20,
            "use_cached_pair_candidates": True,
            "validation_candidate_stream_until_valid_pairs": True,
        },
        "kg": {"backend": "auto"},
        "model": {
            "backend": "openai_compatible",
            "api_base": "https://chat-ai.academiccloud.de/v1",
            "model_name": "qwen3.5-397b-a17b",
            "max_tokens": 4096,
            "api_disable_thinking": True,
            "api_extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
            "model_fallbacks": ["qwen3.5-397b-a17b", "llama-3.3-70b-instruct"],
        },
    }
    p = root / "config46_like.yaml"
    p.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return p


def _run_research_argv(
    tmp_path: Path,
    kg: dict,
    llm: dict | None = None,
    selection: dict | None = None,
    base_cfg: Path | None = None,
):
    base_cfg = base_cfg or _write_base_config(tmp_path)
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    ctx = JobContext(tmp_path, "default_config", "default_challenge")
    params = {
        "config_path": str(base_cfg),
        "selection": selection or {"sample_ids": ["18452"]},
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


# --------------------------------------------------------------------------
# Issue 1: exact sample selection overrides validation-aware pair selection
# --------------------------------------------------------------------------


def test_exact_selection_selects_only_requested_sample(tmp_path: Path):
    base_cfg = _write_pair_config(tmp_path)
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus"},
        selection={"sample_ids": ["18452"], "exact_sample_ids_only": True, "include_pairs": False},
        base_cfg=base_cfg,
    )
    cfg = yaml.safe_load((job_dir / "effective_config.yaml").read_text(encoding="utf-8"))
    ds = cfg["dataset"]
    assert ds["only_sample_ids"] == ["18452"]
    assert ds["exact_sample_ids_only"] is True


def test_exact_selection_disables_pair_mechanisms(tmp_path: Path):
    base_cfg = _write_pair_config(tmp_path)
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus"},
        selection={"sample_ids": ["18452"], "exact_sample_ids_only": True},
        base_cfg=base_cfg,
    )
    ds = yaml.safe_load((job_dir / "effective_config.yaml").read_text(encoding="utf-8"))["dataset"]
    assert ds["validation_aware_pair_selection"] is False
    assert ds["sample_selection"] == "standard"
    assert ds["validated_pair_limit"] is None
    assert ds["candidate_pair_limit"] is None
    assert ds["use_cached_pair_candidates"] is False
    assert ds["validation_candidate_stream_until_valid_pairs"] is False


def test_include_pairs_keeps_pair_selection(tmp_path: Path):
    base_cfg = _write_pair_config(tmp_path)
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus"},
        selection={"sample_ids": ["18452"], "exact_sample_ids_only": True, "include_pairs": True},
        base_cfg=base_cfg,
    )
    ds = yaml.safe_load((job_dir / "effective_config.yaml").read_text(encoding="utf-8"))["dataset"]
    # Opt-in: pair selection is preserved from the base config.
    assert ds["validation_aware_pair_selection"] is True


def test_pipeline_exact_override_skips_pair_loading(monkeypatch):
    """The pipeline routes exact selection through select_samples, not pair loading."""
    from types import SimpleNamespace
    from vuln_commit_kg.orchestration import pipeline as pl

    captured = {"pair_called": False, "select_called": False}
    monkeypatch.setattr(pl, "load_samples", lambda *a, **k: [object()])
    monkeypatch.setattr(
        pl, "select_samples",
        lambda all_samples, ds, seed: captured.__setitem__("select_called", True) or all_samples,
    )

    ds = SimpleNamespace(
        path="x", mode="file",
        validation_aware_pair_selection=True,
        exact_sample_ids_only=True, only_sample_ids=["18452"],
    )
    pipe = SimpleNamespace(
        cfg=SimpleNamespace(dataset=ds, experiment=SimpleNamespace(seed=0)),
        logger=logging.getLogger("test"),
        _dashboard_load_repo_inventory=lambda: None,
        _load_validation_aware_pair_candidates=lambda all_samples: captured.__setitem__("pair_called", True) or all_samples,
    )
    result = pl.CommitKGPipeline._load_selected_samples(pipe)
    assert result  # non-empty
    assert captured["select_called"] is True
    assert captured["pair_called"] is False


# --------------------------------------------------------------------------
# Issue 2: AcademicCloud model override + payload + 400 capture
# --------------------------------------------------------------------------


def test_selected_model_overrides_config_and_no_qwen397b_leak(tmp_path: Path):
    base_cfg = _write_pair_config(tmp_path)
    job_dir, _ = _run_research_argv(
        tmp_path,
        kg={"preset": "joern_plus"},
        llm={"profile_id": "academiccloud", "model": "qwen3-coder-30b-a3b-instruct",
             "temperature": 0.0, "max_tokens": 2048},
        base_cfg=base_cfg,
    )
    cfg = yaml.safe_load((job_dir / "effective_config.yaml").read_text(encoding="utf-8"))
    mc = cfg["model"]
    assert mc["model_name"] == "qwen3-coder-30b-a3b-instruct"
    assert mc["model_fallbacks"] == ["qwen3-coder-30b-a3b-instruct"]
    assert mc["api_minimal_payload"] is True
    assert mc["api_extra_body"] == {}
    assert mc["api_disable_thinking"] is False
    assert mc["max_tokens"] == 2048
    assert "qwen397b" not in cfg["experiment"]["name"]
    # llm_profile_used.json records the effective model
    used = json.loads((job_dir / "llm_profile_used.json").read_text(encoding="utf-8"))
    assert used["effective_model_name"] == "qwen3-coder-30b-a3b-instruct"
    assert used["api_minimal_payload"] is True


def test_academiccloud_payload_minimal_keys_only():
    from vuln_commit_kg.config import ModelConfig
    from vuln_commit_kg.models.openai_compatible import build_chat_payload
    from student_system_creator.dashboard.jobs import _apply_llm_override

    cfg_dict: dict = {}
    _apply_llm_override(cfg_dict, "academiccloud", "qwen3-coder-30b-a3b-instruct")
    mcfg = ModelConfig.model_validate(cfg_dict["model"])
    payload = build_chat_payload(mcfg, "hi", system="sys")
    assert set(payload.keys()) <= {"model", "messages", "temperature", "top_p", "max_tokens", "stop"}
    assert "chat_template_kwargs" not in payload
    assert "response_format" not in payload
    assert payload["model"] == "qwen3-coder-30b-a3b-instruct"


def test_non_minimal_payload_includes_extras():
    from vuln_commit_kg.config import ModelConfig
    from vuln_commit_kg.models.openai_compatible import build_chat_payload

    mcfg = ModelConfig.model_validate({
        "backend": "openai_compatible",
        "model_name": "m",
        "request_json_object": True,
        "api_disable_thinking": True,
        "api_extra_body": {"foo": "bar"},
    })
    payload = build_chat_payload(mcfg, "hi")
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["foo"] == "bar"
    assert payload["chat_template_kwargs"]["enable_thinking"] is False


def test_http_400_body_captured_and_no_secret_logged(monkeypatch, caplog):
    from vuln_commit_kg.config import ModelConfig
    from vuln_commit_kg.models import openai_compatible as oc

    monkeypatch.setenv("ACADEMIC_CLOUD_API_KEY", "sk-super-secret-xyz")

    class _Resp:
        status_code = 400
        ok = False
        headers = {"content-type": "application/json"}
        text = '{"error":{"message":"model qwen3.5-397b-a17b does not exist"}}'

    monkeypatch.setattr(oc.requests, "post", lambda *a, **k: _Resp())

    mcfg = ModelConfig.model_validate({
        "backend": "openai_compatible",
        "api_base": "https://chat-ai.academiccloud.de/v1",
        "api_key_env": "ACADEMIC_CLOUD_API_KEY",
        "model_name": "qwen3.5-397b-a17b",
        "api_minimal_payload": True,
    })
    model = oc.OpenAICompatibleModel(mcfg)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(oc.requests.HTTPError) as exc:
            model.generate("hello")
    msg = str(exc.value)
    assert "does not exist" in msg  # provider message surfaced
    assert "400" in msg
    # No secret anywhere in the raised message or logs
    log_text = msg + " " + " ".join(r.getMessage() for r in caplog.records)
    assert "sk-super-secret-xyz" not in log_text
    assert "Authorization" not in log_text


# --------------------------------------------------------------------------
# WebSocket-first dashboard architecture (no REST polling by default)
# --------------------------------------------------------------------------


def test_ws_dashboard_sends_snapshot(client: TestClient):
    with client.websocket_connect("/ws/dashboard") as ws:
        snap = ws.receive_json()
    assert snap["type"] == "dashboard_snapshot"
    assert snap["health"]["ok"] is True
    assert "drive_free_bytes" in snap["disk"]
    assert isinstance(snap["jobs"], list)
    assert "polling_fallback" in snap


def test_wsmanager_translates_job_events():
    """A raw DashboardEvent fans out to dashboard sockets as job_created (first
    time) + job_event + job_updated. Unit-tested to avoid cross-thread timing."""
    from student_system_creator.dashboard.app import WSManager
    from student_system_creator.dashboard.events import DashboardEvent

    mgr = WSManager()
    sent: list = []
    mgr._dash_conns = [object()]
    mgr._send = lambda ws, payload: sent.append(payload)  # type: ignore

    class _Job:
        def to_dict(self):
            return {"job_id": "j1", "status": "running", "type": "research_agentic_audit"}

    mgr.job_lookup = lambda jid: _Job() if jid == "j1" else None

    mgr._broadcast_dashboard(DashboardEvent(type="status", job_id="j1", message="started"))
    types = [m["type"] for m in sent]
    assert types == ["job_created", "job_event", "job_updated"]
    assert sent[0]["job"]["job_id"] == "j1"
    assert sent[2]["status"] == "running"

    # A second event for the same job does NOT re-create it.
    sent.clear()
    mgr._broadcast_dashboard(DashboardEvent(type="progress", job_id="j1", data={"processed": 1}))
    types2 = [m["type"] for m in sent]
    assert "job_created" not in types2
    assert "job_event" in types2 and "job_updated" in types2
    assert sent[-1]["progress"] == {"processed": 1}


def test_wsmanager_disk_updates_are_throttled():
    from student_system_creator.dashboard.app import WSManager

    mgr = WSManager()
    sent: list = []

    class _FakeWS:
        pass

    # Stub the loop hop so _send just records payloads.
    mgr._dash_conns = [_FakeWS()]
    mgr._send = lambda ws, payload: sent.append(payload)  # type: ignore
    mgr.disk_provider = lambda: {"drive_free_bytes": 1}
    mgr.disk_min_interval = 60.0

    mgr.push_disk(force=False)   # first push allowed
    mgr.push_disk(force=False)   # throttled (within 60s)
    assert len(sent) == 1
    mgr.push_disk(force=True)    # explicit/manual refresh always pushes
    assert len(sent) == 2
    assert all(p["type"] == "disk_updated" for p in sent)


def test_quiet_access_log_predicate():
    from student_system_creator.dashboard.app import _access_log_should_emit

    # Suppress routine 200s on noisy paths
    assert _access_log_should_emit('127.0.0.1 - "GET /api/dashboard/health HTTP/1.1" 200') is False
    assert _access_log_should_emit('127.0.0.1 - "GET /api/dashboard/jobs HTTP/1.1" 200') is False
    assert _access_log_should_emit('127.0.0.1 - "GET /api/dashboard/disk HTTP/1.1" 200') is False
    # Never hide errors
    assert _access_log_should_emit('127.0.0.1 - "GET /api/dashboard/jobs HTTP/1.1" 500') is True
    # Always log unrelated paths
    assert _access_log_should_emit('127.0.0.1 - "POST /api/dashboard/jobs/x/cancel HTTP/1.1" 200') is True
    assert _access_log_should_emit('127.0.0.1 - "GET /api/research/runs HTTP/1.1" 200') is True


def test_frontend_topbar_has_no_polling_interval():
    # Guard against reintroducing continuous REST polling in the TopBar.
    root = Path(__file__).resolve().parents[1]
    topbar = (root / "frontend" / "src" / "components" / "TopBar.tsx").read_text(encoding="utf-8")
    assert "setInterval" not in topbar
    assert "useDashboard" in topbar


def test_frontend_kgqueryflow_defaults_to_codekg_tab():
    root = Path(__file__).resolve().parents[1]
    page = (root / "frontend" / "src" / "pages" / "KGQueryFlowPage.tsx").read_text(encoding="utf-8")
    assert 'useState<Tab>("codekg")' in page
    # The recommended CodeKG dashboard tab must be declared first.
    assert page.index('id: "codekg"') < page.index('id: "react"')


def test_log_parser_progress_fields():
    parsed = parse_line("student_challenge.progress | processed=277/1178 | ready=237 | eta=37m42s | rate=23.9/min")
    assert parsed["data"]["processed"] == 277
    assert parsed["data"]["total"] == 1178
    assert parsed["data"]["ready"] == 237
    assert parsed["data"]["eta_seconds"] == pytest.approx(2262.0)
    assert parsed["data"]["rate_per_minute"] == pytest.approx(23.9)
