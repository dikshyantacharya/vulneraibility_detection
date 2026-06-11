"""RED tests for research run metrics computation.

Covers: live metric fallback when metrics.json absent/stale, TP/FP/TN/FN
computation, inconclusive separation, zero-denominator safety, enriched
sample rows (true_label/result/error_type), and no-secrets guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from student_system_creator.dashboard.app import create_app  # noqa: E402
from student_system_creator.dashboard.settings import DashboardSettings  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(tmp_path: Path) -> TestClient:
    s = DashboardSettings()
    s.project_root = str(tmp_path)
    s.jobs_root = str(tmp_path / "outputs" / "dashboard" / "jobs")
    s.frontend_dist = str(tmp_path / "no_frontend")
    return TestClient(create_app(s, None))


def _make_sample_dir(run_dir: Path, sample_id: str, func: str, *,
                     is_vulnerable_true: bool | None,
                     is_vulnerable_pred: bool | None,
                     decision_status: str = "confident",
                     confidence: float = 0.8,
                     parse_error: str | None = None) -> Path:
    """Create a minimal agent_demos/sample_X_Y directory."""
    sd = run_dir / "agent_demos" / f"sample_{sample_id}_{func}"
    sd.mkdir(parents=True)
    if is_vulnerable_true is not None:
        (sd / "sample.json").write_text(json.dumps({
            "sample_id": sample_id,
            "project": "testproj",
            "func_name": func,
            "filepath": f"src/{func}.c",
            "is_vulnerable": is_vulnerable_true,
            "commit_message": "fix: patch CVE-9999",
        }), encoding="utf-8")
    fp: dict[str, Any] = {
        "sample_id": sample_id,
        "decision_status": decision_status,
        "confidence": confidence,
        "model_backend": "openai_compatible",
    }
    if is_vulnerable_pred is not None:
        fp["is_vulnerable"] = is_vulnerable_pred
    if parse_error:
        fp["parse_error"] = parse_error
    (sd / "final_prediction.json").write_text(json.dumps(fp), encoding="utf-8")
    return sd


def _run_dir(tmp_path: Path, run_id: str) -> Path:
    rd = tmp_path / "outputs" / "runs" / run_id
    rd.mkdir(parents=True)
    return rd


# ---------------------------------------------------------------------------
# Fixtures — four canonical cases
# ---------------------------------------------------------------------------

@pytest.fixture()
def run_no_metrics_json(tmp_path: Path):
    """Two samples, no metrics.json — the exact broken case from the bug report.

    sample 1: true=vulnerable, pred=safe, status=inconclusive  (FN if definitive)
    sample 2: true=safe,       pred=safe, status=inconclusive  (TN if definitive)

    Because both are inconclusive the binary metrics should report 0 definitive
    predictions and all precision/recall/F1 should be null — but metrics_available
    MUST be True and the reason must NOT be "no completed predictions".
    """
    rd = _run_dir(tmp_path, "20260611_test_no_metrics")
    _make_sample_dir(rd, "18452", "count_rows",
                     is_vulnerable_true=True, is_vulnerable_pred=False,
                     decision_status="inconclusive", confidence=0.6)
    _make_sample_dir(rd, "18453", "count_rows",
                     is_vulnerable_true=False, is_vulnerable_pred=False,
                     decision_status="inconclusive", confidence=0.6)
    # Deliberately NO metrics.json written
    return tmp_path, rd.name


@pytest.fixture()
def run_two_definitive(tmp_path: Path):
    """Two samples with definitive predictions, no metrics.json.

    sample 1: true=vulnerable, pred=vulnerable → TP
    sample 2: true=safe,       pred=safe       → TN
    """
    rd = _run_dir(tmp_path, "20260611_test_definitive")
    _make_sample_dir(rd, "10", "func_a",
                     is_vulnerable_true=True, is_vulnerable_pred=True,
                     decision_status="vulnerable", confidence=0.9)
    _make_sample_dir(rd, "11", "func_b",
                     is_vulnerable_true=False, is_vulnerable_pred=False,
                     decision_status="safe/non-vulnerable", confidence=0.85)
    return tmp_path, rd.name


@pytest.fixture()
def run_fn_fp(tmp_path: Path):
    """Four samples to test FN and FP, no metrics.json.

    sample 20: true=vuln,  pred=vuln  → TP
    sample 21: true=vuln,  pred=safe  → FN
    sample 22: true=safe,  pred=vuln  → FP
    sample 23: true=safe,  pred=safe  → TN
    """
    rd = _run_dir(tmp_path, "20260611_test_fn_fp")
    _make_sample_dir(rd, "20", "f0", is_vulnerable_true=True,  is_vulnerable_pred=True,
                     decision_status="vulnerable", confidence=0.9)
    _make_sample_dir(rd, "21", "f1", is_vulnerable_true=True,  is_vulnerable_pred=False,
                     decision_status="safe", confidence=0.7)
    _make_sample_dir(rd, "22", "f2", is_vulnerable_true=False, is_vulnerable_pred=True,
                     decision_status="vulnerable", confidence=0.65)
    _make_sample_dir(rd, "23", "f3", is_vulnerable_true=False, is_vulnerable_pred=False,
                     decision_status="safe", confidence=0.8)
    return tmp_path, rd.name


@pytest.fixture()
def run_no_sample_json(tmp_path: Path):
    """Samples that have predictions but no sample.json (no true labels)."""
    rd = _run_dir(tmp_path, "20260611_test_no_labels")
    _make_sample_dir(rd, "30", "g0",
                     is_vulnerable_true=None, is_vulnerable_pred=False,
                     decision_status="safe", confidence=0.7)
    return tmp_path, rd.name


# ---------------------------------------------------------------------------
# Backend tests — run_summary endpoint
# ---------------------------------------------------------------------------

def test_metrics_available_when_no_metrics_json(run_no_metrics_json):
    """metrics_available must be True when sample predictions exist even with no metrics.json."""
    tmp_path, run_id = run_no_metrics_json
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["samples_completed"] == 2, "should count 2 completed predictions"
    assert s["metrics_available"] is True, (
        f"metrics_available should be True but got {s.get('metrics_available')!r}; "
        f"reason={s.get('metrics_reason')!r}"
    )


def test_metrics_reason_not_no_completed_predictions(run_no_metrics_json):
    """The old generic 'no completed predictions' message must not appear when predictions exist."""
    tmp_path, run_id = run_no_metrics_json
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    reason = s.get("metrics_reason") or ""
    assert "no completed predictions" not in reason.lower(), (
        f"Should not say 'no completed predictions' when predictions exist. Got: {reason!r}"
    )


def test_all_inconclusive_shows_zero_counts(run_no_metrics_json):
    """All-inconclusive run: TP/FP/TN/FN=0, inconclusive count=2."""
    tmp_path, run_id = run_no_metrics_json
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    m = s["metrics"]
    assert m is not None
    assert m.get("inconclusive", 0) == 2
    assert m.get("tp", -1) == 0
    assert m.get("fp", -1) == 0
    assert m.get("tn", -1) == 0
    assert m.get("fn", -1) == 0


def test_all_inconclusive_null_precision_recall_f1(run_no_metrics_json):
    """Precision/recall/F1/accuracy must be null (not crash) when all predictions inconclusive."""
    tmp_path, run_id = run_no_metrics_json
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    m = s["metrics"]
    assert m is not None
    assert m.get("precision") is None, f"precision should be null, got {m.get('precision')}"
    assert m.get("recall") is None, f"recall should be null, got {m.get('recall')}"
    assert m.get("f1") is None, f"f1 should be null, got {m.get('f1')}"


def test_tp_tn_correct_two_definitive(run_two_definitive):
    """TP=1, TN=1, FP=0, FN=0 for one TP + one TN run."""
    tmp_path, run_id = run_two_definitive
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["metrics_available"] is True
    m = s["metrics"]
    assert m["tp"] == 1
    assert m["tn"] == 1
    assert m["fp"] == 0
    assert m["fn"] == 0
    assert m.get("accuracy") == pytest.approx(1.0)
    assert m.get("recall") == pytest.approx(1.0)


def test_fn_fp_counts_correct(run_fn_fp):
    """TP=1, FN=1, FP=1, TN=1 for the 4-sample fixture."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["metrics_available"] is True
    m = s["metrics"]
    assert m["tp"] == 1
    assert m["fn"] == 1
    assert m["fp"] == 1
    assert m["tn"] == 1
    assert m.get("accuracy") == pytest.approx(0.5)


def test_missing_true_labels_reports_diagnostic(run_no_sample_json):
    """When sample.json is absent (no true labels) metrics should show available=False with a clear diagnostic."""
    tmp_path, run_id = run_no_sample_json
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    # Either metrics_available=False with a specific diagnostic, or metrics shows 0 definitive
    if not s.get("metrics_available"):
        reason = (s.get("metrics_reason") or "").lower()
        # Must not say "no completed predictions" — that's the wrong reason
        assert "no completed predictions" not in reason, f"Got generic reason: {reason!r}"
    else:
        # If available, samples without labels should be excluded, not crash
        m = s["metrics"]
        assert m is not None


def test_metrics_student_mode_hidden(run_two_definitive):
    """Metrics must be hidden in student mode (labels not available)."""
    tmp_path, run_id = run_two_definitive
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=student").json()
    assert s["metrics_available"] is False
    assert s.get("metrics") is None


# ---------------------------------------------------------------------------
# Backend tests — list_samples endpoint (enriched fields)
# ---------------------------------------------------------------------------

def test_list_samples_includes_true_label_admin(run_fn_fp):
    """list_samples in admin mode should include true_label per sample."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    samples = client.get(f"/api/research/runs/{run_id}/samples?mode=admin").json()
    has_true_label = any(s.get("true_label") is not None for s in samples)
    assert has_true_label, f"No true_label in any sample: {[s.get('true_label') for s in samples]}"


def test_list_samples_includes_result_and_error_type(run_fn_fp):
    """list_samples admin should return result (tp/fp/tn/fn/inconclusive) and error_type per sample."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    samples = client.get(f"/api/research/runs/{run_id}/samples?mode=admin").json()
    by_id = {str(s["sample_id"]): s for s in samples}
    # sample 20: TP
    s20 = by_id.get("20", {})
    assert s20.get("result") == "correct", f"sample 20 expected correct, got {s20.get('result')!r}"
    assert s20.get("error_type") == "tp", f"sample 20 expected tp, got {s20.get('error_type')!r}"
    # sample 21: FN
    s21 = by_id.get("21", {})
    assert s21.get("result") == "incorrect", f"sample 21 expected incorrect"
    assert s21.get("error_type") == "fn", f"sample 21 expected fn"
    # sample 22: FP
    s22 = by_id.get("22", {})
    assert s22.get("result") == "incorrect", f"sample 22 expected incorrect"
    assert s22.get("error_type") == "fp", f"sample 22 expected fp"
    # sample 23: TN
    s23 = by_id.get("23", {})
    assert s23.get("result") == "correct", f"sample 23 expected correct"
    assert s23.get("error_type") == "tn", f"sample 23 expected tn"


def test_list_samples_inconclusive_result(run_no_metrics_json):
    """Inconclusive samples should have result='inconclusive' and error_type=None."""
    tmp_path, run_id = run_no_metrics_json
    client = _make_client(tmp_path)
    samples = client.get(f"/api/research/runs/{run_id}/samples?mode=admin").json()
    for sm in samples:
        assert sm.get("result") == "inconclusive", (
            f"sample {sm['sample_id']} should be inconclusive, got {sm.get('result')!r}"
        )
        assert sm.get("error_type") is None, (
            f"inconclusive sample should have null error_type, got {sm.get('error_type')!r}"
        )


def test_list_samples_true_label_hidden_student(run_fn_fp):
    """true_label must not be returned in student mode."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    samples = client.get(f"/api/research/runs/{run_id}/samples?mode=student").json()
    for sm in samples:
        assert sm.get("true_label") is None, (
            f"true_label must be hidden in student mode for sample {sm['sample_id']}"
        )


# ---------------------------------------------------------------------------
# Backend tests — run_live_metrics endpoint
# ---------------------------------------------------------------------------

def test_live_metrics_available_no_metrics_json(run_fn_fp):
    """metrics-live endpoint must return available=True when samples have predictions but no metrics.json."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    m = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert m["available"] is True, f"live metrics should be available, got reason={m.get('reason')!r}"
    assert m.get("tp") == 1
    assert m.get("fn") == 1
    assert m.get("fp") == 1
    assert m.get("tn") == 1


def test_live_metrics_per_sample_has_enriched_fields(run_fn_fp):
    """per_sample in metrics-live should include true_label, prediction, result, error_type."""
    tmp_path, run_id = run_fn_fp
    client = _make_client(tmp_path)
    m = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert m["available"] is True
    per = {str(s["sample_id"]): s for s in (m.get("per_sample") or [])}
    # Sample 21 is FN
    assert per.get("21", {}).get("true_label") == "vulnerable"
    assert per.get("21", {}).get("prediction") in ("safe", "safe/non-vulnerable")
    assert per.get("21", {}).get("outcome") == "FN"


# ---------------------------------------------------------------------------
# Security test — no secrets in metrics response
# ---------------------------------------------------------------------------

def test_no_secrets_in_metrics_response(run_fn_fp):
    """Metrics response must not expose api_key, authorization, password, or raw env values."""
    tmp_path, run_id = run_fn_fp
    # Write a fake config with a secret to ensure it's never leaked
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "test.yaml").write_text(
        "model:\n  api_key: SUPERSECRET_KEY_12345\n  model_name: test\n",
        encoding="utf-8",
    )
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    body = json.dumps(s)
    assert "SUPERSECRET_KEY_12345" not in body
    m_resp = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert "SUPERSECRET_KEY_12345" not in json.dumps(m_resp)


# ---------------------------------------------------------------------------
# Forced-binary prediction metrics
# ---------------------------------------------------------------------------

def _make_forced_sample_dir(run_dir: Path, sample_id: str, func: str, *,
                             is_vulnerable_true: bool,
                             is_vulnerable_pred: bool,
                             forced_prediction: str,
                             forced_prediction_bool: bool,
                             decision_status: str,
                             confidence: float = 0.45) -> Path:
    """Create a sample dir with both is_vulnerable (inconclusive) and forced_prediction_bool."""
    sd = run_dir / "agent_demos" / f"sample_{sample_id}_{func}"
    sd.mkdir(parents=True)
    (sd / "sample.json").write_text(json.dumps({
        "sample_id": sample_id, "project": "testproj", "func_name": func,
        "filepath": f"src/{func}.c", "is_vulnerable": is_vulnerable_true,
    }), encoding="utf-8")
    (sd / "final_prediction.json").write_text(json.dumps({
        "sample_id": sample_id,
        "decision_status": decision_status,
        "is_vulnerable": is_vulnerable_pred,
        "forced_prediction": forced_prediction,
        "forced_prediction_bool": forced_prediction_bool,
        "confidence": confidence,
        "model_backend": "openai_compatible",
    }), encoding="utf-8")
    return sd


@pytest.fixture()
def run_forced_binary(tmp_path: Path):
    """Two inconclusive samples with forced binary predictions.

    sample 40: true=vulnerable, forced=vulnerable (local_risk=True) → TP via forced
    sample 41: true=safe,       forced=safe                          → TN via forced
    """
    rd = _run_dir(tmp_path, "20260611_test_forced_binary")
    _make_forced_sample_dir(rd, "40", "fn_a",
                             is_vulnerable_true=True, is_vulnerable_pred=False,
                             forced_prediction="vulnerable", forced_prediction_bool=True,
                             decision_status="inconclusive", confidence=0.45)
    _make_forced_sample_dir(rd, "41", "fn_b",
                             is_vulnerable_true=False, is_vulnerable_pred=False,
                             forced_prediction="fixed/non-vulnerable", forced_prediction_bool=False,
                             decision_status="inconclusive", confidence=0.42)
    return tmp_path, rd.name


def test_forced_binary_samples_count_as_completed(run_forced_binary):
    """Inconclusive samples with forced_prediction_bool must count as completed predictions."""
    tmp_path, run_id = run_forced_binary
    client = _make_client(tmp_path)
    s = client.get(f"/api/research/runs/{run_id}/summary?mode=admin").json()
    assert s["samples_completed"] == 2, (
        f"Both forced-binary samples must count as completed; got {s['samples_completed']}"
    )


def test_forced_binary_tp_counted_in_metrics(run_forced_binary):
    """Forced binary vulnerable+correct sample must count as TP in metrics."""
    tmp_path, run_id = run_forced_binary
    client = _make_client(tmp_path)
    m = client.get(f"/api/research/runs/{run_id}/metrics-live?mode=admin").json()
    assert m["available"] is True
    # sample 40: true=vuln, forced=vuln → TP
    # sample 41: true=safe, forced=safe → TN
    assert m.get("tp") == 1, f"Expected tp=1, got {m.get('tp')}"
    assert m.get("tn") == 1, f"Expected tn=1, got {m.get('tn')}"
    assert m.get("fp") == 0
    assert m.get("fn") == 0
