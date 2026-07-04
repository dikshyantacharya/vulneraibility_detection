"""Tests and smoke tests for the classical TF-IDF + Logistic Regression baseline."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from vuln_commit_kg.baseline import TfidfLogisticRegressionBaseline
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.evaluation.binary import binary_metrics


def _build_synthetic_dataset() -> tuple[list[SecVulEvalSample], list[SecVulEvalSample]]:
    """Build synthetic train and test samples with schema identical to SecVulEval."""
    train_samples = [
        SecVulEvalSample(
            sample_id="train_vuln_1",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/packet.c",
            func_name="process_packet",
            func_body="""
            void process_packet(char *user_input) {
                char local_buf[64];
                strcpy(local_buf, user_input);
                printf(local_buf);
            }
            """,
            commit_id="c0ffee0001",
            is_vulnerable=True,
            cve_list=["CVE-2021-1001"],
            cwe_list=["CWE-120", "CWE-134"],
        ),
        SecVulEvalSample(
            sample_id="train_vuln_2",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/parser.c",
            func_name="parse_header",
            func_body="""
            int parse_header(char *raw_header) {
                char header_name[32];
                gets(header_name);
                sprintf(header_name, "%s", raw_header);
                return 0;
            }
            """,
            commit_id="c0ffee0002",
            is_vulnerable=True,
            cve_list=["CVE-2021-1002"],
            cwe_list=["CWE-120"],
        ),
        SecVulEvalSample(
            sample_id="train_safe_1",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/packet.c",
            func_name="process_packet_safe",
            func_body="""
            void process_packet_safe(const char *user_input, size_t input_len) {
                char local_buf[64];
                if (input_len >= sizeof(local_buf)) {
                    return;
                }
                strncpy(local_buf, user_input, sizeof(local_buf) - 1);
                local_buf[sizeof(local_buf) - 1] = '\\0';
            }
            """,
            commit_id="c0ffee0003",
            is_vulnerable=False,
            cve_list=[],
            cwe_list=[],
        ),
        SecVulEvalSample(
            sample_id="train_safe_2",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/parser.c",
            func_name="parse_header_safe",
            func_body="""
            int parse_header_safe(const char *raw_header, size_t maxlen) {
                char header_name[32];
                if (!raw_header || maxlen >= sizeof(header_name)) {
                    return -1;
                }
                snprintf(header_name, sizeof(header_name), "%s", raw_header);
                return 0;
            }
            """,
            commit_id="c0ffee0004",
            is_vulnerable=False,
            cve_list=[],
            cwe_list=[],
        ),
    ]

    test_samples = [
        SecVulEvalSample(
            sample_id="test_vuln_1",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/handler.c",
            func_name="handle_request",
            func_body="""
            void handle_request(char *input) {
                char dest[128];
                strcpy(dest, input);
            }
            """,
            commit_id="c0ffee0005",
            is_vulnerable=True,
            cve_list=["CVE-2022-2001"],
            cwe_list=["CWE-120"],
        ),
        SecVulEvalSample(
            sample_id="test_safe_1",
            project="libnetwork",
            project_url="https://github.com/example/libnetwork",
            filepath="src/handler.c",
            func_name="handle_request_safe",
            func_body="""
            void handle_request_safe(const char *input, size_t len) {
                char dest[128];
                if (len < sizeof(dest)) {
                    strncpy(dest, input, sizeof(dest) - 1);
                    dest[sizeof(dest) - 1] = '\\0';
                }
            }
            """,
            commit_id="c0ffee0006",
            is_vulnerable=False,
            cve_list=[],
            cwe_list=[],
        ),
    ]

    return train_samples, test_samples


def test_baseline_fit_predict_smoke():
    """Smoke test: verify fitting, batch prediction, and single prediction."""
    train_samples, test_samples = _build_synthetic_dataset()

    baseline = TfidfLogisticRegressionBaseline(max_features=500, ngram_range=(1, 2), random_state=42)
    baseline.fit(train_samples)

    # Test single sample prediction
    single_pred = baseline.predict_sample(test_samples[0])
    assert single_pred.sample_id == test_samples[0].sample_id
    assert single_pred.decision_status in {"vulnerable", "non_vulnerable"}
    assert 0.0 <= single_pred.confidence <= 1.0
    assert single_pred.model_backend == "tfidf_logistic_regression"

    # Test batch predictions
    preds = baseline.predict(test_samples)
    assert len(preds) == len(test_samples)
    for p in preds:
        assert p.decision_status in {"vulnerable", "non_vulnerable"}
        assert isinstance(p.is_vulnerable, bool)


def test_baseline_evaluation_metrics_pluggable():
    """Verify that baseline predictions plug directly into binary_metrics."""
    train_samples, test_samples = _build_synthetic_dataset()

    baseline = TfidfLogisticRegressionBaseline(max_features=500, random_state=42)
    baseline.fit(train_samples)

    preds = baseline.predict(test_samples)

    # Plug directly into the system's binary_metrics function
    metrics = binary_metrics(test_samples, preds)

    # Verify standard metrics structure
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert "tp" in metrics
    assert "tn" in metrics
    assert "fp" in metrics
    assert "fn" in metrics
    assert metrics["invalid_predictions"] == 0
    assert metrics["valid_predictions"] == len(test_samples)
    assert metrics["n"] == len(test_samples)

    # Also test the convenience evaluate method
    eval_metrics = baseline.evaluate(test_samples)
    assert eval_metrics["n"] == metrics["n"]
    assert eval_metrics["f1"] == metrics["f1"]


def test_baseline_save_and_load(tmp_path: Path):
    """Verify model persistence with save and load."""
    train_samples, test_samples = _build_synthetic_dataset()

    baseline = TfidfLogisticRegressionBaseline(max_features=200, random_state=42)
    baseline.fit(train_samples)
    orig_preds = baseline.predict(test_samples)

    model_path = tmp_path / "baseline_model.joblib"
    baseline.save(model_path)
    assert model_path.exists()

    loaded_baseline = TfidfLogisticRegressionBaseline.load(model_path)
    loaded_preds = loaded_baseline.predict(test_samples)

    for p_orig, p_loaded in zip(orig_preds, loaded_preds):
        assert p_orig.is_vulnerable == p_loaded.is_vulnerable
        assert pytest.approx(p_orig.confidence, abs=1e-5) == p_loaded.confidence
