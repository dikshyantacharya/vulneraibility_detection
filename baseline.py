"""Classical Text-Classification Baseline (TF-IDF + Logistic Regression).

Root entry point exposing TfidfLogisticRegressionBaseline for vulnerability detection.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src is in python path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from vuln_commit_kg.baseline import TfidfLogisticRegressionBaseline
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.evaluation.binary import binary_metrics

__all__ = ["TfidfLogisticRegressionBaseline", "SecVulEvalSample", "binary_metrics"]


if __name__ == "__main__":
    print("TF-IDF + Logistic Regression Baseline module loaded successfully.")
    print("Usage: from vuln_commit_kg.baseline import TfidfLogisticRegressionBaseline")
