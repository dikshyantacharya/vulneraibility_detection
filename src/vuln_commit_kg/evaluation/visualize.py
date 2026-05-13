from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def save_metric_tables(run_dir: Path, metrics: dict, usage: dict) -> None:
    tables = run_dir / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    flat_rows = []
    for section, obj in metrics.items():
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(v, (list, dict)):
                    flat_rows.append({"section": section, "metric": k, "value": v})
    for k, v in usage.items():
        flat_rows.append({"section": "usage", "metric": k, "value": v})
    pd.DataFrame(flat_rows).to_csv(tables / "metrics.csv", index=False)
    if "binary" in metrics and "rows" in metrics["binary"]:
        pd.DataFrame(metrics["binary"]["rows"]).to_csv(tables / "binary_predictions.csv", index=False)
    if "statement" in metrics and "rows" in metrics["statement"]:
        pd.DataFrame(metrics["statement"]["rows"]).to_csv(tables / "statement_metrics_by_sample.csv", index=False)


def make_visualizations(run_dir: Path, metrics: dict, usage: dict) -> None:
    fig_dir = run_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    binary = metrics.get("binary", {})
    if binary:
        _confusion_matrix(fig_dir / "confusion_matrix.png", binary)
        _binary_bars(fig_dir / "binary_metrics.png", binary)
    statement = metrics.get("statement", {})
    if statement:
        _statement_bars(fig_dir / "statement_metrics.png", statement)
    _token_bars(fig_dir / "token_usage.png", usage)


def _confusion_matrix(path: Path, binary: dict) -> None:
    matrix = [[binary.get("tn", 0), binary.get("fp", 0)], [binary.get("fn", 0), binary.get("tp", 0)]]
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.imshow(matrix)
    ax.set_xticks([0, 1], labels=["Pred Safe", "Pred Vuln"])
    ax.set_yticks([0, 1], labels=["True Safe", "True Vuln"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(matrix[i][j]), ha="center", va="center")
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _binary_bars(path: Path, binary: dict) -> None:
    keys = ["accuracy", "precision", "recall", "f1", "balanced_accuracy"]
    vals = [binary.get(k, 0.0) for k in keys]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(keys, vals)
    ax.set_ylim(0, 1)
    ax.set_title("Binary Metrics")
    ax.tick_params(axis="x", rotation=25)
    for i, v in enumerate(vals):
        ax.text(i, min(v + 0.03, 1), f"{v:.2f}", ha="center")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _statement_bars(path: Path, statement: dict) -> None:
    keys = ["statement_precision", "statement_recall", "statement_f1"]
    vals = [statement.get(k, 0.0) for k in keys]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(keys, vals)
    ax.set_ylim(0, 1)
    ax.set_title("Statement Localization Metrics")
    ax.tick_params(axis="x", rotation=20)
    for i, v in enumerate(vals):
        ax.text(i, min(v + 0.03, 1), f"{v:.2f}", ha="center")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _token_bars(path: Path, usage: dict) -> None:
    keys = ["prompt_tokens", "completion_tokens", "total_tokens"]
    vals = [usage.get(k, 0) for k in keys]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(keys, vals)
    ax.set_title("Token Usage")
    for i, v in enumerate(vals):
        ax.text(i, v, str(v), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)
