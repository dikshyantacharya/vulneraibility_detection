from __future__ import annotations

import csv
import html
import json
import math
import time
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from vuln_commit_kg.utils.jsonl import read_jsonl, write_json


def dir_size_bytes(path: str | Path | None) -> int:
    if not path:
        return 0
    root = Path(path)
    if not root.exists():
        return 0
    total = 0
    for p in root.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def fmt_bytes(n: int | float | None) -> str:
    n = float(n or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_seconds(n: int | float | None) -> str:
    s = float(n or 0)
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{int(m)}m {sec:.1f}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h {int(m)}m {sec:.1f}s"


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    keys: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in keys:
                keys.append(key)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def _flatten_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return read_jsonl(path)


def _sample_prediction_rows(run_dir: Path) -> list[dict[str, Any]]:
    samples = {str(x.get("sample_id")): x for x in _flatten_jsonl(run_dir / "runnable_samples.jsonl")}
    preds = _flatten_jsonl(run_dir / "predictions.jsonl")
    traces = {str(x.get("sample_id")): x for x in _flatten_jsonl(run_dir / "agent_traces.jsonl")}
    runtime = {str(x.get("sample_id")): x for x in _flatten_jsonl(run_dir / "sample_runtime.jsonl")}
    out = []
    for p in preds:
        sid = str(p.get("sample_id"))
        s = samples.get(sid, {})
        tr = traces.get(sid, {})
        rt = runtime.get(sid, {})
        truth = bool(s.get("is_vulnerable"))
        pred = bool(p.get("is_vulnerable"))
        report = tr.get("report_path")
        if report:
            try:
                rp = Path(str(report))
                # Dashboard lives in run_dir/scaling_analysis, so links should be relative from there.
                if not rp.is_absolute():
                    rp = Path.cwd() / rp
                rd = run_dir if run_dir.is_absolute() else Path.cwd() / run_dir
                report = Path("..") / rp.relative_to(rd)
            except Exception:
                report = tr.get("report_path")
        out.append({
            "sample_id": sid,
            "idx": s.get("idx"),
            "project": s.get("project"),
            "filepath": s.get("filepath"),
            "function": s.get("func_name"),
            "ground_truth": "vulnerable" if truth else "non_vulnerable",
            "prediction": "vulnerable" if pred else "non_vulnerable",
            "correct": truth == pred,
            "error_type": "TP" if truth and pred else "TN" if (not truth and not pred) else "FP" if (not truth and pred) else "FN",
            "confidence": p.get("confidence"),
            "primary_vulnerability_type": p.get("primary_vulnerability_type"),
            "prompt_tokens": (p.get("usage") or {}).get("prompt_tokens", 0),
            "completion_tokens": (p.get("usage") or {}).get("completion_tokens", 0),
            "total_tokens": (p.get("usage") or {}).get("total_tokens", 0),
            "cost_total_usd": (p.get("usage") or {}).get("cost_total_usd", 0.0),
            "usage_estimated": (p.get("usage") or {}).get("estimated", True),
            "parse_error": p.get("parse_error"),
            "resolved_commit_label": p.get("resolved_commit_label"),
            "target_validation_status": p.get("target_validation_status"),
            "target_validation_similarity": p.get("target_validation_similarity"),
            "initial_evidence_count": rt.get("initial_evidence_count", tr.get("initial_evidence_count")),
            "accumulated_evidence_count": rt.get("accumulated_evidence_count", tr.get("accumulated_evidence_count")),
            "model_calls": rt.get("model_calls", len(tr.get("model_calls") or [])),
            "kg_tool_steps": rt.get("kg_tool_steps", len(tr.get("kg_tool_steps") or [])),
            "retrieval_seconds": rt.get("retrieval_seconds"),
            "agent_seconds": rt.get("agent_seconds"),
            "model_call_seconds": rt.get("model_call_seconds"),
            "graph_status": rt.get("graph_status"),
            "graph_nodes": rt.get("graph_nodes"),
            "graph_edges": rt.get("graph_edges"),
            "agent_report": report,
        })
    return out


def _model_call_rows(run_dir: Path) -> list[dict[str, Any]]:
    traces = _flatten_jsonl(run_dir / "agent_traces.jsonl")
    rows: list[dict[str, Any]] = []
    for tr in traces:
        sid = str(tr.get("sample_id"))
        for i, call in enumerate(tr.get("model_calls") or [], start=1):
            usage = call.get("total_stage_usage") or call.get("usage") or {}
            rows.append({
                "sample_id": sid,
                "call_index": i,
                "stage": call.get("name"),
                "json_status": call.get("json_status"),
                "repair_attempts": len(call.get("repair_attempts") or []),
                "prompt_chars": len(call.get("prompt") or ""),
                "raw_response_chars": len(call.get("raw_response") or call.get("response") or ""),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "cost_total_usd": usage.get("cost_total_usd", 0.0),
                "estimated": usage.get("estimated", True),
                "elapsed_seconds": call.get("elapsed_seconds"),
            })
    return rows


def _project_rows(run_dir: Path) -> list[dict[str, Any]]:
    # Preferred structured rows written by the new pipeline. Fall back to kg manifests.
    rows = _flatten_jsonl(run_dir / "project_runtime.jsonl")
    if rows:
        return rows
    out = []
    for r in _flatten_jsonl(run_dir / "kg_manifests.jsonl"):
        out.append({
            "project": r.get("project"),
            "project_url": r.get("project_url"),
            "resolved_commit_id": r.get("commit_id"),
            "graph_status": r.get("status"),
            "kg_build_seconds_manifest": r.get("seconds"),
            "num_files": r.get("num_files"),
            "num_functions": r.get("num_functions"),
            "num_statements": r.get("num_statements"),
            "num_nodes": r.get("num_nodes"),
            "num_edges": r.get("num_edges"),
            "graph_dir": r.get("graph_dir"),
            "graph_dir_size_bytes": dir_size_bytes(r.get("graph_dir")),
        })
    return out


def _aggregate_runtime(project_rows: list[dict[str, Any]], sample_rows: list[dict[str, Any]], model_rows: list[dict[str, Any]], profile_rows: list[dict[str, Any]], usage: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    cold_like_projects = [r for r in project_rows if str(r.get("graph_status")) == "built" or str(r.get("repo_status")) == "cloned_mirror"]
    n_samples = len(sample_rows)
    n_projects = len({r.get("project") for r in project_rows if r.get("project")}) or len({r.get("project") for r in sample_rows if r.get("project")})
    kg_seconds = sum(float(r.get("kg_wall_seconds") or r.get("kg_build_seconds_manifest") or 0) for r in project_rows)
    clone_seconds = sum(float(r.get("repo_elapsed_seconds") or 0) for r in project_rows)
    snapshot_seconds = sum(float(r.get("snapshot_elapsed_seconds") or 0) for r in project_rows)
    agent_seconds = sum(float(r.get("agent_seconds") or 0) for r in sample_rows)
    retrieval_seconds = sum(float(r.get("retrieval_seconds") or 0) for r in sample_rows)
    model_seconds = sum(float(r.get("elapsed_seconds") or 0) for r in model_rows)
    measured_components = clone_seconds + snapshot_seconds + kg_seconds + retrieval_seconds + agent_seconds
    total_profile = (
        sum(float(r.get("seconds") or 0) for r in profile_rows if r.get("name") == "full_run")
        or sum(float(r.get("seconds") or 0) for r in profile_rows if r.get("name") == "full_run_so_far")
        or measured_components
    )
    total_tokens = int(usage.get("total_tokens", 0) or 0)
    return {
        "samples": n_samples,
        "projects": n_projects,
        "project_snapshots": len(project_rows),
        "model_calls": len(model_rows),
        "total_profile_seconds": total_profile,
        "clone_seconds_total": clone_seconds,
        "snapshot_seconds_total": snapshot_seconds,
        "kg_seconds_total": kg_seconds,
        "retrieval_seconds_total": retrieval_seconds,
        "agent_seconds_total": agent_seconds,
        "model_generation_seconds_total": model_seconds,
        "avg_seconds_per_sample_observed": safe_div(total_profile, n_samples),
        "avg_agent_seconds_per_sample": safe_div(agent_seconds, n_samples),
        "avg_retrieval_seconds_per_sample": safe_div(retrieval_seconds, n_samples),
        "avg_kg_seconds_per_project_snapshot": safe_div(kg_seconds, len(project_rows)),
        "avg_clone_seconds_per_project_snapshot": safe_div(clone_seconds, len(project_rows)),
        "avg_total_tokens_per_sample": safe_div(total_tokens, n_samples),
        "avg_prompt_tokens_per_sample": safe_div(float(usage.get("prompt_tokens", 0) or 0), n_samples),
        "avg_completion_tokens_per_sample": safe_div(float(usage.get("completion_tokens", 0) or 0), n_samples),
        "avg_cost_per_sample_usd": safe_div(float(usage.get("cost_total_usd", 0.0) or 0.0), n_samples),
        "accuracy": (metrics.get("binary") or {}).get("accuracy"),
        "precision": (metrics.get("binary") or {}).get("precision"),
        "recall": (metrics.get("binary") or {}).get("recall"),
        "f1": (metrics.get("binary") or {}).get("f1"),
        "positive_rate_predicted": safe_div(sum(1 for r in sample_rows if r.get("prediction") == "vulnerable"), n_samples),
        "positive_rate_true": safe_div(sum(1 for r in sample_rows if r.get("ground_truth") == "vulnerable"), n_samples),
    }


def _projection_rows(summary: dict[str, Any], projection_sample_counts: list[int], projection_project_counts: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    base_samples = int(summary.get("samples") or 0)
    base_projects = int(summary.get("projects") or 0)
    if not base_samples:
        return rows
    avg_agent = float(summary.get("avg_agent_seconds_per_sample") or 0)
    avg_retrieval = float(summary.get("avg_retrieval_seconds_per_sample") or 0)
    avg_tokens = float(summary.get("avg_total_tokens_per_sample") or 0)
    avg_prompt = float(summary.get("avg_prompt_tokens_per_sample") or 0)
    avg_completion = float(summary.get("avg_completion_tokens_per_sample") or 0)
    avg_cost = float(summary.get("avg_cost_per_sample_usd") or 0)
    avg_kg_project = float(summary.get("avg_kg_seconds_per_project_snapshot") or 0)
    avg_clone_project = float(summary.get("avg_clone_seconds_per_project_snapshot") or 0)
    for samples in projection_sample_counts:
        for projects in projection_project_counts:
            if samples < 1 or projects < 1:
                continue
            kg_clone = projects * (avg_kg_project + avg_clone_project)
            per_sample = samples * (avg_agent + avg_retrieval)
            total = kg_clone + per_sample
            rows.append({
                "target_samples": samples,
                "target_projects_or_snapshots": projects,
                "estimated_clone_plus_kg_seconds": kg_clone,
                "estimated_retrieval_plus_agent_seconds": per_sample,
                "estimated_total_seconds": total,
                "estimated_total_hours": total / 3600,
                "estimated_prompt_tokens": samples * avg_prompt,
                "estimated_completion_tokens": samples * avg_completion,
                "estimated_total_tokens": samples * avg_tokens,
                "estimated_cost_usd": samples * avg_cost,
                "basis_samples": base_samples,
                "basis_projects": base_projects,
                "method": "linear extrapolation from observed local run; validate with 2→5→50 project calibration before full scale",
            })
    return rows


def _plot_bar(path: Path, labels: list[str], values: list[float], title: str, ylabel: str = "") -> None:
    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.3), 4))
    ax.bar(labels, values)
    ax.set_title(title)
    if ylabel:
        ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", rotation=25)
    for i, v in enumerate(values):
        ax.text(i, v, f"{v:.1f}", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _plot_scatter(path: Path, x: list[float], y: list[float], labels: list[str], title: str, xlabel: str, ylabel: str) -> None:
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.scatter(x, y)
    for xi, yi, lab in zip(x, y, labels):
        ax.annotate(str(lab)[:18], (xi, yi), fontsize=8, xytext=(4, 4), textcoords="offset points")
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _make_figures(fig_dir: Path, summary: dict[str, Any], project_rows: list[dict[str, Any]], sample_rows: list[dict[str, Any]], projection_rows: list[dict[str, Any]]) -> None:
    fig_dir.mkdir(parents=True, exist_ok=True)
    _plot_bar(
        fig_dir / "runtime_breakdown_seconds.png",
        ["clone", "snapshot", "KG", "retrieval", "agent", "model gen"],
        [
            summary.get("clone_seconds_total") or 0,
            summary.get("snapshot_seconds_total") or 0,
            summary.get("kg_seconds_total") or 0,
            summary.get("retrieval_seconds_total") or 0,
            summary.get("agent_seconds_total") or 0,
            summary.get("model_generation_seconds_total") or 0,
        ],
        "Observed runtime breakdown",
        "seconds",
    )
    if sample_rows:
        _plot_bar(
            fig_dir / "token_usage_by_sample.png",
            [str(r.get("sample_id")) for r in sample_rows],
            [float(r.get("total_tokens") or 0) for r in sample_rows],
            "Total tokens by sample",
            "tokens",
        )
        _plot_bar(
            fig_dir / "cost_by_sample.png",
            [str(r.get("sample_id")) for r in sample_rows],
            [float(r.get("cost_total_usd") or 0) for r in sample_rows],
            "Cost by sample",
            "USD",
        )
    if project_rows:
        x = [float(r.get("num_statements") or r.get("num_nodes") or 0) for r in project_rows]
        y = [float(r.get("kg_wall_seconds") or r.get("kg_build_seconds_manifest") or 0) for r in project_rows]
        labs = [str(r.get("project") or "project") for r in project_rows]
        _plot_scatter(fig_dir / "project_size_vs_kg_time.png", x, y, labs, "Project/KG size vs KG time", "statements or nodes", "seconds")
        x2 = [float(r.get("worktree_size_bytes") or 0) / (1024 * 1024) for r in project_rows]
        y2 = [float(r.get("graph_dir_size_bytes") or 0) / (1024 * 1024) for r in project_rows]
        _plot_scatter(fig_dir / "source_size_vs_kg_size.png", x2, y2, labs, "Source worktree size vs KG cache size", "source MB", "KG MB")
    # Keep one row per target sample count for a fixed closest project count to reduce clutter.
    if projection_rows:
        chosen = {}
        for r in projection_rows:
            samples = int(r.get("target_samples") or 0)
            # prefer project count proportional to observed ratio when possible
            if samples not in chosen:
                chosen[samples] = r
        rows = [chosen[k] for k in sorted(chosen)]
        _plot_bar(
            fig_dir / "projection_time_by_samples.png",
            [str(int(r.get("target_samples") or 0)) for r in rows],
            [float(r.get("estimated_total_hours") or 0) for r in rows],
            "Projected total runtime by sample count",
            "hours",
        )
        _plot_bar(
            fig_dir / "projection_cost_by_samples.png",
            [str(int(r.get("target_samples") or 0)) for r in rows],
            [float(r.get("estimated_cost_usd") or 0) for r in rows],
            "Projected cost by sample count",
            "USD",
        )


def _html_table(rows: list[dict[str, Any]], table_id: str, max_rows: int | None = None) -> str:
    if not rows:
        return "<p>No rows.</p>"
    show = rows[:max_rows] if max_rows else rows
    keys = []
    for row in show:
        for k in row.keys():
            if k not in keys:
                keys.append(k)
    head = "".join(f"<th>{html.escape(str(k))}</th>" for k in keys)
    body = []
    for row in show:
        cells = []
        for k in keys:
            v = row.get(k, "")
            if k == "agent_report" and v:
                val = f'<a href="{html.escape(str(v))}">open</a>'
            elif isinstance(v, bool):
                val = "yes" if v else "no"
            elif isinstance(v, float):
                val = f"{v:.6g}"
            else:
                val = html.escape(str(v))
            cells.append(f"<td>{val}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f'<table id="{table_id}"><thead><tr>{head}</tr></thead><tbody>' + "\n".join(body) + "</tbody></table>"


def _write_dashboard(run_dir: Path, summary: dict[str, Any], metrics: dict[str, Any], usage: dict[str, Any], project_rows: list[dict[str, Any]], sample_rows: list[dict[str, Any]], model_rows: list[dict[str, Any]], projection_rows: list[dict[str, Any]]) -> Path:
    out_dir = run_dir / "scaling_analysis"
    fig_rel = "figures"
    cards = [
        ("Samples", summary.get("samples")),
        ("Projects", summary.get("projects")),
        ("Accuracy", summary.get("accuracy")),
        ("Precision", summary.get("precision")),
        ("Recall", summary.get("recall")),
        ("F1", summary.get("f1")),
        ("Total tokens", usage.get("total_tokens")),
        ("Cost", f"${float(usage.get('cost_total_usd', 0) or 0):.6f}"),
        ("Total runtime", fmt_seconds(summary.get("total_profile_seconds"))),
        ("KG seconds", fmt_seconds(summary.get("kg_seconds_total"))),
    ]
    card_html = "".join(f"<div class='card'><div class='label'>{html.escape(str(k))}</div><div class='value'>{html.escape(str(v))}</div></div>" for k, v in cards)
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Scaling Analysis Dashboard</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:24px;color:#111827;line-height:1.45}}
h1,h2,h3{{color:#1f2937}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.card{{border:1px solid #d1d5db;border-radius:12px;padding:12px;background:#f9fafb}} .label{{font-size:12px;color:#6b7280}} .value{{font-size:20px;font-weight:700}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}} th,td{{border:1px solid #d1d5db;padding:5px;vertical-align:top}} th{{background:#f3f4f6;position:sticky;top:0}}
.good{{color:#047857;font-weight:700}} .bad{{color:#b91c1c;font-weight:700}} .note{{border-left:4px solid #60a5fa;background:#eff6ff;padding:10px}}
.controls{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}} input,select{{padding:6px;border:1px solid #cbd5e1;border-radius:8px}}
img{{max-width:100%;border:1px solid #e5e7eb;border-radius:8px;background:white;margin:8px 0}}
</style>
<script>
function filterPredictions(){{
  const q=(document.getElementById('search').value||'').toLowerCase();
  const status=document.getElementById('status').value;
  document.querySelectorAll('#predictions tbody tr').forEach(tr=>{{
    const text=tr.innerText.toLowerCase();
    const ok=text.includes('yes');
    const isWrong=text.includes(' no ' ) || text.endsWith('no');
    let show=text.includes(q);
    if(status==='correct') show=show && text.includes('yes');
    if(status==='wrong') show=show && text.includes('no');
    tr.style.display=show?'':'none';
  }});
}}
</script>
</head><body>
<h1>Scaling Analysis Dashboard</h1>
<p class="note">This dashboard is for local calibration and projection. It reports observed runtime, KG/cache sizes, token usage, cost, binary metrics, and linear projections. Use 2 → 5 → 50 project runs to check whether projections remain stable before full-scale execution.</p>
<div class="grid">{card_html}</div>
<h2>Observed runtime and resource figures</h2>
<img src="{fig_rel}/runtime_breakdown_seconds.png" alt="runtime breakdown">
<img src="{fig_rel}/project_size_vs_kg_time.png" alt="project size vs KG time">
<img src="{fig_rel}/source_size_vs_kg_size.png" alt="source size vs KG size">
<img src="{fig_rel}/token_usage_by_sample.png" alt="token usage">
<img src="{fig_rel}/cost_by_sample.png" alt="cost by sample">
<h2>Projection figures</h2>
<img src="{fig_rel}/projection_time_by_samples.png" alt="projection time">
<img src="{fig_rel}/projection_cost_by_samples.png" alt="projection cost">
<h2>Prediction browser</h2>
<div class="controls"><input id="search" oninput="filterPredictions()" placeholder="filter by sample/project/function/error"><select id="status" onchange="filterPredictions()"><option value="all">all</option><option value="correct">correct only</option><option value="wrong">wrong only</option></select></div>
{_html_table(sample_rows, 'predictions')}
<h2>Project / snapshot resource table</h2>
{_html_table(project_rows, 'projects')}
<h2>Model call usage table</h2>
{_html_table(model_rows, 'modelcalls')}
<h2>Projection estimates</h2>
{_html_table(projection_rows, 'projections')}
<h2>Machine-readable files</h2>
<ul>
<li><a href="summary.json">summary.json</a></li>
<li><a href="sample_predictions.csv">sample_predictions.csv</a></li>
<li><a href="project_runtime.csv">project_runtime.csv</a></li>
<li><a href="model_call_usage.csv">model_call_usage.csv</a></li>
<li><a href="projection_estimates.csv">projection_estimates.csv</a></li>
</ul>
</body></html>"""
    path = out_dir / "index.html"
    path.write_text(content, encoding="utf-8")
    return path


def write_scaling_analysis(
    run_dir: str | Path,
    *,
    metrics: dict[str, Any] | None = None,
    usage: dict[str, Any] | None = None,
    projection_sample_counts: Iterable[int] | None = None,
    projection_project_counts: Iterable[int] | None = None,
) -> Path:
    run_dir = Path(run_dir)
    out_dir = run_dir / "scaling_analysis"
    fig_dir = out_dir / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics = metrics if metrics is not None else read_json(run_dir / "metrics.json")
    usage = usage if usage is not None else read_json(run_dir / "usage_summary.json")
    project_rows = _project_rows(run_dir)
    sample_rows = _sample_prediction_rows(run_dir)
    model_rows = _model_call_rows(run_dir)
    profile_rows = _flatten_jsonl(run_dir / "profile_events.jsonl")
    summary = _aggregate_runtime(project_rows, sample_rows, model_rows, profile_rows, usage, metrics)
    projection_sample_counts = list(projection_sample_counts or [len(sample_rows), 5, 10, 50, 100, 1000, 25000])
    projection_project_counts = list(projection_project_counts or [max(1, summary.get("projects") or 1), 5, 50, 100, 900])
    projections = _projection_rows(summary, [int(x) for x in projection_sample_counts], [int(x) for x in projection_project_counts])

    _write_csv(out_dir / "sample_predictions.csv", sample_rows)
    _write_csv(out_dir / "project_runtime.csv", project_rows)
    _write_csv(out_dir / "model_call_usage.csv", model_rows)
    _write_csv(out_dir / "projection_estimates.csv", projections)
    write_json(out_dir / "summary.json", summary)
    write_json(out_dir / "projection_estimates.json", projections)
    _make_figures(fig_dir, summary, project_rows, sample_rows, projections)
    return _write_dashboard(run_dir, summary, metrics, usage, project_rows, sample_rows, model_rows, projections)
