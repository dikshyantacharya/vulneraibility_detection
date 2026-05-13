from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from vuln_commit_kg.config import DatasetConfig
from vuln_commit_kg.data.sample_selector import find_vulnerable_fixed_pairs, summarize_projects
from vuln_commit_kg.data.schema import SecVulEvalSample


def pair_rows(samples: list[SecVulEvalSample], cfg: DatasetConfig, limit: int | None = None) -> list[dict]:
    pairs = find_vulnerable_fixed_pairs(samples, cfg)
    stats_by_project = {p.project: p for p in summarize_projects(samples)}
    rows: list[dict] = []
    for pair in pairs:
        ps = stats_by_project.get(pair.project or "")
        rows.append({
            "project": pair.project,
            "project_url": pair.project_url,
            "project_num_samples": ps.num_samples if ps else None,
            "project_num_commits": ps.num_commits if ps else None,
            "vulnerable_idx": pair.vulnerable_idx,
            "fixed_idx": pair.fixed_idx,
            "filepath": pair.filepath,
            "func_name": pair.func_name,
            "patch_commit_id": pair.patch_commit_id,
            "cve_list": ",".join(pair.cve_list or []),
            "cwe_list": ",".join(pair.cwe_list or []),
        })
    rows.sort(key=lambda r: (
        r.get("project_num_samples") if r.get("project_num_samples") is not None else 10**12,
        0 if str(r.get("project_url") or "").startswith("https://github.com/") else 1,
        str(r.get("project") or ""),
        int(r.get("vulnerable_idx") or 0),
    ))
    return rows[:limit] if limit else rows


def write_pair_scan_outputs(run_dir: Path, rows: list[dict]) -> Path:
    out_dir = run_dir / "pair_scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "vulnerable_fixed_pairs.csv"
    fieldnames = [
        "project", "project_url", "project_num_samples", "project_num_commits",
        "vulnerable_idx", "fixed_idx", "filepath", "func_name", "patch_commit_id", "cve_list", "cwe_list",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return csv_path
