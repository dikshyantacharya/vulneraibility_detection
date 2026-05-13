from __future__ import annotations

import csv
import json
import logging
import re
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import requests

from vuln_commit_kg.data.sample_selector import ProjectStats, summarize_projects
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.utils.jsonl import write_json

_GITHUB_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?/?$")


def parse_github_repo(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None
    m = _GITHUB_RE.search(url.strip())
    if not m:
        return None
    return m.group("owner"), m.group("repo")


def fetch_github_size_kb(url: str | None, timeout: float = 8.0) -> int | None:
    parsed = parse_github_repo(url)
    if not parsed:
        return None
    owner, repo = parsed
    api = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github+json"}
    r = requests.get(api, headers=headers, timeout=timeout)
    if r.status_code == 403 and "rate limit" in r.text.lower():
        raise RuntimeError("GitHub API rate limit reached. Re-run without --fetch-github-size or set GITHUB_TOKEN support manually.")
    r.raise_for_status()
    data = r.json()
    # GitHub repository size is in KiB.
    size = data.get("size")
    return int(size) if size is not None else None


def project_stats_rows(
    samples: list[SecVulEvalSample],
    fetch_github_size: bool = False,
    github_limit: int | None = None,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    stats = summarize_projects(samples)
    stats.sort(key=lambda p: (p.num_samples, p.project))
    rows: list[dict[str, Any]] = []
    fetched = 0
    for p in stats:
        row = p.to_dict()
        row["github_repo"] = None
        row["github_size_kb"] = None
        row["github_size_mb"] = None
        parsed = parse_github_repo(p.project_url)
        if parsed:
            row["github_repo"] = f"{parsed[0]}/{parsed[1]}"
        if fetch_github_size and parsed and (github_limit is None or fetched < github_limit):
            try:
                size_kb = fetch_github_size_kb(p.project_url)
                row["github_size_kb"] = size_kb
                row["github_size_mb"] = round(size_kb / 1024, 2) if size_kb is not None else None
                fetched += 1
                if logger:
                    logger.info("GitHub size: %s=%s KiB", p.project, size_kb)
                time.sleep(0.1)
            except Exception as exc:
                row["github_size_error"] = str(exc)
                if logger:
                    logger.warning("Could not fetch GitHub size for %s: %s", p.project, exc)
        rows.append(row)
    return rows


def write_project_scan_outputs(run_dir: Path, rows: list[dict[str, Any]], top_n: int = 30) -> Path:
    out_dir = run_dir / "project_scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "project_summary.csv"
    json_path = out_dir / "project_summary.json"
    cols = [
        "project", "project_url", "github_repo", "github_size_kb", "github_size_mb",
        "num_samples", "num_vulnerable", "num_safe", "num_commits", "num_files",
    ]
    extra_cols = sorted({k for row in rows for k in row.keys()} - set(cols))
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=cols + extra_cols)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    small_vul = [r for r in rows if r.get("num_vulnerable", 0) > 0]
    small_vul.sort(key=lambda r: (r.get("github_size_kb") is None, r.get("github_size_kb") or 10**12, r["num_samples"], r["project"]))
    if all(r.get("github_size_kb") is None for r in small_vul):
        small_vul.sort(key=lambda r: (r["num_samples"], r["num_commits"], r["num_files"], r["project"]))

    recommendations = {
        "small_vulnerable_projects": small_vul[:top_n],
        "small_by_dataset_samples": sorted(rows, key=lambda r: (r["num_samples"], r["project"]))[:top_n],
        "large_by_dataset_samples": sorted(rows, key=lambda r: (-r["num_samples"], r["project"]))[:top_n],
    }
    write_json(out_dir / "recommendations.json", recommendations)
    return csv_path
