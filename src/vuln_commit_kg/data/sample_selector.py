from __future__ import annotations

import random
from dataclasses import dataclass, asdict
from collections import defaultdict
from typing import Any

from .schema import SecVulEvalSample


@dataclass
class ProjectStats:
    project: str
    project_url: str | None
    num_samples: int
    num_vulnerable: int
    num_safe: int
    num_commits: int
    num_files: int
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerableFixedPair:
    project: str
    project_url: str | None
    vulnerable_idx: int
    fixed_idx: int
    filepath: str
    func_name: str
    patch_commit_id: str | None = None
    cve_list: list[str] | None = None
    cwe_list: list[str] | None = None


def group_by_project_commit(samples: list[SecVulEvalSample]) -> dict[tuple[str, str], list[SecVulEvalSample]]:
    out: dict[tuple[str, str], list[SecVulEvalSample]] = defaultdict(list)
    for s in samples:
        out[(s.project_url or s.project, s.commit_id or "unknown_commit")].append(s)
    return dict(out)


def summarize_projects(samples: list[SecVulEvalSample]) -> list[ProjectStats]:
    by_project: dict[str, list[SecVulEvalSample]] = defaultdict(list)
    for s in samples:
        by_project[s.project].append(s)
    stats = []
    for project, rows in by_project.items():
        stats.append(ProjectStats(
            project=project,
            project_url=next((r.project_url for r in rows if r.project_url), None),
            num_samples=len(rows),
            num_vulnerable=sum(1 for r in rows if r.is_vulnerable),
            num_safe=sum(1 for r in rows if not r.is_vulnerable),
            num_commits=len({r.commit_id for r in rows if r.commit_id}),
            num_files=len({r.filepath for r in rows if r.filepath}),
        ))
    return stats


def find_vulnerable_fixed_pairs(samples: list[SecVulEvalSample], cfg: Any) -> list[VulnerableFixedPair]:
    vulns = [s for s in samples if s.is_vulnerable]
    fixed = [s for s in samples if not s.is_vulnerable]
    pairs: list[VulnerableFixedPair] = []
    for v in vulns:
        candidates = [f for f in fixed if (f.project_url or f.project) == (v.project_url or v.project)]
        if getattr(cfg, "pair_require_same_file", True):
            candidates = [f for f in candidates if f.filepath == v.filepath]
        if getattr(cfg, "pair_require_same_function", True):
            candidates = [f for f in candidates if f.func_name == v.func_name]
        if not candidates:
            continue
        f = candidates[0]
        pairs.append(VulnerableFixedPair(v.project, v.project_url, v.idx, f.idx, v.filepath, v.func_name, f.commit_id or v.commit_id, v.cve_list, v.cwe_list))
    return pairs


def select_samples(samples: list[SecVulEvalSample], cfg: Any, seed: int = 0) -> list[SecVulEvalSample]:
    rows = list(samples)
    include = {str(x).lower() for x in getattr(cfg, "project_include", []) or []}
    exclude = {str(x).lower() for x in getattr(cfg, "project_exclude", []) or []}
    if include:
        rows = [s for s in rows if s.project.lower() in include or str(s.project_url or "").lower() in include]
    if exclude:
        rows = [s for s in rows if s.project.lower() not in exclude and str(s.project_url or "").lower() not in exclude]
    if getattr(cfg, "require_project_url", False) and not getattr(cfg, "allow_missing_repo_fields", False):
        rows = [s for s in rows if s.project_url]

    # If exact_sample_ids_only is true and only_sample_ids is specified, skip pair selection.
    exact_ids_requested = getattr(cfg, "exact_sample_ids_only", False) and getattr(cfg, "only_sample_ids", None)

    if not exact_ids_requested and getattr(cfg, "sample_selection", "standard") in {"smallest_vuln_fixed_pair", "smallest_vuln_fixed_pairs_by_project", "explicit_pair"}:
        if getattr(cfg, "sample_selection", "") == "explicit_pair" and getattr(cfg, "explicit_pair_indices", None):
            wanted = {int(x) for x in cfg.explicit_pair_indices}
            rows = [s for s in rows if s.idx in wanted]
        else:
            pairs = find_vulnerable_fixed_pairs(rows, cfg)
            by_idx = {s.idx: s for s in rows}
            selected=[]; seen=set()
            for p in pairs:
                for idx in [p.vulnerable_idx, p.fixed_idx]:
                    if idx in by_idx and idx not in seen:
                        selected.append(by_idx[idx]); seen.add(idx)
                if getattr(cfg, "sample_selection", "") == "smallest_vuln_fixed_pair":
                    break
                if getattr(cfg, "project_limit", None) and len({s.project for s in selected}) >= int(cfg.project_limit):
                    break
            rows = selected
    if getattr(cfg, "shuffle", False):
        rng = random.Random(seed); rng.shuffle(rows)
    if getattr(cfg, "vulnerable_count", None) is not None:
        vc = int(cfg.vulnerable_count)
        rows = [s for s in rows if s.is_vulnerable][:vc] + [s for s in rows if not s.is_vulnerable]
    if getattr(cfg, "non_vulnerable_count", None) is not None:
        nc = int(cfg.non_vulnerable_count)
        rows = [s for s in rows if s.is_vulnerable] + [s for s in rows if not s.is_vulnerable][:nc]
    if getattr(cfg, "project_limit", None) and getattr(cfg, "sample_selection", "standard") == "standard":
        keep = {p.project for p in sorted(summarize_projects(rows), key=lambda p:(p.num_samples,p.project))[:int(cfg.project_limit)]}
        rows = [s for s in rows if s.project in keep]
    # Dashboard-driven explicit selection (additive; empty lists are no-ops).
    only_ids = {str(x) for x in getattr(cfg, "only_sample_ids", []) or []}
    if only_ids:
        rows = [s for s in rows if str(s.sample_id) in only_ids or str(s.idx) in only_ids]
    only_funcs = {str(x).lower() for x in getattr(cfg, "only_function_names", []) or []}
    if only_funcs:
        rows = [s for s in rows if str(getattr(s, "func_name", "")).lower() in only_funcs]
    if getattr(cfg, "sample_limit", None) is not None:
        rows = rows[:int(cfg.sample_limit)]
    return rows
