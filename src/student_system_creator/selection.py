from __future__ import annotations

import fnmatch
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from vuln_commit_kg.data.pair_candidates import read_pair_candidate_cache
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.repos.repo_manager import RepoManager

from .config import ChallengeCreatorConfig


_SIZE_KEYS = [
    "total_size_bytes",
    "repo_size_bytes",
    "mirror_size_bytes",
    "worktree_size_bytes",
    "checkout_size_bytes",
    "disk_size_bytes",
    "source_size_bytes",
    "source_bytes",
    "bytes",
    "size_bytes",
    "total_bytes",
]
_COUNT_KEYS = [
    "source_files",
    "c_files",
    "cpp_files",
    "files",
    "file_count",
    "total_files",
    "function_count",
    "functions",
]


def _function_ok(sample: SecVulEvalSample, min_chars: int, max_chars: int | None) -> bool:
    body = sample.func_body or ""
    if len(body.strip()) < min_chars:
        return False
    if max_chars is not None and len(body) > max_chars:
        return False
    if not sample.project or not sample.func_name or not sample.filepath:
        return False
    return True


def _project_skipped(sample: SecVulEvalSample, cfg: ChallengeCreatorConfig) -> bool:
    values = {
        str(sample.project or "").lower(),
        str(sample.project_url or "").lower(),
        RepoManager.repo_key(sample.project_url, sample.project).lower(),
    }
    exact = {str(x).strip().lower() for x in (cfg.selection.skip_projects or []) if str(x).strip()}
    if values & exact:
        return True
    patterns = [str(x).strip().lower() for x in (cfg.selection.skip_project_patterns or []) if str(x).strip()]
    return any(fnmatch.fnmatch(v, pat) or pat in v for v in values for pat in patterns)


def _iter_json_rows(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        if path.suffix.lower() == ".jsonl":
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
        elif path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, list):
                rows.extend(x for x in data if isinstance(x, dict))
            elif isinstance(data, dict):
                for key in ["rows", "projects", "data", "items", "entries", "repos", "repositories"]:
                    vals = data.get(key)
                    if isinstance(vals, list):
                        rows.extend(x for x in vals if isinstance(x, dict))
                    elif isinstance(vals, dict):
                        rows.extend(x for x in vals.values() if isinstance(x, dict))
                # Some caches are already mapping repo_key -> metadata.
                for k, v in data.items():
                    if isinstance(v, dict):
                        vv = dict(v)
                        vv.setdefault("repo_key", k)
                        rows.append(vv)
    except Exception:
        return []
    return rows


def _inventory_rows(inventory_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(inventory_dir)
    names = [
        "projects.jsonl",
        "repo_inventory.jsonl",
        "inventory.jsonl",
        "project_stats.jsonl",
        "project_sizes.jsonl",
        "repo_stats.jsonl",
        "repo_sizes.jsonl",
        "projects.json",
        "repo_inventory.json",
        "inventory.json",
        "project_stats.json",
        "project_sizes.json",
        "repo_stats.json",
        "repo_sizes.json",
    ]
    rows: list[dict[str, Any]] = []
    for name in names:
        rows.extend(_iter_json_rows(root / name))
    return rows


def _repo_key_from_row(row: dict[str, Any]) -> str | None:
    key = row.get("repo_key") or row.get("key") or row.get("repository_key")
    if key:
        return str(key)
    project = row.get("project") or row.get("project_name") or row.get("name")
    url = row.get("project_url") or row.get("repo_url") or row.get("url") or row.get("repository_url")
    if project or url:
        return RepoManager.repo_key(url, project)
    return None


def _numeric(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except Exception:
        return None
    if not math.isfinite(f) or f < 0:
        return None
    return f


def _row_size_score(row: dict[str, Any]) -> float | None:
    # Prefer byte-like measurements if available.
    for key in _SIZE_KEYS:
        f = _numeric(row.get(key))
        if f is not None:
            return f
    # Otherwise approximate from counts. The absolute unit does not matter; only ordering does.
    score = 0.0
    found = False
    for key in _COUNT_KEYS:
        f = _numeric(row.get(key))
        if f is not None:
            score += f * 1000.0
            found = True
    return score if found else None


def load_project_size_scores(inventory_dir: str | Path) -> dict[str, float]:
    """Load cached project size/order information from repo inventory caches.

    This intentionally supports many field names because existing VCKG cache files
    can vary between runs. When no explicit size is present, it falls back to file
    or function counts. Smaller score means earlier build order.
    """
    scores: dict[str, float] = {}
    for row in _inventory_rows(inventory_dir):
        key = _repo_key_from_row(row)
        if not key:
            continue
        score = _row_size_score(row)
        if score is None:
            continue
        if key not in scores or score < scores[key]:
            scores[key] = score
    return scores


def load_usable_repo_keys(inventory_dir: str | Path) -> set[str]:
    usable: set[str] = set()
    for row in _inventory_rows(inventory_dir):
        key = _repo_key_from_row(row)
        if not key:
            continue
        status = str(row.get("status") or row.get("mirror_status") or "").lower()
        explicit_usable = row.get("usable")
        if explicit_usable is True or status in {
            "usable",
            "ok",
            "ready",
            "reused_existing_mirror",
            "cloned_mirror",
            "fetched_existing_mirror",
        }:
            usable.add(str(key))
    return usable


def _sample_repo_key(sample: SecVulEvalSample) -> str:
    return RepoManager.repo_key(sample.project_url, sample.project)


def _project_order_key(repo_key: str, size_scores: dict[str, float], cfg: ChallengeCreatorConfig) -> tuple[float, str]:
    if not cfg.selection.order_by_project_size:
        return (0.0, repo_key)
    if repo_key in size_scores:
        return (float(size_scores[repo_key]), repo_key)
    return ((float("inf") if cfg.selection.unknown_size_last else 0.0), repo_key)


def _select_from_pair_cache(samples: list[SecVulEvalSample], cfg: ChallengeCreatorConfig) -> list[SecVulEvalSample]:
    path = Path(cfg.input.pair_candidate_cache_path)
    if not (cfg.input.use_pair_candidate_cache and cfg.selection.prefer_validated_pair_cache and path.exists()):
        return []
    rows = read_pair_candidate_cache(path)
    by_id = {str(s.sample_id): s for s in samples}
    by_idx = {int(s.idx): s for s in samples}
    selected_pairs: list[tuple[str, list[SecVulEvalSample]]] = []
    seen_projects: set[str] = set()
    usable_keys = load_usable_repo_keys(cfg.input.repo_inventory_dir) if cfg.input.require_repo_inventory_usable else set()
    size_scores = load_project_size_scores(cfg.input.repo_inventory_dir)

    for row in rows:
        pair_samples: list[SecVulEvalSample] = []
        for sample_id_key, idx_key in [("vulnerable_sample_id", "vulnerable_idx"), ("fixed_sample_id", "fixed_idx")]:
            sample = by_id.get(str(row.get(sample_id_key)))
            if sample is None:
                try:
                    sample = by_idx.get(int(row.get(idx_key)))
                except Exception:
                    sample = None
            if sample is not None:
                pair_samples.append(sample)
        if not pair_samples:
            continue
        project_key = _sample_repo_key(pair_samples[0])
        if project_key in seen_projects:
            continue
        if usable_keys and project_key not in usable_keys:
            continue
        if any(_project_skipped(s, cfg) for s in pair_samples):
            continue
        if not all(_function_ok(s, cfg.selection.min_function_chars, cfg.selection.max_function_chars) for s in pair_samples):
            continue
        seen_projects.add(project_key)
        selected_pairs.append((project_key, pair_samples[: cfg.selection.max_functions_per_project]))

    selected_pairs.sort(key=lambda kv: _project_order_key(kv[0], size_scores, cfg))
    if cfg.selection.max_projects is not None:
        selected_pairs = selected_pairs[: cfg.selection.max_projects]

    selected: list[SecVulEvalSample] = []
    selected_ids: set[str] = set()
    for _, pair_samples in selected_pairs:
        # Keep vulnerable then safe order inside each pair for easier progress interpretation.
        pair_samples = sorted(pair_samples, key=lambda s: (-int(bool(s.is_vulnerable)), str(s.sample_id)))
        for sample in pair_samples:
            sid = str(sample.sample_id)
            if sid not in selected_ids:
                selected.append(sample)
                selected_ids.add(sid)
    return selected


def select_candidate_samples(samples: Iterable[SecVulEvalSample], cfg: ChallengeCreatorConfig) -> list[SecVulEvalSample]:
    samples = list(samples)
    cached = _select_from_pair_cache(samples, cfg)
    if cached:
        return cached

    rng = random.Random(cfg.selection.seed)
    usable_keys = load_usable_repo_keys(cfg.input.repo_inventory_dir) if cfg.input.require_repo_inventory_usable else set()
    size_scores = load_project_size_scores(cfg.input.repo_inventory_dir)
    by_project: dict[str, dict[int, list[SecVulEvalSample]]] = defaultdict(lambda: {0: [], 1: []})

    for sample in samples:
        if _project_skipped(sample, cfg):
            continue
        if not _function_ok(sample, cfg.selection.min_function_chars, cfg.selection.max_function_chars):
            continue
        repo_key = _sample_repo_key(sample)
        if usable_keys and repo_key not in usable_keys:
            continue
        label = 1 if sample.is_vulnerable else 0
        by_project[repo_key][label].append(sample)

    project_keys = sorted(by_project, key=lambda k: _project_order_key(k, size_scores, cfg))
    if not cfg.selection.order_by_project_size:
        rng.shuffle(project_keys)
    if cfg.selection.max_projects is not None:
        project_keys = project_keys[: cfg.selection.max_projects]

    selected: list[SecVulEvalSample] = []
    for key in project_keys:
        label_groups = by_project[key]
        per_project: list[SecVulEvalSample] = []
        for label in [1, 0]:
            group = list(label_groups[label])
            group.sort(key=lambda s: (len(s.func_body or ""), str(s.sample_id)))
            if group:
                per_project.extend(group[: cfg.selection.max_functions_per_label_per_project])
        selected.extend(per_project[: cfg.selection.max_functions_per_project])
    return selected


def split_records(records, cfg: ChallengeCreatorConfig):
    rng = random.Random(cfg.selection.seed)
    size_scores = load_project_size_scores(cfg.input.repo_inventory_dir)
    by_project: dict[str, dict[int, list]] = defaultdict(lambda: {0: [], 1: []})
    for rec in records:
        by_project[rec.repo_key][int(rec.vulnerability)].append(rec)

    pair_projects = [k for k, v in by_project.items() if v[0] and v[1]]
    pair_projects.sort(key=lambda k: _project_order_key(k, size_scores, cfg))
    if not cfg.selection.order_by_project_size:
        rng.shuffle(pair_projects)
    wanted_projects = min(cfg.selection.test_projects, len(pair_projects))
    if cfg.selection.strict_test_size and wanted_projects < cfg.selection.test_projects:
        raise RuntimeError(
            f"Requested {cfg.selection.test_projects} paired test projects, but only {len(pair_projects)} are available."
        )
    test_project_set = set(pair_projects[:wanted_projects])
    test_records = []
    train_records = []
    for repo_key, groups in by_project.items():
        if repo_key in test_project_set:
            for label in [1, 0]:
                groups[label].sort(key=lambda r: str(r.sample_id))
                rec = groups[label][0]
                rec.split = "test"
                test_records.append(rec)
                for extra in groups[label][1:]:
                    extra.split = "train"
                    train_records.append(extra)
        else:
            for label in [1, 0]:
                for rec in groups[label]:
                    rec.split = "train"
                    train_records.append(rec)
    test_records.sort(key=lambda r: (_project_order_key(r.repo_key, size_scores, cfg), -r.vulnerability, str(r.sample_id)))
    train_records.sort(key=lambda r: (_project_order_key(r.repo_key, size_scores, cfg), -r.vulnerability, str(r.sample_id)))
    if cfg.selection.strict_test_size and len(test_records) != cfg.selection.test_functions:
        raise RuntimeError(f"Requested {cfg.selection.test_functions} test functions, got {len(test_records)}")
    return train_records, test_records
