from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Iterable

from vuln_commit_kg.config import RepoConfig, RepoInventoryConfig
from vuln_commit_kg.analysis_outputs.scaling import dir_size_bytes
from vuln_commit_kg.repos.git_runner import GitRunner
from vuln_commit_kg.repos.repo_manager import RepoManager, RepoStatus
from vuln_commit_kg.utils.jsonl import append_jsonl, write_json, write_jsonl


_FUNCTION_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_\s\*:&<>~,\[\]]{0,160}\s+"
    r"[A-Za-z_~][A-Za-z0-9_:~]*\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
    re.MULTILINE,
)


def _sample_project_key(sample: Any) -> str:
    return str(getattr(sample, "project_url", None) or getattr(sample, "project", None) or "unknown_project")


def unique_projects_from_samples(samples: Iterable[Any]) -> list[dict[str, Any]]:
    """Return one row per project URL/name, preserving deterministic order.

    The row includes only dataset-level information; repository clone/status
    data is added by RepoInventoryBuilder.
    """
    rows: dict[str, dict[str, Any]] = {}
    for sample in samples:
        project = getattr(sample, "project", None)
        project_url = getattr(sample, "project_url", None)
        key = _sample_project_key(sample)
        row = rows.setdefault(
            key,
            {
                "project_key": key,
                "project": project,
                "project_url": project_url,
                "repo_key": RepoManager.repo_key(project_url, project),
                "dataset_num_samples": 0,
                "dataset_num_vulnerable": 0,
                "dataset_num_fixed": 0,
                "dataset_unique_files": set(),
                "dataset_unique_functions": set(),
                "dataset_commits": set(),
            },
        )
        row["dataset_num_samples"] += 1
        if bool(getattr(sample, "is_vulnerable", False)):
            row["dataset_num_vulnerable"] += 1
        else:
            row["dataset_num_fixed"] += 1
        fp = getattr(sample, "filepath", None)
        fn = getattr(sample, "func_name", None)
        cid = getattr(sample, "commit_id", None)
        if fp:
            row["dataset_unique_files"].add(str(fp))
        if fn:
            row["dataset_unique_functions"].add(str(fn))
        if cid:
            row["dataset_commits"].add(str(cid))
    out: list[dict[str, Any]] = []
    for row in rows.values():
        row["dataset_unique_files"] = len(row["dataset_unique_files"])
        row["dataset_unique_functions"] = len(row["dataset_unique_functions"])
        row["dataset_unique_commits"] = len(row["dataset_commits"])
        row.pop("dataset_commits", None)
        out.append(row)
    out.sort(key=lambda r: (int(r.get("dataset_num_samples") or 0), str(r.get("project") or ""), str(r.get("project_url") or "")))
    return out


class RepoInventory:
    """Read-only helper for persistent repository inventory files."""

    def __init__(self, cfg: RepoInventoryConfig):
        self.cfg = cfg
        self.cache_dir = Path(cfg.cache_dir)
        self.by_key_dir = self.cache_dir / "by_repo_key"

    def project_path(self, repo_key: str) -> Path:
        return self.by_key_dir / f"{repo_key}.json"

    def load_project(self, project_url: str | None, project: str | None = None) -> dict[str, Any] | None:
        repo_key = RepoManager.repo_key(project_url, project)
        path = self.project_path(repo_key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def load_all(self) -> list[dict[str, Any]]:
        if not self.by_key_dir.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(self.by_key_dir.glob("*.json")):
            try:
                rows.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return rows


class RepoInventoryBuilder:
    """Clone/reuse dataset repositories and cache cheap, stable size stats."""

    def __init__(
        self,
        repo_cfg: RepoConfig,
        inv_cfg: RepoInventoryConfig,
        logger: logging.Logger,
        run_dir: Path | None = None,
    ):
        self.repo_cfg = repo_cfg
        self.inv_cfg = inv_cfg
        self.logger = logger
        self.run_dir = run_dir
        self.inventory = RepoInventory(inv_cfg)
        self.repo_manager = RepoManager(repo_cfg, logger, run_dir)
        self.git = GitRunner(logger, timeout_seconds=repo_cfg.timeout_seconds)
        self.inventory.cache_dir.mkdir(parents=True, exist_ok=True)
        self.inventory.by_key_dir.mkdir(parents=True, exist_ok=True)

    def build_for_projects(self, projects: list[dict[str, Any]], limit: int | None = None) -> dict[str, Any]:
        selected = projects[:limit] if limit is not None else list(projects)
        rows: list[dict[str, Any]] = []
        started = time.perf_counter()
        for idx, project_row in enumerate(selected, start=1):
            row = self.prepare_one(project_row, index=idx, total=len(selected))
            rows.append(row)
            if self.run_dir:
                append_jsonl(self.run_dir / "repo_inventory.jsonl", row)
        self._write_indexes(rows)
        summary = self._summary(rows, elapsed=time.perf_counter() - started)
        if self.run_dir:
            write_json(self.run_dir / "repo_inventory_summary.json", summary)
        write_json(self.inventory.cache_dir / "repo_inventory_summary.json", summary)
        return summary

    def prepare_one(self, project_row: dict[str, Any], index: int | None = None, total: int | None = None) -> dict[str, Any]:
        project = project_row.get("project")
        project_url = project_row.get("project_url")
        repo_key = project_row.get("repo_key") or RepoManager.repo_key(project_url, project)
        cached_path = self.inventory.project_path(repo_key)
        if (
            self.inv_cfg.reuse_existing_stats
            and not self.inv_cfg.force_refresh
            and cached_path.exists()
        ):
            try:
                cached = json.loads(cached_path.read_text(encoding="utf-8"))
                mirror_ok = (not cached.get("repo_usable")) or bool(cached.get("mirror_path") and Path(str(cached.get("mirror_path"))).exists())
                clone_mode_ok = cached.get("repo_partial_clone_requested") == self.repo_cfg.partial_clone
                if not mirror_ok or (self.repo_cfg.replace_partial_mirror_with_full_clone and not clone_mode_ok):
                    raise ValueError("cached inventory is stale for current mirror/clone-mode request")
                cached["inventory_status"] = "reused_cached_stats"
                if self.run_dir:
                    append_jsonl(self.run_dir / "repo_inventory_reused.jsonl", cached)
                self.logger.info(
                    "repo_inventory.reuse | %s/%s | project=%s | repo_key=%s | usable=%s",
                    index or "?", total or "?", project, repo_key, cached.get("repo_usable"),
                )
                return cached
            except Exception:
                pass

        self.logger.info(
            "repo_inventory.prepare | %s/%s | project=%s | url=%s",
            index or "?", total or "?", project, project_url,
        )
        repo_status = self.repo_manager.ensure_mirror(project_url, project) if self.inv_cfg.clone_missing else self._existing_status(project_url, project, repo_key)
        row = self._make_row(project_row, repo_status)
        cached_path.parent.mkdir(parents=True, exist_ok=True)
        cached_path.write_text(json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8")
        return row

    def _existing_status(self, project_url: str | None, project: str | None, repo_key: str) -> RepoStatus:
        mirror_path = Path(self.repo_cfg.cache_dir) / f"{repo_key}.git"
        if mirror_path.exists():
            return RepoStatus(project_url, repo_key, str(mirror_path), "reused_existing_mirror", mirror_size_bytes=dir_size_bytes(mirror_path))
        return RepoStatus(project_url, repo_key, None, "missing_mirror", "mirror does not exist", mirror_size_bytes=0)

    def _make_row(self, project_row: dict[str, Any], repo_status: RepoStatus) -> dict[str, Any]:
        row: dict[str, Any] = dict(project_row)
        row.update({
            "repo_key": repo_status.repo_key,
            "repo_status": repo_status.status,
            "repo_error": repo_status.error,
            "mirror_path": repo_status.mirror_path,
            "mirror_size_bytes": repo_status.mirror_size_bytes,
            "repo_partial_clone_requested": self.repo_cfg.partial_clone,
            "repo_filter_spec": self.repo_cfg.filter_spec if self.repo_cfg.partial_clone else None,
            "repo_usable": bool(repo_status.mirror_path and repo_status.status not in {"clone_failed", "missing_project_url", "missing_mirror"}),
            "inventory_status": "computed",
            "inventory_computed_at": time.time(),
        })
        if row["repo_usable"] and self.inv_cfg.compute_commit_count:
            row.update(self._commit_stats(Path(repo_status.mirror_path)))
        if row["repo_usable"] and self.inv_cfg.compute_git_tree_stats:
            tree_stats = self._tree_stats(Path(repo_status.mirror_path))
            row.update(tree_stats)
        return row

    def _commit_stats(self, mirror_path: Path) -> dict[str, Any]:
        out: dict[str, Any] = {}
        try:
            result = self.git.run(["--git-dir", str(mirror_path), "rev-list", "--count", "--all"], check=False)
            if result.returncode == 0:
                out["git_commit_count"] = int((result.stdout or "0").strip() or 0)
            else:
                out["git_commit_count_error"] = (result.stderr or "").strip()[-500:]
        except Exception as exc:
            out["git_commit_count_error"] = str(exc)
        try:
            result = self.git.run(["--git-dir", str(mirror_path), "for-each-ref", "--count=100000", "--format=%(refname)", "refs/heads", "refs/tags"], check=False)
            if result.returncode == 0:
                refs = [x for x in result.stdout.splitlines() if x.strip()]
                out["git_ref_count"] = len(refs)
        except Exception as exc:
            out["git_ref_count_error"] = str(exc)
        return out

    def _tree_stats(self, mirror_path: Path) -> dict[str, Any]:
        exts = {str(x).lower() for x in self.inv_cfg.include_file_types}
        stats: dict[str, Any] = {
            "git_head_commit": None,
            "tree_total_files": 0,
            "tree_total_bytes": 0,
            "tree_source_files": 0,
            "tree_source_bytes": 0,
            "tree_largest_file_bytes": 0,
            "tree_largest_file_path": None,
            "tree_stats_error": None,
            "function_count_approx": None,
        }
        head = self.git.run(["--git-dir", str(mirror_path), "rev-parse", "HEAD"], check=False)
        if head.returncode != 0:
            stats["tree_stats_error"] = (head.stderr or head.stdout or "rev-parse HEAD failed").strip()[-500:]
            return stats
        commit = (head.stdout or "").strip()
        stats["git_head_commit"] = commit
        result = self.git.run(["--git-dir", str(mirror_path), "ls-tree", "-r", "-l", "--full-tree", "HEAD"], check=False)
        if result.returncode != 0:
            stats["tree_stats_error"] = (result.stderr or result.stdout or "ls-tree failed").strip()[-500:]
            return stats
        source_paths: list[tuple[str, int]] = []
        for line in result.stdout.splitlines():
            # Format: mode type object size<TAB>path ; size may be '-'.
            if "\t" not in line:
                continue
            meta, path = line.split("\t", 1)
            parts = meta.split()
            size = 0
            if len(parts) >= 4:
                try:
                    size = int(parts[3]) if parts[3] != "-" else 0
                except Exception:
                    size = 0
            stats["tree_total_files"] += 1
            stats["tree_total_bytes"] += max(size, 0)
            if size > int(stats.get("tree_largest_file_bytes") or 0):
                stats["tree_largest_file_bytes"] = size
                stats["tree_largest_file_path"] = path
            if Path(path).suffix.lower() in exts:
                stats["tree_source_files"] += 1
                stats["tree_source_bytes"] += max(size, 0)
                source_paths.append((path, size))
        if self.inv_cfg.compute_function_count_approx:
            stats["function_count_approx"] = self._approx_function_count(mirror_path, source_paths[: self.inv_cfg.max_files_for_function_scan])
        return stats

    def _approx_function_count(self, mirror_path: Path, source_paths: list[tuple[str, int]]) -> int | None:
        count = 0
        scanned = 0
        for rel, size in source_paths:
            if size > self.inv_cfg.max_file_bytes_for_function_scan:
                continue
            result = self.git.run(["--git-dir", str(mirror_path), "show", f"HEAD:{rel}"], check=False)
            if result.returncode != 0:
                continue
            scanned += 1
            count += len(_FUNCTION_RE.findall(result.stdout or ""))
        return count if scanned else None

    def _write_indexes(self, new_rows: list[dict[str, Any]]) -> None:
        all_rows = self.inventory.load_all()
        # Replace rows by repo_key with newly computed rows so aggregate indexes
        # remain stable across partial runs.
        by_key = {r.get("repo_key"): r for r in all_rows if r.get("repo_key")}
        for row in new_rows:
            if row.get("repo_key"):
                by_key[row["repo_key"]] = row
        rows = list(by_key.values())
        rows.sort(key=lambda r: (
            not bool(r.get("repo_usable")),
            int(r.get("tree_source_bytes") or r.get("mirror_size_bytes") or 10**18),
            int(r.get("tree_source_files") or 10**18),
            str(r.get("project") or ""),
        ))
        write_jsonl(self.inventory.cache_dir / "projects.jsonl", rows)
        write_json(self.inventory.cache_dir / "projects.json", rows)
        write_json(self.inventory.cache_dir / "projects_by_repo_key.json", {r.get("repo_key"): r for r in rows if r.get("repo_key")})
        usable = [r for r in rows if r.get("repo_usable")]
        write_json(self.inventory.cache_dir / "smallest_usable_projects.json", usable[:100])

    def _summary(self, rows: list[dict[str, Any]], elapsed: float) -> dict[str, Any]:
        usable = [r for r in rows if r.get("repo_usable")]
        failed = [r for r in rows if not r.get("repo_usable")]
        return {
            "projects_attempted": len(rows),
            "usable_projects": len(usable),
            "failed_or_unusable_projects": len(failed),
            "elapsed_seconds": elapsed,
            "inventory_cache_dir": str(self.inventory.cache_dir),
            "repo_cache_dir": self.repo_cfg.cache_dir,
            "total_mirror_size_bytes_for_attempted": sum(int(r.get("mirror_size_bytes") or 0) for r in rows),
            "total_tree_source_bytes_for_usable": sum(int(r.get("tree_source_bytes") or 0) for r in usable),
            "smallest_usable_projects": [
                {
                    "project": r.get("project"),
                    "project_url": r.get("project_url"),
                    "repo_key": r.get("repo_key"),
                    "tree_source_files": r.get("tree_source_files"),
                    "tree_source_bytes": r.get("tree_source_bytes"),
                    "mirror_size_bytes": r.get("mirror_size_bytes"),
                    "dataset_num_samples": r.get("dataset_num_samples"),
                }
                for r in sorted(usable, key=lambda x: (int(x.get("tree_source_bytes") or x.get("mirror_size_bytes") or 10**18), str(x.get("project") or "")))[:20]
            ],
            "failed_projects": [
                {"project": r.get("project"), "project_url": r.get("project_url"), "repo_status": r.get("repo_status"), "repo_error": r.get("repo_error")}
                for r in failed[:50]
            ],
        }
