from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from vuln_commit_kg.config import RepoConfig
from vuln_commit_kg.utils.hashing import safe_name, url_hash
from vuln_commit_kg.utils.jsonl import append_jsonl
from vuln_commit_kg.analysis_outputs.scaling import dir_size_bytes

from .git_runner import GitRunner


@dataclass
class RepoStatus:
    project_url: str | None
    repo_key: str
    mirror_path: str | None
    status: str
    error: str | None = None
    elapsed_seconds: float | None = None
    mirror_size_bytes: int | None = None


class RepoManager:
    def __init__(self, cfg: RepoConfig, logger: logging.Logger, run_dir: Path | None = None):
        self.cfg = cfg
        self.logger = logger
        self.run_dir = run_dir
        self.git = GitRunner(logger, timeout_seconds=cfg.timeout_seconds)
        self.cache_dir = Path(cfg.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def repo_key(project_url: str | None, project_name: str | None = None) -> str:
        basis = project_url or project_name or "unknown_project"
        return f"{safe_name(project_name or basis, 48)}__{url_hash(basis)}"

    def ensure_mirror(self, project_url: str | None, project_name: str | None = None) -> RepoStatus:
        start_time = time.perf_counter()
        key = self.repo_key(project_url, project_name)
        if not self.cfg.enabled:
            status = RepoStatus(project_url, key, None, "repo_disabled", elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=0)
            self._record(status)
            return status
        if not project_url:
            status = RepoStatus(project_url, key, None, "missing_project_url", "project_url is required", elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=0)
            self._record(status)
            if self.cfg.skip_if_clone_fails:
                return status
            raise ValueError("project_url is required when repo.enabled=true")

        mirror_path = self.cache_dir / f"{key}.git"
        try:
            if mirror_path.exists() and self._should_replace_partial_mirror(mirror_path):
                self.logger.warning(
                    "Existing mirror for %s appears to be partial/blobless; deleting it because full clone was requested.",
                    project_name or project_url,
                )
                shutil.rmtree(mirror_path, ignore_errors=True)
            if mirror_path.exists() and not self.cfg.use_existing_mirror:
                status = RepoStatus(project_url, key, str(mirror_path), "existing_mirror_disabled", "use_existing_mirror=false", elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=dir_size_bytes(mirror_path))
                self._record(status)
                return status
            if mirror_path.exists():
                if self.cfg.fetch_if_exists:
                    self.logger.info("Fetching existing mirror for %s -> %s", project_name or project_url, mirror_path)
                    cmd = ["--git-dir", str(mirror_path), "fetch", "--all", "--prune"]
                    if self.cfg.clone_progress:
                        cmd.append("--progress")
                    if self.cfg.passthrough_git_output:
                        self.git.run_passthrough(cmd)
                    else:
                        self.git.run(cmd)
                    state = "fetched_existing_mirror"
                else:
                    self.logger.info("Reusing existing mirror for %s -> %s", project_name or project_url, mirror_path)
                    state = "reused_existing_mirror"
            else:
                if not self.cfg.clone_if_missing:
                    status = RepoStatus(project_url, key, None, "missing_mirror", "mirror missing and clone_if_missing=false", elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=0)
                    self._record(status)
                    self.logger.warning("repo.missing_mirror | project=%s | repo_key=%s | clone_if_missing=false", project_name or project_url, key)
                    return status
                clone_args = ["clone", "--mirror"]
                if self.cfg.clone_progress:
                    clone_args.append("--progress")
                if self.cfg.partial_clone and self.cfg.filter_spec:
                    clone_args.extend([f"--filter={self.cfg.filter_spec}"])
                clone_args.extend([project_url, str(mirror_path)])
                self.logger.info(
                    "Cloning mirror for %s -> %s | partial_clone=%s filter=%s",
                    project_name or project_url,
                    mirror_path,
                    self.cfg.partial_clone,
                    self.cfg.filter_spec if self.cfg.partial_clone else None,
                )
                self.logger.info("Git will print clone progress directly below this line when available.")
                if self.cfg.passthrough_git_output:
                    self.git.run_passthrough(clone_args)
                else:
                    self.git.run(clone_args)
                state = "cloned_mirror"
            status = RepoStatus(project_url, key, str(mirror_path), state, elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=dir_size_bytes(mirror_path))
            self._record(status)
            return status
        except Exception as exc:
            status = RepoStatus(project_url, key, str(mirror_path), "clone_failed", str(exc), elapsed_seconds=time.perf_counter() - start_time, mirror_size_bytes=dir_size_bytes(mirror_path))
            self._record(status)
            if self.cfg.skip_if_clone_fails:
                self.logger.error(f"Clone failed for {project_url}: {exc}")
                return status
            raise

    def _should_replace_partial_mirror(self, mirror_path: Path) -> bool:
        if self.cfg.partial_clone:
            return False
        if not getattr(self.cfg, "replace_partial_mirror_with_full_clone", False):
            return False
        try:
            result = self.git.run(["--git-dir", str(mirror_path), "config", "--get", "remote.origin.promisor"], check=False)
            return str(result.stdout or "").strip().lower() in {"true", "1", "yes"}
        except Exception:
            return False

    def _record(self, status: RepoStatus) -> None:
        if self.run_dir:
            append_jsonl(self.run_dir / "repo_status.jsonl", status)
