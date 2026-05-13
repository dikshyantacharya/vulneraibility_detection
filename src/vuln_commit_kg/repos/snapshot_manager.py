from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from vuln_commit_kg.config import RepoConfig
from vuln_commit_kg.utils.hashing import safe_name
from vuln_commit_kg.utils.jsonl import append_jsonl
from vuln_commit_kg.analysis_outputs.scaling import dir_size_bytes

from .git_runner import GitError, GitRunner
from .repo_manager import RepoStatus


@dataclass
class SnapshotStatus:
    repo_key: str
    commit_id: str | None
    worktree_path: str | None
    status: str
    error: str | None = None
    elapsed_seconds: float | None = None
    worktree_size_bytes: int | None = None


class SnapshotManager:
    def __init__(self, cfg: RepoConfig, logger: logging.Logger, run_dir: Path | None = None):
        self.cfg = cfg
        self.logger = logger
        self.run_dir = run_dir
        self.git = GitRunner(logger, timeout_seconds=cfg.timeout_seconds)
        self.worktree_root = Path(cfg.worktree_dir)
        self.worktree_root.mkdir(parents=True, exist_ok=True)

    def ensure_snapshot(self, repo_status: RepoStatus, commit_id: str | None) -> SnapshotStatus:
        start_time = time.perf_counter()
        if not self.cfg.enabled:
            status = SnapshotStatus(repo_status.repo_key, commit_id, None, "snapshot_disabled", elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=0)
            self._record(status)
            return status
        if not repo_status.mirror_path or repo_status.status in {"clone_failed", "missing_project_url"}:
            status = SnapshotStatus(repo_status.repo_key, commit_id, None, "repo_unavailable", repo_status.error, elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=0)
            self._record(status)
            return status
        if not commit_id:
            status = SnapshotStatus(repo_status.repo_key, commit_id, None, "missing_commit_id", "commit_id is required", elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=0)
            self._record(status)
            return status

        worktree = self.worktree_root / repo_status.repo_key / safe_name(commit_id, 48)
        mirror_path = Path(repo_status.mirror_path)
        try:
            if self._is_usable_worktree(worktree):
                status = SnapshotStatus(repo_status.repo_key, commit_id, str(worktree), "reused_existing_worktree", elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=dir_size_bytes(worktree))
                self._record(status)
                return status

            if worktree.exists() and self.cfg.clean_failed_worktree:
                # A directory without .git is not a usable snapshot. Remove it,
                # then prune stale mirror registrations before recreating.
                shutil.rmtree(worktree, ignore_errors=True)

            if getattr(self.cfg, "prune_stale_worktrees", True):
                self._prune_stale_worktrees(mirror_path)

            worktree.parent.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Creating worktree {repo_status.repo_key}@{commit_id[:12]} -> {worktree}")
            self._add_worktree(mirror_path, worktree, commit_id, force=False)

            status = SnapshotStatus(repo_status.repo_key, commit_id, str(worktree), "created_worktree", elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=dir_size_bytes(worktree))
            self._record(status)
            return status
        except GitError as exc:
            recovered = self._try_recover_stale_registration(mirror_path, worktree, commit_id, exc)
            if recovered is not None:
                status = SnapshotStatus(repo_status.repo_key, commit_id, str(worktree), recovered, elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=dir_size_bytes(worktree))
                self._record(status)
                return status
            if worktree.exists() and self.cfg.clean_failed_worktree:
                shutil.rmtree(worktree, ignore_errors=True)
            status = SnapshotStatus(repo_status.repo_key, commit_id, str(worktree), "worktree_failed", str(exc), elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=dir_size_bytes(worktree))
            self._record(status)
            self.logger.error(f"Worktree failed for {repo_status.repo_key}@{commit_id}: {exc}")
            return status
        except Exception as exc:
            if worktree.exists() and self.cfg.clean_failed_worktree:
                shutil.rmtree(worktree, ignore_errors=True)
            status = SnapshotStatus(repo_status.repo_key, commit_id, str(worktree), "worktree_failed", str(exc), elapsed_seconds=time.perf_counter() - start_time, worktree_size_bytes=dir_size_bytes(worktree))
            self._record(status)
            self.logger.error(f"Worktree failed for {repo_status.repo_key}@{commit_id}: {exc}")
            return status

    def _is_usable_worktree(self, worktree: Path) -> bool:
        return worktree.exists() and (worktree / ".git").exists()

    def _prune_stale_worktrees(self, mirror_path: Path) -> None:
        try:
            self.git.run(["--git-dir", str(mirror_path), "worktree", "prune"], check=False)
        except Exception as exc:
            self.logger.debug("worktree.prune_failed | mirror=%s | error=%s", mirror_path, exc)

    def _remove_registered_worktree(self, mirror_path: Path, worktree: Path) -> None:
        try:
            self.git.run(["--git-dir", str(mirror_path), "worktree", "remove", "--force", str(worktree)], check=False)
        except Exception as exc:
            self.logger.debug("worktree.remove_registered_failed | mirror=%s | worktree=%s | error=%s", mirror_path, worktree, exc)

    def _add_worktree(self, mirror_path: Path, worktree: Path, commit_id: str, *, force: bool) -> None:
        args = ["--git-dir", str(mirror_path), "worktree", "add"]
        if force:
            args.append("--force")
        args.extend(["--detach", str(worktree), commit_id])
        self.git.run(args)

    @staticmethod
    def _looks_like_stale_registered_worktree_error(exc: GitError) -> bool:
        text = f"{exc.result.stdout}\n{exc.result.stderr}\n{exc}".lower()
        return (
            "missing but already registered worktree" in text
            or "is already a registered worktree" in text
            or "use 'add -f' to override" in text
            or "use 'add -f'" in text
        )

    def _try_recover_stale_registration(self, mirror_path: Path, worktree: Path, commit_id: str, exc: GitError) -> str | None:
        if not self._looks_like_stale_registered_worktree_error(exc):
            return None
        if not getattr(self.cfg, "prune_stale_worktrees", True) and not getattr(self.cfg, "force_recreate_registered_worktree", True):
            return None
        self.logger.warning(
            "worktree.stale_registration_detected | mirror=%s | worktree=%s | retrying_from_cached_mirror=true",
            mirror_path,
            worktree,
        )
        if worktree.exists() and self.cfg.clean_failed_worktree:
            shutil.rmtree(worktree, ignore_errors=True)
        if getattr(self.cfg, "prune_stale_worktrees", True):
            self._prune_stale_worktrees(mirror_path)
        self._remove_registered_worktree(mirror_path, worktree)
        try:
            self._add_worktree(mirror_path, worktree, commit_id, force=bool(getattr(self.cfg, "force_recreate_registered_worktree", True)))
            return "created_worktree_after_prune"
        except GitError as retry_exc:
            self.logger.error("worktree.recovery_failed | mirror=%s | worktree=%s | error=%s", mirror_path, worktree, retry_exc)
            return None

    def _record(self, status: SnapshotStatus) -> None:
        if self.run_dir:
            append_jsonl(self.run_dir / "snapshot_status.jsonl", status)
