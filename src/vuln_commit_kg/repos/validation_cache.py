from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from vuln_commit_kg.config import ValidationCacheConfig
from vuln_commit_kg.utils.jsonl import append_jsonl


NEGATIVE_STATUSES = {
    "invalid_reference",
    "worktree_failed",
    "repo_unavailable",
    "file_missing",
    "function_missing",
    "function_name_only",
    "low_similarity",
    "validation_error",
    "no_snapshot",
    "missing_commit_id",
    "missing_mirror",
}


def _looks_like_transient_stale_worktree_error(row: dict[str, Any]) -> bool:
    """Return true for old cache rows produced by deleted worktree dirs.

    Those rows are operational failures, not semantic evidence that a commit,
    file, or function is invalid. Reusing them would permanently skip valid
    candidate pairs after the user deletes cache/worktrees.
    """
    text = " ".join(str(row.get(k) or "") for k in ("error", "status", "validation_status")).lower()
    return (
        "missing but already registered worktree" in text
        or "already registered worktree" in text
        or "use 'add -f' to override" in text
        or "use add -f to override" in text
    )


class CommitValidationCache:
    """Append-only cache for target validation/worktree failures.

    It prevents repeated `git worktree add <bad-ref>` calls across scaling runs.
    Positive results may be recorded for diagnostics, but only negative statuses
    are reused to skip work by default.
    """

    def __init__(self, cfg: ValidationCacheConfig):
        self.cfg = cfg
        self.path = Path(cfg.cache_dir) / cfg.filename
        self._loaded = False
        self._latest: dict[str, dict[str, Any]] = {}

    def _key(self, *, repo_key: str | None, commit: str | None, sample_id: str | None, filepath: str | None, function: str | None) -> str:
        return "|".join(str(x or "") for x in (repo_key, commit, sample_id, filepath, function))

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    key = self._key(
                        repo_key=row.get("repo_key"),
                        commit=row.get("commit"),
                        sample_id=row.get("sample_id"),
                        filepath=row.get("filepath"),
                        function=row.get("function"),
                    )
                    self._latest[key] = row
        except Exception:
            self._latest = {}

    def get_negative(self, *, repo_key: str | None, commit: str | None, sample_id: str | None, filepath: str | None, function: str | None) -> dict[str, Any] | None:
        if not self.cfg.enabled or not self.cfg.reuse_negative_results:
            return None
        self._load()
        row = self._latest.get(self._key(repo_key=repo_key, commit=commit, sample_id=sample_id, filepath=filepath, function=function))
        if not row or row.get("status") not in NEGATIVE_STATUSES:
            return None
        # Do not reuse stale worktree-registration failures. They are recoverable
        # by pruning the mirror's worktree registry and recreating the snapshot.
        if _looks_like_transient_stale_worktree_error(row):
            return None
        days = self.cfg.retry_invalid_after_days
        if days is not None:
            ts = float(row.get("timestamp") or 0)
            if ts and (time.time() - ts) > days * 86400:
                return None
        return row

    def record(self, **row: Any) -> None:
        if not self.cfg.enabled:
            return
        row.setdefault("timestamp", time.time())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        append_jsonl(self.path, row)
        key = self._key(repo_key=row.get("repo_key"), commit=row.get("commit"), sample_id=row.get("sample_id"), filepath=row.get("filepath"), function=row.get("function"))
        self._latest[key] = row
