from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from pathlib import Path

from vuln_commit_kg.config import SnapshotConfig
from vuln_commit_kg.data.schema import SecVulEvalSample

from .git_runner import GitRunner
from .repo_manager import RepoStatus


@dataclass
class CommitCandidate:
    label: str
    commit_id: str


@dataclass
class CommitResolution:
    sample_id: str
    project: str | None
    filepath: str | None
    func_name: str | None
    dataset_commit_id: str | None
    selected_commit_id: str | None
    selected_label: str | None
    strategy: str
    selected_status: str | None
    selected_similarity: float | None
    candidates: list[dict]
    selected_artifact_dir: str | None = None
    warning: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class CommitResolver:
    """Resolve the deterministic snapshot commit for a SecVulEval sample.

    SecVulEval is patch-based: the dataset card says patches are collected from
    repositories; vulnerable rows contain deleted lines/statements, and
    non-vulnerable rows contain added lines/statements. Therefore the intended
    deterministic repository state is:

    * vulnerable sample -> first parent of the patch commit, before the fix
    * fixed/non-vulnerable sample -> the patch commit itself, after the fix

    This resolver deliberately does not perform open-ended history search.
    """

    def __init__(self, cfg: SnapshotConfig, logger: logging.Logger, run_dir: Path | None = None):
        self.cfg = cfg
        self.logger = logger
        self.run_dir = run_dir
        self.git = GitRunner(logger)

    def candidates(self, repo_status: RepoStatus, sample: SecVulEvalSample) -> list[CommitCandidate]:
        commit = sample.commit_id
        if not commit:
            return []
        strategy = self.cfg.commit_resolution

        if strategy == "dataset_commit" or not repo_status.mirror_path:
            return [CommitCandidate("dataset_commit", commit)]

        if strategy == "secvuleval_patch":
            if sample.is_vulnerable:
                parent = self._rev_parse(repo_status.mirror_path, f"{commit}^1")
                if not parent:
                    self.logger.warning(
                        "commit_resolution.parent_missing | sample=%s | commit=%s | strategy=secvuleval_patch",
                        sample.sample_id,
                        commit[:12],
                    )
                    return [CommitCandidate("dataset_commit_parent_missing", commit)]
                return [CommitCandidate("pre_fix_parent_for_vulnerable", parent)]
            return [CommitCandidate("patch_commit_for_fixed", commit)]

        parent = self._rev_parse(repo_status.mirror_path, f"{commit}^1")
        if not parent:
            self.logger.warning(
                "commit_resolution.parent_missing | sample=%s | commit=%s | strategy=%s",
                sample.sample_id,
                commit[:12],
                strategy,
            )
            return [CommitCandidate("dataset_commit_parent_missing", commit)]

        if strategy == "parent_for_vulnerable":
            return [CommitCandidate("parent_1", parent)] if sample.is_vulnerable else [CommitCandidate("dataset_commit", commit)]
        if strategy == "parent_for_all":
            return [CommitCandidate("parent_1", parent)]
        return [CommitCandidate("dataset_commit", commit)]

    def _rev_parse(self, mirror_path: str | Path, expr: str) -> str | None:
        try:
            result = self.git.run(["--git-dir", str(mirror_path), "rev-parse", "--verify", expr], check=False)
            if result.returncode != 0:
                return None
            value = result.stdout.strip().splitlines()[-1].strip()
            return value or None
        except Exception as exc:
            self.logger.warning("commit_resolution.rev_parse_failed | expr=%s | error=%s", expr, exc)
            return None
