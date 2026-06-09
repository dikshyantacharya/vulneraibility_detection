from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Any

from vuln_commit_kg.config import AppConfig, KGConfig, load_config
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_cache import GraphCache
from vuln_commit_kg.repos.commit_resolver import CommitResolver, CommitResolution
from vuln_commit_kg.repos.repo_manager import RepoManager
from vuln_commit_kg.repos.snapshot_manager import SnapshotStatus, SnapshotManager
from vuln_commit_kg.repos.target_validator import TargetValidation, TargetValidator
from vuln_commit_kg.utils.jsonl import append_jsonl

from .config import ChallengeCreatorConfig
from .records import ChallengeRecord, make_kg_id
from .progress import fmt_duration


_WORKTREE_FATAL_MARKERS = (
    "filename too long",
    "invalid path",
    "invalid reference",
    "could not reset index file",
    "cannot create directory",
)


class ChallengeKGMaterializer:
    """Resolve snapshots, build/reuse CodeKG graphs, and emit challenge records.

    This challenge materializer deliberately reuses the production VCKG repository,
    snapshot, validation and CodeKG cache layers.  It is conservative: only rows
    whose target function is found with high source-body similarity are released
    to students.
    """

    def __init__(self, cfg: ChallengeCreatorConfig, *, work_dir: Path, logger: logging.Logger):
        self.cfg = cfg
        self.work_dir = Path(work_dir)
        self.logger = logger
        self.vckg_cfg = self._load_base_config()
        self._bad_repo_keys: dict[str, str] = {}
        self._apply_challenge_overrides()
        self.repo_manager = RepoManager(self.vckg_cfg.repo, logger, self.work_dir)
        self.snapshot_manager = SnapshotManager(self.vckg_cfg.repo, logger, self.work_dir)
        self.resolver = CommitResolver(self.vckg_cfg.snapshot, logger, self.work_dir)
        # Correct TargetValidator signature: (logger, artifact_root, save_artifacts).
        self.validator = TargetValidator(logger, self.work_dir / "target_validation", True)
        self.graph_cache = GraphCache(self.vckg_cfg.kg, logger)

    def _load_base_config(self) -> AppConfig:
        base_path = self.cfg.input.base_vckg_config
        if base_path and Path(base_path).exists():
            return load_config(base_path)
        return AppConfig()

    def _apply_challenge_overrides(self) -> None:
        kg: KGConfig = self.vckg_cfg.kg
        kg.cache_mode = "persistent"
        kg.cache_dir = self.cfg.kg.cache_dir
        kg.persistent_cache_dir = self.cfg.kg.cache_dir
        kg.backend = self.cfg.kg.backend
        kg.joern_home = self.cfg.kg.joern_home
        kg.require_joern = self.cfg.kg.require_joern
        kg.joern_language = self.cfg.kg.joern_language
        kg.joern_timeout_seconds = self.cfg.kg.joern_timeout_seconds
        kg.force_rebuild = self.cfg.kg.force_rebuild
        kg.build_if_missing = self.cfg.kg.build_if_missing
        kg.use_codekg = True

        # Challenge rows should be deterministic SecVulEval snapshots.
        self.vckg_cfg.snapshot.commit_resolution = "secvuleval_patch"
        self.vckg_cfg.snapshot.body_match_threshold = self.cfg.selection.body_match_threshold
        self.vckg_cfg.snapshot.require_function_found = False
        self.vckg_cfg.snapshot.validate_target_function = True

        # Keep challenge creation responsive.  Very large/Windows-hostile repos
        # are skipped instead of blocking the whole build for minutes.
        if getattr(self.cfg.input, "git_timeout_seconds", None):
            self.vckg_cfg.repo.timeout_seconds = int(self.cfg.input.git_timeout_seconds)
        if getattr(self.cfg.input, "worktree_dir", None):
            self.vckg_cfg.repo.worktree_dir = str(self.cfg.input.worktree_dir)
        self.vckg_cfg.repo.clone_if_missing = bool(getattr(self.cfg.input, "clone_if_missing", False))

    def materialize_sample(self, sample: SecVulEvalSample, *, private_kg_store: Path | None = None) -> ChallengeRecord | None:
        t0 = time.time()
        repo_status = self.repo_manager.ensure_mirror(sample.project_url, sample.project)
        if repo_status.repo_key in self._bad_repo_keys:
            self.logger.warning(
                "challenge.skip_bad_repo | sample=%s | repo_key=%s | reason=%s",
                sample.sample_id,
                repo_status.repo_key,
                self._bad_repo_keys[repo_status.repo_key],
            )
            return None
        if repo_status.status in {"clone_failed", "missing_project_url", "missing_mirror", "repo_disabled"}:
            self.logger.warning(
                "challenge.skip_repo | sample=%s | repo_status=%s | error=%s",
                sample.sample_id,
                repo_status.status,
                repo_status.error,
            )
            return None

        resolve_start = time.time()
        resolution = self._resolve_best_sample(sample, repo_status)
        self.logger.info("challenge.resolve.done | sample=%s | project=%s | commit=%s | status=%s | similarity=%s | time=%s", sample.sample_id, sample.project, str(resolution.selected_commit_id or "")[:12], resolution.selected_status, resolution.selected_similarity, fmt_duration(time.time() - resolve_start))
        if not resolution.selected_commit_id:
            self.logger.warning("challenge.skip_no_commit | sample=%s", sample.sample_id)
            return None
        if resolution.warning:
            self.logger.warning("challenge.skip_resolution_warning | sample=%s | warning=%s", sample.sample_id, resolution.warning)
            return None
        if resolution.selected_status in {"file_missing", "function_missing", "validation_error", "no_snapshot", "function_name_only", "worktree_failed"}:
            self.logger.warning("challenge.skip_invalid_target | sample=%s | status=%s", sample.sample_id, resolution.selected_status)
            return None
        if resolution.selected_similarity is not None and resolution.selected_similarity < self.cfg.selection.body_match_threshold:
            self.logger.warning("challenge.skip_low_similarity | sample=%s | sim=%s", sample.sample_id, resolution.selected_similarity)
            return None

        snap_start = time.time()
        snap = self.snapshot_manager.ensure_snapshot(repo_status, resolution.selected_commit_id)
        self.logger.info("challenge.snapshot.done | sample=%s | project=%s | status=%s | time=%s", sample.sample_id, sample.project, snap.status, fmt_duration(time.time() - snap_start))
        if not self._snapshot_ok(snap):
            self._maybe_mark_bad_repo(repo_status.repo_key, snap)
            self.logger.warning("challenge.skip_snapshot | sample=%s | status=%s | error=%s", sample.sample_id, snap.status, snap.error)
            return None

        kg_start = time.time()
        self.logger.info("challenge.kg.start | sample=%s | project=%s | function=%s | commit=%s", sample.sample_id, sample.project, sample.func_name, resolution.selected_commit_id[:12])
        graph, graph_dir, graph_status = self.graph_cache.get_or_build(
            Path(snap.worktree_path), sample.project, sample.project_url, resolution.selected_commit_id
        )
        self.logger.info("challenge.kg.done | sample=%s | project=%s | status=%s | time=%s | graph_dir=%s", sample.sample_id, sample.project, graph_status, fmt_duration(time.time() - kg_start), graph_dir)
        manifest = getattr(graph, "manifest", {}) or {}
        kg_id = make_kg_id(sample, repo_status.repo_key, resolution.selected_commit_id)
        final_graph_dir = Path(graph_dir)
        if private_kg_store is not None and self.cfg.kg.copy_kg_artifacts and self.cfg.kg.kg_store_mode == "copy":
            final_graph_dir = private_kg_store / kg_id
            self._copy_graph_dir(Path(graph_dir), final_graph_dir)

        rec = ChallengeRecord(
            sample_id=str(sample.sample_id),
            project=sample.project,
            project_url=sample.project_url,
            repo_key=repo_status.repo_key,
            filepath=sample.filepath,
            function_name=sample.func_name,
            function=sample.func_body,
            vulnerability=1 if sample.is_vulnerable else 0,
            dataset_commit=sample.commit_id,
            resolved_commit=resolution.selected_commit_id,
            resolved_label=resolution.selected_label,
            target_status=resolution.selected_status,
            target_similarity=resolution.selected_similarity,
            knowledge_graph_id=kg_id,
            graph_dir=str(final_graph_dir),
            dashboard_path=str((final_graph_dir / "dashboard" / "index.html").resolve()) if (final_graph_dir / "dashboard" / "index.html").exists() else manifest.get("dashboard_path"),
            cve_list=list(sample.cve_list or []),
            cwe_list=list(sample.cwe_list or []),
        )
        self.logger.info(
            "challenge.kg_ready | sample=%s | project=%s | label=%s | commit=%s | kg=%s | status=%s | total_time=%s",
            sample.sample_id,
            sample.project,
            rec.vulnerability,
            resolution.selected_commit_id[:12],
            kg_id,
            graph_status,
            fmt_duration(time.time() - t0),
        )
        append_jsonl(self.work_dir / "materialized_records.jsonl", rec.private_row())
        return rec

    @staticmethod
    def _snapshot_ok(snap: SnapshotStatus) -> bool:
        return bool(snap.worktree_path) and snap.status in {"created_worktree", "reused_existing_worktree", "created_worktree_after_prune"}

    def _maybe_mark_bad_repo(self, repo_key: str, snap: SnapshotStatus) -> None:
        text = f"{snap.status} {snap.error or ''}".lower()
        if any(marker in text for marker in _WORKTREE_FATAL_MARKERS):
            self._bad_repo_keys[repo_key] = snap.error or snap.status

    def _resolve_best_sample(self, sample: SecVulEvalSample, repo_status: Any) -> CommitResolution:
        candidates = self.resolver.candidates(repo_status, sample)
        records: list[dict[str, Any]] = []
        best: tuple[float, str, str, TargetValidation | None, SnapshotStatus] | None = None

        for cand in candidates:
            if repo_status.repo_key in self._bad_repo_keys:
                break
            snap = self.snapshot_manager.ensure_snapshot(repo_status, cand.commit_id)
            if not self._snapshot_ok(snap):
                self._maybe_mark_bad_repo(repo_status.repo_key, snap)
                validation = TargetValidation(sample.sample_id, "worktree_failed", False, False, 0.0, error=snap.error)
            else:
                validation = self.validator.validate(
                    Path(snap.worktree_path),
                    sample,
                    candidate_commit_id=cand.commit_id,
                    candidate_label=cand.label,
                )
            rec = {
                "sample_id": sample.sample_id,
                "candidate_label": cand.label,
                "candidate_commit_id": cand.commit_id,
                "snapshot_status": snap.__dict__,
                "validation": validation.__dict__ if validation else None,
            }
            records.append(rec)
            sim = float(validation.body_similarity if validation else 0.0)
            score = sim
            if validation and validation.function_found:
                score += 0.10
            if validation and validation.filepath_exists:
                score += 0.05
            if validation and validation.status == "match_exact":
                score += 0.20
            if best is None or score > best[0]:
                best = (score, cand.commit_id, cand.label, validation, snap)

        if best is None:
            return CommitResolution(
                sample_id=sample.sample_id,
                project=sample.project,
                filepath=sample.filepath,
                func_name=sample.func_name,
                dataset_commit_id=sample.commit_id,
                selected_commit_id=sample.commit_id,
                selected_label="dataset_commit",
                strategy=self.vckg_cfg.snapshot.commit_resolution,
                selected_status=None,
                selected_similarity=None,
                candidates=records,
                warning="no_commit_candidate_available",
            )

        _, commit, label, validation, snap = best
        warning = None
        sim = validation.body_similarity if validation else None
        status = validation.status if validation else None
        if status == "worktree_failed":
            warning = f"worktree failed: {snap.error}"
        elif sim is not None and sim < self.cfg.selection.body_match_threshold:
            warning = f"best candidate similarity {sim:.4f} is below threshold {self.cfg.selection.body_match_threshold:.4f}"

        res = CommitResolution(
            sample_id=sample.sample_id,
            project=sample.project,
            filepath=sample.filepath,
            func_name=sample.func_name,
            dataset_commit_id=sample.commit_id,
            selected_commit_id=commit,
            selected_label=label,
            strategy=self.vckg_cfg.snapshot.commit_resolution,
            selected_status=status,
            selected_similarity=sim,
            candidates=records,
            selected_artifact_dir=validation.artifact_dir if validation else None,
            warning=warning,
        )
        append_jsonl(self.work_dir / "target_resolution.jsonl", res.to_dict())
        return res

    def _copy_graph_dir(self, src: Path, dst: Path) -> None:
        if dst.exists() and not self.cfg.kg.force_rebuild:
            return
        if dst.exists():
            shutil.rmtree(dst)
        ignore = shutil.ignore_patterns("*.tmp", "joern/workspace", "joern/cpg.bin.tmp")
        shutil.copytree(src, dst, ignore=ignore)
