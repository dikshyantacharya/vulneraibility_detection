from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import fnmatch
import json
import re
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from typing import Any

from vuln_commit_kg.agents.agent_controller import AgentController
from vuln_commit_kg.agents.prompts import SYSTEM_PROMPT, final_decision_prompt, risk_hypothesis_prompt
from vuln_commit_kg.analysis.project_scanner import project_stats_rows, write_project_scan_outputs
from vuln_commit_kg.analysis.pair_scanner import pair_rows, write_pair_scan_outputs
from vuln_commit_kg.agents.schemas import AgentTrace, Prediction
from vuln_commit_kg.agents.reporting import write_agent_demo_index, write_sample_agent_demo
from vuln_commit_kg.config import AppConfig, save_config
from vuln_commit_kg.data.dataset_loader import load_samples, smoke_samples
from vuln_commit_kg.data.sample_selector import group_by_project_commit, select_samples, summarize_projects, find_vulnerable_fixed_pairs
from vuln_commit_kg.data.pair_candidates import read_pair_candidate_cache, write_pair_candidate_cache
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.evaluation.binary import binary_metrics
from vuln_commit_kg.evaluation.statement import statement_metrics
from vuln_commit_kg.evaluation.usage import usage_summary
from vuln_commit_kg.evaluation.visualize import make_visualizations, save_metric_tables
from vuln_commit_kg.analysis_outputs.scaling import dir_size_bytes, write_scaling_analysis
from vuln_commit_kg.analysis_outputs.live_dashboard import LiveDashboard
from vuln_commit_kg.api_limits import RateLimiter, fetch_provider_quota_headers, parse_rate_limit_headers
from vuln_commit_kg.kg.graph_cache import GraphCache
from vuln_commit_kg.kg.graph_store import ProjectGraph
from vuln_commit_kg.kg.project_graph_builder import ProjectGraphBuilder
from vuln_commit_kg.logging_utils import ProgressMeter, log_kv, profile, setup_logging
from vuln_commit_kg.models.factory import build_model
from vuln_commit_kg.models.token_counter import TokenCounter
from vuln_commit_kg.repos.repo_manager import RepoManager
from vuln_commit_kg.repos.inventory import RepoInventory, RepoInventoryBuilder, unique_projects_from_samples
from vuln_commit_kg.repos.commit_resolver import CommitResolver, CommitResolution
from vuln_commit_kg.repos.snapshot_manager import SnapshotManager
from vuln_commit_kg.repos.target_validator import TargetValidator
from vuln_commit_kg.repos.validation_cache import CommitValidationCache
from vuln_commit_kg.retrieval.evidence_retriever import EvidenceRetriever
from vuln_commit_kg.utils.jsonl import append_jsonl, write_json, write_jsonl
from vuln_commit_kg.utils.paths import make_run_dir


def _enrich_call_parse_result(call: dict[str, Any]) -> None:
    """Post-parse enrichment: extract <answer> JSON and add parse diagnostics to call record.

    Mutates *call* in-place adding:
      parsed_answer, answer_text, parse_status, parse_error, json_status (updated).

    Called once after run_agentic_proof_pipeline() returns so model_calls.jsonl is
    rewritten with parse diagnostics. Tests import this function directly.
    """
    from vckg_agentic_proof.parser import extract_answer_text, ANSWER_RE

    name = call.get("name") or ""

    # final_decision is a synthetic record already validated; mark it directly.
    if name == "final_decision" or call.get("json_status") == "json_ok":
        call.setdefault("parse_status", "valid")
        call.setdefault("parsed_answer", call.get("parsed") or call.get("parsed_answer"))
        call.setdefault("answer_text", call.get("response") or "")
        return

    # Error stages: no response to parse.
    if call.get("error") or not (call.get("response") or "").strip():
        call["parse_status"] = "failed"
        return

    response = call.get("response") or ""
    try:
        _, answer_text = extract_answer_text(response)
        has_answer_tag = bool(ANSWER_RE.search(response))
        call["answer_text"] = answer_text
        if answer_text:
            try:
                parsed = json.loads(answer_text)
                call["parsed_answer"] = parsed
                call["parse_status"] = "valid"
                call["json_status"] = "json_ok"
            except Exception as e:
                call["parse_status"] = "invalid"
                call["parse_error"] = str(e)
                call["json_status"] = "json_invalid"
        else:
            # extract_answer_text fell back to the full response (no <answer> tag)
            call["parse_status"] = "text_only" if not has_answer_tag else "invalid"
            if not has_answer_tag:
                call["json_status"] = "text_only"
    except Exception as e:
        call["parse_status"] = "invalid"
        call["parse_error"] = str(e)


class PipelineResult:
    def __init__(self, run_dir: Path, metrics_path: Path):
        self.run_dir = run_dir
        self.metrics_path = metrics_path


class CommitKGPipeline:
    def __init__(self, cfg: AppConfig, config_path: Path | None = None):
        self.cfg = cfg
        self.config_path = config_path
        self.run_dir = make_run_dir(cfg.experiment.output_root, cfg.experiment.name)
        # CodeKG artifacts default to a persistent project/commit/config cache,
        # so repeated runs reuse the same Joern-enhanced graph instead of
        # rebuilding it under every run directory.  Set kg.cache_mode=run_local
        # to recover the earlier per-run artifact layout.
        kg_cache_mode = str(getattr(cfg.kg, "cache_mode", "persistent") or "persistent").strip().lower()
        if kg_cache_mode == "run_local":
            kg_out_dir = str(getattr(cfg.kg, "kg_out_dir", "") or "").strip()
            if kg_out_dir:
                kg_root = Path(kg_out_dir)
                cfg.kg.cache_dir = str(kg_root if kg_root.is_absolute() else (self.run_dir / kg_root))
        else:
            # Persistent CodeKG cache belongs under the project cache/ tree, not
            # under outputs/runs.  Prefer an explicit persistent_cache_dir, but
            # otherwise honor the existing kg.cache_dir setting from older
            # configs such as cache/kg.
            persistent_root = str(getattr(cfg.kg, "persistent_cache_dir", None) or getattr(cfg.kg, "cache_dir", "") or "cache/codekg").strip()
            kg_root = Path(persistent_root)
            cfg.kg.cache_dir = str(kg_root if kg_root.is_absolute() else Path(persistent_root))
        self.logger = setup_logging(self.run_dir, cfg.logging.level, cfg.logging.rich)
        save_config(cfg, self.run_dir / "resolved_config.yaml")
        self.sample_graph_keys: dict[str, tuple[str, str]] = {}
        self.sample_resolution: dict[str, CommitResolution] = {}
        self.skipped_sample_ids: set[str] = set()
        # When validation-aware pair selection oversamples candidates, only the
        # final validated vulnerable/fixed pairs must be classified.  This set is
        # populated by the validation-aware selection stage and consumed by run().
        self.classification_sample_ids: set[str] | None = None
        self.sample_runtime_rows: list[dict[str, Any]] = []
        self.project_runtime_rows: list[dict[str, Any]] = []
        self._repo_inventory_rows_cache: list[dict[str, Any]] | None = None
        self._repo_inventory_by_key_cache: dict[str, dict[str, Any]] | None = None
        self._dashboard_inventory_loaded = False
        self.write_lock = threading.Lock()
        self.live = LiveDashboard(self.run_dir, cfg.live_dashboard) if cfg.live_dashboard.enabled else None
        self.api_rate_limiter = RateLimiter(cfg.api_quota) if bool(getattr(cfg.api_quota, "enabled", False)) else None
        if self.api_rate_limiter is not None and self.live is not None:
            self.api_rate_limiter.set_event_sink(lambda kind, data: self.live.event(kind, data))
        self.logger.info(f"Run directory: {self.run_dir}")
        if config_path:
            self.logger.info(f"Config: {config_path}")
        if self.live:
            cfg_snapshot = cfg.to_plain_dict()
            self.live.update_run_metadata({
                "run_id": self.run_dir.name,
                "config_path": str(config_path) if config_path else None,
                "config_name": config_path.name if config_path else None,
                "output_dir": str(self.run_dir),
                "config": cfg_snapshot,
                "config_summary": {
                    "model_backend": cfg.model.backend,
                    "model_name": cfg.model.model_name or cfg.model.repo_id or cfg.model.local_path,
                    "temperature": cfg.model.temperature,
                    "top_p": cfg.model.top_p,
                    "max_tokens": cfg.model.max_tokens,
                    "kg_scope": cfg.kg.scope,
                    "kg_version": cfg.kg.version,
                    "kg_force_rebuild": cfg.kg.force_rebuild,
                    "kg_include_headers": cfg.kg.include_headers,
                    "repo_inventory_enabled": cfg.repo_inventory.enabled,
                    "repo_inventory_cache_dir": cfg.repo_inventory.cache_dir,
                    "retrieval_strategy": cfg.retrieval.strategy,
                    "agent_mode": cfg.agent.mode,
                    "agent_max_rounds": cfg.agent.max_rounds,
                    "max_evidence_items_after_tools": cfg.agent.max_evidence_items_after_tools,
                    "api_max_concurrent_requests": cfg.api_quota.max_concurrent_requests,
                    "classification_workers": cfg.execution.api_classification_max_workers if cfg.model.backend == "openai_compatible" else cfg.execution.classification_max_workers,
                },
            })
            self.logger.info("Live dashboard: %s", self.live.url())

    def _demo_report_options(self, *, stage: str | None = None, in_progress: bool = False) -> dict[str, Any]:
        return {
            "hide_initial_deterministic_retrieval": bool(getattr(self.cfg.agent, "hide_initial_deterministic_retrieval_in_demo", False)),
            "show_only_kg_tool_evidence": bool(getattr(self.cfg.agent, "demo_show_only_kg_tool_evidence", False)),
            "in_progress": bool(in_progress),
            "stage": stage or ("running" if in_progress else "done"),
            "autorefresh_seconds": float(getattr(self.cfg.agent, "demo_report_autorefresh_seconds", 2.0) or 2.0),
            "report_revision": int(time.time() * 1000),
        }

    def _pending_prediction(self, sample: SecVulEvalSample, *, stage: str, usage: dict[str, Any] | None = None) -> Prediction:
        pred = Prediction(
            sample_id=sample.sample_id,
            is_vulnerable=False,
            confidence=0.0,
            primary_vulnerability_type=None,
            vuln_statements=[],
            evidence_used=[],
            decision_status="running",
            binary_prediction_policy="sample is still running; no benchmark prediction has been accepted yet",
            reasoning_summary=f"Sample is in progress at stage: {stage}",
            model_backend=self.cfg.model.backend,
            usage=usage or {},
        )
        resolution = self.sample_resolution.get(sample.sample_id)
        pred.dataset_commit_id = sample.commit_id
        pred.resolved_commit_id = resolution.selected_commit_id if resolution else sample.commit_id
        pred.resolved_commit_label = resolution.selected_label if resolution else "dataset_commit"
        pred.target_validation_status = resolution.selected_status if resolution else None
        pred.target_validation_similarity = resolution.selected_similarity if resolution else None
        pred.target_validation_artifact_dir = resolution.selected_artifact_dir if resolution else None
        return pred

    def _write_live_agent_report(
        self,
        *,
        stage: str,
        sample: SecVulEvalSample,
        evidence: Any,
        trace: Any,
        prediction: Prediction | None,
        graph_manifest: dict[str, Any] | None,
        graph_status: str | None,
        graph_dir: str | None,
        validation_artifact_dir: str | None,
        in_progress: bool,
    ) -> str | None:
        if not (self.cfg.agent.save_demo_reports and bool(getattr(self.cfg.agent, "live_partial_demo_reports", True))):
            return None
        pred = prediction or self._pending_prediction(sample, stage=stage)
        opts = self._demo_report_options(stage=stage, in_progress=in_progress)
        try:
            report_path = write_sample_agent_demo(
                run_dir=self.run_dir,
                sample=sample,
                evidence=evidence,
                trace=trace,
                prediction=pred,
                dataset_path=self.cfg.dataset.path,
                graph_manifest=graph_manifest,
                graph_status=graph_status,
                graph_dir=str(graph_dir) if graph_dir else None,
                validation_artifact_dir=validation_artifact_dir,
                prompting_config=self.cfg.prompting.model_dump(mode="json"),
                report_options=opts,
            )
            trace.report_path = str(report_path)
            rel = report_path.relative_to(self.run_dir).as_posix()
            status_payload = {
                "sample_id": sample.sample_id,
                "stage": stage,
                "in_progress": bool(in_progress),
                "revision": opts.get("report_revision"),
                "updated_at": time.time(),
                "model_calls": len(getattr(trace, "model_calls", []) or []),
                "kg_tool_steps": len(getattr(trace, "kg_tool_steps", []) or []),
                "hypothesis_ledger_entries": len(getattr(trace, "hypothesis_ledger", []) or []),
            }
            write_json(report_path.parent / "live_status.json", status_payload)
            if self.live:
                self.live.update_sample(sample.sample_id, {
                    "agent_report": str(report_path),
                    "agent_report_rel": rel,
                    "agent_report_url": self._dashboard_url_for_path(report_path),
                    "current_report_stage": stage,
                    "report_revision": opts.get("report_revision"),
                })
            return str(report_path)
        except Exception:
            self.logger.debug("live_agent_report_write_failed | sample=%s | stage=%s", sample.sample_id, stage, exc_info=True)
            return None

    def _make_agent_progress_callback(self, *, graph_manifest: dict[str, Any] | None, graph_status: str | None, graph_dir: str | None, validation_artifact_dir: str | None):
        def _callback(*, stage: str, sample: SecVulEvalSample, evidence: Any, trace: Any, prediction: Prediction | None = None) -> None:
            with self.write_lock:
                self._write_live_agent_report(
                    stage=stage,
                    sample=sample,
                    evidence=evidence,
                    trace=trace,
                    prediction=prediction,
                    graph_manifest=graph_manifest,
                    graph_status=graph_status,
                    graph_dir=str(graph_dir) if graph_dir else None,
                    validation_artifact_dir=validation_artifact_dir,
                    in_progress=prediction is None or str(getattr(prediction, "decision_status", "")) == "running",
                )
        return _callback

    def inspect(self) -> PipelineResult:
        with profile(self.logger, self.run_dir, "inspect_dataset"):
            all_samples = load_samples(self.cfg.dataset.path, self.cfg.dataset.mode, self.logger)
            selected = select_samples(all_samples, self.cfg.dataset, self.cfg.experiment.seed)
            write_jsonl(self.run_dir / "samples.jsonl", selected)
            grouped = group_by_project_commit(selected)
            project_stats = summarize_projects(all_samples)
            selected_project_stats = summarize_projects(selected)
            stats = {
                "loaded_samples": len(all_samples),
                "available_projects": len(project_stats),
                "selected_samples": len(selected),
                "selected_projects": len(selected_project_stats),
                "project_commit_groups": len(grouped),
                "vulnerable": sum(1 for s in selected if s.is_vulnerable),
                "safe": sum(1 for s in selected if not s.is_vulnerable),
                "selected_project_summary": [p.to_dict() for p in selected_project_stats],
                "smallest_projects_by_dataset_samples": [p.to_dict() for p in sorted(project_stats, key=lambda x: (x.num_samples, x.project))[:20]],
                "largest_projects_by_dataset_samples": [p.to_dict() for p in sorted(project_stats, key=lambda x: (-x.num_samples, x.project))[:20]],
                "first_samples": [s.model_dump(mode="json") for s in selected[:5]],
            }
            write_json(self.run_dir / "inspect_summary.json", stats)
            self.logger.info(
                "Inspect: loaded=%s projects=%s selected=%s selected_projects=%s groups=%s",
                stats["loaded_samples"], stats["available_projects"], stats["selected_samples"],
                stats["selected_projects"], stats["project_commit_groups"],
            )
            return PipelineResult(self.run_dir, self.run_dir / "inspect_summary.json")

    def scan_projects(self, fetch_github_size: bool = False, github_limit: int | None = None) -> PipelineResult:
        with profile(self.logger, self.run_dir, "scan_projects"):
            all_samples = load_samples(self.cfg.dataset.path, self.cfg.dataset.mode, self.logger)
            rows = project_stats_rows(
                all_samples,
                fetch_github_size=fetch_github_size,
                github_limit=github_limit,
                logger=self.logger,
            )
            csv_path = write_project_scan_outputs(self.run_dir, rows)
            self.logger.info("Project scan written: %s", csv_path)
            self.logger.info("Use configs with dataset.project_include or dataset.project_selection before cloning.")
            return PipelineResult(self.run_dir, csv_path)


    def prepare_repos(self, limit: int | None = None) -> PipelineResult:
        """Clone/reuse all dataset project mirrors and cache repo statistics.

        This is an offline preparation step. It intentionally does not build
        KGs or call an LLM. Failed/inaccessible repositories are recorded in
        the inventory and later scaling selection can skip them.
        """
        with profile(self.logger, self.run_dir, "prepare_repos"):
            all_samples = load_samples(self.cfg.dataset.path, self.cfg.dataset.mode, self.logger)
            projects = unique_projects_from_samples(all_samples)
            if self.cfg.dataset.project_include:
                include = {str(x).strip().lower() for x in self.cfg.dataset.project_include}
                projects = [p for p in projects if str(p.get("project") or "").lower() in include or str(p.get("project_url") or "").lower() in include]
            if self.cfg.dataset.project_exclude:
                exclude = {str(x).strip().lower() for x in self.cfg.dataset.project_exclude}
                projects = [p for p in projects if str(p.get("project") or "").lower() not in exclude and str(p.get("project_url") or "").lower() not in exclude]
            builder = RepoInventoryBuilder(self.cfg.repo, self.cfg.repo_inventory, self.logger, self.run_dir)
            summary = builder.build_for_projects(projects, limit=limit)
            if getattr(self.cfg.repo_inventory, "build_pair_candidate_cache", False) or getattr(self.cfg.dataset, "build_pair_candidate_cache", False):
                inventory_rows = RepoInventory(self.cfg.repo_inventory).load_all()
                pair_summary = write_pair_candidate_cache(
                    all_samples,
                    self.cfg.dataset,
                    cache_dir=self.cfg.repo_inventory.cache_dir,
                    inventory_rows=inventory_rows,
                )
                summary["pair_candidate_cache"] = pair_summary
                self.logger.info("Pair candidate cache prepared: %s", pair_summary)
            write_json(self.run_dir / "prepare_repos_summary.json", summary)
            self.logger.info("Repository inventory prepared: %s", summary)
            return PipelineResult(self.run_dir, self.run_dir / "prepare_repos_summary.json")


    def scan_pairs(self, limit: int | None = None) -> PipelineResult:
        with profile(self.logger, self.run_dir, "scan_pairs"):
            all_samples = load_samples(self.cfg.dataset.path, self.cfg.dataset.mode, self.logger)
            rows = pair_rows(all_samples, self.cfg.dataset, limit=limit)
            csv_path = write_pair_scan_outputs(self.run_dir, rows)
            self.logger.info("Pair scan written: %s", csv_path)
            if rows:
                first = rows[0]
                log_kv(
                    self.logger,
                    "Smallest vulnerable/fixed pair",
                    project=first.get("project"),
                    project_url=first.get("project_url"),
                    vulnerable_idx=first.get("vulnerable_idx"),
                    fixed_idx=first.get("fixed_idx"),
                    filepath=first.get("filepath"),
                    func_name=first.get("func_name"),
                    patch_commit=first.get("patch_commit_id"),
                )
            return PipelineResult(self.run_dir, csv_path)

    def build_kg_only(self) -> PipelineResult:
        """Build/load KGs for the configured dataset selection without classification.

        Important: validation-aware curriculum configs intentionally over-sample a
        candidate pool, then stream-validate until the requested number of
        vulnerable/fixed function pairs is found.  KG-only mode must use the same
        validated-pair selection path as `run`; otherwise it builds KGs for the
        entire candidate pool and looks as if many unrelated projects were
        selected.
        """
        with profile(self.logger, self.run_dir, "build_kg_only"):
            selected = self._load_selected_samples()
            # classify=True here means "apply final runnable/validated pair
            # filtering", not "run the LLM classifier".
            self._prepare_project_commit_graphs(selected, classify=True)
            return PipelineResult(self.run_dir, self.run_dir / "kg_manifests.jsonl")

    def validate_targets(self) -> PipelineResult:
        """Clone/reuse repos and resolve/validate target commits without building KGs."""
        with profile(self.logger, self.run_dir, "validate_targets"):
            selected = self._load_selected_samples()
            write_jsonl(self.run_dir / "samples.jsonl", selected)
            original_scope = self.cfg.kg.scope
            self.cfg.kg.scope = "disabled"
            try:
                self._prepare_project_commit_graphs(selected, classify=True)
            finally:
                self.cfg.kg.scope = original_scope
            low_similarity = sum(
                1 for r in self.sample_resolution.values()
                if r.selected_similarity is not None and r.selected_similarity < self.cfg.snapshot.body_match_threshold
            )
            summary = {
                "samples": len(selected),
                "resolved": len(self.sample_resolution),
                "valid": len(selected) - len(self.skipped_sample_ids) - low_similarity if self.cfg.snapshot.on_validation_failure != "skip" else len(selected) - len(self.skipped_sample_ids),
                "skipped": len(self.skipped_sample_ids),
                "low_similarity": low_similarity,
                "threshold": self.cfg.snapshot.body_match_threshold,
                "commit_resolution": self.cfg.snapshot.commit_resolution,
                "on_validation_failure": self.cfg.snapshot.on_validation_failure,
            }
            write_json(self.run_dir / "target_validation_summary.json", summary)
            self.logger.info("Target validation summary: %s", summary)
            return PipelineResult(self.run_dir, self.run_dir / "target_validation_summary.json")

    def run(self) -> PipelineResult:
        with profile(self.logger, self.run_dir, "full_run"):
            full_run_start = time.perf_counter()
            samples = self._load_selected_samples()
            write_jsonl(self.run_dir / "samples.jsonl", samples)
            log_kv(self.logger, "Sample selection", selected=len(samples), projects=len({s.project for s in samples}), project_commit_groups=len(group_by_project_commit(samples)))

            model = build_model(self.cfg.model, self.cfg.api_quota)
            self._attach_live_model_events(model)
            if (
                self.live
                and self.cfg.model.backend == "openai_compatible"
                and getattr(self.cfg.api_quota, "provider_header_probe", "off") != "off"
            ):
                provider_quota = fetch_provider_quota_headers(self.cfg.model, self.cfg.api_quota)
                self.live.event("api.provider_quota_probe", provider_quota)
            agent = AgentController(self.cfg.agent, self.cfg.retrieval, self.cfg.model, model, self.logger, self.cfg.prompting, event_sink=self._live_agent_event)
            retriever = EvidenceRetriever(self.cfg.retrieval)

            predictions: list[Prediction] = []
            graph_context = self._prepare_project_commit_graphs(samples, classify=True)
            if self.live:
                self.live.set_status("classification")
                if getattr(model, "rate_limiter", None) is not None:
                    self.live.update_api(model.rate_limiter.snapshot())
            if self.cfg.dataset.validation_aware_pair_selection and self.classification_sample_ids is not None:
                # Critical propagation fix: `samples` is the oversampled validation
                # candidate pool.  It can be 160+ samples even when only 5 validated
                # function pairs were requested.  Classification must use only the
                # final selected validated sample ids.
                selected_for_classification = set(self.classification_sample_ids)
                runnable_samples = [
                    s for s in samples
                    if s.sample_id in selected_for_classification and s.sample_id not in self.skipped_sample_ids
                ]
                selected_count_for_log = len(selected_for_classification)
                skipped_count_for_log = selected_count_for_log - len(runnable_samples)
            else:
                runnable_samples = [s for s in samples if s.sample_id not in self.skipped_sample_ids]
                selected_count_for_log = len(samples)
                skipped_count_for_log = len(self.skipped_sample_ids)
            write_jsonl(self.run_dir / "runnable_samples.jsonl", runnable_samples)
            log_kv(
                self.logger,
                "Runnable sample selection",
                selected=selected_count_for_log,
                runnable=len(runnable_samples),
                skipped=skipped_count_for_log,
                original_candidate_pool=len(samples),
            )
            if self.live:
                for q_i, s in enumerate(runnable_samples, start=1):
                    self.live.update_sample(s.sample_id, {
                        "sample_id": s.sample_id,
                        "project": s.project,
                        "filepath": s.filepath,
                        "function": s.func_name,
                        "dataset_label_report_only": "vulnerable" if s.is_vulnerable else "fixed/non-vulnerable",
                        "commit_message_report_only": s.commit_message,
                        "status": "queued",
                        "agent_stage": "queued",
                        "queue_index": q_i,
                    })
            if not runnable_samples:
                raise RuntimeError(
                    "No runnable samples remain after target validation. "
                    "Use dataset.sample_selection=smallest_vuln_fixed_pair, increase dataset.sample_limit, "
                    "or choose another project/pair from scan-pairs."
                )
            log_kv(self.logger, "Classification start", samples=len(runnable_samples), model_backend=self.cfg.model.backend, agent_mode=self.cfg.agent.mode)
            progress = ProgressMeter(self.logger, len(runnable_samples), "classify.samples", self.cfg.logging.log_every_n_samples, self.cfg.logging.log_every_seconds)

            runnable_loop_samples = runnable_samples
            api_workers = int(self.cfg.execution.api_classification_max_workers or self.cfg.execution.classification_max_workers or 1)
            should_parallel_api = (
                self.cfg.model.backend == "openai_compatible"
                and self.cfg.execution.parallelize_api_samples
                and api_workers > 1
                and len(runnable_samples) > 1
            )
            if should_parallel_api:
                self.logger.info("api.parallel_classification | workers=%s | samples=%s", api_workers, len(runnable_samples))
                if self.live:
                    self.live.event("api.parallel_classification.start", {"workers": api_workers, "samples": len(runnable_samples)})
                runnable_loop_samples = []
                executor = ThreadPoolExecutor(max_workers=api_workers)
                future_map = {}
                try:
                    future_map = {
                        executor.submit(self._classify_one_sample_threadsafe, sample, graph_context, model): sample
                        for sample in runnable_samples
                    }
                    for future in as_completed(future_map):
                        sample = future_map[future]
                        try:
                            result = future.result()
                            pred = result.get("prediction")
                            if pred is not None:
                                predictions.append(pred)
                            runtime = result.get("sample_runtime")
                            if runtime is not None:
                                self.sample_runtime_rows.append(runtime)
                            progress.update(extra=f"sample={sample.sample_id} parallel_done")
                        except Exception as exc:
                            self.logger.exception("Parallel sample failed: %s %s", sample.sample_id, sample.display_name)
                            with self.write_lock:
                                append_jsonl(self.run_dir / "failed_samples.jsonl", {"sample_id": sample.sample_id, "display_name": sample.display_name, "error": str(exc)})
                                try:
                                    _par_sd = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}"
                                    _par_fp = _par_sd / "final_prediction.json"
                                    if not _par_fp.exists():
                                        _par_sd.mkdir(parents=True, exist_ok=True)
                                        _par_fp.write_text(json.dumps({
                                            "sample_id": str(sample.sample_id),
                                            "is_vulnerable": False,
                                            "confidence": 0.0,
                                            "decision_status": "failed_parse",
                                            "parse_error": f"{type(exc).__name__}: {exc}",
                                            "error_type": type(exc).__name__,
                                            "binary_prediction_policy": "sample failed before final prediction",
                                            "reasoning_summary": f"Sample failed: {type(exc).__name__}: {exc}",
                                        }, ensure_ascii=False), encoding="utf-8")
                                except Exception:
                                    pass
                            if self.live:
                                self.live.update_sample(sample.sample_id, {"sample_id": sample.sample_id, "project": sample.project, "filepath": sample.filepath, "function": sample.func_name, "status": "failed", "agent_stage": "failed", "error": str(exc)})
                            progress.update(extra=f"sample={sample.sample_id} failed")
                except KeyboardInterrupt:
                    self.logger.warning("parallel_classification.interrupted | cancelling outstanding futures=%s", len(future_map))
                    for fut, sample in future_map.items():
                        if not fut.done():
                            fut.cancel()
                            if self.live:
                                self.live.update_sample(sample.sample_id, {"sample_id": sample.sample_id, "project": sample.project, "filepath": sample.filepath, "function": sample.func_name, "status": "cancelled", "agent_stage": "cancelled", "error": "interrupted by user"})
                    if self.live:
                        self.live.event("run.interrupted", {"message": "KeyboardInterrupt: outstanding API tasks cancelled"})
                    raise
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)

            for sample in runnable_loop_samples:
                try:
                    resolution = self.sample_resolution.get(sample.sample_id)
                    resolved_commit = resolution.selected_commit_id if resolution else sample.commit_id
                    resolved_label = resolution.selected_label if resolution else "dataset_commit"
                    validation_status = resolution.selected_status if resolution else None
                    validation_similarity = resolution.selected_similarity if resolution else None
                    validation_artifact_dir = resolution.selected_artifact_dir if resolution else None
                    if self.live:
                        self.live.update_sample(sample.sample_id, {"sample_id": sample.sample_id, "project": sample.project, "filepath": sample.filepath, "function": sample.func_name, "status": "running", "agent_stage": "starting"})
                        self.live.event("sample.start", {"sample_id": sample.sample_id, "project": sample.project, "function": sample.func_name})
                    log_kv(
                        self.logger,
                        "sample.start",
                        id=sample.sample_id,
                        project=sample.project,
                        label="vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
                        dataset_commit=(sample.commit_id or "?")[:12],
                        resolved_commit=(resolved_commit or "?")[:12],
                        resolved_label=resolved_label,
                        target_status=validation_status,
                        target_similarity=validation_similarity,
                        function=sample.func_name,
                    )
                    graph_key = self.sample_graph_keys.get(sample.sample_id)
                    graph_context_item = graph_context.get(graph_key, {}) if graph_key else {}
                    graph = self._graph_for_sample(sample, graph_context)
                    if graph is None:
                        graph = self._function_only_graph(sample)
                    graph_manifest = getattr(graph, "manifest", {}) or {}
                    graph_status = graph_context_item.get("graph_status") or graph_manifest.get("graph_status") or "function_only_fallback"
                    graph_dir = graph_context_item.get("graph_dir")
                    self.logger.info(
                        "sample.graph | id=%s | graph_commit=%s | graph_scope=%s | nodes=%s | edges=%s",
                        sample.sample_id,
                        str(graph_manifest.get("commit_id") or resolved_commit or "?")[:12],
                        graph_manifest.get("scope") or graph_manifest.get("kg_version") or "unknown",
                        len(getattr(graph, "nodes", [])),
                        len(getattr(graph, "edges", [])),
                    )
                    if self.live:
                        self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "retrieval"})
                    self.logger.info("retrieval.start | sample=%s | resolved_commit=%s", sample.sample_id, (resolved_commit or "?")[:12])
                    retrieval_start = time.perf_counter()
                    evidence = retriever.retrieve(graph, sample)
                    retrieval_seconds = time.perf_counter() - retrieval_start
                    evidence.dataset_commit_id = sample.commit_id
                    evidence.resolved_commit_id = resolved_commit
                    evidence.resolved_commit_label = resolved_label
                    evidence.target_validation_status = validation_status
                    evidence.target_validation_similarity = validation_similarity
                    evidence.retrieval_diagnostics.setdefault("graph", {}).update({
                        "graph_status": graph_status,
                        "graph_dir": str(graph_dir) if graph_dir else None,
                        "manifest": graph_manifest,
                        "kg_source_integrity": "KG was built only from repository source code; labels/CVE/commit metadata were not inserted into KG.",
                    })
                    self.logger.info(
                        "retrieval.done | sample=%s | resolved_commit=%s | target_found=%s | items=%s",
                        sample.sample_id,
                        (resolved_commit or "?")[:12],
                        evidence.target_found,
                        len(evidence.items),
                    )
                    if self.live:
                        self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "agent_loop", "initial_evidence_count": len(evidence.items)})
                        if getattr(model, "rate_limiter", None) is not None:
                            self.live.update_api(model.rate_limiter.snapshot())
                    self.logger.info("agent.start | sample=%s | evidence_items=%s", sample.sample_id, len(evidence.items))
                    agent.progress_callback = self._make_agent_progress_callback(graph_manifest=graph_manifest, graph_status=graph_status, graph_dir=str(graph_dir) if graph_dir else None, validation_artifact_dir=validation_artifact_dir)
                    # Create/open a live report as soon as the sample enters the agent loop; it will be overwritten after each model/KG stage.
                    self._write_live_agent_report(stage="agent_loop_start", sample=sample, evidence=evidence, trace=AgentTrace(sample_id=sample.sample_id, mode=self.cfg.agent.mode), prediction=None, graph_manifest=graph_manifest, graph_status=graph_status, graph_dir=str(graph_dir) if graph_dir else None, validation_artifact_dir=validation_artifact_dir, in_progress=True)
                    agent_start = time.perf_counter()
                    pred, trace, evidence = self._classify_with_configured_agent(agent=agent, model=model, sample=sample, evidence=evidence, graph=graph)
                    agent_seconds = time.perf_counter() - agent_start
                    append_jsonl(self.run_dir / "evidence_packs.jsonl", evidence)
                    pred.dataset_commit_id = sample.commit_id
                    pred.resolved_commit_id = resolved_commit
                    pred.resolved_commit_label = resolved_label
                    pred.target_validation_status = validation_status
                    pred.target_validation_similarity = validation_similarity
                    pred.target_validation_artifact_dir = validation_artifact_dir
                    trace.dataset_commit_id = sample.commit_id
                    trace.resolved_commit_id = resolved_commit
                    trace.resolved_commit_label = resolved_label
                    trace.target_validation_artifact_dir = validation_artifact_dir
                    if self.cfg.agent.save_demo_reports:
                        report_path = write_sample_agent_demo(
                            run_dir=self.run_dir,
                            sample=sample,
                            evidence=evidence,
                            trace=trace,
                            prediction=pred,
                            dataset_path=self.cfg.dataset.path,
                            graph_manifest=graph_manifest,
                            graph_status=graph_status,
                            graph_dir=str(graph_dir) if graph_dir else None,
                            validation_artifact_dir=validation_artifact_dir,
                            prompting_config=self.cfg.prompting.model_dump(mode="json"),
                            report_options=self._demo_report_options(stage="done", in_progress=False),
                        )
                        trace.report_path = str(report_path)
                        self.logger.info("agent.demo | sample=%s | report=%s", sample.sample_id, report_path)
                    self.logger.info(
                        "agent.done | sample=%s | resolved_commit=%s | pred=%s | conf=%.2f | tokens=%s",
                        sample.sample_id,
                        (resolved_commit or "?")[:12],
                        pred.is_vulnerable,
                        pred.confidence,
                        pred.usage.get("total_tokens"),
                    )
                    predictions.append(pred)
                    append_jsonl(self.run_dir / "predictions.jsonl", pred)
                    append_jsonl(self.run_dir / "agent_traces.jsonl", trace)
                    append_jsonl(self.run_dir / "usage_events.jsonl", {
                        "sample_id": sample.sample_id,
                        "dataset_commit_id": sample.commit_id,
                        "resolved_commit_id": resolved_commit,
                        "resolved_commit_label": resolved_label,
                        **pred.usage,
                    })
                    decision_flow_summary = self._trace_decision_flow_summary(trace, pred)
                    sample_runtime = {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "filepath": sample.filepath,
                        "function": sample.func_name,
                        "commit_message_report_only": sample.commit_message,
                        "ground_truth_is_vulnerable": bool(sample.is_vulnerable),
                        "prediction_is_vulnerable": bool(pred.is_vulnerable),
                        "valid_binary_prediction": self._is_valid_binary_prediction(pred),
                        "correct": self._is_valid_binary_prediction(pred) and (bool(sample.is_vulnerable) == bool(pred.is_vulnerable)),
                        "error_type": self._prediction_error_type(sample, pred),
                        "decision_status": pred.decision_status,
                        "parse_error": pred.parse_error,
                        "confidence": pred.confidence,
                        "reasoning_summary": pred.reasoning_summary,
                        "primary_vulnerability_type": pred.primary_vulnerability_type,
                        "evidence_used": list(pred.evidence_used or []),
                        "resolved_commit_id": resolved_commit,
                        "resolved_commit_label": resolved_label,
                        "target_validation_status": validation_status,
                        "target_validation_similarity": validation_similarity,
                        "graph_status": graph_status,
                        "graph_dir": str(graph_dir) if graph_dir else None,
                        "graph_nodes": len(getattr(graph, "nodes", [])),
                        "graph_edges": len(getattr(graph, "edges", [])),
                        "graph_num_files": graph_manifest.get("num_files"),
                        "graph_num_functions": graph_manifest.get("num_functions"),
                        "graph_num_statements": graph_manifest.get("num_statements"),
                        "initial_evidence_count": trace.initial_evidence_count,
                        "accumulated_evidence_count": trace.accumulated_evidence_count,
                        "kg_tool_steps": len(trace.kg_tool_steps),
                        "model_calls": len(trace.model_calls),
                        "retrieval_seconds": retrieval_seconds,
                        "agent_seconds": agent_seconds,
                        "model_call_seconds": sum(float(c.get("elapsed_seconds") or 0) for c in trace.model_calls),
                        "model_stage_breakdown": [
                            {
                                "stage": c.get("name"),
                                "elapsed_seconds": c.get("elapsed_seconds", 0.0),
                                "prompt_chars": c.get("prompt_chars"),
                                "prompt_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("prompt_tokens"),
                                "completion_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("completion_tokens"),
                                "total_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("total_tokens"),
                                "cost_total_usd": (c.get("total_stage_usage") or c.get("usage") or {}).get("cost_total_usd"),
                                "json_status": c.get("json_status"),
                            }
                            for c in trace.model_calls
                        ],
                        "prompt_tokens": pred.usage.get("prompt_tokens", 0),
                        "completion_tokens": pred.usage.get("completion_tokens", 0),
                        "total_tokens": pred.usage.get("total_tokens", 0),
                        "cost_total_usd": pred.usage.get("cost_total_usd", 0.0),
                        "usage_estimated": pred.usage.get("estimated", True),
                        "agent_report": trace.report_path,
                        "agent_report_rel": Path(trace.report_path).relative_to(self.run_dir).as_posix() if trace.report_path else None,
                        "agent_report_url": self._dashboard_url_for_path(trace.report_path) if trace.report_path else None,
                        "posthoc_commit_audit": trace.posthoc_commit_audit,
                        "validation_notes": pred.validation_notes,
                        "final_validator_modifications": trace.final_validator_modifications,
                        "decision_flow_summary": decision_flow_summary,
                        "raw_model_decision": decision_flow_summary.get("raw_model_decision"),
                        "evidence_validated_decision": decision_flow_summary.get("evidence_validated_decision"),
                        "final_system_decision": decision_flow_summary.get("final_system_decision"),
                        "raw_model_is_vulnerable": decision_flow_summary.get("raw_model_is_vulnerable"),
                        "raw_model_decision_status": decision_flow_summary.get("raw_model_decision_status"),
                        "raw_model_confidence": decision_flow_summary.get("raw_model_confidence"),
                        "validator_modified": decision_flow_summary.get("validator_modified"),
                        "validator_modification_count": decision_flow_summary.get("validator_modification_count"),
                        "validator_stages": decision_flow_summary.get("validator_stages"),
                        "final_system_is_vulnerable": bool(pred.is_vulnerable),
                        "final_system_decision_status": pred.decision_status,
                        "final_system_confidence": pred.confidence,
                        "json_repair_attempts": self._trace_json_repair_attempts(trace),
                        "json_repaired_calls": self._trace_json_repaired_calls(trace),
                        "mechanical_normalizations": sum(len(c.get("mechanical_normalizations", []) or []) for c in trace.model_calls),
                    }
                    self.sample_runtime_rows.append(sample_runtime)
                    append_jsonl(self.run_dir / "sample_runtime.jsonl", sample_runtime)
                    if self.live:
                        self.live.update_sample(sample.sample_id, {**sample_runtime, "status": "done", "agent_stage": "done"})
                        if getattr(model, "rate_limiter", None) is not None:
                            self.live.update_api(model.rate_limiter.snapshot())
                        self.live.event("sample.done", {"sample_id": sample.sample_id, "error_type": sample_runtime.get("error_type"), "cost_total_usd": sample_runtime.get("cost_total_usd")})
                    progress.update(extra=f"sample={sample.sample_id} resolved={(resolved_commit or '?')[:12]} pred={pred.is_vulnerable} conf={pred.confidence:.2f}")
                except Exception as exc:
                    self.logger.exception(f"Sample failed: {sample.sample_id} {sample.display_name}")
                    append_jsonl(
                        self.run_dir / "failed_samples.jsonl",
                        {"sample_id": sample.sample_id, "display_name": sample.display_name, "error": str(exc)},
                    )
                    # Write partial agent_flow.json so Agentic Flow UI can show
                    # completed stages and failure reason for failed/partial runs.
                    try:
                        _partial_sd = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}"
                        _partial_mc_path = _partial_sd / "model_calls.jsonl"
                        _partial_calls: list[dict] = []
                        if _partial_mc_path.exists():
                            for _line in _partial_mc_path.read_text(encoding="utf-8", errors="replace").splitlines():
                                _line = _line.strip()
                                if _line:
                                    try:
                                        _partial_calls.append(json.loads(_line))
                                    except Exception:
                                        pass
                            # Enrich any unenriched call records so UI shows correct parse badges.
                            for _pc in _partial_calls:
                                _enrich_call_parse_result(_pc)
                            _partial_mc_path.write_text(
                                "\n".join(json.dumps(c, ensure_ascii=False, default=str) for c in _partial_calls) + "\n",
                                encoding="utf-8",
                            )
                        _partial_flow_path = _partial_sd / "agent_flow.json"
                        if not _partial_flow_path.exists():
                            _partial_sd.mkdir(parents=True, exist_ok=True)
                            _partial_flow_path.write_text(
                                json.dumps({
                                    "sample_id": sample.sample_id,
                                    "loop_stop_reason": "sample_failed",
                                    "iterations_completed": 0,
                                    "iterative_loop_enabled": False,
                                    "partial": True,
                                    "failure_error": str(exc),
                                    "stages": [
                                        {
                                            "stage": c.get("name"),
                                            "status": "failed" if c.get("error") else "completed",
                                            "elapsed_seconds": c.get("elapsed_seconds"),
                                            "finish_reason": c.get("finish_reason"),
                                            "was_truncated": c.get("was_truncated", False),
                                        }
                                        for c in _partial_calls
                                        if c.get("name") not in ("final_decision",)
                                    ],
                                    "iterations": [],
                                }, indent=2, ensure_ascii=False, default=str),
                                encoding="utf-8",
                            )
                        # Write a minimal final_prediction.json so the dashboard can
                        # display failure details rather than "Prediction: not available".
                        _partial_fp_path = _partial_sd / "final_prediction.json"
                        if not _partial_fp_path.exists():
                            _partial_sd.mkdir(parents=True, exist_ok=True)
                            _partial_fp_path.write_text(
                                json.dumps({
                                    "sample_id": str(sample.sample_id),
                                    "is_vulnerable": False,
                                    "confidence": 0.0,
                                    "decision_status": "failed_parse",
                                    "parse_error": f"{type(exc).__name__}: {exc}",
                                    "error_type": type(exc).__name__,
                                    "binary_prediction_policy": "sample failed before final prediction",
                                    "reasoning_summary": f"Sample failed: {type(exc).__name__}: {exc}",
                                }, ensure_ascii=False),
                                encoding="utf-8",
                            )
                    except Exception:
                        pass
                    if self.live:
                        self.live.update_sample(sample.sample_id, {"sample_id": sample.sample_id, "project": sample.project, "filepath": sample.filepath, "function": sample.func_name, "status": "failed", "agent_stage": "failed", "error": str(exc)})
                        self.live.event("sample.failed", {"sample_id": sample.sample_id, "error": str(exc)})
                    progress.update(extra=f"sample={sample.sample_id} failed")

            if self.cfg.agent.save_demo_reports:
                index_path = write_agent_demo_index(self.run_dir)
                self.logger.info("agent.demo.index | report=%s", index_path)
            metrics = self._evaluate(runnable_samples, predictions)
            usage = usage_summary(predictions)
            write_json(self.run_dir / "metrics.json", metrics)
            write_json(self.run_dir / "usage_summary.json", usage)
            if self.cfg.evaluation.save_tables:
                save_metric_tables(self.run_dir, metrics, usage)
            if self.cfg.evaluation.make_visualizations:
                make_visualizations(self.run_dir, metrics, usage)
            if self.cfg.scaling_analysis.enabled:
                append_jsonl(self.run_dir / "profile_events.jsonl", {
                    "name": "full_run_so_far",
                    "seconds": time.perf_counter() - full_run_start,
                    "rss_mb_start": None,
                    "rss_mb_end": None,
                    "rss_mb_delta": None,
                    "status": "partial_before_dashboard",
                })
                dashboard = write_scaling_analysis(
                    self.run_dir,
                    metrics=metrics,
                    usage=usage,
                    projection_sample_counts=self.cfg.scaling_analysis.projection_sample_counts,
                    projection_project_counts=self.cfg.scaling_analysis.projection_project_counts,
                )
                self.logger.info("Scaling analysis dashboard: %s", dashboard)
            self._write_summary(metrics, usage, len(runnable_samples), len(predictions))
            self.logger.info(f"Metrics written: {self.run_dir / 'metrics.json'}")
            self.logger.info(f"Usage summary: {usage}")
            if self.live:
                self.live.update_metrics({"metrics": metrics, "usage": usage})
                if getattr(model, "rate_limiter", None) is not None:
                    self.live.update_api(model.rate_limiter.snapshot())
                self.live.set_status("done")
            return PipelineResult(self.run_dir, self.run_dir / "metrics.json")



    def _classify_with_configured_agent(self, *, agent: AgentController, model: Any, sample: SecVulEvalSample, evidence: Any, graph: ProjectGraph) -> tuple[Prediction, AgentTrace, Any]:
        """Dispatch to the standard iterative agent or the optional agentic-proof agent.

        The agentic-proof path is intentionally adapted back into the existing
        Prediction/AgentTrace/EvidencePack schema so evaluation, reports, live
        dashboard, and scaling analysis continue to work unchanged.
        """
        if self.cfg.agent.mode != "agentic_proof":
            return agent.classify(sample, evidence, graph=graph)
        return self._classify_agentic_proof(sample=sample, evidence=evidence, graph=graph, model=model)

    def _classify_agentic_proof(self, *, sample: SecVulEvalSample, evidence: Any, graph: ProjectGraph, model: Any) -> tuple[Prediction, AgentTrace, Any]:
        from dataclasses import asdict, is_dataclass
        from vckg_agentic_proof import AgenticProofConfig, run_agentic_proof_pipeline
        from vuln_commit_kg.agents.tool_query import KGToolExecutor, KGToolResult

        ap_cfg = getattr(self.cfg, "agentic_proof", None)
        proof_cfg = AgenticProofConfig(
            max_hypotheses=int(getattr(ap_cfg, "max_hypotheses", 12) or 12),
            max_queries_per_hypothesis=int(getattr(ap_cfg, "max_queries_per_hypothesis", 6) or 6),
            evidence_limit_per_query=int(getattr(ap_cfg, "evidence_limit_per_query", 8) or 8),
            max_tokens_source_only_hypothesis=max(4096, int(getattr(ap_cfg, "max_tokens_source_only_hypothesis", 16384) or 16384)),
            max_tokens_kg_query_planning=max(4096, int(getattr(ap_cfg, "max_tokens_kg_query_planning", 8192) or 8192)),
            max_tokens_hypothesis_verification=max(4096, int(getattr(ap_cfg, "max_tokens_hypothesis_verification", 16384) or 16384)),
            max_tokens_counter_evidence_review=int(getattr(ap_cfg, "max_tokens_counter_evidence_review", 16384) or 16384),
            max_tokens_final_decision=max(4096, int(getattr(ap_cfg, "max_tokens_final_decision", 8192) or 8192)),
            max_tokens_schema_repair=max(4096, int(getattr(ap_cfg, "max_tokens_schema_repair", 4096) or 4096)),
            max_tokens_evidence_gap_analysis=int(getattr(ap_cfg, "max_tokens_evidence_gap_analysis", 8192) or 8192),
            iterative_evidence_loop=bool(getattr(ap_cfg, "iterative_evidence_loop", False)),
            max_evidence_iterations=int(getattr(ap_cfg, "max_evidence_iterations", 3) or 3),
            max_queries_per_iteration=int(getattr(ap_cfg, "max_queries_per_iteration", 5) or 5),
            stop_when_no_new_evidence=bool(getattr(ap_cfg, "stop_when_no_new_evidence", True)),
            stop_when_no_new_queries=bool(getattr(ap_cfg, "stop_when_no_new_queries", True)),
            stop_when_all_hypotheses_resolved=bool(getattr(ap_cfg, "stop_when_all_hypotheses_resolved", True)),
            stop_on_confirmed_vulnerability=bool(getattr(ap_cfg, "stop_on_confirmed_vulnerability", True)),
            enable_proof_obligation_ledger=bool(getattr(ap_cfg, "enable_proof_obligation_ledger", True)),
            max_obligations_per_hypothesis=int(getattr(ap_cfg, "max_obligations_per_hypothesis", 8) or 8),
            max_queries_per_obligation=int(getattr(ap_cfg, "max_queries_per_obligation", 3) or 3),
            enable_counter_evidence_loop=bool(getattr(ap_cfg, "enable_counter_evidence_loop", False)),
            max_counter_iterations=int(getattr(ap_cfg, "max_counter_iterations", 2) or 2),
            temperature=float(getattr(self.cfg.model, "temperature", 0.0) or 0.0),
            provider_extra_body=dict(getattr(self.cfg.model, "api_extra_body", {}) or {"chat_template_kwargs": {"enable_thinking": False}}),
            enable_pair_aware_dev_mode=bool(getattr(ap_cfg, "pair_aware_dev_mode", False)),
        )
        if bool(getattr(self.cfg.model, "api_disable_thinking", False)):
            proof_cfg.provider_extra_body.setdefault("chat_template_kwargs", {})["enable_thinking"] = False

        trace = AgentTrace(sample_id=sample.sample_id, mode="agentic_proof")
        trace.initial_evidence_count = len(evidence.items)
        trace.accumulated_evidence_count = len(evidence.items)
        if self.live:
            self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "agentic_proof_start"})

        def evidence_to_dict(item: Any) -> dict[str, Any]:
            if hasattr(item, "model_dump"):
                d = item.model_dump(mode="json")
            elif isinstance(item, dict):
                d = dict(item)
            else:
                d = {"text": str(item)}
            return {
                "id": d.get("evidence_id") or d.get("id") or d.get("node_id") or "unknown",
                "kind": d.get("kind") or "evidence",
                "file": d.get("relpath") or d.get("file"),
                "function": d.get("function"),
                "line_start": d.get("line_start"),
                "line_end": d.get("line_end"),
                "text": d.get("text") or "",
                "relation": d.get("scope") or d.get("relation") or d.get("match_type"),
                "score": d.get("score"),
            }

        def public_sample_dict() -> dict[str, Any]:
            # Never expose ground-truth label, commit message, CVE/CWE, or patch metadata to model-visible prompts.
            return {
                "sample_id": sample.sample_id,
                "project": sample.project,
                "project_url": sample.project_url,
                "filepath": sample.filepath,
                "function": sample.func_name,
            }

        def usage_to_dict(usage_obj: Any) -> dict[str, Any]:
            if usage_obj is None:
                return {}
            if isinstance(usage_obj, dict):
                return dict(usage_obj)
            if is_dataclass(usage_obj):
                return asdict(usage_obj)
            return {k: getattr(usage_obj, k) for k in ("prompt_tokens", "completion_tokens", "total_tokens", "cost_total_usd", "estimated") if hasattr(usage_obj, k)}

        def llm_generate(messages: list[dict[str, str]], *, stage: str, max_tokens: int, temperature: float, extra_body: dict[str, Any] | None = None) -> dict[str, Any]:
            system_parts: list[str] = []
            user_parts: list[str] = []
            for m in messages:
                role = str(m.get("role") or "user").lower()
                content = str(m.get("content") or "")
                if role == "system":
                    system_parts.append(content)
                else:
                    user_parts.append(content)
            system = "\n\n".join(system_parts)
            prompt = "\n\n".join(user_parts)
            prompt_chars = len(system) + len(prompt)
            prompt_has_truncation_marker = ("...<truncated>..." in system) or ("...<truncated>..." in prompt)
            self.logger.info("model.generate_start | sample=%s | stage=%s | attempt=primary | prompt_chars=%s | prompt_has_truncation_marker=%s", sample.sample_id, stage, prompt_chars, prompt_has_truncation_marker)
            if self.live:
                self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": stage, "api_stage": stage, "api_state": "requesting", "last_prompt_chars": prompt_chars, "current_model_stage": stage})
                self.live.event("model_call.prompt_ready", {"sample_id": sample.sample_id, "stage": stage, "prompt_chars": prompt_chars, "prompt_has_truncation_marker": prompt_has_truncation_marker})
                self.live.event("model_call.start", {"sample_id": sample.sample_id, "stage": stage, "prompt_chars": prompt_chars, "prompt_has_truncation_marker": prompt_has_truncation_marker})
            def _provider_wait_seconds_from_error(exc: Exception) -> float:
                resp = getattr(exc, "response", None)
                if resp is not None:
                    try:
                        parsed = parse_rate_limit_headers(getattr(resp, "headers", {}))
                        reset = parsed.get("reset_seconds")
                        if reset is not None:
                            return max(1.0, float(reset) + 2.0)
                    except Exception:
                        pass
                msg = str(exc).lower()
                if "429" in msg or "rate limit" in msg or "ratelimit" in msg or "too many requests" in msg:
                    return 65.0
                return 0.0

            def _is_retryable_provider_error(exc: Exception) -> bool:
                msg = f"{type(exc).__name__}: {exc}".lower()
                return (
                    "429" in msg or "rate limit" in msg or "ratelimit" in msg or "too many requests" in msg
                    or "timeout" in msg or "readtimeout" in msg
                    or "502" in msg or "503" in msg or "504" in msg
                )

            old_max_tokens = getattr(model.cfg, "max_tokens", None) if hasattr(model, "cfg") else None
            old_temperature = getattr(model.cfg, "temperature", None) if hasattr(model, "cfg") else None
            old_extra_body = dict(getattr(model.cfg, "api_extra_body", {}) or {}) if hasattr(model, "cfg") else {}
            try:
                if hasattr(model, "cfg"):
                    model.cfg.max_tokens = int(max_tokens)
                    model.cfg.temperature = float(temperature)
                    merged_extra = dict(old_extra_body)
                    if isinstance(extra_body, dict):
                        for k, v in extra_body.items():
                            if isinstance(v, dict) and isinstance(merged_extra.get(k), dict):
                                merged_extra[k] = {**merged_extra[k], **v}
                            else:
                                merged_extra[k] = v
                    model.cfg.api_extra_body = merged_extra
                if hasattr(model, "set_request_context"):
                    model.set_request_context({"sample_id": sample.sample_id, "stage": stage, "attempt": "primary"})
                start = time.perf_counter()
                # Run the blocking provider call in a tiny worker so the main
                # orchestration thread can emit periodic waiting events. Wrap it
                # with the local API scheduler so 50+ function batches respect
                # SAIA/GWDG request ceilings without extra quota probes.
                max_attempts = max(1, int(getattr(self.cfg.api_quota, "retry_max_attempts", 1) or 1))
                attempt_no = 0
                while True:
                    attempt_no += 1
                    rate_token = None
                    if self.api_rate_limiter is not None and self.cfg.model.backend == "openai_compatible":
                        rate_token = self.api_rate_limiter.acquire({
                            "sample_id": sample.sample_id,
                            "stage": stage,
                            "attempt": attempt_no,
                            "model": getattr(self.cfg.model, "model_name", None),
                        })
                    try:
                        with ThreadPoolExecutor(max_workers=1) as _model_exec:
                            _future = _model_exec.submit(model.generate, prompt, system=system)
                            while True:
                                try:
                                    resp = _future.result(timeout=15.0)
                                    break
                                except FutureTimeout:
                                    elapsed_wait = time.perf_counter() - start
                                    self.logger.info(
                                        "model.generate_waiting | sample=%s | stage=%s | attempt=%s | elapsed=%.1fs | prompt_chars=%s",
                                        sample.sample_id, stage, attempt_no, elapsed_wait, prompt_chars,
                                    )
                                    if self.live:
                                        self.live.event("model_call.waiting", {"sample_id": sample.sample_id, "stage": stage, "attempt": attempt_no, "elapsed_seconds": elapsed_wait, "prompt_chars": prompt_chars})
                                        self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": stage, "api_stage": stage, "api_state": "waiting", "last_model_elapsed_seconds": elapsed_wait})
                        if self.api_rate_limiter is not None and rate_token is not None:
                            self.api_rate_limiter.release(rate_token, success=True, response_chars=len(getattr(resp, "text", "") or ""))
                        break
                    except Exception as provider_exc:
                        wait_seconds = _provider_wait_seconds_from_error(provider_exc)
                        retryable = _is_retryable_provider_error(provider_exc) and attempt_no < max_attempts
                        if self.api_rate_limiter is not None and rate_token is not None:
                            self.api_rate_limiter.release(rate_token, success=False, error=f"{type(provider_exc).__name__}: {provider_exc}", will_retry=retryable)
                        if not retryable:
                            raise
                        delay = wait_seconds or min(float(getattr(self.cfg.api_quota, "retry_max_delay_seconds", 120.0) or 120.0), float(getattr(self.cfg.api_quota, "retry_initial_delay_seconds", 4.0) or 4.0) * (2 ** (attempt_no - 1)))
                        self.logger.warning(
                            "model.generate_retry_wait | sample=%s | stage=%s | attempt=%s/%s | wait=%.1fs | error=%s",
                            sample.sample_id, stage, attempt_no, max_attempts, delay, provider_exc,
                        )
                        if self.live:
                            self.live.event("api.rate_limit_retry_waiting", {"sample_id": sample.sample_id, "stage": stage, "attempt": attempt_no, "max_attempts": max_attempts, "wait_seconds": delay, "error": f"{type(provider_exc).__name__}: {provider_exc}"})
                            self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": stage, "api_stage": stage, "api_state": "rate_limit_waiting", "last_model_error": f"{type(provider_exc).__name__}: {provider_exc}"})
                        time.sleep(delay)
                elapsed = time.perf_counter() - start
                text = resp.text or ""
                usage = usage_to_dict(getattr(resp, "usage", None))
                if usage and "cost_total_usd" not in usage:
                    pt = int(usage.get("prompt_tokens") or 0)
                    ct = int(usage.get("completion_tokens") or 0)
                    usage["cost_total_usd"] = (pt / 1000 * self.cfg.model.cost.input_per_1k_usd) + (ct / 1000 * self.cfg.model.cost.output_per_1k_usd)
                # Extract finish_reason and detect truncation from the raw response.
                raw_resp = getattr(resp, "raw", None) or {}
                finish_reason: str | None = None
                if isinstance(raw_resp, dict):
                    finish_reason = raw_resp.get("response_stats", {}).get("finish_reason")
                was_truncated = finish_reason in ("length", "content_filter")
                self.logger.info(
                    "model.generate_done | sample=%s | stage=%s | attempt=primary | elapsed=%.1fs | response_chars=%s | completion_tokens=%s | finish_reason=%s | was_truncated=%s | enable_thinking=%s",
                    sample.sample_id, stage, elapsed, len(text), usage.get("completion_tokens"),
                    finish_reason, was_truncated,
                    proof_cfg.provider_extra_body.get("chat_template_kwargs", {}).get("enable_thinking"),
                )
                call_record = {
                    "name": stage,
                    # Full chat messages (no secrets — only prompt content).
                    "messages": [dict(m) for m in messages],
                    "system_prompt": system,
                    "user_prompt": prompt,
                    "request_payload_keys": ["model", "messages", "temperature", "max_tokens"],
                    # Backward-compatible single-string fields kept for old readers.
                    "prompt": prompt,
                    "system": system,
                    "prompt_chars": prompt_chars,
                    "prompt_has_truncation_marker": prompt_has_truncation_marker,
                    "response": text,
                    "raw": text,
                    "usage": usage,
                    "total_stage_usage": usage,
                    "elapsed_seconds": elapsed,
                    "json_status": "raw_agentic_proof_pending_parse",
                    "provider_raw": raw_resp,
                    # Token budget and truncation fields.
                    "requested_max_tokens": max_tokens,
                    "effective_max_tokens": int(max_tokens),
                    "finish_reason": finish_reason,
                    "was_truncated": was_truncated,
                }
                trace.model_calls.append(call_record)
                # Write incrementally so flow() can read it during a live run.
                try:
                    _mc_path = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}" / "model_calls.jsonl"
                    _mc_path.parent.mkdir(parents=True, exist_ok=True)
                    with _mc_path.open("a", encoding="utf-8") as _mcf:
                        _mcf.write(json.dumps(call_record, ensure_ascii=False, default=str) + "\n")
                except Exception:
                    pass
                trace.raw_outputs.append(text)
                if self.live:
                    done_payload = {"sample_id": sample.sample_id, "stage": stage, "prompt_chars": prompt_chars, "prompt_has_truncation_marker": prompt_has_truncation_marker, "response_chars": len(text), "elapsed_seconds": elapsed, "usage": usage, "json_status": "raw_agentic_proof_pending_parse"}
                    self.live.event("model_call.done", done_payload)
                    # Do not overwrite cumulative live token/cost counters here;
                    # model_call.done already increments them stage-by-stage.
                    self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": stage, "api_stage": stage, "api_state": "done", "last_response_chars": len(text), "last_model_elapsed_seconds": elapsed})
                return {"content": text, "usage": usage, "raw": getattr(resp, "raw", None)}
            except Exception as exc:
                elapsed = time.perf_counter() - start if "start" in locals() else 0.0
                error_text = f"{type(exc).__name__}: {exc}"
                self.logger.error(
                    "model.generate_error | sample=%s | stage=%s | attempt=primary | elapsed=%.1fs | error=%s",
                    sample.sample_id, stage, elapsed, error_text,
                )
                trace.model_calls.append({
                    "name": stage,
                    "messages": [dict(m) for m in messages],
                    "system_prompt": system,
                    "user_prompt": prompt,
                    "request_payload_keys": ["model", "messages", "temperature", "max_tokens"],
                    "prompt": prompt,
                    "system": system,
                    "prompt_chars": prompt_chars,
                    "response": "",
                    "raw": "",
                    "usage": {},
                    "elapsed_seconds": elapsed,
                    "json_status": "provider_error",
                    "error": error_text,
                    "requested_max_tokens": max_tokens,
                    "effective_max_tokens": int(max_tokens),
                    "finish_reason": None,
                    "was_truncated": False,
                })
                if self.live:
                    self.live.event("model_call.error", {"sample_id": sample.sample_id, "stage": stage, "elapsed_seconds": elapsed, "error": error_text, "prompt_chars": prompt_chars})
                    self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": stage, "api_stage": stage, "api_state": "error", "last_model_error": error_text, "last_model_elapsed_seconds": elapsed})
                # Persist the error record to disk so Agentic Flow can display
                # the failed stage even when the exception later fails the sample.
                try:
                    _mc_err_path = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}" / "model_calls.jsonl"
                    _mc_err_path.parent.mkdir(parents=True, exist_ok=True)
                    with _mc_err_path.open("a", encoding="utf-8") as _mcef:
                        _mcef.write(json.dumps(trace.model_calls[-1], ensure_ascii=False, default=str) + "\n")
                except Exception:
                    pass
                raise
            finally:
                if hasattr(model, "cfg"):
                    model.cfg.max_tokens = old_max_tokens
                    model.cfg.temperature = old_temperature
                    model.cfg.api_extra_body = old_extra_body

        executor = KGToolExecutor(max_items_per_query=int(getattr(ap_cfg, "evidence_limit_per_query", 8) or 8), max_text_chars=1200)
        kg_tool_steps: list[dict[str, Any]] = []

        def infer_query_type(q: dict[str, Any]) -> str:
            """Infer a legacy query type only when query_text is not CodeKG-call syntax.

            Agentic-proof prompts emit deterministic function-call style CodeKG
            queries such as ``variable_flow(...)``.  The previous adapter mapped
            those calls back to coarse legacy labels (risk/guard/variable) and
            then replaced the executable query with the first variable name.  In
            practice this starved the KG layer: broad CodeKG queries were not
            actually executed and many returned zero items.

            If query_text is already a CodeKG function call, preserve its kind so
            ``KGToolExecutor._as_codekg_query`` can execute the exact query.
            """
            text_raw = str(q.get("query_text") or q.get("query") or "").strip()
            m = re.match(r"^\s*([A-Za-z_]\w*)\s*\(", text_raw)
            if m:
                return m.group(1).lower()
            purpose = str(q.get("purpose") or "").lower()
            text = text_raw.lower()
            if "guard" in purpose or "guard" in text or "check" in text:
                return "guard"
            if "caller" in purpose:
                return "caller"
            if "callee" in purpose:
                return "callee"
            if "dataflow" in purpose or "variable" in purpose:
                return "variable"
            if "sink" in text or "danger" in purpose or "prove" in purpose:
                return "risk"
            if "disprove" in purpose or "safe" in text:
                return "safety"
            return "search"

        def kg_search(query_dicts: list[dict[str, Any]], *, sample: dict[str, Any], limit: int) -> list[dict[str, Any]]:
            mapped: list[dict[str, Any]] = []
            for q in query_dicts:
                text = str(q.get("query_text") or q.get("query") or "").strip()
                qtype = infer_query_type(q)
                variables = [str(v).strip() for v in (q.get("variables") or []) if str(v).strip()]
                is_codekg_call = bool(re.match(r"^\s*[A-Za-z_]\w*\s*\(", text))
                # Preserve executable CodeKG query_text.  Only legacy non-CodeKG
                # queries use a variable as their query payload.
                query_payload = text if is_codekg_call else (variables[0] if qtype in {"variable", "guard", "safety", "risk"} and variables else text)
                mapped.append({
                    "query_type": qtype,
                    "query": query_payload,
                    "query_id": q.get("query_id"),
                    "hypothesis_id": q.get("hypothesis_id") or q.get("_hypothesis_id"),
                    "agentic_stage": q.get("_agentic_stage"),
                    "query_text": text,
                    "reason": q.get("purpose") or q.get("expected_evidence"),
                    "match": "substring" if qtype in {"search", "safety", "risk"} else "exact_identifier",
                    "wanted_evidence": [q.get("expected_evidence")] if q.get("expected_evidence") else [],
                    "_source": "agentic_proof",
                })
            results = executor.execute_many(graph=graph, sample=sample_obj, queries=mapped, round_index=3, evidence_id_prefix="AP", query_source="agentic_proof")
            new_items = []
            seen = {item.evidence_id for item in evidence.items}
            for _idx, result in enumerate(results):
                step = result.to_dict()
                kg_tool_steps.append(step)
                if _idx < len(mapped):
                    mapped[_idx]["returned_items"] = len(result.items or [])
                    mapped[_idx]["status"] = result.status
                    mapped[_idx]["diagnostics"] = result.diagnostics
                    mapped[_idx]["items"] = [KGToolResult._item_to_dict(i) for i in KGToolResult._flatten_items(result.items)]
                for item in result.items:
                    if item.evidence_id not in seen:
                        evidence.items.append(item)
                        seen.add(item.evidence_id)
                        new_items.append(item)
            trace.kg_tool_steps = kg_tool_steps
            trace.kg_queries.extend(mapped)
            trace.accumulated_evidence_count = len(evidence.items)
            self.logger.info("agent.kg_tools | sample=%s | round=agentic_proof | queries=%s | returned_items=%s | evidence_items=%s", sample_obj.sample_id, len(mapped), len(new_items), len(evidence.items))
            if self.live:
                self.live.update_sample(sample_obj.sample_id, {"status": "running", "agent_stage": "agentic_proof_kg_tools", "kg_queries_last_round": len(mapped), "kg_returned_items_last_round": len(new_items), "accumulated_evidence_count": len(evidence.items)})
            return [evidence_to_dict(i) for i in new_items]

        sample_obj = sample

        # evidence_iterations.jsonl — one row per follow-up retrieval round
        _iter_log_path = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}" / "evidence_iterations.jsonl"
        _iter_rows: list[dict[str, Any]] = []

        def _on_iteration_event(event_type: str, data: dict[str, Any]) -> None:
            """Relay adapter iteration events to live dashboard and durable JSONL artifact."""
            if self.live:
                if event_type == "evidence_iteration_started":
                    self.live.event("evidence_iteration_started", data)
                    self.live.update_sample(sample.sample_id, {
                        "status": "running",
                        "agent_stage": f"evidence_iteration_{data.get('iteration')}",
                        "evidence_phase": data.get("phase"),
                    })
                elif event_type == "evidence_iteration_completed":
                    self.live.event("evidence_iteration_completed", data)
            if event_type == "evidence_iteration_completed":
                row = {
                    "iteration": data.get("iteration"),
                    "phase": data.get("phase"),
                    "new_evidence_count": data.get("new_evidence_count", 0),
                    "stop_reason": data.get("stop_reason"),
                }
                _iter_rows.append(row)
                try:
                    _iter_log_path.parent.mkdir(parents=True, exist_ok=True)
                    with _iter_log_path.open("a", encoding="utf-8") as _f:
                        _f.write(json.dumps(row, ensure_ascii=False) + "\n")
                except Exception:
                    pass

        result = run_agentic_proof_pipeline(
            sample=public_sample_dict(),
            target_source=sample.func_body,
            initial_evidence=[evidence_to_dict(i) for i in evidence.items],
            llm_generate=llm_generate,
            kg_search=kg_search,
            config=proof_cfg,
            on_iteration_event=_on_iteration_event,
        )
        decision = result.decision.normalize_prediction_bool()
        final_json = decision.model_dump(mode="json")
        trace.risk_hypotheses = list((result.hypotheses or {}).get("hypotheses") or [])
        trace.verification = final_json.get("final_hypothesis_statuses") or []
        trace.hypothesis_ledger = trace.verification
        trace.accumulated_evidence_count = len(evidence.items)

        # Preserve the accepted final JSON in the legacy report schema while
        # keeping the real LLM input/output stages above.  This synthetic row is
        # clearly marked and has no model usage.
        trace.model_calls.append({
            "name": "final_decision",
            "prompt": "[accepted parsed final JSON produced by agentic-proof validator; not a separate LLM call]",
            "response": json.dumps(final_json, indent=2, ensure_ascii=False),
            "parsed": final_json,
            "json_status": "json_ok",
            "elapsed_seconds": 0.0,
            "usage": {},
        })
        validator_mods = []
        for ev in getattr(result, "events", []) or []:
            if getattr(ev, "event", None) == "validated":
                details = getattr(ev, "details", {}) or {}
                if details.get("validator_notes") or details.get("modified"):
                    validator_mods.append({
                        "stage": getattr(ev, "stage", "agentic_proof_validator"),
                        "notes": details.get("validator_notes") or [],
                        "modified": bool(details.get("modified")),
                        "after": final_json,
                    })
        trace.final_validator_modifications = validator_mods

        # Post-parse enrichment: add parsed_answer / parse_status / answer_text to
        # every model_calls entry, then rewrite model_calls.jsonl so the Agentic Flow
        # dashboard can show the correct JSON valid/invalid badge and detail panel.
        for _call in trace.model_calls:
            _enrich_call_parse_result(_call)
        try:
            _mc_enrich_path = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}" / "model_calls.jsonl"
            _mc_enrich_path.parent.mkdir(parents=True, exist_ok=True)
            _mc_enrich_path.write_text(
                "\n".join(json.dumps(c, ensure_ascii=False, default=str) for c in trace.model_calls) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

        # Write agent_flow.json — durable artifact for the Agentic Flow dashboard tab.
        # Captures the full stage sequence with iteration metadata so finished runs
        # can be inspected without the live WS connection.
        try:
            _flow_path = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name}" / "agent_flow.json"
            _flow_path.parent.mkdir(parents=True, exist_ok=True)
            _flow_data = {
                "sample_id": sample.sample_id,
                "loop_stop_reason": getattr(result, "loop_stop_reason", None),
                "iterations_completed": getattr(result, "iterations_completed", 0),
                "iterative_loop_enabled": proof_cfg.iterative_evidence_loop,
                "stages": [
                    {
                        "stage": c.get("name"),
                        "status": "completed" if not c.get("error") else "failed",
                        "elapsed_seconds": c.get("elapsed_seconds"),
                        "finish_reason": c.get("finish_reason"),
                        "was_truncated": c.get("was_truncated", False),
                        "requested_max_tokens": c.get("requested_max_tokens"),
                        "effective_max_tokens": c.get("effective_max_tokens"),
                        "prompt_chars": c.get("prompt_chars"),
                        "response_chars": len(c.get("response") or ""),
                        "usage": c.get("usage") or {},
                    }
                    for c in (trace.model_calls or [])
                    if c.get("name") not in ("final_decision",)
                ],
                "iterations": _iter_rows,
                "controller_events": [
                    {
                        "stage": getattr(ev, "stage", None),
                        "event": getattr(ev, "event", None),
                        "elapsed_seconds": getattr(ev, "elapsed_seconds", 0.0),
                        "details": getattr(ev, "details", {}) or {},
                    }
                    for ev in (getattr(result, "events", []) or [])
                ],
                "total_evidence_items": len(evidence.items),
                "initial_evidence_items": trace.initial_evidence_count,
            }
            _flow_path.write_text(
                json.dumps(_flow_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

        usage = dict(result.usage or {})
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        usage.setdefault("total_tokens", pt + ct)
        usage.setdefault("cost_total_usd", (pt / 1000 * self.cfg.model.cost.input_per_1k_usd) + (ct / 1000 * self.cfg.model.cost.output_per_1k_usd))
        usage.setdefault("estimated", False)
        pred_bool = decision.prediction_bool if decision.prediction_bool is not None else decision.forced_prediction_bool
        pred = Prediction(
            sample_id=sample.sample_id,
            is_vulnerable=bool(pred_bool) if pred_bool is not None else False,
            confidence=decision.confidence,
            primary_vulnerability_type=(decision.minimum_vulnerability_proof.dangerous_operation if decision.minimum_vulnerability_proof else None),
            vuln_statements=[],
            evidence_used=list(decision.decisive_evidence_ids or []),
            decision_status=decision.decision_status or decision.prediction.value,
            binary_prediction_policy="agentic_proof: vulnerable requires complete minimum proof after counter-evidence review",
            reasoning_summary=decision.explanation,
            model_backend=self.cfg.model.backend,
            usage=usage,
            validation_notes=list(decision.limitations or []),
            forced_prediction=decision.forced_prediction,
            forced_prediction_bool=decision.forced_prediction_bool,
            evidence_strength=decision.evidence_strength,
            why_forced_binary=decision.why_forced_binary,
            residual_uncertainty=list(decision.residual_uncertainty or []),
            final_hypothesis_statuses=[h.model_dump(mode="json") if hasattr(h, "model_dump") else dict(h) for h in (decision.final_hypothesis_statuses or [])],
            normalization_warnings=list(decision.normalization_warnings or []),
        )
        pred.raw_response = str(final_json)
        if self.live:
            self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "agentic_proof_done", "decision_status": pred.decision_status, "prediction_is_vulnerable": pred.is_vulnerable, "confidence": pred.confidence, "total_tokens": usage.get("total_tokens"), "cost_total_usd": usage.get("cost_total_usd")})
        return pred, trace, evidence

    def _classify_one_sample_threadsafe(self, sample: SecVulEvalSample, graph_context: dict[tuple[str, str], dict[str, Any]], model: Any) -> dict[str, Any]:
        """Classify one sample for API-parallel mode.

        This mirrors the sequential path but keeps all shared file writes behind
        self.write_lock.  The model object is intentionally shared so the
        provider-wide rate limiter coordinates all concurrent agent calls.
        """
        agent = AgentController(self.cfg.agent, self.cfg.retrieval, self.cfg.model, model, self.logger, self.cfg.prompting, event_sink=self._live_agent_event)
        retriever = EvidenceRetriever(self.cfg.retrieval)

        resolution = self.sample_resolution.get(sample.sample_id)
        resolved_commit = resolution.selected_commit_id if resolution else sample.commit_id
        resolved_label = resolution.selected_label if resolution else "dataset_commit"
        validation_status = resolution.selected_status if resolution else None
        validation_similarity = resolution.selected_similarity if resolution else None
        validation_artifact_dir = resolution.selected_artifact_dir if resolution else None

        if self.live:
            self.live.update_sample(sample.sample_id, {
                "sample_id": sample.sample_id,
                "project": sample.project,
                "filepath": sample.filepath,
                "function": sample.func_name,
                "status": "running",
                "agent_stage": "starting",
            })
            self.live.event("sample.start", {"sample_id": sample.sample_id, "project": sample.project, "function": sample.func_name})

        log_kv(
            self.logger,
            "sample.start",
            id=sample.sample_id,
            project=sample.project,
            label="vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
            dataset_commit=(sample.commit_id or "?")[:12],
            resolved_commit=(resolved_commit or "?")[:12],
            resolved_label=resolved_label,
            target_status=validation_status,
            target_similarity=validation_similarity,
            function=sample.func_name,
        )

        graph_key = self.sample_graph_keys.get(sample.sample_id)
        graph_context_item = graph_context.get(graph_key, {}) if graph_key else {}
        graph = self._graph_for_sample(sample, graph_context)
        if graph is None:
            graph = self._function_only_graph(sample)
        graph_manifest = getattr(graph, "manifest", {}) or {}
        graph_status = graph_context_item.get("graph_status") or graph_manifest.get("graph_status") or "function_only_fallback"
        graph_dir = graph_context_item.get("graph_dir")

        self.logger.info(
            "sample.graph | id=%s | graph_commit=%s | graph_scope=%s | nodes=%s | edges=%s",
            sample.sample_id,
            str(graph_manifest.get("commit_id") or resolved_commit or "?")[:12],
            graph_manifest.get("scope") or graph_manifest.get("kg_version") or "unknown",
            len(getattr(graph, "nodes", [])),
            len(getattr(graph, "edges", [])),
        )

        if self.live:
            self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "retrieval"})
        self.logger.info("retrieval.start | sample=%s | resolved_commit=%s", sample.sample_id, (resolved_commit or "?")[:12])
        retrieval_start = time.perf_counter()
        evidence = retriever.retrieve(graph, sample)
        retrieval_seconds = time.perf_counter() - retrieval_start
        evidence.dataset_commit_id = sample.commit_id
        evidence.resolved_commit_id = resolved_commit
        evidence.resolved_commit_label = resolved_label
        evidence.target_validation_status = validation_status
        evidence.target_validation_similarity = validation_similarity
        evidence.retrieval_diagnostics.setdefault("graph", {}).update({
            "graph_status": graph_status,
            "graph_dir": str(graph_dir) if graph_dir else None,
            "manifest": graph_manifest,
            "kg_source_integrity": "KG was built only from repository source code; labels/CVE/commit metadata were not inserted into KG.",
        })
        self.logger.info(
            "retrieval.done | sample=%s | resolved_commit=%s | target_found=%s | items=%s",
            sample.sample_id,
            (resolved_commit or "?")[:12],
            evidence.target_found,
            len(evidence.items),
        )

        if self.live:
            self.live.update_sample(sample.sample_id, {"status": "running", "agent_stage": "agent_loop", "initial_evidence_count": len(evidence.items)})
            if getattr(model, "rate_limiter", None) is not None:
                self.live.update_api(model.rate_limiter.snapshot())
        self.logger.info("agent.start | sample=%s | evidence_items=%s", sample.sample_id, len(evidence.items))
        agent.progress_callback = self._make_agent_progress_callback(graph_manifest=graph_manifest, graph_status=graph_status, graph_dir=str(graph_dir) if graph_dir else None, validation_artifact_dir=validation_artifact_dir)
        # Create/open a live report as soon as the sample enters the agent loop; it will be overwritten after each model/KG stage.
        self._write_live_agent_report(stage="agent_loop_start", sample=sample, evidence=evidence, trace=AgentTrace(sample_id=sample.sample_id, mode=self.cfg.agent.mode), prediction=None, graph_manifest=graph_manifest, graph_status=graph_status, graph_dir=str(graph_dir) if graph_dir else None, validation_artifact_dir=validation_artifact_dir, in_progress=True)
        agent_start = time.perf_counter()
        pred, trace, evidence = self._classify_with_configured_agent(agent=agent, model=model, sample=sample, evidence=evidence, graph=graph)
        agent_seconds = time.perf_counter() - agent_start

        pred.dataset_commit_id = sample.commit_id
        pred.resolved_commit_id = resolved_commit
        pred.resolved_commit_label = resolved_label
        pred.target_validation_status = validation_status
        pred.target_validation_similarity = validation_similarity
        pred.target_validation_artifact_dir = validation_artifact_dir
        trace.dataset_commit_id = sample.commit_id
        trace.resolved_commit_id = resolved_commit
        trace.resolved_commit_label = resolved_label
        trace.target_validation_artifact_dir = validation_artifact_dir

        if self.cfg.agent.save_demo_reports:
            report_path = write_sample_agent_demo(
                run_dir=self.run_dir,
                sample=sample,
                evidence=evidence,
                trace=trace,
                prediction=pred,
                dataset_path=self.cfg.dataset.path,
                graph_manifest=graph_manifest,
                graph_status=graph_status,
                graph_dir=str(graph_dir) if graph_dir else None,
                validation_artifact_dir=validation_artifact_dir,
                prompting_config=self.cfg.prompting.model_dump(mode="json"),
                report_options=self._demo_report_options(stage="done", in_progress=False),
            )
            trace.report_path = str(report_path)
            self.logger.info("agent.demo | sample=%s | report=%s", sample.sample_id, report_path)

        self.logger.info(
            "agent.done | sample=%s | resolved_commit=%s | pred=%s | conf=%.2f | tokens=%s",
            sample.sample_id,
            (resolved_commit or "?")[:12],
            pred.is_vulnerable,
            pred.confidence,
            pred.usage.get("total_tokens"),
        )

        decision_flow_summary = self._trace_decision_flow_summary(trace, pred)
        sample_runtime = {
            "sample_id": sample.sample_id,
            "project": sample.project,
            "filepath": sample.filepath,
            "function": sample.func_name,
            "commit_message_report_only": sample.commit_message,
            "ground_truth_is_vulnerable": bool(sample.is_vulnerable),
            "prediction_is_vulnerable": bool(pred.is_vulnerable),
            "valid_binary_prediction": self._is_valid_binary_prediction(pred),
            "correct": self._is_valid_binary_prediction(pred) and (bool(sample.is_vulnerable) == bool(pred.is_vulnerable)),
            "error_type": self._prediction_error_type(sample, pred),
            "decision_status": pred.decision_status,
            "parse_error": pred.parse_error,
            "confidence": pred.confidence,
            "reasoning_summary": pred.reasoning_summary,
            "primary_vulnerability_type": pred.primary_vulnerability_type,
            "evidence_used": list(pred.evidence_used or []),
            "resolved_commit_id": resolved_commit,
            "resolved_commit_label": resolved_label,
            "target_validation_status": validation_status,
            "target_validation_similarity": validation_similarity,
            "graph_status": graph_status,
            "graph_dir": str(graph_dir) if graph_dir else None,
            "graph_nodes": len(getattr(graph, "nodes", [])),
            "graph_edges": len(getattr(graph, "edges", [])),
            "graph_num_files": graph_manifest.get("num_files"),
            "graph_num_functions": graph_manifest.get("num_functions"),
            "graph_num_statements": graph_manifest.get("num_statements"),
            "initial_evidence_count": trace.initial_evidence_count,
            "accumulated_evidence_count": trace.accumulated_evidence_count,
            "kg_tool_steps": len(trace.kg_tool_steps),
            "model_calls": len(trace.model_calls),
            "retrieval_seconds": retrieval_seconds,
            "agent_seconds": agent_seconds,
            "model_call_seconds": sum(float(c.get("elapsed_seconds") or 0) for c in trace.model_calls),
            "model_stage_breakdown": [
                {
                    "stage": c.get("name"),
                    "elapsed_seconds": c.get("elapsed_seconds", 0.0),
                    "prompt_chars": c.get("prompt_chars"),
                    "prompt_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("prompt_tokens"),
                    "completion_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("completion_tokens"),
                    "total_tokens": (c.get("total_stage_usage") or c.get("usage") or {}).get("total_tokens"),
                    "cost_total_usd": (c.get("total_stage_usage") or c.get("usage") or {}).get("cost_total_usd"),
                    "json_status": c.get("json_status"),
                }
                for c in trace.model_calls
            ],
            "prompt_tokens": pred.usage.get("prompt_tokens", 0),
            "completion_tokens": pred.usage.get("completion_tokens", 0),
            "total_tokens": pred.usage.get("total_tokens", 0),
            "cost_total_usd": pred.usage.get("cost_total_usd", 0.0),
            "usage_estimated": pred.usage.get("estimated", True),
            "agent_report": trace.report_path,
            "agent_report_rel": Path(trace.report_path).relative_to(self.run_dir).as_posix() if trace.report_path else None,
            "agent_report_url": self._dashboard_url_for_path(trace.report_path) if trace.report_path else None,
            "posthoc_commit_audit": trace.posthoc_commit_audit,
            "validation_notes": pred.validation_notes,
            "final_validator_modifications": trace.final_validator_modifications,
            "decision_flow_summary": decision_flow_summary,
            "raw_model_is_vulnerable": decision_flow_summary.get("raw_model_is_vulnerable"),
            "raw_model_decision_status": decision_flow_summary.get("raw_model_decision_status"),
            "raw_model_confidence": decision_flow_summary.get("raw_model_confidence"),
            "validator_modified": decision_flow_summary.get("validator_modified"),
            "validator_modification_count": decision_flow_summary.get("validator_modification_count"),
            "validator_stages": decision_flow_summary.get("validator_stages"),
            "final_system_is_vulnerable": bool(pred.is_vulnerable),
            "final_system_decision_status": pred.decision_status,
            "final_system_confidence": pred.confidence,
            "json_repair_attempts": self._trace_json_repair_attempts(trace),
            "json_repaired_calls": self._trace_json_repaired_calls(trace),
            "mechanical_normalizations": sum(len(c.get("mechanical_normalizations", []) or []) for c in trace.model_calls),
        }

        with self.write_lock:
            append_jsonl(self.run_dir / "evidence_packs.jsonl", evidence)
            append_jsonl(self.run_dir / "predictions.jsonl", pred)
            append_jsonl(self.run_dir / "agent_traces.jsonl", trace)
            append_jsonl(self.run_dir / "usage_events.jsonl", {
                "sample_id": sample.sample_id,
                "dataset_commit_id": sample.commit_id,
                "resolved_commit_id": resolved_commit,
                "resolved_commit_label": resolved_label,
                **pred.usage,
            })
            append_jsonl(self.run_dir / "sample_runtime.jsonl", sample_runtime)

        if self.live:
            self.live.update_sample(sample.sample_id, {**sample_runtime, "status": "done", "agent_stage": "done"})
            if getattr(model, "rate_limiter", None) is not None:
                self.live.update_api(model.rate_limiter.snapshot())
            self.live.event("sample.done", {"sample_id": sample.sample_id, "error_type": sample_runtime.get("error_type"), "cost_total_usd": sample_runtime.get("cost_total_usd")})

        return {"prediction": pred, "trace": trace, "evidence": evidence, "sample_runtime": sample_runtime}


    def _attach_live_model_events(self, model: Any) -> None:
        if not self.live:
            return
        if hasattr(model, "set_event_sink"):
            model.set_event_sink(self._live_model_event)
        elif getattr(model, "rate_limiter", None) is not None and hasattr(model.rate_limiter, "set_event_sink"):
            model.rate_limiter.set_event_sink(self._live_model_event)

    def _live_agent_event(self, kind: str, data: dict[str, Any]) -> None:
        if not self.live:
            return
        sample_id = data.get("sample_id")
        if sample_id:
            update: dict[str, Any] = {"last_agent_event": kind}
            stage = data.get("stage") or data.get("agent_stage")
            if stage:
                update["agent_stage"] = stage
                update["current_model_stage"] = stage
            if kind == "agent.classify.start":
                update.update({"status": "running", "agent_stage": "agent_loop"})
            elif kind == "model_call.start":
                update.update({"status": "waiting_api", "api_state": "queued", "current_model_stage": stage, "current_prompt_chars": data.get("prompt_chars")})
            elif kind == "model_call.repair_start":
                update.update({"status": "waiting_api", "api_state": "repair_queued", "current_model_stage": stage, "current_prompt_chars": data.get("prompt_chars"), "last_parse_error": data.get("parse_error")})
            elif kind in {"model_call.done", "model_call.repair_done"}:
                update.update({"status": "running", "api_state": "done", "last_json_status": data.get("json_status"), "last_parse_error": data.get("parse_error"), "last_response_chars": data.get("response_chars")})
                usage = data.get("usage") or {}
                if isinstance(usage, dict):
                    update.update({
                        "prompt_tokens": usage.get("prompt_tokens", update.get("prompt_tokens")),
                        "completion_tokens": usage.get("completion_tokens", update.get("completion_tokens")),
                        "total_tokens": usage.get("total_tokens", update.get("total_tokens")),
                        "cost_total_usd": usage.get("cost_total_usd", update.get("cost_total_usd")),
                    })
            elif kind == "kg_tools.done":
                update.update({"status": "running", "agent_stage": f"kg_tool_round_{data.get('round')}", "kg_queries_last_round": data.get("queries"), "kg_returned_items_last_round": data.get("returned_items"), "accumulated_evidence_count": data.get("evidence_items")})
            elif kind.startswith("posthoc_commit_audit"):
                update.update({"status": "running", "agent_stage": "posthoc_commit_audit", "posthoc_commit_audit": {k: v for k, v in data.items() if k != "sample_id"}})
            elif kind == "agent.classify.done":
                update.update({"status": "running", "agent_stage": "agent_done", "decision_status": data.get("decision_status"), "prediction_is_vulnerable": data.get("is_vulnerable"), "confidence": data.get("confidence"), "total_tokens": data.get("total_tokens")})
            self.live.update_sample(str(sample_id), update)
        self.live.event(kind, data)

    def _live_model_event(self, kind: str, data: dict[str, Any]) -> None:
        if not self.live:
            return
        self.live.event(kind, data)

    @staticmethod
    def _trace_json_repair_attempts(trace: Any) -> int:
        return sum(len(c.get("repair_attempts", []) or []) for c in getattr(trace, "model_calls", []) or [])

    @staticmethod
    def _trace_json_repaired_calls(trace: Any) -> int:
        return sum(1 for c in getattr(trace, "model_calls", []) or [] if c.get("json_status") == "json_repaired")

    @staticmethod
    def _trace_decision_flow_summary(trace: Any, pred: Prediction | None = None) -> dict[str, Any]:
        """Expose raw/final decision separation for research metrics.

        The raw final model JSON is the parsed output of the final_decision call
        before consistency repair and source/evidence validators. The final
        prediction is the system decision used for benchmark metrics.
        """
        raw = None
        repair = None
        for call in getattr(trace, "model_calls", []) or []:
            if call.get("name") == "final_decision" and isinstance(call.get("parsed"), dict):
                raw = call.get("parsed")
            elif call.get("name") == "final_decision_consistency_repair" and isinstance(call.get("parsed"), dict):
                repair = call.get("parsed")
        mods = list(getattr(trace, "final_validator_modifications", []) or [])
        accepted = None
        for mod in reversed(mods):
            if isinstance(mod, dict) and isinstance(mod.get("after"), dict):
                accepted = mod.get("after")
                break
        if accepted is None:
            accepted = repair or raw
        notes: list[str] = []
        stages: list[str] = []
        for mod in mods:
            if not isinstance(mod, dict):
                continue
            if mod.get("stage"):
                stages.append(str(mod.get("stage")))
            for note in mod.get("notes", []) or []:
                notes.append(str(note))
        raw_decision = {
            "is_vulnerable": raw.get("is_vulnerable"),
            "decision_status": raw.get("decision_status"),
            "confidence": raw.get("confidence"),
            "primary_vulnerability_type": raw.get("primary_vulnerability_type"),
        } if isinstance(raw, dict) else None
        evidence_validated = {
            "is_vulnerable": accepted.get("is_vulnerable"),
            "decision_status": accepted.get("decision_status"),
            "confidence": accepted.get("confidence"),
            "primary_vulnerability_type": accepted.get("primary_vulnerability_type"),
        } if isinstance(accepted, dict) else None
        final = {
            "is_vulnerable": pred.is_vulnerable,
            "decision_status": pred.decision_status,
            "confidence": pred.confidence,
            "primary_vulnerability_type": pred.primary_vulnerability_type,
        } if pred is not None else None
        return {
            "raw_model_decision": raw_decision,
            "evidence_validated_decision": evidence_validated,
            "final_system_decision": final,
            "raw_model_is_vulnerable": raw.get("is_vulnerable") if isinstance(raw, dict) else None,
            "raw_model_decision_status": raw.get("decision_status") if isinstance(raw, dict) else None,
            "raw_model_confidence": raw.get("confidence") if isinstance(raw, dict) else None,
            "raw_model_primary_vulnerability_type": raw.get("primary_vulnerability_type") if isinstance(raw, dict) else None,
            "consistency_repair_is_vulnerable": repair.get("is_vulnerable") if isinstance(repair, dict) else None,
            "consistency_repair_decision_status": repair.get("decision_status") if isinstance(repair, dict) else None,
            "validator_modified": bool(mods),
            "validator_modification_count": len(mods),
            "validator_stages": stages,
            "validator_reasons": notes,
            "accepted_final_is_vulnerable": accepted.get("is_vulnerable") if isinstance(accepted, dict) else None,
            "accepted_final_decision_status": accepted.get("decision_status") if isinstance(accepted, dict) else None,
            "accepted_final_confidence": accepted.get("confidence") if isinstance(accepted, dict) else None,
        }

    @staticmethod
    def _is_valid_binary_prediction(pred: Prediction) -> bool:
        if pred.parse_error:
            return False
        if str(pred.decision_status or "") in {"parse_failed", "inconclusive", "invalid", "error"}:
            return False
        return True

    def _prediction_error_type(self, sample: SecVulEvalSample, pred: Prediction) -> str:
        if not self._is_valid_binary_prediction(pred):
            return "INVALID"
        if sample.is_vulnerable and pred.is_vulnerable:
            return "TP"
        if (not sample.is_vulnerable) and (not pred.is_vulnerable):
            return "TN"
        if (not sample.is_vulnerable) and pred.is_vulnerable:
            return "FP"
        return "FN"


    def estimate_cost(self, assumed_completion_tokens_per_call: int | None = None) -> PipelineResult:
        """Build/reuse KG and retrieval context, then count prompt tokens without model generation.

        This is designed for pre-flight cost estimation before using a paid API.
        For `model.tokenizer_backend: llama_cpp`, a running llama-server is used
        through `/tokenize`; no transformers dependency is used.
        """
        import csv

        with profile(self.logger, self.run_dir, "estimate_cost"):
            samples = self._load_selected_samples()
            write_jsonl(self.run_dir / "samples.jsonl", samples)
            log_kv(self.logger, "Sample selection", selected=len(samples), projects=len({s.project for s in samples}), project_commit_groups=len(group_by_project_commit(samples)))

            graph_context = self._prepare_project_commit_graphs(samples, classify=True)
            if self.live:
                self.live.set_status("classification")
                if getattr(model, "rate_limiter", None) is not None:
                    self.live.update_api(model.rate_limiter.snapshot())
            runnable_samples = [s for s in samples if s.sample_id not in self.skipped_sample_ids]
            write_jsonl(self.run_dir / "runnable_samples.jsonl", runnable_samples)
            if not runnable_samples:
                raise RuntimeError("No runnable samples remain after target validation.")

            retriever = EvidenceRetriever(self.cfg.retrieval)
            managed_token_server = None
            if self.cfg.model.tokenizer_backend == "llama_cpp" and self.cfg.model.server_start:
                from vuln_commit_kg.models.llama_server import LlamaServerModel
                self.logger.info("Starting managed llama-server for tokenization-only estimate")
                managed_token_server = LlamaServerModel(self.cfg.model)
            counter = TokenCounter(self.cfg.model)
            completion_budget = int(assumed_completion_tokens_per_call or self.cfg.model.max_tokens)
            calls_per_sample = 2 if (self.cfg.agent.enabled and self.cfg.agent.mode == "iterative") else 1
            rows: list[dict[str, Any]] = []
            progress = ProgressMeter(self.logger, len(runnable_samples), "estimate.samples", self.cfg.logging.log_every_n_samples, self.cfg.logging.log_every_seconds)

            for sample in runnable_samples:
                resolution = self.sample_resolution.get(sample.sample_id)
                resolved_commit = resolution.selected_commit_id if resolution else sample.commit_id
                resolved_label = resolution.selected_label if resolution else "dataset_commit"
                graph = self._graph_for_sample(sample, graph_context)
                if graph is None:
                    graph = self._function_only_graph(sample)
                evidence = retriever.retrieve(graph, sample)
                evidence.dataset_commit_id = sample.commit_id
                evidence.resolved_commit_id = resolved_commit
                evidence.resolved_commit_label = resolved_label
                append_jsonl(self.run_dir / "evidence_packs.jsonl", evidence)

                prompts: list[tuple[str, str]] = []
                if self.cfg.agent.enabled and self.cfg.agent.mode == "iterative":
                    p1 = risk_hypothesis_prompt(sample, evidence, self.cfg.retrieval.max_context_chars, self.cfg.prompting)
                    p2 = final_decision_prompt(
                        sample,
                        evidence,
                        trace_summary="ESTIMATION_ONLY: no model-generated prior analysis was produced.",
                        max_context_chars=self.cfg.retrieval.max_context_chars,
                        prompting_cfg=self.cfg.prompting,
                    )
                    prompts.extend([("risk_hypothesis", p1), ("final_decision", p2)])
                else:
                    p = final_decision_prompt(
                        sample,
                        evidence,
                        trace_summary="ESTIMATION_ONLY: single-pass classification estimate.",
                        max_context_chars=self.cfg.retrieval.max_context_chars,
                        prompting_cfg=self.cfg.prompting,
                    )
                    prompts.append(("final_decision", p))

                sample_prompt_tokens = 0
                for prompt_name, prompt_text in prompts:
                    input_text = SYSTEM_PROMPT + "\n\n" + prompt_text
                    counted = counter.count_result(input_text)
                    row = {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "label": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
                        "dataset_commit_id": sample.commit_id,
                        "resolved_commit_id": resolved_commit,
                        "resolved_commit_label": resolved_label,
                        "prompt_name": prompt_name,
                        "prompt_chars": len(input_text),
                        "prompt_tokens": counted.tokens,
                        "tokenization_method": counted.method,
                        "estimated": counted.estimated,
                        "assumed_completion_tokens": completion_budget,
                        "input_cost_usd": counted.tokens / 1000 * self.cfg.model.cost.input_per_1k_usd,
                        "completion_cost_usd": completion_budget / 1000 * self.cfg.model.cost.output_per_1k_usd,
                        "total_cost_usd": (counted.tokens / 1000 * self.cfg.model.cost.input_per_1k_usd) + (completion_budget / 1000 * self.cfg.model.cost.output_per_1k_usd),
                    }
                    rows.append(row)
                    append_jsonl(self.run_dir / "prompt_token_estimates.jsonl", row)
                    sample_prompt_tokens += counted.tokens

                progress.update(extra=f"sample={sample.sample_id} resolved={(resolved_commit or '?')[:12]} prompt_tokens={sample_prompt_tokens}")

            csv_path = self.run_dir / "prompt_token_estimates.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
                if rows:
                    writer.writeheader()
                    writer.writerows(rows)

            total_prompt = sum(int(r["prompt_tokens"]) for r in rows)
            total_completion_budget = completion_budget * len(rows)
            total_cost = sum(float(r["total_cost_usd"]) for r in rows)
            summary = {
                "samples": len(runnable_samples),
                "calls": len(rows),
                "calls_per_sample": calls_per_sample,
                "prompt_tokens": total_prompt,
                "assumed_completion_tokens": total_completion_budget,
                "assumed_total_tokens": total_prompt + total_completion_budget,
                "avg_prompt_tokens_per_sample": total_prompt / len(runnable_samples) if runnable_samples else 0.0,
                "avg_assumed_total_tokens_per_sample": (total_prompt + total_completion_budget) / len(runnable_samples) if runnable_samples else 0.0,
                "estimated_cost_usd": total_cost,
                "tokenization_method": rows[0]["tokenization_method"] if rows else None,
                "estimated_tokenizer": bool(any(r["estimated"] for r in rows)),
                "completion_budget_per_call": completion_budget,
                "note": "Prompt tokens are counted without making model-generation/API calls. Completion tokens use the configured budget.",
            }
            write_json(self.run_dir / "cost_estimate_summary.json", summary)
            self.logger.info("Cost estimate summary: %s", summary)
            if managed_token_server is not None:
                managed_token_server.close()
            return PipelineResult(self.run_dir, self.run_dir / "cost_estimate_summary.json")

    def _sample_from_pair_index(self, all_samples: list[SecVulEvalSample], value: Any) -> SecVulEvalSample | None:
        """Resolve a pair-scanner index to a sample.

        SecVulEval sample IDs usually match Arrow row indices, but this helper
        also supports positional indices and string IDs so validation-aware
        selection is robust to future loader changes.
        """
        by_id = {str(getattr(s, "sample_id", "")): s for s in all_samples}
        key = str(value)
        if key in by_id:
            return by_id[key]
        try:
            idx = int(value)
        except Exception:
            return None
        if 0 <= idx < len(all_samples):
            return all_samples[idx]
        return None

    def _candidate_pair_key(self, sample: SecVulEvalSample) -> tuple[str, str, str, str, str]:
        return (
            str(sample.project_url or sample.project or ""),
            str(sample.project or ""),
            str(sample.filepath or ""),
            str(sample.func_name or ""),
            str(sample.commit_id or ""),
        )

    def _sample_project_key(self, sample: SecVulEvalSample) -> str:
        return str(getattr(sample, "project_url", None) or getattr(sample, "project", None) or "unknown_project")

    def _dashboard_project_key(self, project: Any = None, project_url: Any = None, repo_key: Any = None, commit: Any = None) -> str:
        base = str(repo_key or RepoManager.repo_key(project_url, project) or project_url or project or "unknown_project")
        if commit:
            return f"{base}@{str(commit)[:12]}"
        return base

    @staticmethod
    def _dashboard_bytes(value: Any) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except Exception:
            return None

    def _compact_inventory_dashboard_row(self, row: dict[str, Any]) -> dict[str, Any]:
        usable = bool(row.get("repo_usable") or row.get("usable_repo"))
        return {
            "kind": "repo_inventory",
            "status": "usable_repo" if usable else "unusable_repo",
            "inventory_status": row.get("inventory_status"),
            "project": row.get("project"),
            "project_url": row.get("project_url"),
            "repo_key": row.get("repo_key"),
            "repo_status": row.get("repo_status"),
            "repo_error": row.get("repo_error"),
            "mirror_path": row.get("mirror_path"),
            "mirror_size_bytes": self._dashboard_bytes(row.get("mirror_size_bytes")),
            "repo_usable": usable,
            "dataset_num_samples": row.get("dataset_num_samples"),
            "dataset_num_vulnerable": row.get("dataset_num_vulnerable"),
            "dataset_num_fixed": row.get("dataset_num_fixed"),
            "dataset_unique_files": row.get("dataset_unique_files"),
            "dataset_unique_functions": row.get("dataset_unique_functions"),
            "dataset_unique_commits": row.get("dataset_unique_commits"),
            "tree_source_bytes": self._dashboard_bytes(row.get("tree_source_bytes")),
            "tree_source_files": row.get("tree_source_files"),
            "tree_total_bytes": self._dashboard_bytes(row.get("tree_total_bytes")),
            "tree_total_files": row.get("tree_total_files"),
            "git_commit_count": row.get("git_commit_count"),
        }

    def _dashboard_load_repo_inventory(self, *, limit: int | None = 2000) -> None:
        """Publish cached repository inventory into the live dashboard once.

        The dashboard table is intentionally read-only/reporting-only. It is
        never passed to prompts or validators, so it does not affect prediction.
        """
        if not self.live or self._dashboard_inventory_loaded or not self.cfg.repo_inventory.enabled:
            return
        self._dashboard_inventory_loaded = True
        rows = RepoInventory(self.cfg.repo_inventory).load_all()
        if not rows:
            return
        rows.sort(key=lambda r: (
            not bool(r.get("repo_usable")),
            int(r.get("tree_source_bytes") or r.get("mirror_size_bytes") or 10**18),
            int(r.get("tree_source_files") or 10**18),
            str(r.get("project") or ""),
        ))
        updates: dict[str, dict[str, Any]] = {}
        for rank, row in enumerate(rows[:limit] if limit else rows, start=1):
            key = self._dashboard_project_key(row.get("project"), row.get("project_url"), row.get("repo_key"))
            updates[key] = {**self._compact_inventory_dashboard_row(row), "inventory_rank": rank}
        self.live.update_projects_bulk(updates)
        self.live.event("repo_inventory.dashboard_loaded", {
            "rows": len(rows),
            "published_rows": len(updates),
            "cache_dir": self.cfg.repo_inventory.cache_dir,
        })

    def _dashboard_update_candidate_project(self, row: dict[str, Any]) -> None:
        if not self.live:
            return
        key = self._dashboard_project_key(row.get("project"), row.get("project_url"), row.get("repo_key"))
        self.live.update_project(key, {
            "kind": "candidate_project",
            "status": "candidate_for_validation",
            "candidate_rank": row.get("candidate_rank"),
            "candidate_key": row.get("candidate_key"),
            "candidate_order": row.get("candidate_order") or row.get("ordering"),
            "candidate_loaded_from_cache": bool(row.get("loaded_from_pair_candidate_cache")),
            "project": row.get("project"),
            "project_url": row.get("project_url"),
            "repo_key": row.get("repo_key"),
            "repo_status": row.get("repo_status"),
            "repo_usable": row.get("usable_repo"),
            "mirror_path": row.get("mirror_path"),
            "filepath": row.get("filepath"),
            "function": row.get("function") or row.get("func_name"),
            "tree_source_bytes": self._dashboard_bytes(row.get("tree_source_bytes")),
            "tree_source_files": row.get("tree_source_files"),
            "mirror_size_bytes": self._dashboard_bytes(row.get("mirror_size_bytes")),
            "dataset_num_samples": row.get("dataset_num_samples"),
            "vulnerable_sample_id": row.get("vulnerable_sample_id"),
            "fixed_sample_id": row.get("fixed_sample_id"),
        })

    def _dashboard_update_repo_status(self, project: Any, project_url: Any, repo_status: Any, *, status: str | None = None, extra: dict[str, Any] | None = None) -> None:
        if not self.live:
            return
        repo_key = getattr(repo_status, "repo_key", None) if repo_status is not None else None
        key = self._dashboard_project_key(project, project_url, repo_key)
        data = {
            "project": project,
            "project_url": project_url,
            "repo_key": repo_key,
            "status": status or "repo_ready",
            "repo_status": getattr(repo_status, "status", None),
            "repo_error": getattr(repo_status, "error", None),
            "mirror_path": getattr(repo_status, "mirror_path", None),
            "mirror_size_bytes": self._dashboard_bytes(getattr(repo_status, "mirror_size_bytes", None)),
            "repo_usable": bool(getattr(repo_status, "mirror_path", None)) and getattr(repo_status, "status", None) not in {"clone_failed", "missing_project_url", "missing_mirror"},
        }
        if extra:
            data.update(extra)
        self.live.update_project(key, data)

    def _dashboard_update_kg_status(self, project: Any, project_url: Any, repo_key: Any, commit: Any, *, status: str, extra: dict[str, Any] | None = None) -> None:
        if not self.live:
            return
        key = self._dashboard_project_key(project, project_url, repo_key, commit)
        data = {
            "kind": "project_commit_kg",
            "project": project,
            "project_url": project_url,
            "repo_key": repo_key,
            "resolved_commit": commit,
            "status": status,
            "kg_status": status,
        }
        if extra:
            data.update(extra)
        self.live.update_project(key, data)


    def _dashboard_url_for_path(self, path: Any) -> str | None:
        if not self.live or not path:
            return None
        try:
            return self.live.url_for_path(path)
        except Exception:
            return None

    def _sample_text_len(self, sample: SecVulEvalSample | None) -> int:
        if sample is None:
            return 0
        for attr in ("func_body", "function_body", "code", "source", "content"):
            value = getattr(sample, attr, None)
            if isinstance(value, str) and value:
                return len(value)
        return 0

    def _build_validation_candidate_project_stats(self, all_samples: list[SecVulEvalSample]) -> dict[str, dict[str, Any]]:
        stats: dict[str, dict[str, Any]] = {}
        for sample in all_samples:
            key = self._sample_project_key(sample)
            row = stats.setdefault(key, {
                "project_key": key,
                "project": getattr(sample, "project", None),
                "project_url": getattr(sample, "project_url", None),
                "num_samples": 0,
                "num_vulnerable": 0,
                "num_fixed": 0,
                "unique_files": set(),
                "unique_functions": set(),
                "total_function_chars": 0,
                "metadata_num_files": None,
                "metadata_repo_size": None,
            })
            row["num_samples"] += 1
            if bool(getattr(sample, "is_vulnerable", False)):
                row["num_vulnerable"] += 1
            else:
                row["num_fixed"] += 1
            if getattr(sample, "filepath", None):
                row["unique_files"].add(str(sample.filepath))
            if getattr(sample, "func_name", None):
                row["unique_functions"].add(str(sample.func_name))
            row["total_function_chars"] += self._sample_text_len(sample)

            # Some dataset variants expose repository/project size metadata.
            # Use it if present, but keep this optional so older schemas work.
            for attr in ("project_num_files", "repo_num_files", "num_files", "files_count"):
                value = getattr(sample, attr, None)
                if isinstance(value, (int, float)) and value >= 0:
                    current = row.get("metadata_num_files")
                    row["metadata_num_files"] = int(value) if current is None else max(int(current), int(value))
            for attr in ("repo_size", "project_size", "repo_bytes", "project_bytes", "loc", "sloc"):
                value = getattr(sample, attr, None)
                if isinstance(value, (int, float)) and value >= 0:
                    current = row.get("metadata_repo_size")
                    row["metadata_repo_size"] = int(value) if current is None else max(int(current), int(value))

        for row in stats.values():
            row["unique_file_count"] = len(row.pop("unique_files"))
            row["unique_function_count"] = len(row.pop("unique_functions"))
            row["avg_function_chars"] = (row["total_function_chars"] / row["num_samples"]) if row["num_samples"] else 0.0
        return stats

    def _project_name_variants(self, project: Any, project_url: Any) -> list[str]:
        values = []
        for value in (project, project_url):
            if value:
                text = str(value).strip()
                values.append(text)
                values.append(text.rsplit("/", 1)[-1].replace(".git", ""))
        seen: set[str] = set()
        out: list[str] = []
        for value in values:
            low = value.lower()
            if low not in seen:
                seen.add(low)
                out.append(low)
        return out

    def _is_validation_candidate_project_excluded(self, project: Any, project_url: Any) -> tuple[bool, str | None]:
        ds = self.cfg.dataset
        names = self._project_name_variants(project, project_url)
        exact_excludes = {str(x).strip().lower() for x in list(ds.project_exclude or []) + list(getattr(ds, "validation_candidate_exclude_projects", []) or []) if str(x).strip()}
        for name in names:
            if name in exact_excludes:
                return True, f"excluded_project:{name}"

        patterns = list(getattr(ds, "validation_candidate_exclude_project_patterns", []) or [])
        for pattern in patterns:
            pat = str(pattern).strip().lower()
            if not pat:
                continue
            for name in names:
                if fnmatch.fnmatch(name, pat) or pat in name:
                    return True, f"excluded_project_pattern:{pattern}"
        return False, None

    def _repo_inventory_rows(self) -> list[dict[str, Any]]:
        """Load repository inventory once per run.

        Earlier versions called RepoInventory.load_project() for every candidate
        pair.  On a full SecVulEval inventory this meant thousands of tiny JSON
        reads before scaling even started.  Cached-inventory runs should make
        the small/large project decision directly from the already prepared
        inventory index, so we load the per-project inventory files once and
        reuse them for all candidate scoring.
        """
        if self._repo_inventory_rows_cache is not None:
            return self._repo_inventory_rows_cache
        if not getattr(self.cfg.repo_inventory, "enabled", True):
            self._repo_inventory_rows_cache = []
            self._repo_inventory_by_key_cache = {}
            return self._repo_inventory_rows_cache
        rows = RepoInventory(self.cfg.repo_inventory).load_all()
        self._repo_inventory_rows_cache = rows
        self._repo_inventory_by_key_cache = {str(r.get("repo_key")): r for r in rows if r.get("repo_key")}
        self.logger.info(
            "repo_inventory.cache_loaded | rows=%s | cache_dir=%s",
            len(rows),
            getattr(self.cfg.repo_inventory, "cache_dir", None),
        )
        return rows

    def _repo_inventory_row_for(self, project: Any, project_url: Any) -> dict[str, Any] | None:
        if not getattr(self.cfg.repo_inventory, "enabled", True):
            return None
        self._repo_inventory_rows()
        by_key = self._repo_inventory_by_key_cache or {}
        repo_key = RepoManager.repo_key(str(project_url) if project_url else None, str(project) if project else None)
        return by_key.get(repo_key)

    def _repo_inventory_size_score(self, inv: dict[str, Any] | None, fallback: int = 10**12) -> int:
        if not inv:
            return fallback
        metric = getattr(self.cfg.dataset, "validation_candidate_repo_inventory_sort_metric", "auto")
        if metric == "mirror_size_bytes":
            return int(inv.get("mirror_size_bytes") or fallback)
        if metric == "source_bytes":
            return int(inv.get("tree_source_bytes") or fallback)
        if metric == "source_files":
            return int(inv.get("tree_source_files") or fallback)
        if metric == "total_files":
            return int(inv.get("tree_total_files") or fallback)
        if metric == "dataset_samples":
            return int(inv.get("dataset_num_samples") or fallback)
        # auto: source bytes is the best cheap proxy for KG size; mirror size is
        # next best; source file count is a useful fallback.
        return int(inv.get("tree_source_bytes") or inv.get("mirror_size_bytes") or inv.get("tree_source_files") or fallback)

    def _candidate_pair_preselection_record(self, rank: int, pair: Any, vuln: SecVulEvalSample | None, fixed: SecVulEvalSample | None, project_stats: dict[str, dict[str, Any]]) -> dict[str, Any]:
        sample_for_key = vuln or fixed
        project = (
            getattr(pair, "project", None)
            or (getattr(vuln, "project", None) if vuln else None)
            or (getattr(fixed, "project", None) if fixed else None)
        )
        project_url = (
            getattr(pair, "project_url", None)
            or (getattr(vuln, "project_url", None) if vuln else None)
            or (getattr(fixed, "project_url", None) if fixed else None)
        )
        pkey = self._sample_project_key(sample_for_key) if sample_for_key else str(project_url or project or "unknown_project")
        stats = project_stats.get(pkey, {})
        inventory_row = self._repo_inventory_row_for(project, project_url) if getattr(self.cfg.dataset, "validation_candidate_use_repo_inventory", True) else None
        pair_chars = self._sample_text_len(vuln) + self._sample_text_len(fixed)
        excluded, exclude_reason = self._is_validation_candidate_project_excluded(project, project_url)

        ds = self.cfg.dataset
        if not excluded and getattr(ds, "validation_candidate_require_repo_inventory_usable", False):
            if not inventory_row:
                excluded = True
                exclude_reason = "repo_inventory_missing"
            elif not bool(inventory_row.get("repo_usable")):
                excluded = True
                exclude_reason = f"repo_inventory_unusable:{inventory_row.get('repo_status') or 'unknown'}"
        if not excluded and ds.validation_candidate_max_project_dataset_samples is not None:
            if int(stats.get("num_samples") or 0) > int(ds.validation_candidate_max_project_dataset_samples):
                excluded = True
                exclude_reason = f"project_dataset_samples>{ds.validation_candidate_max_project_dataset_samples}"
        if not excluded and ds.validation_candidate_max_unique_files is not None:
            file_count = int(stats.get("metadata_num_files") or stats.get("unique_file_count") or 0)
            if file_count > int(ds.validation_candidate_max_unique_files):
                excluded = True
                exclude_reason = f"project_unique_files>{ds.validation_candidate_max_unique_files}"
        if not excluded and ds.validation_candidate_max_pair_function_chars is not None:
            if pair_chars > int(ds.validation_candidate_max_pair_function_chars):
                excluded = True
                exclude_reason = f"pair_function_chars>{ds.validation_candidate_max_pair_function_chars}"

        return {
            "original_rank": rank,
            "project": project,
            "project_url": project_url,
            "project_key": pkey,
            "vulnerable_idx": getattr(pair, "vulnerable_idx", None),
            "fixed_idx": getattr(pair, "fixed_idx", None),
            "vulnerable_sample_id": getattr(vuln, "sample_id", None) if vuln else None,
            "fixed_sample_id": getattr(fixed, "sample_id", None) if fixed else None,
            "filepath": getattr(pair, "filepath", None),
            "func_name": getattr(pair, "func_name", None),
            "patch_commit_id": getattr(pair, "patch_commit_id", None),
            "project_dataset_samples": stats.get("num_samples"),
            "project_dataset_vulnerable": stats.get("num_vulnerable"),
            "project_dataset_fixed": stats.get("num_fixed"),
            "project_unique_files_in_dataset": stats.get("unique_file_count"),
            "project_unique_functions_in_dataset": stats.get("unique_function_count"),
            "project_metadata_num_files": stats.get("metadata_num_files"),
            "project_metadata_repo_size": stats.get("metadata_repo_size"),
            "repo_inventory_present": inventory_row is not None,
            "repo_inventory_usable": bool(inventory_row.get("repo_usable")) if inventory_row else None,
            "repo_inventory_status": inventory_row.get("repo_status") if inventory_row else None,
            "repo_inventory_error": inventory_row.get("repo_error") if inventory_row else None,
            "repo_key": inventory_row.get("repo_key") if inventory_row else None,
            "mirror_size_bytes": inventory_row.get("mirror_size_bytes") if inventory_row else None,
            "tree_total_files": inventory_row.get("tree_total_files") if inventory_row else None,
            "tree_total_bytes": inventory_row.get("tree_total_bytes") if inventory_row else None,
            "tree_source_files": inventory_row.get("tree_source_files") if inventory_row else None,
            "tree_source_bytes": inventory_row.get("tree_source_bytes") if inventory_row else None,
            "git_commit_count": inventory_row.get("git_commit_count") if inventory_row else None,
            "repo_inventory_size_score": self._repo_inventory_size_score(inventory_row),
            "pair_function_chars": pair_chars,
            "excluded_by_small_first_filter": excluded,
            "exclude_reason": exclude_reason,
        }

    def _validation_candidate_sort_key(self, rec: dict[str, Any]) -> tuple[Any, ...]:
        # Prefer cached repository-inventory stats when present.  This makes
        # repeated scaling runs cheap and deterministic after `prepare-repos`
        # has cloned projects and computed source-size proxies.
        dataset_samples = int(rec.get("project_dataset_samples") or 10**9)
        metadata_files = rec.get("project_metadata_num_files")
        unique_files = int(rec.get("project_unique_files_in_dataset") or 10**9)
        file_score = int(metadata_files) if isinstance(metadata_files, (int, float)) else unique_files
        pair_chars = int(rec.get("pair_function_chars") or 10**9)
        inv_present_penalty = 0 if rec.get("repo_inventory_present") else 1
        inv_unusable_penalty = 0 if rec.get("repo_inventory_usable") is not False else 2
        inv_size = int(rec.get("repo_inventory_size_score") or 10**12)
        if getattr(self.cfg.dataset, "validation_candidate_use_repo_inventory", True):
            return (inv_unusable_penalty, inv_present_penalty, inv_size, dataset_samples, file_score, pair_chars, str(rec.get("project") or ""), str(rec.get("filepath") or ""), str(rec.get("func_name") or ""), int(rec.get("original_rank") or 0))
        return (dataset_samples, file_score, pair_chars, str(rec.get("project") or ""), str(rec.get("filepath") or ""), str(rec.get("func_name") or ""), int(rec.get("original_rank") or 0))

    def _load_cached_validation_pair_candidates(self, all_samples: list[SecVulEvalSample]) -> list[SecVulEvalSample] | None:
        ds = self.cfg.dataset
        if not getattr(ds, "use_cached_pair_candidates", False):
            return None
        path = Path(getattr(ds, "pair_candidate_cache_path", "cache/repo_inventory/pair_candidates_smallest_first.jsonl"))
        if not path.exists():
            self.logger.warning("pair_candidate_cache.missing | path=%s | falling back to on-the-fly candidate build", path)
            return None
        rows = read_pair_candidate_cache(path)
        requested_pairs = int(ds.validated_pair_limit or ds.sample_limit or ds.project_limit or 5)
        candidate_pairs = int(ds.candidate_pair_limit or max(requested_pairs * int(ds.candidate_pair_oversample_factor or 1), requested_pairs))
        if getattr(ds, "validation_candidate_require_repo_inventory_usable", False):
            rows = [r for r in rows if bool(r.get("usable_repo") or r.get("repo_inventory_usable"))]
        excluded_projects = {str(x).strip().lower() for x in (getattr(ds, "validation_candidate_exclude_projects", []) or []) if str(x).strip()}
        if excluded_projects:
            rows = [r for r in rows if str(r.get("project") or "").strip().lower() not in excluded_projects and str(r.get("project_url") or "").strip().lower() not in excluded_projects]
        if getattr(ds, "validation_candidate_one_pair_per_project", True):
            diverse_rows: list[dict[str, Any]] = []
            seen_projects: set[str] = set()
            for row in rows:
                project_id = str(row.get("project") or row.get("project_url") or row.get("repo_key") or "unknown_project")
                if project_id in seen_projects:
                    continue
                seen_projects.add(project_id)
                diverse_rows.append(row)
            rows = diverse_rows
        rows = rows[:candidate_pairs]

        by_id = {str(s.sample_id): s for s in all_samples}
        by_idx = {int(s.idx): s for s in all_samples}
        selected: list[SecVulEvalSample] = []
        seen_ids: set[str] = set()
        materialized_rows: list[dict[str, Any]] = []
        for candidate_rank, row in enumerate(rows, start=1):
            vuln = by_id.get(str(row.get("vulnerable_sample_id")))
            fixed = by_id.get(str(row.get("fixed_sample_id")))
            if vuln is None:
                try:
                    vuln = by_idx.get(int(row.get("vulnerable_idx")))
                except Exception:
                    vuln = None
            if fixed is None:
                try:
                    fixed = by_idx.get(int(row.get("fixed_idx")))
                except Exception:
                    fixed = None
            out_row = dict(row)
            out_row["candidate_rank"] = candidate_rank
            out_row["candidate_order"] = getattr(ds, "validation_candidate_order", "cached_smallest_first")
            out_row["loaded_from_pair_candidate_cache"] = True
            out_row["cache_path"] = str(path)
            out_row["materialized"] = bool(vuln is not None and fixed is not None)
            materialized_rows.append(out_row)
            self._dashboard_update_candidate_project(out_row)
            for sample in (vuln, fixed):
                if sample is None:
                    continue
                sid = str(sample.sample_id)
                if sid not in seen_ids:
                    selected.append(sample)
                    seen_ids.add(sid)
        write_jsonl(self.run_dir / "candidate_pairs_for_validation.jsonl", materialized_rows)
        summary = {
            "requested_valid_pairs": requested_pairs,
            "candidate_pair_limit": candidate_pairs,
            "candidate_pairs_found": len(materialized_rows),
            "candidate_samples_selected_for_resolution": len(selected),
            "one_pair_per_project": bool(getattr(ds, "validation_candidate_one_pair_per_project", True)),
            "candidate_order": getattr(ds, "validation_candidate_order", "cached_smallest_first"),
            "loaded_from_pair_candidate_cache": True,
            "pair_candidate_cache_path": str(path),
            "note": "Candidate pairs loaded directly from persistent cache; no raw pair rebuild/scoring occurred in this run.",
        }
        write_json(self.run_dir / "candidate_pairs_for_validation_summary.json", summary)
        if self.live:
            self.live.event("dataset.validation_aware_pair_candidates", summary)
        self.logger.info(
            "validation_aware_pair_candidates.cache_loaded | requested_valid_pairs=%s | candidate_pair_limit=%s | preselected=%s | candidate_samples=%s | path=%s",
            requested_pairs,
            candidate_pairs,
            len(materialized_rows),
            len(selected),
            path,
        )
        return selected

    def _load_validation_aware_pair_candidates(self, all_samples: list[SecVulEvalSample]) -> list[SecVulEvalSample]:
        """Return oversampled candidate-pair samples for validation-aware selection.

        The previous implementation simply took the first N vulnerable/fixed
        pairs.  That can unexpectedly pull in very large repositories when many
        earlier candidates fail validation.  For staged scaling we explicitly
        rank candidates from small to large using clone-free dataset metadata
        before any repository is cloned.
        """
        ds = self.cfg.dataset
        cached = self._load_cached_validation_pair_candidates(all_samples)
        if cached is not None:
            return cached
        requested_pairs = int(ds.validated_pair_limit or ds.sample_limit or ds.project_limit or 5)
        candidate_pairs = int(ds.candidate_pair_limit or max(requested_pairs * int(ds.candidate_pair_oversample_factor or 1), requested_pairs))
        raw_pairs = find_vulnerable_fixed_pairs(all_samples, ds)
        project_stats = self._build_validation_candidate_project_stats(all_samples)

        preselection_rows: list[dict[str, Any]] = []
        pair_records: list[tuple[Any, SecVulEvalSample | None, SecVulEvalSample | None, dict[str, Any]]] = []
        for rank, pair in enumerate(raw_pairs, start=1):
            vuln = self._sample_from_pair_index(all_samples, getattr(pair, "vulnerable_idx", None))
            fixed = self._sample_from_pair_index(all_samples, getattr(pair, "fixed_idx", None))
            rec = self._candidate_pair_preselection_record(rank, pair, vuln, fixed, project_stats)
            preselection_rows.append(rec)
            if rec.get("excluded_by_small_first_filter"):
                continue
            pair_records.append((pair, vuln, fixed, rec))

        order = getattr(ds, "validation_candidate_order", "dataset_smallest_first")
        if order in {"dataset_smallest_first", "cached_smallest_first"}:
            pair_records.sort(key=lambda item: self._validation_candidate_sort_key(item[3]))
        elif order == "dataset_largest_first":
            pair_records.sort(key=lambda item: self._validation_candidate_sort_key(item[3]), reverse=True)

        selected: list[SecVulEvalSample] = []
        seen_ids: set[str] = set()
        rows: list[dict[str, Any]] = []
        for candidate_rank, (pair, vuln, fixed, rec) in enumerate(pair_records[:candidate_pairs], start=1):
            row = dict(rec)
            row["candidate_rank"] = candidate_rank
            row["candidate_order"] = order
            row["candidate_sort_key"] = list(self._validation_candidate_sort_key(row))
            rows.append(row)
            self._dashboard_update_candidate_project(row)
            for sample in (vuln, fixed):
                if sample is None:
                    continue
                sid = str(sample.sample_id)
                if sid not in seen_ids:
                    selected.append(sample)
                    seen_ids.add(sid)

        write_jsonl(self.run_dir / "candidate_pairs_preselection.jsonl", preselection_rows)
        write_jsonl(self.run_dir / "candidate_pairs_for_validation.jsonl", rows)
        summary = {
            "requested_valid_pairs": requested_pairs,
            "candidate_pair_limit": candidate_pairs,
            "raw_pairs_found": len(raw_pairs),
            "preselection_pairs_considered": len(preselection_rows),
            "preselection_pairs_excluded": sum(1 for r in preselection_rows if r.get("excluded_by_small_first_filter")),
            "candidate_pairs_found": len(rows),
            "candidate_samples_selected_for_resolution": len(selected),
            "candidate_order": order,
            "small_first_filters": {
                "validation_candidate_exclude_projects": list(getattr(ds, "validation_candidate_exclude_projects", []) or []),
                "validation_candidate_exclude_project_patterns": list(getattr(ds, "validation_candidate_exclude_project_patterns", []) or []),
                "validation_candidate_max_project_dataset_samples": getattr(ds, "validation_candidate_max_project_dataset_samples", None),
                "validation_candidate_max_unique_files": getattr(ds, "validation_candidate_max_unique_files", None),
                "validation_candidate_max_pair_function_chars": getattr(ds, "validation_candidate_max_pair_function_chars", None),
                "validation_candidate_one_pair_per_project": getattr(ds, "validation_candidate_one_pair_per_project", True),
                "validation_candidate_clone_mirrors": getattr(ds, "validation_candidate_clone_mirrors", True),
                "validation_candidate_use_repo_inventory": getattr(ds, "validation_candidate_use_repo_inventory", True),
                "validation_candidate_require_repo_inventory_usable": getattr(ds, "validation_candidate_require_repo_inventory_usable", False),
                "validation_candidate_repo_inventory_sort_metric": getattr(ds, "validation_candidate_repo_inventory_sort_metric", "auto"),
                "repo_inventory_cache_dir": getattr(self.cfg.repo_inventory, "cache_dir", None),
            },
            "note": "Candidate pairs are ranked/filtered before cloning using cached repository inventory when available, falling back to dataset metadata.",
        }
        write_json(self.run_dir / "candidate_pairs_for_validation_summary.json", summary)
        if self.live:
            self.live.event("dataset.validation_aware_pair_candidates", summary)
        self.logger.info(
            "validation_aware_pair_candidates | requested_valid_pairs=%s | candidate_pair_limit=%s | raw_pairs=%s | preselected=%s | excluded=%s | candidate_samples=%s | order=%s",
            requested_pairs,
            candidate_pairs,
            len(raw_pairs),
            len(rows),
            summary["preselection_pairs_excluded"],
            len(selected),
            order,
        )
        return selected

    def _load_selected_samples(self) -> list[SecVulEvalSample]:
        self._dashboard_load_repo_inventory()
        all_samples = load_samples(self.cfg.dataset.path, self.cfg.dataset.mode, self.logger)
        # Exact sample selection (dashboard "selected_samples" / exact_sample_ids_only)
        # overrides validation-aware pair selection. Pair candidate loading expands
        # the selection to vulnerable/fixed pairs and ignores only_sample_ids, so we
        # must skip it entirely when the caller asked for exact ids only.
        exact_ids_requested = bool(
            getattr(self.cfg.dataset, "exact_sample_ids_only", False)
            and getattr(self.cfg.dataset, "only_sample_ids", None)
        )
        if self.cfg.dataset.validation_aware_pair_selection and not exact_ids_requested:
            samples = self._load_validation_aware_pair_candidates(all_samples)
        else:
            if exact_ids_requested and self.cfg.dataset.validation_aware_pair_selection:
                self.logger.info(
                    "sample_selection.exact_override | exact_sample_ids_only=true | "
                    "validation_aware_pair_selection disabled for this run | only_sample_ids=%s",
                    list(self.cfg.dataset.only_sample_ids),
                )
            samples = select_samples(all_samples, self.cfg.dataset, self.cfg.experiment.seed)
        if not samples:
            raise RuntimeError("No samples selected. Check dataset config/project filters.")
        return samples

    def _resolve_and_validate_candidate_sample(
        self,
        *,
        sample: SecVulEvalSample,
        project_key: str,
        repo_status: Any,
        resolver: CommitResolver,
        snapshot_manager: SnapshotManager,
        validator: TargetValidator,
        validation_cache: CommitValidationCache | None = None,
    ) -> dict[str, Any]:
        """Resolve and validate one candidate sample without adding it to KG groups."""
        candidates = resolver.candidates(repo_status, sample)
        if not candidates and sample.commit_id:
            candidates = []
        candidate_records: list[dict[str, Any]] = []
        best: tuple[float, str | None, str | None, Any, Any] | None = None

        for cand in candidates:
            cached_negative = validation_cache.get_negative(
                repo_key=getattr(repo_status, "repo_key", None),
                commit=cand.commit_id,
                sample_id=sample.sample_id,
                filepath=sample.filepath,
                function=sample.func_name,
            ) if validation_cache is not None else None
            if cached_negative is not None:
                from vuln_commit_kg.repos.snapshot_manager import SnapshotStatus
                from vuln_commit_kg.repos.target_validator import TargetValidation
                snapshot_status = SnapshotStatus(
                    repo_key=getattr(repo_status, "repo_key", "unknown"),
                    commit_id=cand.commit_id,
                    worktree_path=None,
                    status=str(cached_negative.get("status") or "cached_negative"),
                    error=str(cached_negative.get("error") or "cached negative validation result"),
                    elapsed_seconds=0.0,
                    worktree_size_bytes=0,
                )
                validation = TargetValidation(
                    sample_id=sample.sample_id,
                    status=str(cached_negative.get("validation_status") or cached_negative.get("status") or "cached_negative"),
                    filepath_exists=False,
                    function_found=False,
                    body_similarity=float(cached_negative.get("similarity") or 0.0),
                    error=str(cached_negative.get("error") or "cached negative validation result"),
                )
            else:
                snapshot_status = snapshot_manager.ensure_snapshot(repo_status, cand.commit_id)
                snapshot_path = Path(snapshot_status.worktree_path) if snapshot_status.worktree_path else None
                validation = validator.validate(
                    snapshot_path,
                    sample,
                    candidate_commit_id=cand.commit_id,
                    candidate_label=cand.label,
                ) if self.cfg.snapshot.validate_target_function else None
                if validation_cache is not None:
                    validation_status = validation.status if validation else snapshot_status.status
                    similarity = validation.body_similarity if validation else None
                    negative = snapshot_status.status not in {"created_worktree", "reused_existing_worktree"}
                    negative = negative or validation_status in {"file_missing", "function_missing", "validation_error", "no_snapshot", "function_name_only"}
                    negative = negative or (similarity is not None and similarity < self.cfg.snapshot.body_match_threshold)
                    if negative:
                        # Prefer the operational snapshot failure when the worktree was not usable.
                        # Otherwise stale/failed worktree attempts can be misrecorded as semantic
                        # low_similarity entries and then wrongly skipped in later runs.
                        if snapshot_status.status not in {"created_worktree", "reused_existing_worktree"}:
                            status_for_cache = snapshot_status.status
                        elif similarity is not None and similarity < self.cfg.snapshot.body_match_threshold:
                            status_for_cache = "low_similarity"
                        else:
                            status_for_cache = validation_status or snapshot_status.status
                        validation_cache.record(
                            repo_key=getattr(repo_status, "repo_key", None),
                            project=sample.project,
                            project_url=sample.project_url,
                            commit=cand.commit_id,
                            sample_id=sample.sample_id,
                            filepath=sample.filepath,
                            function=sample.func_name,
                            status=status_for_cache,
                            validation_status=validation_status,
                            similarity=similarity,
                            error=(validation.error if validation else None) or snapshot_status.error,
                        )
            validation_dict = validation.__dict__ if validation else None
            record = {
                "sample_id": sample.sample_id,
                "project": sample.project,
                "dataset_commit_id": sample.commit_id,
                "candidate_label": cand.label,
                "candidate_commit_id": cand.commit_id,
                "snapshot_status": snapshot_status.__dict__,
                "validation": validation_dict,
            }
            append_jsonl(self.run_dir / "target_validation_candidates.jsonl", record)
            candidate_records.append(record)

            sim = validation.body_similarity if validation else 0.0
            function_bonus = 0.10 if validation and validation.function_found else 0.0
            file_bonus = 0.05 if validation and validation.filepath_exists else 0.0
            exact_bonus = 0.20 if validation and validation.status == "match_exact" else 0.0
            score = sim + function_bonus + file_bonus + exact_bonus
            if best is None or score > best[0]:
                best = (score, cand.commit_id, cand.label, snapshot_status, validation)

        if best is None:
            selected_commit = sample.commit_id or "unknown_commit"
            selected_label = "dataset_commit"
            selected_status = None
            selected_similarity = None
            selected_artifact_dir = None
            warning = "no_commit_candidate_available"
        else:
            _, selected_commit, selected_label, _, selected_validation = best
            selected_status = selected_validation.status if selected_validation else None
            selected_similarity = selected_validation.body_similarity if selected_validation else None
            selected_artifact_dir = selected_validation.artifact_dir if selected_validation else None
            warning = None
            if selected_similarity is not None and selected_similarity < self.cfg.snapshot.body_match_threshold:
                warning = (
                    f"best candidate similarity {selected_similarity:.4f} is below threshold "
                    f"{self.cfg.snapshot.body_match_threshold:.4f}"
                )

        resolution = CommitResolution(
            sample_id=sample.sample_id,
            project=sample.project,
            filepath=sample.filepath,
            func_name=sample.func_name,
            dataset_commit_id=sample.commit_id,
            selected_commit_id=selected_commit,
            selected_label=selected_label,
            strategy=self.cfg.snapshot.commit_resolution,
            selected_status=selected_status,
            selected_similarity=selected_similarity,
            candidates=candidate_records,
            selected_artifact_dir=selected_artifact_dir,
            warning=warning,
        )
        self.sample_resolution[sample.sample_id] = resolution
        append_jsonl(self.run_dir / "target_resolution.jsonl", resolution.to_dict())
        self.logger.info(
            "commit_resolution | sample=%s | strategy=%s | selected=%s:%s | status=%s | similarity=%s%s",
            sample.sample_id,
            self.cfg.snapshot.commit_resolution,
            selected_label,
            (selected_commit or "?")[:12],
            selected_status,
            selected_similarity,
            f" | WARNING: {warning}" if warning else "",
        )
        if warning:
            self.logger.warning(
                "target_validation.low_similarity | sample=%s | selected_commit=%s | similarity=%s | threshold=%s",
                sample.sample_id,
                (selected_commit or "?")[:12],
                selected_similarity,
                self.cfg.snapshot.body_match_threshold,
            )

        selected_bad_status = selected_status in {"file_missing", "function_missing", "validation_error", "no_snapshot", "function_name_only"}
        selected_low_similarity = (
            selected_similarity is not None
            and selected_similarity < self.cfg.snapshot.body_match_threshold
        )
        valid = (not selected_bad_status) and (not selected_low_similarity) and not bool(warning)
        return {
            "sample": sample,
            "project_key": project_key,
            "selected_commit": selected_commit,
            "selected_status": selected_status,
            "selected_similarity": selected_similarity,
            "selected_label": selected_label,
            "valid": valid,
            "reason": warning or (selected_status if selected_bad_status else None) or ("low_similarity" if selected_low_similarity else None),
        }

    def _prepare_project_commit_graphs_streaming_validated_pairs(
        self,
        samples: list[SecVulEvalSample],
        classify: bool,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Validate candidate pairs in order and stop once enough valid pairs exist.

        The non-streaming implementation validates every oversampled candidate
        before selecting the final pairs.  With cached inventory this is wasteful:
        the first few small projects are often already valid, while later
        candidates may contain repeated missing commits or function-name-only
        matches.  This streaming path reads the inventory-sorted candidate list,
        validates pair-by-pair, and immediately proceeds to KG construction once
        the requested number of diverse valid pairs has been found.
        """
        repo_manager = RepoManager(self.cfg.repo, self.logger, self.run_dir)
        snapshot_manager = SnapshotManager(self.cfg.repo, self.logger, self.run_dir)
        resolver = CommitResolver(self.cfg.snapshot, self.logger, self.run_dir)
        validator = TargetValidator(
            self.logger,
            artifact_root=self.run_dir / self.cfg.snapshot.validation_artifact_dirname,
            save_artifacts=self.cfg.snapshot.save_validation_artifacts,
        )
        graph_cache = GraphCache(self.cfg.kg, self.logger)
        validation_cache = CommitValidationCache(self.cfg.validation_cache)
        context: dict[tuple[str, str], dict[str, Any]] = {}
        self.sample_graph_keys = {}
        self.sample_resolution = {}
        self.skipped_sample_ids = set()
        self.classification_sample_ids = None

        pair_groups: dict[tuple[str, str, str, str, str], list[SecVulEvalSample]] = {}
        pair_order: list[tuple[str, str, str, str, str]] = []
        for sample in samples:
            key = self._candidate_pair_key(sample)
            if key not in pair_groups:
                pair_groups[key] = []
                pair_order.append(key)
            pair_groups[key].append(sample)

        requested_pairs = int(self.cfg.dataset.validated_pair_limit or self.cfg.dataset.sample_limit or 5)
        one_pair_per_project = bool(getattr(self.cfg.dataset, "validation_candidate_one_pair_per_project", True))
        resolved_groups: dict[tuple[str, str], list[SecVulEvalSample]] = defaultdict(list)
        repo_status_by_project: dict[str, Any] = {}
        selected_projects: set[str] = set()
        selected_sample_ids: set[str] = set()
        selection_rows: list[dict[str, Any]] = []
        validation_started_samples = 0
        validation_progress = ProgressMeter(self.logger, len(samples), "commit_resolution.samples", self.cfg.logging.log_every_n_samples, self.cfg.logging.log_every_seconds)

        for pair_index, key in enumerate(pair_order, start=1):
            if sum(1 for r in selection_rows if r.get("selected_for_classification")) >= requested_pairs:
                break
            pair_samples = pair_groups[key]
            first = pair_samples[0]
            project_key = first.project_url or first.project or "unknown_project"
            project_name = str(first.project or "")
            blocked_by_project_diversity = bool(one_pair_per_project and project_name in selected_projects)
            if blocked_by_project_diversity:
                selection_rows.append({
                    "project": first.project,
                    "filepath": first.filepath,
                    "func_name": first.func_name,
                    "pair_key": list(key),
                    "pair_valid": False,
                    "selected_for_classification": False,
                    "blocked_by_project_diversity": True,
                    "streaming_skipped_without_validation": True,
                    "reason": "project_already_selected",
                })
                for sample in pair_samples:
                    self.skipped_sample_ids.add(sample.sample_id)
                    append_jsonl(self.run_dir / "skipped_samples.jsonl", {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "filepath": sample.filepath,
                        "func_name": sample.func_name,
                        "dataset_commit_id": sample.commit_id,
                        "reason": "validated_pair_project_diversity_blocked_before_validation",
                    })
                continue

            log_kv(
                self.logger,
                "Streaming candidate pair validation",
                pair_index=pair_index,
                project=first.project,
                project_url=first.project_url,
                filepath=first.filepath,
                function=first.func_name,
                samples=len(pair_samples),
                selected_pairs=sum(1 for r in selection_rows if r.get("selected_for_classification")),
                requested_pairs=requested_pairs,
            )
            repo_status = repo_status_by_project.get(project_key)
            if repo_status is None:
                if self.live:
                    self.live.update_project(self._dashboard_project_key(first.project, first.project_url, None), {
                        "project": first.project,
                        "project_url": first.project_url,
                        "status": "repo_checking",
                        "candidate_pair_index": pair_index,
                        "filepath": first.filepath,
                        "function": first.func_name,
                    })
                repo_status = repo_manager.ensure_mirror(first.project_url, first.project)
                repo_status_by_project[project_key] = repo_status
                self.logger.info("repo.status | project=%s | status=%s | mirror=%s", first.project, repo_status.status, repo_status.mirror_path)
                self._dashboard_update_repo_status(first.project, first.project_url, repo_status, status="repo_ready", extra={
                    "candidate_pair_index": pair_index,
                    "filepath": first.filepath,
                    "function": first.func_name,
                })

            records: list[dict[str, Any]] = []
            for sample in pair_samples:
                rec = self._resolve_and_validate_candidate_sample(
                    sample=sample,
                    project_key=project_key,
                    repo_status=repo_status,
                    resolver=resolver,
                    snapshot_manager=snapshot_manager,
                    validator=validator,
                    validation_cache=validation_cache,
                )
                records.append(rec)
                validation_started_samples += 1
                validation_progress.update(extra=f"sample={sample.sample_id} candidate_valid={rec.get('valid')}")

            vuln_recs = [r for r in records if bool(r["sample"].is_vulnerable)]
            fixed_recs = [r for r in records if not bool(r["sample"].is_vulnerable)]
            valid_vuln = [r for r in vuln_recs if r.get("valid")]
            valid_fixed = [r for r in fixed_recs if r.get("valid")]
            pair_valid = bool(valid_vuln and valid_fixed) if self.cfg.dataset.require_validated_pair_both_sides else bool(valid_vuln or valid_fixed)
            selected_now = pair_valid and sum(1 for r in selection_rows if r.get("selected_for_classification")) < requested_pairs
            row = {
                "project": first.project,
                "filepath": first.filepath,
                "func_name": first.func_name,
                "pair_key": list(key),
                "pair_index": pair_index,
                "pair_valid": pair_valid,
                "selected_for_classification": selected_now,
                "blocked_by_project_diversity": False,
                "streaming_validation": True,
                "vulnerable_samples": [r["sample"].sample_id for r in vuln_recs],
                "fixed_samples": [r["sample"].sample_id for r in fixed_recs],
                "vulnerable_valid": [r["sample"].sample_id for r in valid_vuln],
                "fixed_valid": [r["sample"].sample_id for r in valid_fixed],
                "statuses": [{
                    "sample_id": r["sample"].sample_id,
                    "is_vulnerable": bool(r["sample"].is_vulnerable),
                    "status": r.get("selected_status"),
                    "similarity": r.get("selected_similarity"),
                    "selected_commit": r.get("selected_commit"),
                    "valid": r.get("valid"),
                    "reason": r.get("reason"),
                } for r in records],
            }
            selection_rows.append(row)
            if self.live:
                self._dashboard_update_repo_status(first.project, first.project_url, repo_status, status=("validated_pair_selected" if selected_now else "validated_pair_rejected"), extra={
                    "pair_valid": pair_valid,
                    "selected_for_classification": selected_now,
                    "candidate_pair_index": pair_index,
                    "filepath": first.filepath,
                    "function": first.func_name,
                    "validation_statuses": row.get("statuses"),
                    "vulnerable_valid": row.get("vulnerable_valid"),
                    "fixed_valid": row.get("fixed_valid"),
                })
            if selected_now:
                selected_projects.add(project_name)
                for r in valid_vuln[:1] + valid_fixed[:1]:
                    sample = r["sample"]
                    selected_sample_ids.add(sample.sample_id)
                    resolved_key = (r["project_key"], r["selected_commit"] or sample.commit_id or "unknown_commit")
                    self.sample_graph_keys[sample.sample_id] = resolved_key
                    resolved_groups[resolved_key].append(sample)
            else:
                reason = "validated_pair_rejected" if not pair_valid else "validated_pair_not_selected"
                for r in records:
                    sample = r["sample"]
                    self.skipped_sample_ids.add(sample.sample_id)
                    append_jsonl(self.run_dir / "skipped_samples.jsonl", {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "filepath": sample.filepath,
                        "func_name": sample.func_name,
                        "dataset_commit_id": sample.commit_id,
                        "selected_commit_id": r.get("selected_commit"),
                        "selected_status": r.get("selected_status"),
                        "selected_similarity": r.get("selected_similarity"),
                        "reason": r.get("reason") or reason,
                        "pair_selection_reason": reason,
                    })

        selected_pairs = sum(1 for r in selection_rows if r.get("selected_for_classification"))
        skipped_unprocessed_pairs = max(0, len(pair_order) - len(selection_rows))
        # Export the exact selected ids to run(), so oversampled candidates are
        # not accidentally reintroduced into classification.
        self.classification_sample_ids = set(selected_sample_ids)
        write_jsonl(self.run_dir / "validated_pair_selection.jsonl", selection_rows)
        summary = {
            "enabled": True,
            "streaming_until_valid_pairs": True,
            "requested_valid_pairs": requested_pairs,
            "candidate_samples_total": len(samples),
            "candidate_pairs_total": len(pair_order),
            "candidate_pairs_validated": len(selection_rows),
            "candidate_samples_validated": validation_started_samples,
            "candidate_pairs_not_processed_after_enough_valid_pairs": skipped_unprocessed_pairs,
            "valid_pairs_found": sum(1 for r in selection_rows if r.get("pair_valid")),
            "selected_pairs": selected_pairs,
            "selected_samples": len(selected_sample_ids),
            "selected_projects": len(selected_projects),
            "one_pair_per_project": one_pair_per_project,
            "project_diversity_blocked_pairs": sum(1 for r in selection_rows if r.get("blocked_by_project_diversity")),
            "rejected_pairs": sum(1 for r in selection_rows if not r.get("pair_valid") and not r.get("streaming_skipped_without_validation")),
            "threshold": self.cfg.snapshot.body_match_threshold,
        }
        write_json(self.run_dir / "validated_pair_selection_summary.json", summary)
        self.logger.info("validated_pair_selection.summary | %s", summary)
        if self.live:
            self.live.event("dataset.validated_pair_selection.done", summary)
        if selected_pairs < requested_pairs:
            raise RuntimeError(
                f"Only {selected_pairs} validated vulnerable/fixed pairs found, requested {requested_pairs}. "
                f"Increase dataset.candidate_pair_limit or relax validation criteria. "
                f"See {self.run_dir / 'validated_pair_selection.jsonl'}."
            )
        validation_progress.finish(extra=f"streaming_validated_samples={validation_started_samples} resolved_groups={len(resolved_groups)} skipped={len(self.skipped_sample_ids)}")

        context = self._build_graphs_for_resolved_groups(
            resolved_groups=resolved_groups,
            repo_status_by_project=repo_status_by_project,
            repo_manager=repo_manager,
            snapshot_manager=snapshot_manager,
            graph_cache=graph_cache,
        )
        return context

    def _build_graphs_for_resolved_groups(
        self,
        *,
        resolved_groups: dict[tuple[str, str], list[SecVulEvalSample]],
        repo_status_by_project: dict[str, Any],
        repo_manager: RepoManager,
        snapshot_manager: SnapshotManager,
        graph_cache: GraphCache,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Build/load one KG per resolved project@commit group."""
        context: dict[tuple[str, str], dict[str, Any]] = {}
        if not resolved_groups:
            self.logger.warning(
                "No resolved project@commit groups remain after validation filtering | skipped=%s",
                len(self.skipped_sample_ids),
            )
            return context
        progress = ProgressMeter(self.logger, len(resolved_groups), "project@resolved_commit", self.cfg.logging.log_every_n_samples)
        for (project_key, resolved_commit), group in resolved_groups.items():
            first = group[0]
            repo_status = repo_status_by_project.get(project_key) or repo_manager.ensure_mirror(first.project_url, first.project)
            graph = None
            graph_dir = None
            graph_status = "not_built"
            kg_wall_seconds = None
            snapshot_path = None
            log_kv(
                self.logger,
                "Resolved group start",
                project=first.project,
                project_url=first.project_url,
                resolved_commit=(resolved_commit or "?")[:12],
                samples_in_group=len(group),
            )
            self._dashboard_update_kg_status(first.project, first.project_url, getattr(repo_status, "repo_key", None), resolved_commit, status="snapshot_preparing", extra={
                "samples": [s.sample_id for s in group],
                "sample_count": len(group),
                "repo_status": getattr(repo_status, "status", None),
                "mirror_path": getattr(repo_status, "mirror_path", None),
                "filepath": first.filepath,
                "function": first.func_name,
            })
            snapshot_status = snapshot_manager.ensure_snapshot(repo_status, resolved_commit)
            if snapshot_status.status not in {"created_worktree", "reused_existing_worktree"}:
                self.logger.warning(
                    "snapshot.unavailable | project=%s | commit=%s | status=%s | error=%s",
                    first.project,
                    (resolved_commit or "?")[:12],
                    snapshot_status.status,
                    snapshot_status.error,
                )
                for sample in group:
                    self.skipped_sample_ids.add(sample.sample_id)
                    append_jsonl(self.run_dir / "skipped_samples.jsonl", {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "filepath": sample.filepath,
                        "func_name": sample.func_name,
                        "dataset_commit_id": sample.commit_id,
                        "selected_commit_id": resolved_commit,
                        "reason": snapshot_status.status,
                        "error": snapshot_status.error,
                    })
                self._dashboard_update_kg_status(first.project, first.project_url, getattr(repo_status, "repo_key", None), resolved_commit, status="snapshot_unavailable", extra={
                    "snapshot_status": snapshot_status.__dict__,
                    "error": snapshot_status.error,
                    "samples": [s.sample_id for s in group],
                    "sample_count": len(group),
                })
                progress.update(extra=f"project={first.project} resolved_commit={(resolved_commit or '?')[:12]} skipped_snapshot")
                continue
            snapshot_path = Path(snapshot_status.worktree_path)
            if self.cfg.kg.scope == "disabled":
                graph = ProjectGraph(manifest={"scope": "disabled"})
                graph_dir = None
                graph_status = "disabled"
            else:
                prospective_graph_dir = graph_cache.graph_dir(first.project_url, first.project, resolved_commit)
                cache_preexists = (prospective_graph_dir / "nodes.jsonl").exists() and (prospective_graph_dir / "edges.jsonl").exists()
                self._dashboard_update_kg_status(first.project, first.project_url, getattr(repo_status, "repo_key", None), resolved_commit, status=("kg_loading_cache" if cache_preexists and not self.cfg.kg.force_rebuild else "kg_building"), extra={
                    "graph_dir": str(prospective_graph_dir),
                    "kg_version": self.cfg.kg.version,
                    "kg_force_rebuild": self.cfg.kg.force_rebuild,
                    "kg_build_if_missing": self.cfg.kg.build_if_missing,
                    "kg_cache_preexists": cache_preexists,
                    "snapshot_status": snapshot_status.__dict__,
                    "snapshot_path": str(snapshot_path),
                    "samples": [s.sample_id for s in group],
                    "sample_count": len(group),
                    "started_at": time.time(),
                })
                kg_wall_start = time.perf_counter()
                graph, graph_dir, graph_status = graph_cache.get_or_build(
                    snapshot_path=snapshot_path,
                    project=first.project,
                    project_url=first.project_url,
                    commit_id=resolved_commit,
                )
                kg_wall_seconds = time.perf_counter() - kg_wall_start
            if graph is not None:
                graph.manifest.setdefault("project", first.project)
                graph.manifest.setdefault("project_url", first.project_url)
                graph.manifest.setdefault("commit_id", resolved_commit)
                graph.manifest.setdefault("snapshot_path", str(snapshot_path))
                graph.manifest.setdefault("graph_status", graph_status)
                graph.manifest.setdefault(
                    "source_only_boundary",
                    "KG built from checked-out repository source only; dataset labels, CVE descriptions, commit messages, and patch diffs are excluded.",
                )
            context[(project_key, resolved_commit)] = {
                "graph": graph,
                "graph_dir": graph_dir,
                "graph_status": graph_status,
                "snapshot_path": snapshot_path,
                "snapshot_status": snapshot_status,
            }
            manifest = getattr(graph, "manifest", {}) or {}
            graph_dir_size = dir_size_bytes(Path(graph_dir)) if graph_dir else None
            dashboard_path = manifest.get("dashboard_path") or (str(Path(graph_dir) / "dashboard" / "index.html") if graph_dir else None)
            manifest_path = str(Path(graph_dir) / "manifest.json") if graph_dir else None
            graph_json_path = str(Path(graph_dir) / "graph.json") if graph_dir else None
            self._dashboard_update_kg_status(first.project, first.project_url, getattr(repo_status, "repo_key", None), resolved_commit, status=f"kg_{graph_status}", extra={
                "graph_status": graph_status,
                "graph_dir": str(graph_dir) if graph_dir else None,
                "graph_dir_size_bytes": graph_dir_size,
                "kg_wall_seconds": kg_wall_seconds,
                "num_nodes": len(graph.nodes) if graph is not None else 0,
                "num_edges": len(graph.edges) if graph is not None else 0,
                "num_files": manifest.get("num_files"),
                "num_functions": manifest.get("num_functions"),
                "num_statements": manifest.get("num_statements"),
                "backend_used": manifest.get("backend_used") or manifest.get("backend"),
                "fallback_used": manifest.get("fallback_used"),
                "cache_hit": graph_status == "loaded_cache",
                "kg_build_seconds_manifest": manifest.get("elapsed_seconds"),
                "dashboard_path": dashboard_path,
                "dashboard_url": self._dashboard_url_for_path(dashboard_path),
                "manifest_url": self._dashboard_url_for_path(manifest_path),
                "graph_json_url": self._dashboard_url_for_path(graph_json_path),
                "graph_dir_url": self._dashboard_url_for_path(graph_dir),
                "snapshot_status": snapshot_status.__dict__,
                "snapshot_path": str(snapshot_path),
                "samples": [s.sample_id for s in group],
                "sample_count": len(group),
                "completed_at": time.time(),
            })
            progress.update(extra=f"project={first.project} resolved_commit={(resolved_commit or '?')[:12]} kg={graph_status}")
            self.project_runtime_rows.append({
                "project": first.project,
                "project_url": first.project_url,
                "resolved_commit": resolved_commit,
                "samples": [s.sample_id for s in group],
                "snapshot_status": snapshot_status.__dict__,
                "graph_status": graph_status,
                "graph_dir": str(graph_dir) if graph_dir else None,
                "kg_nodes": len(graph.nodes) if graph is not None else 0,
                "kg_edges": len(graph.edges) if graph is not None else 0,
            })
        progress.finish(extra=f"groups={len(resolved_groups)}")
        return context

    def _prepare_project_commit_graphs(self, samples: list[SecVulEvalSample], classify: bool) -> dict[tuple[str, str], dict[str, Any]]:
        """Prepare graphs keyed by the *resolved* project@commit snapshot.

        For SecVulEval patch semantics, vulnerable rows are resolved to the
        first parent of the patch commit and fixed rows to the patch commit.
        This is deterministic and deliberately avoids open-ended history search.
        All decisions are written to target_resolution.jsonl and
        target_validation_candidates.jsonl.
        """
        if (
            classify
            and self.cfg.dataset.validation_aware_pair_selection
            and getattr(self.cfg.dataset, "validation_candidate_stream_until_valid_pairs", True)
        ):
            return self._prepare_project_commit_graphs_streaming_validated_pairs(samples, classify)

        repo_manager = RepoManager(self.cfg.repo, self.logger, self.run_dir)
        snapshot_manager = SnapshotManager(self.cfg.repo, self.logger, self.run_dir)
        resolver = CommitResolver(self.cfg.snapshot, self.logger, self.run_dir)
        validator = TargetValidator(
            self.logger,
            artifact_root=self.run_dir / self.cfg.snapshot.validation_artifact_dirname,
            save_artifacts=self.cfg.snapshot.save_validation_artifacts,
        )
        graph_cache = GraphCache(self.cfg.kg, self.logger)
        context: dict[tuple[str, str], dict[str, Any]] = {}
        self.sample_graph_keys = {}
        self.sample_resolution = {}
        self.skipped_sample_ids = set()

        # Clone/reuse once per project, then resolve each sample to the most
        # plausible commit snapshot before grouping for KG construction.
        project_groups: dict[str, list[SecVulEvalSample]] = defaultdict(list)
        for sample in samples:
            pkey = sample.project_url or sample.project or "unknown_project"
            project_groups[pkey].append(sample)

        resolved_groups: dict[tuple[str, str], list[SecVulEvalSample]] = defaultdict(list)
        repo_status_by_project: dict[str, Any] = {}
        validation_aware = bool(classify and self.cfg.dataset.validation_aware_pair_selection)
        pending_pair_candidates: list[dict[str, Any]] = []
        resolution_progress = ProgressMeter(self.logger, len(samples), "commit_resolution.samples", self.cfg.logging.log_every_n_samples, self.cfg.logging.log_every_seconds)

        for project_key, project_samples in project_groups.items():
            first = project_samples[0]
            log_kv(
                self.logger,
                "Project start",
                project=first.project,
                project_url=first.project_url,
                samples=len(project_samples),
                commit_resolution=self.cfg.snapshot.commit_resolution,
            )
            repo_status = repo_manager.ensure_mirror(first.project_url, first.project)
            repo_status_by_project[project_key] = repo_status
            self.logger.info("repo.status | project=%s | status=%s | mirror=%s", first.project, repo_status.status, repo_status.mirror_path)

            for sample in project_samples:
                candidates = resolver.candidates(repo_status, sample)
                if not candidates and sample.commit_id:
                    candidates = []
                candidate_records: list[dict[str, Any]] = []
                best: tuple[float, str | None, str | None, Any, Any] | None = None

                for cand in candidates:
                    snapshot_status = snapshot_manager.ensure_snapshot(repo_status, cand.commit_id)
                    snapshot_path = Path(snapshot_status.worktree_path) if snapshot_status.worktree_path else None
                    validation = validator.validate(
                        snapshot_path,
                        sample,
                        candidate_commit_id=cand.commit_id,
                        candidate_label=cand.label,
                    ) if self.cfg.snapshot.validate_target_function else None
                    validation_dict = validation.__dict__ if validation else None
                    record = {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "dataset_commit_id": sample.commit_id,
                        "candidate_label": cand.label,
                        "candidate_commit_id": cand.commit_id,
                        "snapshot_status": snapshot_status.__dict__,
                        "validation": validation_dict,
                    }
                    append_jsonl(self.run_dir / "target_validation_candidates.jsonl", record)
                    candidate_records.append(record)

                    sim = validation.body_similarity if validation else 0.0
                    function_bonus = 0.10 if validation and validation.function_found else 0.0
                    file_bonus = 0.05 if validation and validation.filepath_exists else 0.0
                    exact_bonus = 0.20 if validation and validation.status == "match_exact" else 0.0
                    score = sim + function_bonus + file_bonus + exact_bonus
                    if best is None or score > best[0]:
                        best = (score, cand.commit_id, cand.label, snapshot_status, validation)

                if best is None:
                    selected_commit = sample.commit_id or "unknown_commit"
                    selected_label = "dataset_commit"
                    selected_status = None
                    selected_similarity = None
                    selected_artifact_dir = None
                    warning = "no_commit_candidate_available"
                else:
                    _, selected_commit, selected_label, _, selected_validation = best
                    selected_status = selected_validation.status if selected_validation else None
                    selected_similarity = selected_validation.body_similarity if selected_validation else None
                    selected_artifact_dir = selected_validation.artifact_dir if selected_validation else None
                    warning = None
                    if selected_similarity is not None and selected_similarity < self.cfg.snapshot.body_match_threshold:
                        warning = (
                            f"best candidate similarity {selected_similarity:.4f} is below threshold "
                            f"{self.cfg.snapshot.body_match_threshold:.4f}"
                        )

                resolution = CommitResolution(
                    sample_id=sample.sample_id,
                    project=sample.project,
                    filepath=sample.filepath,
                    func_name=sample.func_name,
                    dataset_commit_id=sample.commit_id,
                    selected_commit_id=selected_commit,
                    selected_label=selected_label,
                    strategy=self.cfg.snapshot.commit_resolution,
                    selected_status=selected_status,
                    selected_similarity=selected_similarity,
                    candidates=candidate_records,
                    selected_artifact_dir=selected_artifact_dir,
                    warning=warning,
                )
                self.sample_resolution[sample.sample_id] = resolution
                append_jsonl(self.run_dir / "target_resolution.jsonl", resolution.to_dict())
                self.logger.info(
                    "commit_resolution | sample=%s | strategy=%s | selected=%s:%s | status=%s | similarity=%s%s",
                    sample.sample_id,
                    self.cfg.snapshot.commit_resolution,
                    selected_label,
                    (selected_commit or "?")[:12],
                    selected_status,
                    selected_similarity,
                    f" | WARNING: {warning}" if warning else "",
                )

                should_skip = False
                if warning:
                    self.logger.warning(
                        "target_validation.low_similarity | sample=%s | selected_commit=%s | similarity=%s | threshold=%s",
                        sample.sample_id,
                        (selected_commit or "?")[:12],
                        selected_similarity,
                        self.cfg.snapshot.body_match_threshold,
                    )
                    should_skip = self.cfg.snapshot.on_validation_failure == "skip"

                if selected_status in {"file_missing", "function_missing", "validation_error", "no_snapshot"}:
                    should_skip = self.cfg.snapshot.on_validation_failure == "skip"

                selected_bad_status = selected_status in {"file_missing", "function_missing", "validation_error", "no_snapshot", "function_name_only"}
                selected_low_similarity = (
                    selected_similarity is not None
                    and selected_similarity < self.cfg.snapshot.body_match_threshold
                )
                selected_valid_for_pair = (not selected_bad_status) and (not selected_low_similarity) and not bool(warning)

                if validation_aware:
                    pending_pair_candidates.append({
                        "sample": sample,
                        "project_key": project_key,
                        "selected_commit": selected_commit,
                        "selected_status": selected_status,
                        "selected_similarity": selected_similarity,
                        "selected_label": selected_label,
                        "valid": selected_valid_for_pair,
                        "reason": warning or (selected_status if selected_bad_status else None) or ("low_similarity" if selected_low_similarity else None),
                    })
                    resolution_progress.update(extra=f"sample={sample.sample_id} candidate_valid={selected_valid_for_pair}")
                    continue

                if should_skip:
                    self.skipped_sample_ids.add(sample.sample_id)
                    append_jsonl(self.run_dir / "skipped_samples.jsonl", {
                        "sample_id": sample.sample_id,
                        "project": sample.project,
                        "filepath": sample.filepath,
                        "func_name": sample.func_name,
                        "dataset_commit_id": sample.commit_id,
                        "selected_commit_id": selected_commit,
                        "selected_status": selected_status,
                        "selected_similarity": selected_similarity,
                        "reason": warning or selected_status or "validation_failed",
                    })
                    self.logger.warning(
                        "target_validation.skip | sample=%s | selected_commit=%s | status=%s | similarity=%s",
                        sample.sample_id,
                        (selected_commit or "?")[:12],
                        selected_status,
                        selected_similarity,
                    )
                    resolution_progress.update(extra=f"sample={sample.sample_id} skipped")
                    continue

                resolved_key = (project_key, selected_commit or sample.commit_id or "unknown_commit")
                self.sample_graph_keys[sample.sample_id] = resolved_key
                resolved_groups[resolved_key].append(sample)
                resolution_progress.update(extra=f"sample={sample.sample_id} commit={(selected_commit or '?')[:12]}")

        if validation_aware:
            selected_pairs = 0
            requested_pairs = int(self.cfg.dataset.validated_pair_limit or self.cfg.dataset.sample_limit or 5)
            pair_groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
            pair_order: list[tuple[str, str, str, str, str]] = []
            for rec in pending_pair_candidates:
                sample = rec["sample"]
                key = self._candidate_pair_key(sample)
                if key not in pair_groups:
                    pair_groups[key] = {"records": [], "project": sample.project, "filepath": sample.filepath, "func_name": sample.func_name}
                    pair_order.append(key)
                pair_groups[key]["records"].append(rec)

            selection_rows: list[dict[str, Any]] = []
            selected_sample_ids: set[str] = set()
            selected_projects: set[str] = set()
            one_pair_per_project = bool(getattr(self.cfg.dataset, "validation_candidate_one_pair_per_project", True))
            for key in pair_order:
                group = pair_groups[key]
                project_name = str(group.get("project") or "")
                records = group["records"]
                vuln_recs = [r for r in records if bool(r["sample"].is_vulnerable)]
                fixed_recs = [r for r in records if not bool(r["sample"].is_vulnerable)]
                valid_vuln = [r for r in vuln_recs if r.get("valid")]
                valid_fixed = [r for r in fixed_recs if r.get("valid")]
                pair_valid = bool(valid_vuln and valid_fixed) if self.cfg.dataset.require_validated_pair_both_sides else bool(valid_vuln or valid_fixed)
                blocked_by_project_diversity = bool(one_pair_per_project and project_name in selected_projects)
                selected_now = pair_valid and not blocked_by_project_diversity and selected_pairs < requested_pairs
                row = {
                    "project": group.get("project"),
                    "filepath": group.get("filepath"),
                    "func_name": group.get("func_name"),
                    "pair_key": list(key),
                    "pair_valid": pair_valid,
                    "selected_for_classification": selected_now,
                    "blocked_by_project_diversity": blocked_by_project_diversity,
                    "vulnerable_samples": [r["sample"].sample_id for r in vuln_recs],
                    "fixed_samples": [r["sample"].sample_id for r in fixed_recs],
                    "vulnerable_valid": [r["sample"].sample_id for r in valid_vuln],
                    "fixed_valid": [r["sample"].sample_id for r in valid_fixed],
                    "statuses": [{
                        "sample_id": r["sample"].sample_id,
                        "is_vulnerable": bool(r["sample"].is_vulnerable),
                        "status": r.get("selected_status"),
                        "similarity": r.get("selected_similarity"),
                        "selected_commit": r.get("selected_commit"),
                        "valid": r.get("valid"),
                        "reason": r.get("reason"),
                    } for r in records],
                }
                selection_rows.append(row)
                if selected_now:
                    selected_pairs += 1
                    if one_pair_per_project:
                        selected_projects.add(project_name)
                    for r in valid_vuln[:1] + valid_fixed[:1]:
                        sample = r["sample"]
                        selected_sample_ids.add(sample.sample_id)
                        resolved_key = (r["project_key"], r["selected_commit"] or sample.commit_id or "unknown_commit")
                        self.sample_graph_keys[sample.sample_id] = resolved_key
                        resolved_groups[resolved_key].append(sample)
                else:
                    reason = "validated_pair_project_diversity_blocked" if blocked_by_project_diversity else ("validated_pair_not_selected" if pair_valid else "validated_pair_rejected")
                    for r in records:
                        sample = r["sample"]
                        self.skipped_sample_ids.add(sample.sample_id)
                        append_jsonl(self.run_dir / "skipped_samples.jsonl", {
                            "sample_id": sample.sample_id,
                            "project": sample.project,
                            "filepath": sample.filepath,
                            "func_name": sample.func_name,
                            "dataset_commit_id": sample.commit_id,
                            "selected_commit_id": r.get("selected_commit"),
                            "selected_status": r.get("selected_status"),
                            "selected_similarity": r.get("selected_similarity"),
                            "reason": r.get("reason") or reason,
                            "pair_selection_reason": reason,
                        })

            self.classification_sample_ids = set(selected_sample_ids)
            write_jsonl(self.run_dir / "validated_pair_selection.jsonl", selection_rows)
            summary = {
                "enabled": True,
                "requested_valid_pairs": requested_pairs,
                "candidate_samples": len(pending_pair_candidates),
                "candidate_pairs_considered": len(pair_order),
                "valid_pairs_found": sum(1 for r in selection_rows if r["pair_valid"]),
                "selected_pairs": selected_pairs,
                "selected_samples": len(selected_sample_ids),
                "selected_projects": len(selected_projects),
                "one_pair_per_project": one_pair_per_project,
                "project_diversity_blocked_pairs": sum(1 for r in selection_rows if r.get("blocked_by_project_diversity")),
                "rejected_pairs": sum(1 for r in selection_rows if not r["pair_valid"]),
                "not_selected_valid_pairs": sum(1 for r in selection_rows if r["pair_valid"] and not r["selected_for_classification"]),
                "threshold": self.cfg.snapshot.body_match_threshold,
            }
            write_json(self.run_dir / "validated_pair_selection_summary.json", summary)
            self.logger.info("validated_pair_selection.summary | %s", summary)
            if self.live:
                self.live.event("dataset.validated_pair_selection.done", summary)
            if selected_pairs < requested_pairs:
                raise RuntimeError(
                    f"Only {selected_pairs} validated vulnerable/fixed pairs found, requested {requested_pairs}. "
                    f"Increase dataset.candidate_pair_limit or relax validation criteria. "
                    f"See {self.run_dir / 'validated_pair_selection.jsonl'}."
                )

        resolution_progress.finish(extra=f"resolved_groups={len(resolved_groups)} skipped={len(self.skipped_sample_ids)}")
        if not resolved_groups:
            self.logger.warning(
                "No resolved project@commit groups remain after validation filtering | skipped=%s",
                len(self.skipped_sample_ids),
            )
            return context

        # Build/load one KG per resolved project@commit.
        progress = ProgressMeter(self.logger, len(resolved_groups), "project@resolved_commit", self.cfg.logging.log_every_n_samples)
        for (project_key, resolved_commit), group in resolved_groups.items():
            first = group[0]
            repo_status = repo_status_by_project.get(project_key) or repo_manager.ensure_mirror(first.project_url, first.project)
            graph = None
            graph_dir = None
            graph_status = "not_built"
            kg_wall_seconds = None
            snapshot_path = None
            log_kv(
                self.logger,
                "Resolved group start",
                project=first.project,
                project_url=first.project_url,
                resolved_commit=resolved_commit[:12] if resolved_commit else None,
                samples_in_group=len(group),
            )
            snapshot_status = snapshot_manager.ensure_snapshot(repo_status, resolved_commit)
            self.logger.info("snapshot.status | project=%s | status=%s | worktree=%s", first.project, snapshot_status.status, snapshot_status.worktree_path)
            if snapshot_status.worktree_path:
                snapshot_path = Path(snapshot_status.worktree_path)

            # Final validation log for the selected snapshot.
            validation_progress = ProgressMeter(self.logger, len(group), "target_validation.selected", self.cfg.logging.log_every_n_samples, self.cfg.logging.log_every_seconds)
            for sample in group:
                validation = validator.validate(
                    snapshot_path,
                    sample,
                    candidate_commit_id=resolved_commit,
                    candidate_label="selected_snapshot",
                ) if self.cfg.snapshot.validate_target_function else None
                if validation:
                    append_jsonl(self.run_dir / "target_validation.jsonl", validation)
                    self.logger.info(
                        "target_validation.selected | sample=%s | status=%s | main=%s | raw=%s | content=%s | tokens=%s | artifact=%s",
                        sample.sample_id,
                        validation.status,
                        validation.body_similarity,
                        validation.raw_similarity,
                        validation.whitespace_insensitive_similarity,
                        validation.token_sequence_similarity,
                        validation.artifact_dir,
                    )
                    should_skip = self._should_skip_target_validation(validation)
                    if should_skip:
                        msg = f"Target validation failed sample={sample.sample_id}: {validation}"
                        if self.cfg.snapshot.skip_target_validation_failures or self.cfg.snapshot.on_validation_failure == "skip":
                            self._record_target_validation_skip(
                                sample=sample,
                                validation=validation,
                                resolved_commit=resolved_commit,
                                reason="final_selected_snapshot_validation_failed",
                            )
                            self.logger.warning("target_validation.skip | %s", msg)
                        elif self.cfg.snapshot.on_validation_failure == "fail":
                            raise RuntimeError(msg)
                        else:
                            self.logger.warning(msg)
                validation_progress.update(extra=f"sample={sample.sample_id}")
            validation_progress.finish(extra=f"group={first.project}@{resolved_commit[:12] if resolved_commit else '?'}")

            kg_wall_seconds = 0.0
            if self.cfg.kg.scope == "project_snapshot" and snapshot_path:
                try:
                    kg_start = time.perf_counter()
                    graph, graph_dir, graph_status = graph_cache.get_or_build(
                        snapshot_path=snapshot_path,
                        project=first.project,
                        project_url=first.project_url,
                        commit_id=resolved_commit,
                    )
                    kg_wall_seconds = time.perf_counter() - kg_start
                    graph_dir_size = dir_size_bytes(graph_dir)
                    append_jsonl(
                        self.run_dir / "kg_manifests.jsonl",
                        {"status": graph_status, "graph_dir": str(graph_dir), "kg_wall_seconds": kg_wall_seconds, "graph_dir_size_bytes": graph_dir_size, **graph.manifest},
                    )
                except Exception as exc:
                    self.logger.exception(f"KG build/load failed for {project_key}@{resolved_commit}")
                    append_jsonl(
                        self.run_dir / "kg_manifests.jsonl",
                        {"status": "failed", "project_key": project_key, "commit_id": resolved_commit, "error": str(exc)},
                    )
                    if not classify:
                        raise
            manifest = (getattr(graph, "manifest", {}) or {}) if graph else {}
            dashboard_path = manifest.get("dashboard_path") or (str(Path(graph_dir) / "dashboard" / "index.html") if graph_dir else None)
            manifest_path = str(Path(graph_dir) / "manifest.json") if graph_dir else None
            graph_json_path = str(Path(graph_dir) / "graph.json") if graph_dir else None
            project_runtime = {
                "project": first.project,
                "project_url": first.project_url,
                "project_key": project_key,
                "repo_key": getattr(repo_status, "repo_key", None),
                "repo_status": getattr(repo_status, "status", None),
                "repo_elapsed_seconds": getattr(repo_status, "elapsed_seconds", None),
                "mirror_path": getattr(repo_status, "mirror_path", None),
                "mirror_size_bytes": getattr(repo_status, "mirror_size_bytes", None),
                "resolved_commit_id": resolved_commit,
                "resolved_commit_short": resolved_commit[:12] if resolved_commit else None,
                "samples_in_group": len(group),
                "snapshot_status": getattr(snapshot_status, "status", None),
                "snapshot_elapsed_seconds": getattr(snapshot_status, "elapsed_seconds", None),
                "snapshot_path": getattr(snapshot_status, "worktree_path", None),
                "worktree_size_bytes": getattr(snapshot_status, "worktree_size_bytes", None),
                "graph_status": graph_status,
                "graph_dir": str(graph_dir) if graph_dir else None,
                "graph_dir_size_bytes": dir_size_bytes(graph_dir) if graph_dir else 0,
                "kg_wall_seconds": kg_wall_seconds,
                "kg_build_seconds_manifest": manifest.get("seconds") or manifest.get("elapsed_seconds"),
                "num_files": manifest.get("num_files"),
                "num_functions": manifest.get("num_functions"),
                "num_statements": manifest.get("num_statements"),
                "backend_used": manifest.get("backend_used") or manifest.get("backend"),
                "fallback_used": manifest.get("fallback_used"),
                "cache_hit": graph_status == "loaded_cache",
                "dashboard_path": dashboard_path,
                "dashboard_url": self._dashboard_url_for_path(dashboard_path),
                "manifest_url": self._dashboard_url_for_path(manifest_path),
                "graph_json_url": self._dashboard_url_for_path(graph_json_path),
                "graph_dir_url": self._dashboard_url_for_path(graph_dir),
                "num_nodes": len(getattr(graph, "nodes", []) or []),
                "num_edges": len(getattr(graph, "edges", []) or []),
                "source_file_filters": list(self.cfg.kg.include_file_types),
                "kg_scope": self.cfg.kg.scope,
                "kg_version": self.cfg.kg.version,
            }
            self.project_runtime_rows.append(project_runtime)
            append_jsonl(self.run_dir / "project_runtime.jsonl", project_runtime)
            if self.live:
                self.live.update_project(f"{first.project}@{resolved_commit[:12] if resolved_commit else '?'}", {**project_runtime, "status": f"kg_{graph_status}", "kg_status": f"kg_{graph_status}"})
                self.live.event("kg.ready", {"project": first.project, "commit": resolved_commit[:12] if resolved_commit else None, "graph_status": graph_status, "dashboard_url": project_runtime.get("dashboard_url")})
            context[(project_key, resolved_commit)] = {
                "repo_status": repo_status,
                "snapshot_status": snapshot_status,
                "snapshot_path": snapshot_path,
                "graph": graph,
                "graph_dir": graph_dir,
                "graph_status": graph_status,
                "project_runtime": project_runtime,
            }
            progress.update(extra=f"project={first.project} resolved_commit={resolved_commit[:12] if resolved_commit else '?'} kg={graph_status}")
        return context

    def _graph_for_sample(self, sample: SecVulEvalSample, ctx: dict[tuple[str, str], dict[str, Any]]) -> ProjectGraph | None:
        key = self.sample_graph_keys.get(
            sample.sample_id,
            (sample.project_url or sample.project or "unknown_project", sample.commit_id or "unknown_commit"),
        )
        item = ctx.get(key)
        if item:
            return item.get("graph")
        return None

    _TARGET_VALIDATION_SKIP_STATUSES = {
        "file_missing",
        "function_missing",
        "function_name_only",
        "missing_filepath",
        "no_snapshot",
        "validation_error",
    }

    def _should_skip_target_validation(self, validation: Any) -> bool:
        """Return True when the resolved function is too unreliable to classify.

        This gate is intentionally stricter than the target validator itself:
        exact/near-exact matches proceed, but name-only matches, empty dataset
        bodies, and low body similarity are skipped for large research sweeps.
        """
        if validation is None:
            return False
        status = str(getattr(validation, "status", "") or "").strip()
        if status in {"match_exact", "match_near_exact", "match_approximate", "match"}:
            return False
        if status in self._TARGET_VALIDATION_SKIP_STATUSES:
            return True
        if int(getattr(validation, "dataset_chars", 0) or 0) == 0 or int(getattr(validation, "dataset_tokens", 0) or 0) == 0:
            return True
        similarity = float(getattr(validation, "body_similarity", 0.0) or 0.0)
        return similarity < float(self.cfg.snapshot.body_match_threshold)

    def _record_target_validation_skip(
        self,
        *,
        sample: SecVulEvalSample,
        validation: Any,
        resolved_commit: str | None,
        reason: str = "target_validation_failed",
    ) -> None:
        """Persist a skipped sample so dashboard/reporting can show it cleanly.

        Skipped samples are not LLM failures. They are excluded from binary
        metrics and marked separately as skipped_target_validation.
        """
        self.skipped_sample_ids.add(sample.sample_id)
        validation_dict = {
            k: getattr(validation, k)
            for k in getattr(validation, "__dataclass_fields__", {})
        } if validation is not None else {}
        row = {
            "sample_id": sample.sample_id,
            "project": sample.project,
            "filepath": sample.filepath,
            "func_name": sample.func_name,
            "selected_commit_id": resolved_commit,
            "selected_status": validation_dict.get("status"),
            "selected_similarity": validation_dict.get("body_similarity"),
            "reason": reason,
            "target_validation": validation_dict,
        }
        append_jsonl(self.run_dir / "skipped_samples.jsonl", row)
        sample_dir = self.run_dir / "agent_demos" / f"sample_{sample.sample_id}_{sample.func_name or 'target'}"
        sample_dir.mkdir(parents=True, exist_ok=True)
        write_json(sample_dir / "sample.json", sample)
        write_json(sample_dir / "final_prediction.json", {
            "sample_id": str(sample.sample_id),
            "project": sample.project,
            "filepath": sample.filepath,
            "function": sample.func_name,
            "is_vulnerable": None,
            "forced_prediction_bool": None,
            "confidence": None,
            "decision_status": "skipped_target_validation",
            "prediction": None,
            "prediction_bool": None,
            "skip_reason": reason,
            "reasoning_summary": (
                f"Skipped before LLM classification: target validation status={validation_dict.get('status')} "
                f"similarity={validation_dict.get('body_similarity')}."
            ),
            "target_validation_status": validation_dict.get("status"),
            "target_validation_similarity": validation_dict.get("body_similarity"),
            "target_validation": validation_dict,
        })
        write_json(sample_dir / "agent_flow.json", {
            "sample_id": str(sample.sample_id),
            "status": "skipped_target_validation",
            "partial": True,
            "loop_enabled": False,
            "loop_stop_reason": "skipped_target_validation",
            "stages": [],
            "target_validation": validation_dict,
            "message": "No LLM stages were run because strict target validation failed.",
        })
        write_json(sample_dir / "skip_report.json", row)
        if self.live:
            self.live.update_sample(sample.sample_id, {
                "sample_id": sample.sample_id,
                "project": sample.project,
                "filepath": sample.filepath,
                "function": sample.func_name,
                "status": "skipped",
                "agent_stage": "skipped_target_validation",
                "skip_reason": reason,
                "target_validation_status": validation_dict.get("status"),
                "target_validation_similarity": validation_dict.get("body_similarity"),
            })
            self.live.event("sample.skipped_target_validation", row)

    def _function_only_graph(self, sample: SecVulEvalSample) -> ProjectGraph:
        # Fallback/baseline for smoke and failed clone cases; clearly marked as function-only.
        from vuln_commit_kg.kg.extractors.c_like import extract_functions_from_text
        from vuln_commit_kg.kg.graph_store import KGEdge, KGNode, ProjectGraph
        from vuln_commit_kg.kg.extractors.security_patterns import find_risky_calls, is_safety_statement

        graph = ProjectGraph(manifest={"scope": "function_only_baseline", "sample_id": sample.sample_id})
        file_node = f"file:{sample.filepath or 'dataset_func.c'}"
        graph.nodes.append(KGNode(file_node, "File", {"relpath": sample.filepath or "dataset_func.c"}))
        funcs = extract_functions_from_text(sample.func_body, sample.filepath or "dataset_func.c")
        if not funcs:
            # Create a synthetic function node so retrieval always has target evidence.
            fn_node = f"function:{sample.filepath or 'dataset'}:{sample.func_name or 'target'}:0"
            graph.nodes.append(KGNode(fn_node, "Function", {"name": sample.func_name, "relpath": sample.filepath, "body_preview": sample.func_body}))
            graph.edges.append(KGEdge(file_node, fn_node, "FILE_HAS_FUNCTION"))
            graph.nodes.append(KGNode(f"statement:{sample.sample_id}:body", "Statement", {"text": sample.func_body, "function": sample.func_name, "relpath": sample.filepath, "risk_hits": [], "is_safety": False}))
            graph.edges.append(KGEdge(fn_node, f"statement:{sample.sample_id}:body", "FUNCTION_HAS_STATEMENT"))
        else:
            for fn in funcs:
                fn_node = f"function:{fn.function_id}"
                graph.nodes.append(KGNode(fn_node, "Function", {"name": fn.name, "relpath": fn.relpath, "line_start": fn.line_start, "line_end": fn.line_end, "body_preview": fn.body}))
                graph.edges.append(KGEdge(file_node, fn_node, "FILE_HAS_FUNCTION"))
                for stmt in fn.statements:
                    stmt_node = f"statement:{stmt.statement_id}"
                    graph.nodes.append(KGNode(stmt_node, "Statement", {"text": stmt.text, "function": fn.name, "relpath": fn.relpath, "line_start": stmt.line_start, "line_end": stmt.line_end, "calls": stmt.calls, "identifiers": getattr(stmt, "identifiers", []), "defines_variables": getattr(stmt, "defines_variables", []), "uses_variables": getattr(stmt, "uses_variables", []), "risk_hits": [h.__dict__ for h in find_risky_calls(stmt.text)], "is_safety": is_safety_statement(stmt.text)}))
                    graph.edges.append(KGEdge(fn_node, stmt_node, "FUNCTION_HAS_STATEMENT"))
        return graph

    def _evaluate(self, samples: list[SecVulEvalSample], preds: list[Prediction]) -> dict:
        metrics: dict[str, Any] = {}
        if self.cfg.evaluation.binary:
            metrics["binary"] = binary_metrics(samples, preds)
        if self.cfg.evaluation.statement_level:
            metrics["statement"] = statement_metrics(samples, preds, self.cfg.evaluation.statement_match_threshold)
        status_counts: dict[str, int] = {}
        for p in preds:
            key = str(p.decision_status or "missing_status")
            status_counts[key] = status_counts.get(key, 0) + 1
        if self.cfg.evaluation.reasoning_diagnostics:
            metrics["reasoning"] = {
                "parse_errors": sum(1 for p in preds if p.parse_error),
                "with_evidence_used": sum(1 for p in preds if p.evidence_used),
                "decision_status_counts": status_counts,
                "inconclusive": status_counts.get("inconclusive", 0),
                "non_vulnerable": status_counts.get("non_vulnerable", 0),
                "vulnerable": status_counts.get("vulnerable", 0),
                "avg_confidence": sum(p.confidence for p in preds) / len(preds) if preds else 0.0,
            }
        runtime_by_id = {str(r.get("sample_id")): r for r in self.sample_runtime_rows if isinstance(r, dict)}
        pred_by_id = {p.sample_id: p for p in preds}
        per_sample: list[dict[str, Any]] = []
        false_positive = 0
        false_negative = 0
        true_positive = 0
        true_negative = 0
        invalid = 0
        for sample in samples:
            pred = pred_by_id.get(sample.sample_id)
            if pred is None:
                per_sample.append({"sample_id": sample.sample_id, "status": "missing_prediction", "correct": False})
                invalid += 1
                continue
            valid = self._is_valid_binary_prediction(pred)
            correct = valid and (bool(sample.is_vulnerable) == bool(pred.is_vulnerable))
            err = self._prediction_error_type(sample, pred)
            if err == "FP":
                false_positive += 1
            elif err == "FN":
                false_negative += 1
            elif err == "TP":
                true_positive += 1
            elif err == "TN":
                true_negative += 1
            else:
                invalid += 1
            runtime = runtime_by_id.get(sample.sample_id, {})
            per_sample.append({
                "sample_id": sample.sample_id,
                "project": sample.project,
                "filepath": sample.filepath,
                "function": sample.func_name,
                "dataset_label_report_only": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
                "prediction_is_vulnerable": bool(pred.is_vulnerable),
                "decision_status": pred.decision_status,
                "confidence": pred.confidence,
                "valid_binary_prediction": valid,
                "correct": correct,
                "error_type": err,
                "validation_notes": pred.validation_notes,
                "parse_error": pred.parse_error,
                "raw_model_decision": runtime.get("raw_model_decision"),
                "evidence_validated_decision": runtime.get("evidence_validated_decision"),
                "final_system_decision": runtime.get("final_system_decision"),
                "raw_model_is_vulnerable": runtime.get("raw_model_is_vulnerable"),
                "raw_model_decision_status": runtime.get("raw_model_decision_status"),
                "raw_model_confidence": runtime.get("raw_model_confidence"),
                "validator_modified": bool(runtime.get("validator_modified")),
                "validator_modification_count": int(runtime.get("validator_modification_count") or 0),
                "final_system_is_vulnerable": bool(pred.is_vulnerable),
                "final_system_decision_status": pred.decision_status,
                "final_system_confidence": pred.confidence,
                "agent_report": runtime.get("agent_report_rel"),
            })
        metrics["operational"] = {
            "operational_success": len(preds) == len([s for s in samples if s.sample_id not in self.skipped_sample_ids]),
            "selected_sample_count": len(samples),
            "prediction_count": len(preds),
            "skipped_sample_count": len(self.skipped_sample_ids),
            "failed_sample_count": max(0, len(samples) - len(preds) - len(self.skipped_sample_ids)),
            "json_repair_attempts": sum(int(r.get("json_repair_attempts") or 0) for r in self.sample_runtime_rows),
            "json_repaired_calls": sum(int(r.get("json_repaired_calls") or 0) for r in self.sample_runtime_rows),
            "mechanical_normalizations": sum(int(r.get("mechanical_normalizations") or 0) for r in self.sample_runtime_rows),
            "inconclusive_count": status_counts.get("inconclusive", 0),
            "parse_error_count": sum(1 for p in preds if p.parse_error),
        }
        validator_modified_count = sum(1 for r in runtime_by_id.values() if r.get("validator_modified"))
        raw_available = [r for r in runtime_by_id.values() if r.get("raw_model_is_vulnerable") is not None]
        raw_correct = 0
        for sample in samples:
            r = runtime_by_id.get(sample.sample_id, {})
            if r.get("raw_model_is_vulnerable") is None:
                continue
            raw_correct += int(bool(r.get("raw_model_is_vulnerable")) == bool(sample.is_vulnerable))
        metrics["decision_flow_separation"] = {
            "description": "Raw final model decision, evidence-validated accepted JSON, and final system decision are stored separately; only final_system_decision is used for benchmark metrics.",
            "decision_layers": ["raw_model_decision", "evidence_validated_decision", "final_system_decision"],
            "raw_model_decision_available_count": len(raw_available),
            "raw_model_accuracy_when_available": raw_correct / len(raw_available) if raw_available else None,
            "validator_modified_sample_count": validator_modified_count,
            "validator_override_rate_over_predictions": validator_modified_count / len(preds) if preds else 0.0,
            "per_sample": per_sample,
        }
        metrics["prediction_correctness"] = {
            "true_positive_count": true_positive,
            "true_negative_count": true_negative,
            "false_positive_count": false_positive,
            "false_negative_count": false_negative,
            "invalid_or_inconclusive_count": invalid,
            "accuracy_all_selected_invalid_as_wrong": (true_positive + true_negative) / len(samples) if samples else 0.0,
            "per_sample_correctness": per_sample,
        }
        return metrics

    def _write_summary(self, metrics: dict, usage: dict, n_samples: int, n_predictions: int) -> None:
        binary = metrics.get("binary", {})
        statement = metrics.get("statement", {})
        content = f"""# Run Summary

- Samples selected: {n_samples}
- Predictions produced: {n_predictions}
- Operational success: {metrics.get('operational', {}).get('operational_success', False)}
- Accuracy: {binary.get('accuracy', 0):.4f}
- False positives: {metrics.get('prediction_correctness', {}).get('false_positive_count', 0)}
- False negatives: {metrics.get('prediction_correctness', {}).get('false_negative_count', 0)}
- Inconclusive/invalid: {metrics.get('prediction_correctness', {}).get('invalid_or_inconclusive_count', 0)}
- Precision: {binary.get('precision', 0):.4f}
- Recall: {binary.get('recall', 0):.4f}
- F1: {binary.get('f1', 0):.4f}
- Statement F1: {statement.get('statement_f1', 0):.4f}
- Total tokens: {usage.get('total_tokens', 0)}
- Estimated total cost: {usage.get('cost_total_usd', 0):.6f} USD
- Token accounting estimated: {usage.get('estimated', True)}

See `metrics.json`, `usage_summary.json`, `tables/`, `figures/`, and `run.log` for details.
"""
        (self.run_dir / "summary.md").write_text(content, encoding="utf-8")
