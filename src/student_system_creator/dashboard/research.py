"""Read-only inventory for the original research agentic-audit workflow.

This surfaces the artifacts the existing `vckg run` pipeline already writes — it
does NOT re-implement the pipeline. Per run, the pipeline produces:

    outputs/runs/<run>/                      (or <job_dir>/runs/<run> for dashboard jobs)
      run.log, metrics.json, summary.md, resolved_config.yaml, samples.jsonl
      agent_demos/sample_<id>_<fn>/
        agent_trace.json      (embeds model_calls, kg_queries, kg_tool_steps, ...)
        final_prediction.json (verdict, confidence, raw_response, usage, backend)
        model_calls.jsonl, kg_tool_calls.jsonl, evidence_pack.json
        index.html            (existing static per-sample KG/audit dashboard)
        target_function.c
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import yaml

# Config keys that may hold secrets and must never be returned to the UI.
# NOTE: a bare "token" hint wrongly redacts token *counts* (prompt_tokens,
# completion_tokens, total_tokens) which are NOT secrets. We match credential
# tokens specifically and exempt count-style keys.
_SECRET_HINTS = ("api_key", "apikey", "secret", "password", "authorization",
                 "access_token", "api_token", "bearer", "auth_token")
# Token-count keys that must NEVER be redacted (they are integers, not secrets).
_TOKEN_COUNT_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens",
                     "num_tokens", "tokens", "max_tokens", "token_count",
                     "avg_total_tokens_per_prediction")


def _is_secret_key(key: str) -> bool:
    k = str(key).lower()
    if k in _TOKEN_COUNT_KEYS or k.endswith("_tokens") or k.endswith("token_count"):
        return False
    return any(h in k for h in _SECRET_HINTS)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


_ANSWER_RE = re.compile(r"<answer>\s*(.*?)\s*</answer>", re.I | re.S)


def _infer_parse_status_for_call(c: dict[str, Any]) -> str | None:
    """Infer parse_status from raw response text when pipeline enrichment didn't run.

    Called by flow() and flow_report() as a fallback for call records that still
    have json_status='raw_agentic_proof_pending_parse' (i.e., the post-pipeline
    enrichment pass was skipped because the run failed mid-way).
    """
    stored = c.get("parse_status")
    if stored:
        return stored
    # Synthetic final_decision record is always valid.
    if c.get("name") == "final_decision" or c.get("json_status") == "json_ok":
        return "valid"
    if c.get("error") or not (c.get("response") or "").strip():
        return "failed"
    response = c.get("response") or ""
    m = _ANSWER_RE.search(response)
    if m:
        try:
            json.loads(m.group(1))
            return "valid"
        except Exception:
            return "invalid"
    # No <answer> tag — plain-text or non-JSON response.
    return "text_only" if response.strip() else None


def _mask_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        masked = {}
        for k, v in obj.items():
            if _is_secret_key(k):
                masked[k] = "***redacted***"
            else:
                masked[k] = _mask_secrets(v)
        return masked
    if isinstance(obj, list):
        return [_mask_secrets(v) for v in obj]
    return obj


# Decision-status values that mean "no real final prediction yet" — these are
# placeholders written at agent_loop_start that survive a failed/interrupted run.
_INCOMPLETE_STATUSES = {"running", "in_progress", "in progress", "pending",
                        "agent_loop_start", "started", ""}

# Decision-status substrings that mark a prediction as inconclusive (complete
# but not definitively classified as vulnerable or safe).
_INCONCLUSIVE_HINTS = ("inconclusive", "forced_binary")


def _prediction_is_available(fp: dict[str, Any] | None) -> bool:
    """True only if final_prediction holds a real decision (not a placeholder).

    A failed run leaves is_vulnerable=false / confidence=0.0 / decision_status=
    "running"; that must NOT be read as a real "safe" prediction.
    """
    if not fp:
        return False
    status = str(fp.get("decision_status") or "").strip().lower()
    if status in _INCOMPLETE_STATUSES or "running" in status or "progress" in status:
        return False
    if fp.get("parse_error"):
        # parse failures are completed-but-invalid; still not a usable prediction
        return False
    # is_vulnerable is set for definitive predictions; forced_prediction_bool covers
    # inconclusive predictions that got a forced binary choice from the validator.
    return fp.get("is_vulnerable") is not None or fp.get("forced_prediction_bool") is not None


def _is_inconclusive_status(status: str) -> bool:
    s = status.strip().lower()
    return any(h in s for h in _INCONCLUSIVE_HINTS)


def _forced_bool_from_status(status: str) -> bool | None:
    s = (status or "").strip().lower()
    if s == "forced_binary_vulnerable":
        return True
    if s == "forced_binary_non_vulnerable":
        return False
    return None


def _canonical_prediction_bool(fp: dict[str, Any]) -> bool | None:
    """Return the benchmarkable binary prediction, including forced-binary decisions.

    Older artifacts sometimes stored decision_status=forced_binary_* but omitted
    forced_prediction_bool.  Infer it from decision_status so the dashboard
    result/filter columns cannot display forced-binary samples as inconclusive
    while metrics count them as TP/FP/TN/FN.
    """
    forced = fp.get("forced_prediction_bool")
    if forced is not None:
        return bool(forced)
    inferred = _forced_bool_from_status(str(fp.get("decision_status") or ""))
    if inferred is not None:
        return inferred
    raw = fp.get("is_vulnerable")
    if raw is not None:
        return bool(raw)
    return None


def _classify_sample(fp: dict[str, Any], sample: dict[str, Any]) -> tuple[str, str | None, str]:
    """Return (result, error_type, outcome) for one completed prediction.

    result   : "correct" | "incorrect" | "inconclusive" | "unknown"
    error_type: "tp" | "tn" | "fp" | "fn" | None
    outcome  : "TP" | "TN" | "FP" | "FN" | "inconclusive" | "unknown"
    """
    decision_status = str(fp.get("decision_status") or "")
    if _is_inconclusive_status(decision_status):
        # Use forced_prediction_bool if the validator produced a binary forced choice.
        forced = fp.get("forced_prediction_bool")
        if forced is None:
            forced = _forced_bool_from_status(decision_status)
        if forced is None:
            return "inconclusive", None, "inconclusive"
        # Fall through with forced binary prediction for TP/TN/FP/FN scoring.
        true_is_vuln = sample.get("is_vulnerable")
        if true_is_vuln is None:
            return "unknown", None, "unknown"
        tv, pv = bool(true_is_vuln), bool(forced)
        if tv and pv:
            return "correct", "tp", "TP"
        if tv and not pv:
            return "incorrect", "fn", "FN"
        if not tv and pv:
            return "incorrect", "fp", "FP"
        return "correct", "tn", "TN"
    true_is_vuln = sample.get("is_vulnerable")
    if true_is_vuln is None:
        return "unknown", None, "unknown"
    pred_is_vuln = _canonical_prediction_bool(fp)
    if pred_is_vuln is None:
        return "unknown", None, "unknown"
    tv, pv = bool(true_is_vuln), bool(pred_is_vuln)
    if tv and pv:
        return "correct", "tp", "TP"
    if tv and not pv:
        return "incorrect", "fn", "FN"
    if not tv and pv:
        return "incorrect", "fp", "FP"
    return "correct", "tn", "TN"


def _safe_div(num: float, den: float) -> float | None:
    return (num / den) if den > 0 else None


def _compute_metrics_live(sample_dirs: list[Path]) -> dict[str, Any]:
    """Compute binary metrics directly from agent_demo sample directories.

    Works without metrics.json by reading sample.json (true label) and
    final_prediction.json (prediction) from each sample dir.
    """
    total = 0
    completed_count = 0
    failed_count = 0
    inconclusive_count = 0
    tp = tn = fp = fn = correct = incorrect = 0
    has_any_label = False
    rows: list[dict[str, Any]] = []

    for sd in sample_dirs:
        total += 1
        fp_data = _read_json(sd / "final_prediction.json") or {}
        sample_data = _read_json(sd / "sample.json") or {}

        parts = sd.name.split("_")
        sample_id = fp_data.get("sample_id") or (parts[1] if len(parts) >= 2 else sd.name)
        func = sample_data.get("func_name") or sample_data.get("function_name")
        confidence = fp_data.get("confidence")
        decision_status = fp_data.get("decision_status") or ""
        true_is_vuln = sample_data.get("is_vulnerable")
        pred_is_vuln = _canonical_prediction_bool(fp_data)

        avail = _prediction_is_available(fp_data)
        if not avail:
            failed_count += 1
            rows.append({
                "sample_id": str(sample_id), "function": func,
                "true_label": ("vulnerable" if true_is_vuln else "safe") if true_is_vuln is not None else None,
                "prediction": None, "prediction_bool": None,
                "result": "failed", "error_type": None,
                "confidence": None, "status": decision_status or "failed", "outcome": "failed",
            })
            continue

        completed_count += 1
        if true_is_vuln is not None:
            has_any_label = True

        result, error_type, outcome = _classify_sample(fp_data, sample_data)

        if result == "inconclusive":
            inconclusive_count += 1
        elif result == "correct":
            correct += 1
            if error_type == "tp":
                tp += 1
            else:
                tn += 1
        elif result == "incorrect":
            incorrect += 1
            if error_type == "fn":
                fn += 1
            else:
                fp += 1

        rows.append({
            "sample_id": str(sample_id), "function": func,
            "true_label": ("vulnerable" if true_is_vuln else "safe") if true_is_vuln is not None else None,
            "prediction": ("vulnerable" if pred_is_vuln else "safe") if pred_is_vuln is not None else None,
            "prediction_bool": bool(pred_is_vuln) if pred_is_vuln is not None else None,
            "result": result, "error_type": error_type,
            "confidence": confidence, "status": decision_status, "outcome": outcome,
        })

    n = tp + fp + tn + fn  # definitive predictions with labels
    accuracy = _safe_div(tp + tn, n)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1: float | None = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)

    if not has_any_label and completed_count > 0:
        diagnostic: str | None = "true labels missing (no sample.json)"
    elif inconclusive_count > 0 and inconclusive_count == completed_count:
        diagnostic = "all predictions inconclusive"
    elif n == 0 and completed_count > 0:
        diagnostic = "no definitive predictions for metric computation"
    else:
        diagnostic = None

    return {
        "available": True,
        "total": total,
        "completed": completed_count,
        "failed": failed_count,
        "inconclusive": inconclusive_count,
        "correct": correct,
        "incorrect": incorrect,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "diagnostic": diagnostic,
        "rows": rows,
    }


# Log line patterns for recovering a partial stage timeline + KG summary when a
# run failed before persisting per-sample model_calls / agent_trace.
_RE_GEN_START = re.compile(r"model\.generate_start \| sample=(?P<sid>\S+) \| stage=(?P<stage>\S+)(?: \| attempt=(?P<attempt>\S+))?(?: \| prompt_chars=(?P<pc>\d+))?")
_RE_GEN_DONE = re.compile(r"model\.generate_done \| sample=(?P<sid>\S+) \| stage=(?P<stage>\S+)(?: \| attempt=(?P<attempt>\S+))?(?: \| elapsed=(?P<el>[\d.]+)s)?(?: \| response_chars=(?P<rc>\d+))?(?: \| completion_tokens=(?P<ct>\d+))?")
_RE_GEN_ERROR = re.compile(r"model\.generate_error \| sample=(?P<sid>\S+) \| stage=(?P<stage>\S+)(?: \| attempt=(?P<attempt>\S+))?(?: \| elapsed=(?P<el>[\d.]+)s)?(?: \| (?P<msg>.*))?")
_RE_KG_TOOLS = re.compile(r"agent\.kg_tools \| sample=(?P<sid>\S+) \| round=(?P<round>\S+) \| queries=(?P<q>\d+) \| returned_items=(?P<ri>\d+) \| evidence_items=(?P<ei>\d+)")
_RE_SAMPLE_FAILED = re.compile(r"Sample failed: (?P<sid>\S+)")


class ResearchInventory:
    def __init__(self, project_root: str | Path, configs_dir: str = "configs",
                 runs_root: str = "outputs/runs", jobs_root: str = "outputs/dashboard/jobs",
                 candidate_cache: str = "cache/repo_inventory/pair_candidates_smallest_first.jsonl") -> None:
        self.root = Path(project_root).resolve()
        self.configs_dir = self.root / configs_dir
        self.runs_root = self.root / runs_root
        self.jobs_root = self.root / jobs_root
        self.candidate_cache = self.root / candidate_cache

    # ---- configs ----------------------------------------------------
    def list_configs(self) -> list[dict[str, Any]]:
        out = []
        if self.configs_dir.exists():
            for p in sorted(self.configs_dir.glob("*.yaml")):
                out.append({"name": p.name, "path": str(p.relative_to(self.root))})
        return out

    def config_meta(self, name: str) -> dict[str, Any] | None:
        p = self.configs_dir / name
        if not p.exists():
            return None
        cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        model = cfg.get("model") or {}
        ds = cfg.get("dataset") or {}
        kg = cfg.get("kg") or {}
        return {
            "name": name,
            "path": str(p.relative_to(self.root)),
            "dataset_path": ds.get("path"),
            "sample_selection": ds.get("sample_selection"),
            "model_backend": model.get("backend"),
            "model_name": model.get("model_name") or model.get("repo_id"),
            "api_base": model.get("api_base"),
            "thinking": model.get("thinking") or model.get("enable_thinking"),
            "kg_backend": kg.get("backend"),
            "require_joern": kg.get("require_joern"),
            "output_root": (cfg.get("experiment") or {}).get("output_root"),
            "full": _mask_secrets(cfg),
        }

    # ---- runs -------------------------------------------------------
    def _all_run_dirs(self) -> list[Path]:
        dirs: list[Path] = []
        if self.runs_root.exists():
            dirs += [d for d in self.runs_root.iterdir() if d.is_dir()]
        if self.jobs_root.exists():
            for jr in self.jobs_root.glob("*/runs"):
                dirs += [d for d in jr.iterdir() if d.is_dir()]
        return dirs

    def _resolve_run(self, run_id: str) -> Path | None:
        for d in self._all_run_dirs():
            if d.name == run_id:
                return d
        return None

    def list_runs(self) -> list[dict[str, Any]]:
        out = []
        for d in self._all_run_dirs():
            metrics = _read_json(d / "metrics.json")
            n_samples = len(list((d / "agent_demos").glob("sample_*"))) if (d / "agent_demos").exists() else 0
            out.append({
                "run_id": d.name,
                "path": str(d),
                "mtime": d.stat().st_mtime,
                "is_job_run": "dashboard" in str(d),
                "samples": n_samples,
                "metrics": metrics,
            })
        out.sort(key=lambda r: r["mtime"], reverse=True)
        return out

    def run_detail(self, run_id: str) -> dict[str, Any] | None:
        d = self._resolve_run(run_id)
        if not d:
            return None
        return {
            "run_id": run_id,
            "path": str(d),
            "metrics": _read_json(d / "metrics.json"),
            "summary_md": (d / "summary.md").read_text(encoding="utf-8", errors="replace") if (d / "summary.md").exists() else None,
            "samples": self.list_samples(run_id),
        }

    # ---- samples ----------------------------------------------------
    def _sample_dirs(self, run_dir: Path) -> list[Path]:
        demos = run_dir / "agent_demos"
        if not demos.exists():
            return []
        return sorted([p for p in demos.glob("sample_*") if p.is_dir()])

    def _sample_dir(self, run_id: str, sample_id: str) -> Path | None:
        d = self._resolve_run(run_id)
        if not d:
            return None
        for sd in self._sample_dirs(d):
            # dir name is sample_<id>_<fn>; match the id segment
            parts = sd.name.split("_")
            if len(parts) >= 2 and parts[1] == str(sample_id):
                return sd
            fp = _read_json(sd / "final_prediction.json") or {}
            if str(fp.get("sample_id")) == str(sample_id):
                return sd
        return None

    def list_samples(self, run_id: str, mode: str = "admin") -> list[dict[str, Any]]:
        d = self._resolve_run(run_id)
        if not d:
            return []
        out = []
        for sd in self._sample_dirs(d):
            fp = _read_json(sd / "final_prediction.json") or {}
            sample_data = _read_json(sd / "sample.json") or {}
            avail = _prediction_is_available(fp)
            pred_is_vuln = _canonical_prediction_bool(fp) if avail else None
            true_is_vuln = sample_data.get("is_vulnerable")

            result: str | None = None
            error_type: str | None = None
            true_label: str | None = None
            if avail and mode == "admin":
                r, et, _ = _classify_sample(fp, sample_data)
                result = r
                error_type = et
                if true_is_vuln is not None:
                    true_label = "vulnerable" if true_is_vuln else "safe"

            parts = sd.name.split("_")
            out.append({
                "sample_id": fp.get("sample_id") or (parts[1] if len(parts) >= 2 else sd.name),
                "dir": sd.name,
                "function_name": "_".join(parts[2:]) or None,
                # Only surface a prediction when one really exists — a failed run's
                # placeholder (is_vulnerable=false) is NOT "safe".
                "prediction": (None if not avail else ("vulnerable" if pred_is_vuln else "safe")),
                "prediction_bool": bool(pred_is_vuln) if (avail and pred_is_vuln is not None) else None,
                "prediction_available": avail,
                "confidence": fp.get("confidence") if avail else None,
                "decision_status": fp.get("decision_status"),
                "resolved_commit": fp.get("resolved_commit_id"),
                "model_backend": fp.get("model_backend"),
                # Admin-only enriched fields
                "true_label": true_label,
                "result": result,
                "error_type": error_type,
            })
        return out

    def sample_detail(self, run_id: str, sample_id: str) -> dict[str, Any] | None:
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None
        return {
            "run_id": run_id,
            "sample_id": sample_id,
            "dir": str(sd),
            "final_prediction": _mask_secrets(_read_json(sd / "final_prediction.json")),
            "has_dashboard": (sd / "index.html").exists(),
        }

    def agent_trace(self, run_id: str, sample_id: str) -> dict[str, Any] | None:
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None
        return _mask_secrets(_read_json(sd / "agent_trace.json"))

    def model_calls(self, run_id: str, sample_id: str) -> list[dict[str, Any]]:
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return []
        trace = _read_json(sd / "agent_trace.json") or {}
        calls = trace.get("model_calls") or []
        if not calls:
            calls = _read_jsonl(sd / "model_calls.jsonl")
        return _mask_secrets(calls)

    def kg_queries(self, run_id: str, sample_id: str) -> list[dict[str, Any]]:
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return []
        trace = _read_json(sd / "agent_trace.json") or {}
        q = trace.get("kg_queries") or trace.get("kg_tool_steps") or []
        if not q:
            q = _read_jsonl(sd / "kg_tool_calls.jsonl")
        if not q:
            # Fallback: recover a summary-only entry from the run log's
            # "agent.kg_tools queries=N returned_items=N evidence_items=N" line.
            run_dir = self._resolve_run(run_id)
            if run_dir:
                _, ls = self._parse_log_stages(run_dir, sample_id)
                if ls.get("kg_queries"):
                    return [{
                        "_summary_only": True,
                        "query_type": "agent_kg_tools (summary)",
                        "queries": ls.get("kg_queries"),
                        "returned_items": ls.get("kg_returned_items"),
                        "evidence_items": ls.get("kg_evidence_items"),
                        "reason": "Detailed query payload unavailable; only log summary found.",
                    }]
            return []
        return _mask_secrets(q)

    def audit_report(self, run_id: str, sample_id: str) -> dict[str, Any] | None:
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None
        return {
            "final_prediction": _mask_secrets(_read_json(sd / "final_prediction.json")),
            "decision_summary_md": (sd / "decision_summary.md").read_text(encoding="utf-8", errors="replace") if (sd / "decision_summary.md").exists() else None,
            "evidence_pack": _mask_secrets(_read_json(sd / "evidence_pack.json")),
            "dashboard_available": (sd / "index.html").exists(),
        }

    def flow(self, run_id: str, sample_id: str) -> dict[str, Any] | None:
        """Return agentic flow data for the Agentic Flow dashboard tab.

        Merges all available artifacts to build a complete, content-rich view:
        - agent_flow.json (finished-run summary, if written)
        - model_calls.jsonl (full LLM stage content — written incrementally
          during a live run so this endpoint works before the run ends)
        - evidence_iterations.jsonl (loop iteration rows)
        Falls back gracefully for old non-iterative artifacts.
        """
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None

        flow_json = _read_json(sd / "agent_flow.json")
        iter_rows = _read_jsonl(sd / "evidence_iterations.jsonl")

        # Always read model_calls for full content (system/user prompt, messages,
        # response). These are written incrementally during a live run so the
        # flow endpoint returns real data even before the run finishes.
        trace = _read_json(sd / "agent_trace.json") or {}
        calls = trace.get("model_calls") or _read_jsonl(sd / "model_calls.jsonl")
        calls_by_stage: dict[str, dict[str, Any]] = {}
        for c in (calls or []):
            name = c.get("name") or c.get("stage") or ""
            if name and name not in calls_by_stage:
                calls_by_stage[name] = c

        def _enrich(summary: dict[str, Any]) -> dict[str, Any]:
            """Merge full content from model_calls into a stage summary dict."""
            name = summary.get("stage") or ""
            c = calls_by_stage.get(name) or {}
            # Infer parse_status from raw response when enrichment didn't run
            # (e.g., pipeline failed before the post-parse bulk enrichment pass).
            stored_parse_status = c.get("parse_status")
            inferred_parse_status = stored_parse_status or _infer_parse_status_for_call(c)
            return {
                **summary,
                "kind": "llm",
                "system_prompt": c.get("system_prompt") or c.get("system"),
                "user_prompt": c.get("user_prompt") or c.get("prompt"),
                "messages": c.get("messages"),
                "response": c.get("response") or c.get("raw"),
                "usage": c.get("usage") or summary.get("usage") or {},
                "error": c.get("error") or summary.get("error"),
                # Parse diagnostics — prefer stored; fall back to on-read inference.
                "parsed_answer": c.get("parsed_answer"),
                "answer_text": c.get("answer_text"),
                "parse_status": inferred_parse_status,
                "parse_error": c.get("parse_error"),
                "validation_error": c.get("validation_error"),
                "repair_status": c.get("repair_status"),
            }

        if flow_json is None:
            # No finished-run artifact: synthesize from model_calls.
            # This path is hit both for in-progress runs (model_calls.jsonl
            # written incrementally) and old pre-iterative runs.
            stages = [
                _enrich({
                    "stage": c.get("name") or c.get("stage"),
                    "status": "failed" if c.get("error") else "completed",
                    "elapsed_seconds": c.get("elapsed_seconds"),
                    "finish_reason": c.get("finish_reason"),
                    "was_truncated": c.get("was_truncated", False),
                    "requested_max_tokens": c.get("requested_max_tokens"),
                    "effective_max_tokens": c.get("effective_max_tokens"),
                    "prompt_chars": c.get("prompt_chars"),
                    "usage": c.get("usage") or {},
                    "error": c.get("error"),
                })
                for c in (calls or [])
                if (c.get("name") or c.get("stage")) not in ("final_decision",)
            ]
            return _mask_secrets({
                "sample_id": sample_id,
                "fallback": True,
                "iterative_loop_enabled": False,
                "loop_stop_reason": None,
                "iterations_completed": 0,
                "stages": stages,
                "iterations": iter_rows,
                "total_evidence_items": None,
                "initial_evidence_items": None,
            })

        # Merge iterations from JSONL if agent_flow.json didn't capture them.
        if not flow_json.get("iterations") and iter_rows:
            flow_json["iterations"] = iter_rows

        # Enrich agent_flow.json summary stages with full content from model_calls.
        flow_json["stages"] = [_enrich(s) for s in (flow_json.get("stages") or [])]

        return _mask_secrets(flow_json)

    def dashboard_file(self, run_id: str, sample_id: str, rel: str) -> Path | None:
        """Resolve a file inside a sample dir for the embedded static dashboard.

        Guards against path traversal so only files under the sample dir serve.
        """
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None
        rel = (rel or "index.html").lstrip("/")
        candidate = (sd / rel).resolve()
        try:
            candidate.relative_to(sd.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    # ---- old CodeKG static dashboard discovery ----------------------
    #
    # The high-quality CodeKG explorer (left controls / center graph / right
    # details, retrieval queries, search/highlight, source preview) is written
    # by the run at  cache/kg/<repo_key>/<commit>/<kg_version>/<hash>/dashboard/
    # index.html. We discover it from run artifacts + logs and serve it through
    # a tokenized static route restricted to a few safe roots.

    _GRAPH_DIR_KEY_HINTS = ("graph_dir", "dashboard", "codekg_artifacts", "codekg_graph_dir")

    def _safe_roots(self) -> list[Path]:
        return [
            (self.root / "cache" / "kg").resolve(),
            (self.root / "outputs" / "runs").resolve(),
            (self.root / "outputs" / "dashboard" / "jobs").resolve(),
        ]

    def _under_safe_root(self, p: Path) -> bool:
        rp = p.resolve()
        for root in self._safe_roots():
            try:
                rp.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def encode_dir_token(self, d: Path) -> str:
        return base64.urlsafe_b64encode(str(Path(d).resolve()).encode("utf-8")).decode("ascii").rstrip("=")

    def _decode_dir_token(self, token: str) -> Path | None:
        try:
            pad = "=" * (-len(token) % 4)
            raw = base64.urlsafe_b64decode(token + pad).decode("utf-8")
        except Exception:
            return None
        d = Path(raw)
        # A crafted token can only ever resolve inside an allowed root.
        if not self._under_safe_root(d):
            return None
        return d

    def _collect_graph_dirs(self, obj: Any, out: set[str]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and v and any(h in str(k).lower() for h in self._GRAPH_DIR_KEY_HINTS):
                    out.add(v)
                else:
                    self._collect_graph_dirs(v, out)
        elif isinstance(obj, list):
            for v in obj:
                self._collect_graph_dirs(v, out)

    def _dashboard_index_for(self, raw: str) -> Path | None:
        """Normalise a raw path (graph_dir, dashboard dir, or index.html) to the
        actual dashboard/index.html file if it exists."""
        p = Path(raw)
        if not p.is_absolute():
            p = self.root / p
        p = p.resolve()
        if p.name == "index.html" and p.is_file():
            return p
        if (p / "index.html").is_file():
            return p / "index.html"
        if (p / "dashboard" / "index.html").is_file():
            return p / "dashboard" / "index.html"
        return None

    def _dashboards_from_logs(self, run_dir: Path) -> list[str]:
        out: list[str] = []
        log_files = [run_dir / "run.log"]
        # Dashboard jobs run as a subprocess; the line may land in stdout.log.
        parent = run_dir.parent
        if parent.name == "runs":
            log_files.append(parent.parent / "stdout.log")
        for log in log_files:
            if not log.exists():
                continue
            text = log.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"Dashboard written:\s*(.+?\.html)", text):
                out.append(m.group(1).strip())
            for m in re.finditer(r"KG cache check[^\n]*?cache_dir[=:\s]+(\S+)", text):
                out.append(m.group(1).strip())
        return out

    def _glob_cache_dashboards(self, project: str | None, commit: str | None, limit: int = 12) -> list[Path]:
        base = self.root / "cache" / "kg"
        if not base.exists():
            return []
        out: list[Path] = []
        commit_pref = (commit or "")[:12]
        for idx in base.glob("**/dashboard/index.html"):
            s = str(idx).lower()
            ok = True
            if commit_pref and commit_pref.lower() not in s:
                ok = bool(project and project.lower() in s)
            if ok:
                out.append(idx)
            if len(out) >= limit:
                break
        return out

    def kg_dashboard(self, run_id: str, sample_id: str) -> dict[str, Any]:
        """Discover the old static CodeKG dashboard for a run/sample."""
        run_dir = self._resolve_run(run_id)
        sd = self._sample_dir(run_id, sample_id) if run_dir else None
        searched: list[str] = []
        raw_candidates: list[str] = []
        project: str | None = None
        commit: str | None = None

        if sd:
            for fname in ("final_prediction.json", "agent_trace.json", "failure_trace.json",
                          "report.json", "demo_report.json"):
                f = sd / fname
                searched.append(str(f))
                data = _read_json(f)
                if data:
                    found: set[str] = set()
                    self._collect_graph_dirs(data, found)
                    raw_candidates.extend(found)
            fp = _read_json(sd / "final_prediction.json") or {}
            tr = _read_json(sd / "agent_trace.json") or {}
            commit = fp.get("resolved_commit_id") or tr.get("resolved_commit_id")
            project = fp.get("project") or tr.get("project")

        if run_dir:
            for raw in self._dashboards_from_logs(run_dir):
                raw_candidates.append(raw)
                searched.append("log:" + raw)

        indexes: list[Path] = []
        seen: set[str] = set()
        for raw in raw_candidates:
            idx = self._dashboard_index_for(raw)
            if idx and self._under_safe_root(idx) and str(idx) not in seen:
                seen.add(str(idx))
                indexes.append(idx)

        if not indexes:
            for idx in self._glob_cache_dashboards(project, commit):
                searched.append("glob:" + str(idx))
                if self._under_safe_root(idx) and str(idx) not in seen:
                    seen.add(str(idx))
                    indexes.append(idx)

        def _entry(idx: Path) -> dict[str, Any]:
            token = self.encode_dir_token(idx.parent)
            return {
                "dashboard_index": str(idx),
                "graph_dir": str(idx.parent.parent),
                "token": token,
                "iframe_url": f"/api/research/kg-dashboard/{token}/index.html",
            }

        if not indexes:
            return {
                "exists": False,
                "graph_dir": None,
                "dashboard_index": None,
                "iframe_url": None,
                "open_url": None,
                "candidates": [],
                "searched": searched,
                "reason": "No CodeKG dashboard/index.html found from artifacts, run logs, or cache/kg glob.",
            }

        chosen = _entry(indexes[0])
        return {
            "exists": True,
            "graph_dir": chosen["graph_dir"],
            "dashboard_index": chosen["dashboard_index"],
            "iframe_url": chosen["iframe_url"],
            "open_url": chosen["iframe_url"],
            "candidates": [_entry(i) for i in indexes],
            "searched": searched,
        }

    def kg_dashboard_file(self, token: str, rel: str) -> Path | None:
        """Serve a file inside a tokenised dashboard dir (relative assets work).

        Security: the token decodes to a directory that MUST live under a safe
        root, and the requested rel path may not escape that directory.
        """
        d = self._decode_dir_token(token)
        if d is None or not d.is_dir():
            return None
        rel = (rel or "index.html").lstrip("/")
        candidate = (d / rel).resolve()
        try:
            candidate.relative_to(d.resolve())
        except ValueError:
            return None
        if not self._under_safe_root(candidate):
            return None
        return candidate if candidate.is_file() else None

    # ---- provider / job-artifact resolution -------------------------
    #
    # Runs started from the dashboard live at <job>/runs/<run_id> and the job
    # directory holds llm_profile_used.json / kg_builder_used.json /
    # selection.json / effective_config.yaml. We surface the REAL provider and
    # model (e.g. "AcademicCloud · qwen3-coder-30b-a3b-instruct") instead of the
    # generic model_backend ("openai_compatible").

    _PROVIDER_DISPLAY = {
        "academiccloud": "AcademicCloud",
        "tu_berlin_ollama": "TU Berlin / MLSEC Ollama",
        "openai": "OpenAI",
    }

    def _job_dir_for(self, run_dir: Path) -> Path | None:
        if run_dir.parent.name == "runs":
            jd = run_dir.parent.parent
            if (jd / "job.json").exists() or (jd / "llm_profile_used.json").exists():
                return jd
        return None

    def run_meta(self, run_id: str) -> dict[str, Any]:
        """Provider/model/KG/selection/status metadata for a run (no secrets)."""
        run_dir = self._resolve_run(run_id)
        if not run_dir:
            return {}
        job_dir = self._job_dir_for(run_dir)
        llm = _read_json(job_dir / "llm_profile_used.json") if job_dir else None
        kg = _read_json(job_dir / "kg_builder_used.json") if job_dir else None
        sel = _read_json(job_dir / "selection.json") if job_dir else None
        job = _read_json(job_dir / "job.json") if job_dir else None
        cfg = _read_json(run_dir / "resolved_config.yaml")  # may be None (yaml)
        if cfg is None and (run_dir / "resolved_config.yaml").exists():
            try:
                cfg = yaml.safe_load((run_dir / "resolved_config.yaml").read_text(encoding="utf-8"))
            except Exception:
                cfg = None
        model_cfg = (cfg or {}).get("model") or {}
        ds_cfg = (cfg or {}).get("dataset") or {}

        provider_id = (llm or {}).get("profile_id")
        provider_name = self._PROVIDER_DISPLAY.get(provider_id, provider_id) if provider_id else None
        model = (llm or {}).get("effective_model_name") or (llm or {}).get("model") or model_cfg.get("model_name")
        base_url = (llm or {}).get("api_base") or model_cfg.get("api_base")
        params = (job or {}).get("params") or {}
        sel_params = params.get("selection") or {}
        return {
            "run_id": run_id,
            "config_name": Path(((job or {}).get("params") or {}).get("config_path") or "").name or None,
            "status": (job or {}).get("status"),
            "created_at": (job or {}).get("created_at"),
            "started_at": (job or {}).get("started_at"),
            "finished_at": (job or {}).get("finished_at"),
            "llm": {
                "provider_id": provider_id,
                "provider_name": provider_name,
                "base_url": base_url,
                "model": model,
                "model_backend": model_cfg.get("backend"),
                "temperature": (llm or {}).get("temperature", model_cfg.get("temperature")),
                "max_tokens": (llm or {}).get("max_tokens", model_cfg.get("max_tokens")),
                "minimal_payload": (llm or {}).get("api_minimal_payload", model_cfg.get("api_minimal_payload")),
            },
            "kg": {
                "preset": (kg or {}).get("preset"),
                "display_name": (kg or {}).get("display_name"),
                "effective_backend": (kg or {}).get("effective_backend") or ((cfg or {}).get("kg") or {}).get("backend"),
                "reuse_cache": (kg or {}).get("reuse_cache"),
                "force_rebuild": (kg or {}).get("force_rebuild"),
            },
            "selection": {
                "exact_sample_ids_only": ds_cfg.get("exact_sample_ids_only") or sel_params.get("exact_sample_ids_only"),
                "include_pairs": sel_params.get("include_pairs"),
                "sample_ids": (sel or {}).get("sample_ids") or sel_params.get("sample_ids") or [],
            },
            "usage": _read_json(run_dir / "usage_summary.json"),
        }

    def _binary_metrics(self, run_dir: Path) -> dict[str, Any] | None:
        m = _read_json(run_dir / "metrics.json") or {}
        b = m.get("binary")
        return b if isinstance(b, dict) else None

    def run_summary(self, run_id: str, mode: Mode = "admin") -> dict[str, Any] | None:
        run_dir = self._resolve_run(run_id)
        if not run_dir:
            return None
        meta = self.run_meta(run_id)
        samples = self.list_samples(run_id)
        # "completed" = a real, valid prediction exists (not a placeholder).
        completed = sum(1 for s in samples if s.get("prediction_available"))
        failed_path = run_dir / "failed_samples.jsonl"
        failed = len(_read_jsonl(failed_path)) if failed_path.exists() else 0
        if not failed:
            failed = sum(1 for s in samples if not s.get("prediction_available"))
        requested = len(meta.get("selection", {}).get("sample_ids") or []) or len(samples)
        pending = max(0, requested - completed - failed)
        out = {
            **meta,
            "samples_requested": requested,
            "samples_completed": completed,
            "samples_failed": failed,
            "samples_pending": pending,
            "mtime": run_dir.stat().st_mtime,
        }
        if mode != "admin":
            out["metrics"] = None
            out["metrics_available"] = False
            out["metrics_reason"] = "labels not available in this mode"
            return out

        if completed == 0:
            out["metrics"] = None
            out["metrics_available"] = False
            out["metrics_reason"] = "run has no completed predictions yet"
            return out

        # Try metrics.json binary section first; fall back to live computation.
        b = self._binary_metrics(run_dir)
        n_valid = int(b.get("valid_predictions") if (b and b.get("valid_predictions") is not None) else (b.get("n") if b else 0) or 0)
        if b and n_valid > 0:
            out["metrics"] = {k: b.get(k) for k in ("n", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1")}
            out["metrics_available"] = True
            out["metrics_note"] = "single-sample metric" if n_valid <= 1 else (f"{failed} failed excluded" if failed else None)
        else:
            # metrics.json absent/stale or valid_predictions==0 — compute live.
            live = _compute_metrics_live(self._sample_dirs(run_dir))
            out["metrics"] = {k: live.get(k) for k in (
                "available", "total", "completed", "failed", "inconclusive",
                "correct", "incorrect", "tp", "fp", "tn", "fn",
                "accuracy", "precision", "recall", "f1", "specificity", "diagnostic",
            )}
            out["metrics_available"] = True
            diag = live.get("diagnostic")
            out["metrics_note"] = diag if diag else (
                "single-sample metric" if live.get("completed", 0) <= 1 else None
            )
        return out

    def run_live_metrics(self, run_id: str, mode: Mode = "admin") -> dict[str, Any]:
        """Confusion matrix + per-sample correctness. Admin-only (uses labels)."""
        run_dir = self._resolve_run(run_id)
        if not run_dir:
            return {"available": False, "reason": "unknown run"}
        if mode != "admin":
            return {"available": False, "reason": "labels not available in student/public mode"}

        sample_dirs = self._sample_dirs(run_dir)
        samples = self.list_samples(run_id)
        completed = sum(1 for s in samples if s.get("prediction_available"))
        failed = len(_read_jsonl(run_dir / "failed_samples.jsonl")) if (run_dir / "failed_samples.jsonl").exists() else 0
        if not failed:
            failed = sum(1 for s in samples if not s.get("prediction_available"))

        # Try metrics.json binary rows first; fall back to live computation.
        b = self._binary_metrics(run_dir)
        n_valid = int(b.get("valid_predictions") if (b and b.get("valid_predictions") is not None) else (b.get("n") if b else 0) or 0)
        use_live = (not b) or (n_valid == 0 and completed > 0)

        if use_live:
            live = _compute_metrics_live(sample_dirs)
            per = [
                {
                    "sample_id": r["sample_id"],
                    "project": None,
                    "function": r.get("function"),
                    "true_label": r.get("true_label"),
                    "prediction": r.get("prediction"),
                    "correct": r.get("result") == "correct",
                    "outcome": r.get("outcome"),
                    "confidence": r.get("confidence"),
                    "decision_status": r.get("status"),
                }
                for r in live.get("rows", [])
            ]
            n = live.get("tp", 0) + live.get("fp", 0) + live.get("tn", 0) + live.get("fn", 0)
            return {
                "available": True,
                "processed": n,
                "completed_predictions": completed,
                "failed_samples": failed,
                "pending_samples": max(0, len(samples) - completed - failed),
                "computed_on": "live from sample artifacts",
                "single_sample": completed <= 1,
                "tp": live.get("tp", 0), "tn": live.get("tn", 0),
                "fp": live.get("fp", 0), "fn": live.get("fn", 0),
                "inconclusive": live.get("inconclusive", 0),
                "accuracy": live.get("accuracy"), "precision": live.get("precision"),
                "recall": live.get("recall"), "f1": live.get("f1"),
                "specificity": live.get("specificity"),
                "vulnerable_recall": live.get("recall"),
                "safe_recall": live.get("specificity"),
                "diagnostic": live.get("diagnostic"),
                "per_sample": per,
            }

        if completed == 0:
            return {"available": False,
                    "reason": "run has no completed predictions yet",
                    "completed_predictions": 0, "failed_samples": failed,
                    "pending_samples": max(0, len(samples) - failed)}

        rows = b.get("rows") or []
        per = []
        # Enrich rows with project/function from per-sample correctness if present.
        m = _read_json(run_dir / "metrics.json") or {}
        corr = {str(r.get("sample_id")): r for r in (m.get("prediction_correctness") or {}).get("per_sample_correctness", [])}
        for r in rows:
            sid = str(r.get("sample_id"))
            c = corr.get(sid, {})
            per.append({
                "sample_id": sid,
                "project": c.get("project"),
                "function": c.get("function"),
                "true_label": "vulnerable" if r.get("true") else "safe",
                "prediction": "vulnerable" if r.get("pred") else "safe",
                "correct": bool(r.get("outcome") in ("TP", "TN")),
                "outcome": r.get("outcome"),
                "confidence": r.get("confidence"),
                "decision_status": r.get("decision_status"),
            })
        n = int(b.get("n") or len(rows))
        return {
            "available": True,
            "processed": n,
            "completed_predictions": completed,
            "failed_samples": failed,
            "pending_samples": max(0, len(samples) - completed - failed),
            "computed_on": "metrics.json binary section",
            "single_sample": n <= 1,
            "tp": b.get("tp", 0), "tn": b.get("tn", 0), "fp": b.get("fp", 0), "fn": b.get("fn", 0),
            "accuracy": b.get("accuracy"), "precision": b.get("precision"),
            "recall": b.get("recall"), "f1": b.get("f1"),
            "specificity": b.get("specificity"),
            "vulnerable_recall": b.get("recall"),
            "safe_recall": b.get("specificity"),
            "per_sample": per,
        }

    # ---- partial-run recovery from run logs -------------------------
    def _run_log_text(self, run_dir: Path) -> str:
        parts = []
        for name in ("run.log",):
            p = run_dir / name
            if p.exists():
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
        job_dir = self._job_dir_for(run_dir)
        if job_dir and (job_dir / "stdout.log").exists():
            parts.append((job_dir / "stdout.log").read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)

    def _parse_log_stages(self, run_dir: Path, sample_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Recover an ordered stage timeline from textual run logs.

        Returns (stages, summary) where summary has failed/failed_stage/error/
        kg_tools counts. Used when per-sample model_calls were not persisted
        because the run failed mid-way.
        """
        text = self._run_log_text(run_dir)
        sid = str(sample_id)
        stages: list[dict[str, Any]] = []
        index: dict[str, dict[str, Any]] = {}
        summary: dict[str, Any] = {"failed": False, "failed_stage": None, "error_message": None,
                                   "kg_queries": None, "kg_returned_items": None, "kg_evidence_items": None}
        order = 0
        for line in text.splitlines():
            m = _RE_GEN_START.search(line)
            if m and m.group("sid") == sid:
                stage = m.group("stage")
                order += 1
                st = {"index": order, "stage": stage, "status": "started", "source": "log",
                      "prompt_chars": int(m.group("pc")) if m.group("pc") else None,
                      "response_chars": None, "tokens": None, "elapsed_seconds": None,
                      "prompt": None, "response": None, "parsed_json": None, "error": None}
                stages.append(st)
                index[stage] = st
                continue
            m = _RE_GEN_DONE.search(line)
            if m and m.group("sid") == sid:
                st = index.get(m.group("stage"))
                if st:
                    st["status"] = "completed"
                    if m.group("rc"):
                        st["response_chars"] = int(m.group("rc"))
                    if m.group("ct"):
                        st["tokens"] = {"completion": int(m.group("ct"))}
                    if m.group("el"):
                        st["elapsed_seconds"] = float(m.group("el"))
                continue
            m = _RE_GEN_ERROR.search(line)
            if m and m.group("sid") == sid:
                stage = m.group("stage")
                st = index.get(stage)
                msg = (m.group("msg") or "").strip()
                if st:
                    st["status"] = "failed"
                    st["error"] = msg
                else:
                    order += 1
                    st = {"index": order, "stage": stage, "status": "failed", "source": "log",
                          "error": msg, "prompt": None, "response": None, "parsed_json": None}
                    stages.append(st)
                    index[stage] = st
                summary["failed"] = True
                summary["failed_stage"] = stage
                summary["error_message"] = msg or summary.get("error_message")
                continue
            m = _RE_KG_TOOLS.search(line)
            if m and m.group("sid") == sid:
                summary["kg_queries"] = int(m.group("q"))
                summary["kg_returned_items"] = int(m.group("ri"))
                summary["kg_evidence_items"] = int(m.group("ei"))
                continue
            m = _RE_SAMPLE_FAILED.search(line)
            if m and m.group("sid").split(":")[0] == sid:
                summary["failed"] = True
                if not summary["failed_stage"] and stages:
                    # last started/incomplete stage is the failure point
                    inc = [s for s in stages if s["status"] != "completed"]
                    summary["failed_stage"] = (inc[-1] if inc else stages[-1])["stage"]
        return stages, summary

    # ---- per-sample stage timeline + normalized object --------------
    _JSON_STAGE_HINTS = ("source_only_hypothesis", "kg_query_planning", "hypothesis_verification",
                         "counter_evidence_review", "final_adjudication", "final_decision",
                         "schema_consistency_repair")

    @staticmethod
    def _stage_json_meta(name: str) -> dict[str, Any]:
        low = str(name).lower()
        is_repair = "repair" in low
        json_expected = is_repair or any(h in low for h in ResearchInventory._JSON_STAGE_HINTS)
        return {
            "is_repair": is_repair,
            "is_planning": "planning" in low,
            "is_final": "final" in low or "adjudication" in low,
            "json_expected": json_expected,
        }

    def sample_stages(self, run_id: str, sample_id: str) -> list[dict[str, Any]]:
        sd = self._sample_dir(run_id, sample_id)
        run_dir = self._resolve_run(run_id)
        if not sd or not run_dir:
            return []
        trace = _read_json(sd / "agent_trace.json") or {}
        calls = trace.get("model_calls") or _read_jsonl(sd / "model_calls.jsonl")
        out: list[dict[str, Any]] = []
        if calls:
            for i, c in enumerate(calls, start=1):
                name = c.get("name") or c.get("stage") or f"stage_{i}"
                usage = c.get("usage") or c.get("total_stage_usage") or {}
                json_status = c.get("json_status")
                parsed = _read_json(sd / f"parsed_response_{i:02d}_{name}.json")
                meta = self._stage_json_meta(name)
                err = c.get("error")
                if err:
                    status = "failed"
                elif meta["is_repair"]:
                    status = "repaired"
                else:
                    status = "completed"
                tok = usage or {}
                # System/user prompts + full messages, with backward compat for
                # older artifacts that only stored a single "prompt" string.
                system_prompt = c.get("system_prompt") if c.get("system_prompt") is not None else c.get("system")
                user_prompt = c.get("user_prompt") if c.get("user_prompt") is not None else c.get("prompt")
                messages = c.get("messages")
                legacy_only = not messages and c.get("system_prompt") is None and c.get("user_prompt") is None
                if not messages:
                    messages = []
                    if system_prompt:
                        messages.append({"role": "system", "content": system_prompt})
                    if user_prompt:
                        messages.append({"role": "user", "content": user_prompt})
                # Determine json_valid from parse_status (Phase B enriched field) first,
                # then fall back to the legacy parsed_response file, then to None (unknown).
                # NEVER return False when the file is merely absent — that causes a false
                # 'JSON invalid' badge. False is only correct when parse genuinely failed.
                parse_status_field = c.get("parse_status")
                if parse_status_field == "valid":
                    json_valid_val: bool | None = True
                elif parse_status_field in ("invalid", "failed"):
                    json_valid_val = False
                elif parsed is not None:
                    json_valid_val = True      # legacy: parsed_response file exists
                elif meta["json_expected"]:
                    json_valid_val = None      # unknown — not yet enriched or file absent
                else:
                    json_valid_val = None
                out.append({
                    "index": i, "stage": name, "status": status, "source": "model_calls",
                    "prompt": user_prompt, "system": system_prompt,
                    "system_prompt": system_prompt, "user_prompt": user_prompt,
                    "messages": messages,
                    "legacy_prompt_only": legacy_only,
                    "request_payload_keys": c.get("request_payload_keys"),
                    "response": c.get("response") or c.get("raw"),
                    "parsed_json": _mask_secrets(parsed) if parsed is not None else None,
                    "prompt_chars": c.get("prompt_chars") or len(str(c.get("prompt") or "")),
                    "response_chars": len(str(c.get("response") or c.get("raw") or "")),
                    "tokens": {"prompt": tok.get("prompt_tokens"), "completion": tok.get("completion_tokens"),
                               "total": tok.get("total_tokens")} if tok else None,
                    "elapsed_seconds": c.get("elapsed_seconds"),
                    "json_status": json_status,
                    "json_expected": meta["json_expected"],
                    "json_valid": json_valid_val,
                    "parse_status": parse_status_field,
                    "parse_error": c.get("parse_error"),
                    "error": err,
                    "is_repair": meta["is_repair"], "is_planning": meta["is_planning"], "is_final": meta["is_final"],
                    # Token budget and truncation fields (new artifacts; None for old runs).
                    "finish_reason": c.get("finish_reason"),
                    "was_truncated": c.get("was_truncated", False),
                    "requested_max_tokens": c.get("requested_max_tokens"),
                    "effective_max_tokens": c.get("effective_max_tokens"),
                })
        else:
            # Failed/interrupted run: recover the partial timeline from run logs.
            log_stages, _ = self._parse_log_stages(run_dir, sample_id)
            for st in log_stages:
                meta = self._stage_json_meta(st["stage"])
                st.update({
                    "json_expected": meta["json_expected"],
                    "json_valid": None,
                    "is_repair": meta["is_repair"], "is_planning": meta["is_planning"], "is_final": meta["is_final"],
                })
                out.append(st)
        # Cross-stage "invalid → repaired": if a JSON stage is followed by its
        # repair stage that succeeded, annotate it.
        for i, st in enumerate(out):
            if st.get("json_valid") is False and i + 1 < len(out) and out[i + 1].get("is_repair"):
                if out[i + 1].get("json_valid") is not False:
                    st["repaired_next"] = True
        return _mask_secrets(out)

    def sample_normalized(self, run_id: str, sample_id: str, mode: Mode = "admin") -> dict[str, Any] | None:
        return self.trace_normalized(run_id, sample_id, mode)

    def trace_normalized(self, run_id: str, sample_id: str, mode: Mode = "admin") -> dict[str, Any] | None:
        sd = self._sample_dir(run_id, sample_id)
        run_dir = self._resolve_run(run_id)
        if not sd or not run_dir:
            return None
        meta = self.run_meta(run_id)
        fp = _read_json(sd / "final_prediction.json") or {}
        sample = _read_json(sd / "sample.json") or {}
        trace = _read_json(sd / "agent_trace.json") or {}
        stages = self.sample_stages(run_id, sample_id)
        _, log_summary = self._parse_log_stages(run_dir, sample_id)
        kg_queries = self.kg_queries(run_id, sample_id)

        pred_available = _prediction_is_available(fp)
        # Status: prefer log failure, then job status, then prediction availability.
        job_status = meta.get("status")
        failed = bool(log_summary.get("failed")) or job_status in ("failed", "cancelled")
        if failed and not pred_available:
            status = "failed"
        elif pred_available:
            status = "completed"
        elif job_status == "running":
            status = "running"
        else:
            status = "partial"

        failed_stage = log_summary.get("failed_stage")
        if not failed_stage and failed and stages:
            inc = [s for s in stages if s.get("status") not in ("completed", "repaired")]
            failed_stage = (inc[-1] if inc else stages[-1]).get("stage")
        last_completed = None
        for s in stages:
            if s.get("status") in ("completed", "repaired"):
                last_completed = s.get("stage")

        true_is_vuln = sample.get("is_vulnerable")
        pred_is_vuln = _canonical_prediction_bool(fp) if pred_available else None
        true_label = None if true_is_vuln is None or mode != "admin" else ("vulnerable" if true_is_vuln else "safe")
        prediction = None if pred_is_vuln is None else ("vulnerable" if pred_is_vuln else "safe")
        correct = None
        if mode == "admin" and pred_available and true_is_vuln is not None and pred_is_vuln is not None:
            correct = bool(true_is_vuln) == bool(pred_is_vuln)

        kg_info = self.kg_dashboard(run_id, sample_id)
        # KG node/edge counts + target-found from the kg manifest if present.
        graph_dir = kg_info.get("graph_dir")
        nodes = edges = None
        target_found = fp.get("target_validation_status") in ("match_exact", "match") or None
        if graph_dir:
            man = _read_json(Path(graph_dir) / "manifest.json") or _read_json(Path(graph_dir) / "dashboard" / "graph_data.json")
            if isinstance(man, dict):
                nodes = man.get("num_nodes") or man.get("number_of_nodes") or (man.get("manifest") or {}).get("num_nodes")
                edges = man.get("num_edges") or man.get("number_of_edges") or (man.get("manifest") or {}).get("num_edges")

        return {
            "run_id": run_id,
            "sample_id": str(sample_id),
            "project": sample.get("project"),
            "function": sample.get("func_name") or sample.get("function_name"),
            "filepath": sample.get("filepath"),
            "status": status,
            "failed": failed,
            "failed_stage": failed_stage,
            "last_completed_stage": last_completed,
            "error_type": fp.get("error_type"),
            "error_message": log_summary.get("error_message") or fp.get("parse_error"),
            "provider_error": log_summary.get("error_message"),
            "true_label": true_label,
            "prediction": prediction,
            "prediction_available": pred_available,
            "confidence": fp.get("confidence") if pred_available else None,
            "confidence_available": pred_available and fp.get("confidence") is not None,
            "correct": correct,
            "decision_status": fp.get("decision_status"),
            "verdict_text": fp.get("reasoning_summary") if pred_available else None,
            "primary_vulnerability_type": fp.get("primary_vulnerability_type"),
            "parse_error": fp.get("parse_error"),
            "resolved_commit": fp.get("resolved_commit_id"),
            "kg_loaded": bool(kg_info.get("exists")),
            "initial_retrieval": (trace.get("initial_evidence_count") or 0) > 0,
            "kg_queries_count": len(kg_queries) or (log_summary.get("kg_queries") or 0),
            "llm": meta.get("llm"),
            "kg": {
                **meta.get("kg", {}),
                "graph_dir": graph_dir,
                "dashboard_url": kg_info.get("iframe_url"),
                "dashboard_exists": kg_info.get("exists"),
                "nodes": nodes,
                "edges": edges,
                "target_found": target_found,
            },
            "usage": fp.get("usage"),
            "stages": stages,
            "kg_queries": kg_queries,
            # Dashboard-display-only fields — never injected into LLM prompts.
            "commit_message": sample.get("commit_message") if mode == "admin" else None,
            "target_function_source": sample.get("func_body") or None,
        }

    # ---- end-to-end inventory summary -------------------------------
    def inventory_summary(self, challenge_root: str | Path, dataset_path: str | None,
                          mode: Mode = "admin") -> dict[str, Any]:
        """Dataset / repo-clone / KG / challenge / research readiness counts.

        Best-effort and never raises: missing caches simply yield zeros.
        """
        out: dict[str, Any] = {}

        # --- dataset inventory (cheap pyarrow metadata; falls back to candidates)
        dataset = {"total_samples": None, "projects": None, "functions": None,
                   "vulnerable": None, "safe": None, "source": None}
        try:
            if dataset_path:
                p = Path(dataset_path)
                if not p.is_absolute():
                    p = self.root / p
                if p.exists():
                    dataset.update(self._dataset_counts(p))
        except Exception:
            pass
        if dataset["total_samples"] is None:
            cands = _read_jsonl(self.candidate_cache)
            projs = {r.get("project") for r in cands if r.get("project")}
            dataset.update({"total_samples": len(cands) * 2 if cands else 0,
                            "projects": len(projs), "source": "pair_candidate_cache"})
        out["dataset"] = dataset

        # --- repository availability
        mirrors_dir = self.root / "cache" / "repos" / "bare_mirrors"
        worktrees_dir = self.root / "cache" / "worktrees"
        inv_dir = self.root / "cache" / "repo_inventory"
        mirrors = [d for d in mirrors_dir.glob("*.git")] if mirrors_dir.exists() else []
        worktrees = [d for d in worktrees_dir.iterdir() if d.is_dir()] if worktrees_dir.exists() else []
        inv_files = [f for f in inv_dir.glob("*.json")] if inv_dir.exists() else []
        ds_projects = dataset.get("projects") or 0
        cloned = len({m.name.split("__")[0] for m in mirrors})
        out["repos"] = {
            "dataset_projects": ds_projects,
            "mirrored_projects": cloned,
            "missing_projects": max(0, ds_projects - cloned) if ds_projects else None,
            "clone_coverage_pct": round(cloned / ds_projects * 100, 1) if ds_projects else None,
            "worktrees": len(worktrees),
            "repo_inventory_records": len(inv_files),
        }

        # --- KG / CodeKG readiness
        kg_dir = self.root / "cache" / "kg"
        graph_dashboards = list(kg_dir.glob("**/dashboard/index.html")) if kg_dir.exists() else []
        graph_dirs = list(kg_dir.glob("**/graph.json")) if kg_dir.exists() else []
        out["functions"] = {
            "theoretical_analyzable": dataset.get("total_samples"),
            "kg_built": len(graph_dirs),
            "codekg_dashboards": len(graph_dashboards),
        }

        # --- student challenge inventory
        from .inventory import ChallengeInventory

        inv = ChallengeInventory(challenge_root)
        ch: dict[str, Any] = {"exists": inv.exists}
        if inv.exists:
            splits = inv.split_counts()
            vr = inv.validation_report() or {}
            ch.update({
                "rows": sum(splits.values()),
                "train_rows": splits.get("train", 0),
                "test_rows": splits.get("test", 0),
                "registry_entries": len(inv.kgs(mode="admin")),
                "validation_ok": vr.get("ok"),
            })
            if mode == "admin":
                ch["label_balance"] = inv.label_balance("admin")
        out["challenge"] = ch

        # --- research activity
        runs = self.list_runs()
        statuses = []
        for r in runs:
            jm = self.run_meta(r["run_id"]) if r.get("is_job_run") else {}
            statuses.append(jm.get("status"))
        last = runs[0] if runs else None
        last_meta = self.run_meta(last["run_id"]) if last else {}
        out["research"] = {
            "total_runs": len(runs),
            "running": sum(1 for s in statuses if s == "running"),
            "failed": sum(1 for s in statuses if s == "failed"),
            "last_run_id": last["run_id"] if last else None,
            "last_run_time": last["mtime"] if last else None,
            "last_provider": (last_meta.get("llm") or {}).get("provider_name"),
            "last_model": (last_meta.get("llm") or {}).get("model"),
            "last_kg_backend": (last_meta.get("kg") or {}).get("effective_backend"),
        }
        return out

    def _dataset_counts(self, path: Path) -> dict[str, Any]:
        """Cheap-ish dataset counts via pyarrow (num_rows metadata + columns)."""
        try:
            import pyarrow as pa  # noqa
            import pyarrow.ipc as ipc
        except Exception:
            return {}
        try:
            with pa.memory_map(str(path), "r") as src:
                try:
                    reader = ipc.open_file(src)
                except Exception:
                    src.seek(0)
                    reader = ipc.open_stream(src)
                tbl = reader.read_all()
        except Exception:
            return {}
        cols = set(tbl.column_names)
        n = tbl.num_rows
        out: dict[str, Any] = {"total_samples": n, "source": "dataset_arrow"}
        def uniq(col):
            return len(set(tbl.column(col).to_pylist())) if col in cols else None
        for c in ("project", "project_name", "repo"):
            if c in cols:
                out["projects"] = uniq(c); break
        for c in ("func_name", "function_name"):
            if c in cols:
                out["functions"] = uniq(c); break
        for c in ("is_vulnerable", "label", "target"):
            if c in cols:
                vals = tbl.column(c).to_pylist()
                vuln = sum(1 for v in vals if v in (1, True, "1", "vulnerable"))
                out["vulnerable"] = vuln
                out["safe"] = n - vuln
                break
        return out

    # ---- candidates -------------------------------------------------
    def candidates(self, limit: int = 500) -> list[dict[str, Any]]:
        """Selectable functions from the validated pair-candidate cache."""
        rows = _read_jsonl(self.candidate_cache)[:limit]
        out = []
        for r in rows:
            for sid_key, label in (("vulnerable_sample_id", "vulnerable"), ("fixed_sample_id", "fixed")):
                sid = r.get(sid_key)
                if sid is None:
                    continue
                out.append({
                    "sample_id": str(sid),
                    "project": r.get("project"),
                    "function_name": r.get("func_name"),
                    "filepath": r.get("filepath"),
                    "label": label,
                    "repo_key": r.get("repo_key"),
                    "usable_repo": r.get("usable_repo"),
                    "pair_function_chars": r.get("pair_function_chars"),
                    "tree_total_bytes": r.get("tree_total_bytes"),
                })
        return out

    # ---- full-flow text report ----------------------------------------------

    def flow_report(self, run_id: str, sample_id: str) -> str | None:
        """Generate a sanitized, human-readable full-flow text report for one sample.

        Returns a multi-section plain-text string suitable for download, or None when
        the sample directory does not exist.  All secrets are masked via _mask_secrets.
        """
        sd = self._sample_dir(run_id, sample_id)
        if not sd:
            return None

        lines: list[str] = []
        _HR = "=" * 72
        _hr = "-" * 72

        def _sec(title: str) -> None:
            lines.append(_HR)
            lines.append(f"  {title}")
            lines.append(_HR)
            lines.append("")

        def _subsec(title: str) -> None:
            lines.append(_hr)
            lines.append(f"  {title}")
            lines.append(_hr)
            lines.append("")

        def _kv(k: str, v: Any) -> None:
            lines.append(f"  {k}: {v}")

        def _block(label: str, text: str | None) -> None:
            if not text:
                lines.append(f"  [{label}: not available]")
            else:
                lines.append(f"  --- {label} ---")
                for ln in str(text).splitlines():
                    lines.append("  " + ln)
            lines.append("")

        # ── Run / sample metadata ────────────────────────────────────────────
        _sec("FULL AGENTIC FLOW REPORT")
        run_meta = self.run_meta(run_id)
        fp = _read_json(sd / "final_prediction.json") or {}
        flow_json = _read_json(sd / "agent_flow.json") or {}
        sample_json = _read_json(sd / "sample.json") or {}

        _kv("run_id", run_id)
        _kv("sample_id", sample_id)
        _kv("target_function", sample_json.get("func_name") or sample_json.get("function_name") or "—")
        _kv("target_file", sample_json.get("filepath") or "—")
        llm_meta = run_meta.get("llm") or {}
        _kv("provider", llm_meta.get("provider_name") or llm_meta.get("model_backend") or "—")
        _kv("model", llm_meta.get("model") or "—")
        _kv("resolved_commit", fp.get("resolved_commit_id") or "—")
        _kv("loop_enabled", flow_json.get("iterative_loop_enabled", "—"))
        _kv("iterations_completed", flow_json.get("iterations_completed", "—"))
        _kv("loop_stop_reason", flow_json.get("loop_stop_reason") or fp.get("loop_stop_reason") or "—")
        _fp_bool = fp.get("is_vulnerable")
        _ds_fr = str(fp.get("decision_status") or "")
        if "forced_binary" in _ds_fr and fp.get("forced_prediction_bool") is not None:
            _fp_bool = fp.get("forced_prediction_bool")
        elif _fp_bool is None:
            _fp_bool = fp.get("forced_prediction_bool")
        _kv("final_prediction", _fp_bool)
        _kv("confidence", fp.get("confidence") or "—")
        _kv("decision_status", fp.get("decision_status") or "—")
        commit_msg = sample_json.get("commit_message")
        _kv("commit_message", commit_msg if commit_msg else "unavailable")
        lines.append("")

        # ── Target function source ────────────────────────────────────────────
        func_body = sample_json.get("func_body")
        _sec("TARGET FUNCTION SOURCE")
        if func_body:
            _block(f"{sample_json.get('filepath') or '?'} :: {sample_json.get('func_name') or '?'}",
                   func_body)
        else:
            # Fall back to target_function.c if written by the pipeline
            tf_file = sd / "target_function.c"
            if tf_file.exists():
                _block(f"{sample_json.get('filepath') or '?'} :: {sample_json.get('func_name') or '?'}",
                       tf_file.read_text(encoding="utf-8", errors="replace"))
            else:
                lines.append("  [target function source not available]")
                lines.append("")

        # ── Stage timeline ───────────────────────────────────────────────────
        trace = _read_json(sd / "agent_trace.json") or {}
        calls = trace.get("model_calls") or _read_jsonl(sd / "model_calls.jsonl")
        calls = _mask_secrets(calls or [])

        _sec("STAGE TIMELINE")
        if not calls:
            lines.append("  [No model_calls artifacts found]")
            lines.append("")
        else:
            for i, c in enumerate(calls, start=1):
                name = c.get("name") or c.get("stage") or f"stage_{i}"
                status = "failed" if c.get("error") else "completed"
                parse_status = _infer_parse_status_for_call(c) or "—"
                repair_status = c.get("repair_status") or "—"
                elapsed = c.get("elapsed_seconds")
                usage = c.get("usage") or {}
                tok = usage.get("total_tokens") or usage.get("total") or "—"
                lines.append(
                    f"  {i:2d}. {name:<48} status={status:<10} "
                    f"parse={parse_status:<12} repair={repair_status:<18} "
                    f"tok={tok} elapsed={elapsed}s"
                )
            lines.append("")

        # ── Per-stage detail ─────────────────────────────────────────────────
        _sec("PER-STAGE DETAIL")
        for i, c in enumerate(calls, start=1):
            name = c.get("name") or c.get("stage") or f"stage_{i}"
            _subsec(f"Stage {i}: {name}")
            _kv("status", "failed" if c.get("error") else "completed")
            _kv("parse_status", _infer_parse_status_for_call(c) or "—")
            _kv("parse_error", c.get("parse_error") or "—")
            _kv("validation_error", c.get("validation_error") or "—")
            _kv("repair_status", c.get("repair_status") or "—")
            _kv("elapsed_seconds", c.get("elapsed_seconds") or "—")
            _kv("finish_reason", c.get("finish_reason") or "—")
            _kv("was_truncated", c.get("was_truncated", False))
            usage = c.get("usage") or {}
            _kv("prompt_tokens", usage.get("prompt_tokens") or "—")
            _kv("completion_tokens", usage.get("completion_tokens") or "—")
            _kv("total_tokens", usage.get("total_tokens") or "—")
            _kv("max_tokens_requested", c.get("requested_max_tokens") or "—")
            lines.append("")
            _block("System Prompt", c.get("system_prompt") or c.get("system"))
            _block("User Prompt", c.get("user_prompt") or c.get("prompt"))
            _block("Raw Response", c.get("response") or c.get("raw"))
            answer_text = c.get("answer_text")
            if answer_text:
                _block("Extracted <answer>", answer_text)
            parsed = c.get("parsed_answer")
            if parsed is not None:
                try:
                    _block("Parsed JSON", json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception:
                    _block("Parsed JSON", str(parsed))
            if c.get("error"):
                _block("Error", c.get("error"))

        # ── KG queries ───────────────────────────────────────────────────────
        kg_qs = self.kg_queries(run_id, sample_id)
        if kg_qs:
            _sec("KG QUERIES")
            for j, q in enumerate(kg_qs, start=1):
                if q.get("_summary_only"):
                    lines.append(f"  [Summary only — {q.get('queries')} queries, "
                                 f"{q.get('returned_items')} returned, "
                                 f"{q.get('evidence_items')} accumulated]")
                    lines.append("")
                    continue
                _subsec(f"KG Query {j}: {q.get('query_id') or q.get('query_type') or '?'}")
                _kv("type", q.get("query_type") or "—")
                _kv("query", q.get("query") or q.get("query_text") or "—")
                _kv("expected_evidence", q.get("expected_evidence") or q.get("wanted_evidence") or "—")
                _kv("returned_items", q.get("returned_items") or len(q.get("items") or []))
                _kv("new_evidence_count", q.get("new_items") or "—")
                items = q.get("items") or []
                if items:
                    lines.append("  Evidence items:")
                    for item in items[:4]:
                        snippet = str(item.get("text") or item.get("content") or "")[:200]
                        lines.append(f"    [{item.get('evidence_id') or item.get('id') or '?'}] {snippet}")
                lines.append("")

        # ── Loop iterations ──────────────────────────────────────────────────
        iter_rows = _read_jsonl(sd / "evidence_iterations.jsonl")
        if iter_rows:
            _sec("EVIDENCE LOOP ITERATIONS")
            for it in iter_rows:
                lines.append(
                    f"  phase={it.get('phase') or '?'}  iter={it.get('iteration')}  "
                    f"new_evidence={it.get('new_evidence_count')}  stop={it.get('stop_reason') or '—'}"
                )
            lines.append("")

        # ── Final decision ───────────────────────────────────────────────────
        if fp:
            _sec("FINAL DECISION")
            try:
                _block("final_prediction.json", json.dumps(_mask_secrets(fp), indent=2, ensure_ascii=False))
            except Exception:
                _block("final_prediction.json", str(fp))

        # ── Errors / limitations ─────────────────────────────────────────────
        errors: list[str] = []
        for c in calls:
            if c.get("error"):
                errors.append(f"  Stage {c.get('name')}: {c.get('error')}")
            if c.get("parse_error"):
                errors.append(f"  Stage {c.get('name')} parse_error: {c.get('parse_error')}")
        if errors:
            _sec("ERRORS / PARSE FAILURES")
            lines.extend(errors)
            lines.append("")

        lines.append(_HR)
        lines.append("  END OF REPORT")
        lines.append(_HR)
        return "\n".join(lines)
