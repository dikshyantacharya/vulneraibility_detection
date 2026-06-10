"""Durable subprocess job manager for the dashboard.

Every long-running action is executed by invoking the EXISTING CLI entry points
as a subprocess (python -m student_system_creator <cmd> ...). stdout is streamed
line-by-line, parsed via log_parser, persisted to events.jsonl and broadcast to
WebSocket listeners. None of the underlying build/validate/evaluate/package
logic is changed.

Durable layout (survives server restart + browser refresh):

    outputs/dashboard/jobs/<job_id>/
        job.json
        events.jsonl
        stdout.log
        result.json
        effective_config.yaml   (build jobs with overrides only)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .events import DashboardEvent, EventSink, utcnow_iso
from .kg_presets import ALLOWED_BACKEND_VALUES, get_preset, kg_overrides_for, resolve_preset_id
from .log_parser import parse_line
from .llm_profiles import EnvironmentLoader

JobBuilder = Callable[[dict[str, Any], Path, "JobContext"], list[str]]

VALID_STATUSES = ("queued", "running", "completed", "failed", "cancelled")

SUBPROCESS_JOB_TYPES = {
    "build_challenge",
    "build_kg",
    "validate_challenge",
    "evaluate_solution",
    "package_raid",
    "serve_kg_api",
    "research_agentic_audit",
}
# Which python module each subprocess job invokes (-m <module>). Research audit
# drives the original `vckg run` pipeline; everything else is the student CLI.
JOB_MODULES = {"research_agentic_audit": "vuln_commit_kg"}
DEFAULT_JOB_MODULE = "student_system_creator"
INTERNAL_JOB_TYPES = {"inspect_inventory"}
UNSUPPORTED_JOB_TYPES = {"repair_finalize", "anonymize_ids", "clean_unreferenced"}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# Dataset fields that drive validation-aware vulnerable/fixed pair selection in
# the pipeline (names taken verbatim from vuln_commit_kg.config.DatasetConfig and
# configs/46_*.yaml). Exact sample selection must neutralise all of them.
_PAIR_SELECTION_DISABLE: dict[str, Any] = {
    "sample_selection": "standard",
    "validation_aware_pair_selection": False,
    "validated_pair_limit": None,
    "candidate_pair_limit": None,
    "use_cached_pair_candidates": False,
    "build_pair_candidate_cache": False,
    "validation_candidate_stream_until_valid_pairs": False,
    "validation_candidate_clone_mirrors": False,
    "explicit_pair_indices": [],
}


def _disable_pair_selection(ds: dict[str, Any]) -> None:
    """Force exact, non-pair selection on a dataset config block in-place."""
    for key, value in _PAIR_SELECTION_DISABLE.items():
        ds[key] = value


def _validate_effective_config(path: Path) -> None:
    """Validate a generated effective_config.yaml through the SAME parser that
    ``vckg run`` uses (AppConfig). Raising here prevents launching a subprocess
    that would fail immediately on config validation, wasting a run.

    The error message surfaces the offending field and the allowed KG backend
    values so the dashboard can show an actionable message instead of a raw
    pydantic traceback.
    """
    try:
        from vuln_commit_kg.config import load_config

        load_config(path)
    except Exception as exc:  # pydantic ValidationError, FileNotFoundError, etc.
        text = str(exc)
        if "kg.backend" in text or "backend" in text.lower():
            raise ValueError(
                "Invalid effective_config.yaml: kg.backend is not supported. "
                f"Allowed values: {', '.join(ALLOWED_BACKEND_VALUES)}. ({text})"
            ) from exc
        raise ValueError(f"Invalid effective_config.yaml: {text}") from exc


class JobContext:
    """Settings shared with job builders (paths, defaults)."""

    def __init__(self, project_root: Path, default_config: str, default_challenge: str) -> None:
        self.project_root = project_root
        self.default_config = default_config
        self.default_challenge = default_challenge


def _build_challenge_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    config_path = params.get("config_path") or ctx.default_config
    overrides: dict[str, Any] = dict(params.get("overrides") or {})

    if params.get("force_rebuild"):
        overrides.setdefault("kg", {})["force_rebuild"] = True
    excl = params.get("project_exclude")
    if excl:
        overrides.setdefault("selection", {})["skip_projects"] = list(excl)
    mode = params.get("mode")
    if mode == "selected_projects" and params.get("project_ids"):
        overrides.setdefault("selection", {})["only_projects"] = list(params["project_ids"])
    if mode == "selected_functions" and params.get("sample_ids"):
        overrides.setdefault("selection", {})["only_sample_ids"] = list(params["sample_ids"])

    effective = config_path
    if overrides:
        base = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
        merged = _deep_merge(base, overrides)
        effective_path = job_dir / "effective_config.yaml"
        effective_path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
        effective = str(effective_path)

    argv = ["build", "--config", effective, "--progress-every", str(params.get("progress_every", 1))]
    if params.get("limit") is not None:
        argv += ["--limit", str(params["limit"])]
    if params.get("backend"):
        argv += ["--backend", str(params["backend"])]
    if params.get("overwrite"):
        argv += ["--overwrite"]
    if params.get("dry_run"):
        argv += ["--dry-run"]
    return argv


def _validate_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    challenge = params.get("challenge") or ctx.default_challenge
    report = str(job_dir / "validation_report.json")
    argv = ["validate-challenge", "--challenge", challenge, "--write-report", report,
            "--progress-every", str(params.get("progress_every", 10))]
    if params.get("api_base"):
        argv += ["--api-base", str(params["api_base"])]
    if params.get("limit") is not None:
        argv += ["--limit", str(params["limit"])]
    if params.get("require_api"):
        argv += ["--require-api"]
    return argv


def _evaluate_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    argv = ["evaluate",
            "--solution", str(params["solution"]),
            "--input", str(params["input"]),
            "--api-base", str(params.get("api_base", "http://127.0.0.1:8000")),
            "--out", str(params.get("out") or (job_dir / "eval_out"))]
    if params.get("labels"):
        argv += ["--labels", str(params["labels"])]
    if params.get("train"):
        argv += ["--train", str(params["train"])]
    if params.get("limit") is not None:
        argv += ["--limit", str(params["limit"])]
    return argv


def _package_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    challenge = params.get("challenge") or ctx.default_challenge
    out = params.get("out") or "dist/vckg_codekg_raid_bundle"
    argv = ["package-raid", "--challenge", challenge, "--out", str(out)]
    if params.get("overwrite"):
        argv += ["--overwrite"]
    if params.get("no_zip"):
        argv += ["--no-zip"]
    return argv


def _serve_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    challenge = params.get("challenge") or ctx.default_challenge
    registry = params.get("registry") or str(Path(challenge) / "private" / "kg_registry_private.json")
    return ["serve", "--registry", registry,
            "--host", str(params.get("host", "127.0.0.1")),
            "--port", str(params.get("port", 8000))]


def _research_argv(params: dict[str, Any], job_dir: Path, ctx: JobContext) -> list[str]:
    """Build `vckg run` argv for the original agentic audit pipeline.

    A job-scoped effective config is written so the run is fully isolated:
    - dataset selection is enforced
    - KG cache is reused/rebuilt per request
    - outputs land under the job directory
    - LLM profile/model selected from dashboard is applied (overrides original config)
    - no credentials are written to the config file (only api_key_env references)
    """
    config_path = params.get("config_path")
    if not config_path:
        raise ValueError("research_agentic_audit requires config_path (e.g. configs/46_...yaml)")
    base = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}

    sel = params.get("selection") or {}
    ds = base.setdefault("dataset", {})
    if sel.get("sample_ids"):
        ds["only_sample_ids"] = [str(x) for x in sel["sample_ids"]]
        # When sample IDs are explicitly selected from dashboard, enforce exact selection.
        ds["exact_sample_ids_only"] = True
    if sel.get("function_names"):
        ds["only_function_names"] = [str(x) for x in sel["function_names"]]
    if sel.get("project_names"):
        ds["project_include"] = list(sel["project_names"])
    if sel.get("limit") is not None:
        ds["sample_limit"] = int(sel["limit"])

    # Exact sample selection must override every validation-aware pair-selection
    # mechanism inherited from the base config (e.g. config 46). Otherwise the
    # pipeline oversamples vulnerable/fixed pairs and the run would also classify
    # the fixed counterpart (e.g. 18453) of the requested vulnerable sample (18452).
    # `include_pairs: true` opts back into pair expansion explicitly.
    exact_requested = bool(ds.get("exact_sample_ids_only")) and not sel.get("include_pairs")
    if exact_requested:
        _disable_pair_selection(ds)

    kg = params.get("kg") or {}
    kgc = base.setdefault("kg", {})
    # The UI sends a high-level KG *preset* (e.g. "joern_plus") which is NOT a
    # valid kg.backend value. Resolve it here to the real, validated config keys
    # (backend + any semantic-overlay fields) before writing the effective
    # config. `preset` takes precedence over a raw `backend` if both are sent.
    preset_raw = kg.get("preset") or kg.get("backend")
    preset = None
    if preset_raw:
        preset = get_preset(preset_raw)
        # kg_overrides_for raises ValueError for anything that is neither a known
        # preset nor an already-valid backend literal, so we never write junk.
        for k, v in kg_overrides_for(preset_raw).items():
            kgc[k] = v
    if kg.get("force_rebuild"):
        kgc["force_rebuild"] = True
    if kg.get("reuse_cache") is False:
        kgc["force_rebuild"] = True

    # Apply selected LLM provider/model if specified
    llm_spec = params.get("llm") or {}
    if llm_spec:
        profile_id = llm_spec.get("profile_id")
        selected_model = llm_spec.get("model")
        if profile_id and selected_model:
            _apply_llm_override(
                base,
                profile_id,
                selected_model,
                temperature=llm_spec.get("temperature"),
                max_tokens=llm_spec.get("max_tokens"),
            )
            mc = base.get("model", {})
            # Persist which profile/model was used, plus the effective config
            # values so it is unambiguous what really ran (no qwen397b leak).
            llm_used = {
                "profile_id": profile_id,
                "model": selected_model,
                "effective_model_name": mc.get("model_name"),
                "api_base": mc.get("api_base"),
                "api_minimal_payload": mc.get("api_minimal_payload", False),
                "temperature": mc.get("temperature"),
                "max_tokens": mc.get("max_tokens"),
            }
            (job_dir / "llm_profile_used.json").write_text(
                json.dumps(llm_used, indent=2), encoding="utf-8"
            )

    # Persist KG builder selection: record both the user-facing preset and the
    # actual config value written, so it is unambiguous what really ran.
    if kg:
        kg_used = {
            "preset": resolve_preset_id(preset_raw) or preset_raw,
            "display_name": preset["label"] if preset else None,
            "effective_backend": kgc.get("backend"),
            "semantic_enrichment_enabled": kgc.get("semantic_enrichment_enabled"),
            "reuse_cache": kg.get("reuse_cache", True),
            "force_rebuild": bool(kgc.get("force_rebuild", False)),
        }
        (job_dir / "kg_builder_used.json").write_text(
            json.dumps(kg_used, indent=2), encoding="utf-8"
        )

    # Never write raw credentials into the effective config. Only api_key_env
    # references are allowed; strip any inline secret-bearing keys inherited from
    # the base config (these are also not valid AppConfig fields).
    model_block = base.get("model")
    if isinstance(model_block, dict):
        for secret_key in ("api_key", "api_secret", "authorization", "token"):
            model_block.pop(secret_key, None)

    exp_block = base.setdefault("experiment", {})
    exp_block["output_root"] = str((job_dir / "runs").as_posix())
    # experiment.name is required by AppConfig; ensure one exists even if the
    # base config omitted it and no LLM override supplied a name.
    if not exp_block.get("name"):
        exp_block["name"] = f"dashboard_audit_{job_dir.name}"

    effective = job_dir / "effective_config.yaml"
    effective.write_text(yaml.safe_dump(base, sort_keys=False), encoding="utf-8")

    # Validate the generated config through the same parser `vckg run` uses.
    # If it is invalid we raise here, before the subprocess is ever launched.
    _validate_effective_config(effective)

    # Persist the selection for transparency / auditing.
    (job_dir / "selection.json").write_text(json.dumps(sel, indent=2), encoding="utf-8")

    argv = ["run", "--config", str(effective)]
    if params.get("dry_run"):
        # estimate-cost is the closest no-LLM dry path; keep run but mock backend.
        argv += ["--model-backend", "mock"]
    return argv


def _strip_vendor_thinking_extras(model_cfg: dict[str, Any]) -> None:
    """Remove provider-specific generation extras inherited from the base config.

    Gateways like AcademicCloud reject unknown chat-completions body fields
    (e.g. chat_template_kwargs) with HTTP 400. For such providers we force a
    minimal OpenAI-compatible payload and drop the extras unless the user has
    explicitly re-enabled them.
    """
    model_cfg["api_minimal_payload"] = True
    model_cfg["api_extra_body"] = {}
    model_cfg["api_disable_thinking"] = False
    model_cfg["api_force_no_think"] = False
    model_cfg["request_json_object"] = False


def _apply_llm_override(
    config: dict[str, Any],
    profile_id: str,
    model: str,
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> None:
    """Apply LLM provider/model override to config.

    Modifies config in-place to use the selected provider/model. Uses
    api_key_env for credentials (never writes secrets to config). The selected
    UI model fully overrides the base config model (no qwen397b leak): the
    fallback list is clamped to the selected model and the experiment name is
    rewritten so the run directory does not imply an unselected model.
    """
    model_cfg = config.setdefault("model", {})

    if profile_id == "academiccloud":
        model_cfg["backend"] = "openai_compatible"
        model_cfg["api_base"] = "https://chat-ai.academiccloud.de/v1"
        model_cfg["model_name"] = model
        model_cfg["api_key_env"] = "ACADEMIC_CLOUD_API_KEY"
        # AcademicCloud's gateway returns 400 on vendor extensions -> minimal.
        _strip_vendor_thinking_extras(model_cfg)

    elif profile_id == "tu_berlin_ollama":
        # Use OpenAI-compatible endpoint (smallest robust solution)
        model_cfg["backend"] = "openai_compatible"
        model_cfg["api_base"] = "http://gpu1.mlsec.de:11434/v1"
        model_cfg["model_name"] = model
        # Ollama /v1 endpoint may not require auth, but leave space for it
        model_cfg["api_key_env"] = "TU_BERLIN_API_KEY"

    elif profile_id == "openai":
        model_cfg["backend"] = "openai_compatible"
        model_cfg["api_base"] = "https://api.openai.com/v1"
        model_cfg["model_name"] = model
        model_cfg["api_key_env"] = "OPENAI_API_KEY"
    else:
        # Unknown profile: still honour the selected model, leave endpoint as-is.
        model_cfg["model_name"] = model

    if temperature is not None:
        model_cfg["temperature"] = float(temperature)
    if max_tokens is not None:
        model_cfg["max_tokens"] = int(max_tokens)

    # The selected model must win over any base-config model_fallbacks (config
    # 46 lists qwen3.5-397b-a17b first); clamp fallbacks to the selected model
    # so a transient error cannot silently switch to an unselected model.
    model_cfg["model_fallbacks"] = [model]

    # Avoid leaking an unselected model name through the run directory, which is
    # derived from experiment.name.
    exp = config.setdefault("experiment", {})
    safe_model = re.sub(r"[^A-Za-z0-9]+", "_", model).strip("_").lower()
    exp["name"] = f"dashboard_audit_{profile_id}_{safe_model}"


JOB_BUILDERS: dict[str, JobBuilder] = {
    "build_challenge": _build_challenge_argv,
    "build_kg": _build_challenge_argv,
    "validate_challenge": _validate_argv,
    "evaluate_solution": _evaluate_argv,
    "package_raid": _package_argv,
    "serve_kg_api": _serve_argv,
    "research_agentic_audit": _research_argv,
}


class Job:
    def __init__(self, job_id: str, job_dir: Path, spec: dict[str, Any]) -> None:
        self.job_id = job_id
        self.dir = job_dir
        self.spec = spec
        self.status = "queued"
        self.created_at = utcnow_iso()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.return_code: int | None = None
        self.error: str | None = None
        self.sink = EventSink(job_dir / "events.jsonl")
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._cancelled = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "type": self.spec.get("type"),
            "params": self.spec.get("params", {}),
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "return_code": self.return_code,
            "error": self.error,
            "dir": str(self.dir),
        }

    def persist(self) -> None:
        (self.dir / "job.json").write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class JobManager:
    def __init__(self, ctx: JobContext, jobs_root: str | Path,
                 external_env_path: str | Path = "C:/Users/DikshyantAcharya/Personal/env") -> None:
        self.ctx = ctx
        self.root = Path(jobs_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._global_listeners: list[Callable[[DashboardEvent], None]] = []
        # Initialize environment loader for credential inheritance
        self.env_loader = EnvironmentLoader(external_env_path, ctx.project_root)
        self._load_existing()

    def _load_existing(self) -> None:
        for jdir in sorted(self.root.glob("*")):
            jf = jdir / "job.json"
            if not jf.exists():
                continue
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            job = Job(data["job_id"], jdir, {"type": data.get("type"), "params": data.get("params", {})})
            job.status = data.get("status", "completed")
            if job.status in ("running", "queued"):
                job.status = "failed"
                job.error = "interrupted (server restart)"
            job.created_at = data.get("created_at", job.created_at)
            job.started_at = data.get("started_at")
            job.finished_at = data.get("finished_at")
            job.return_code = data.get("return_code")
            self._jobs[job.job_id] = job

    def add_global_listener(self, fn: Callable[[DashboardEvent], None]) -> None:
        self._global_listeners.append(fn)

    def remove_global_listener(self, fn: Callable[[DashboardEvent], None]) -> None:
        if fn in self._global_listeners:
            self._global_listeners.remove(fn)

    def _broadcast(self, event: DashboardEvent) -> None:
        for fn in list(self._global_listeners):
            try:
                fn(event)
            except Exception:
                pass

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = [j.to_dict() for j in self._jobs.values()]
        jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
        return jobs

    def get_job(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def get_events(self, job_id: str) -> list[dict[str, Any]]:
        job = self._jobs.get(job_id)
        if not job:
            jdir = self.root / job_id
            if (jdir / "events.jsonl").exists():
                return EventSink(jdir / "events.jsonl").read_all()
            return []
        return job.sink.read_all()

    def create_job(self, spec: dict[str, Any]) -> dict[str, Any]:
        jtype = spec.get("type")
        if jtype in UNSUPPORTED_JOB_TYPES:
            raise ValueError(
                "job type '" + str(jtype) + "' is not a standalone command; it runs inside build_challenge"
            )
        if jtype not in SUBPROCESS_JOB_TYPES and jtype not in INTERNAL_JOB_TYPES:
            raise ValueError("unknown job type: " + str(jtype))

        job_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
        job_dir = self.root / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        job = Job(job_id, job_dir, spec)
        job.sink.add_listener(self._broadcast)
        with self._lock:
            self._jobs[job_id] = job
        job.persist()

        thread = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        job._thread = thread
        thread.start()
        return job.to_dict()

    def _emit(self, job: Job, **kw: Any) -> None:
        job.sink.emit(DashboardEvent(job_id=job.job_id, **kw))

    def _run_job(self, job: Job) -> None:
        jtype = job.spec["type"]
        try:
            if jtype in INTERNAL_JOB_TYPES:
                self._run_internal(job)
                return
            self._run_subprocess(job)
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = utcnow_iso()
            job.persist()
            self._emit(job, type="status", level="error", message="job error: " + str(exc))

    def _run_internal(self, job: Job) -> None:
        from .inventory import ChallengeInventory

        job.status = "running"
        job.started_at = utcnow_iso()
        job.persist()
        self._emit(job, type="status", message="inspect_inventory started")
        challenge = job.spec["params"].get("challenge") or self.ctx.default_challenge
        inv = ChallengeInventory(challenge)
        result = {
            "exists": inv.exists,
            "projects": len(inv.projects()) if inv.exists else 0,
            "functions": len(inv.functions()) if inv.exists else 0,
            "split_counts": inv.split_counts() if inv.exists else {},
            "label_balance": inv.label_balance() if inv.exists else {},
        }
        (job.dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        job.status = "completed"
        job.return_code = 0
        job.finished_at = utcnow_iso()
        job.persist()
        self._emit(job, type="status", level="success", message="inspect_inventory done", data=result)

    def _run_subprocess(self, job: Job) -> None:
        jtype = job.spec["type"]
        params = job.spec.get("params", {})
        builder = JOB_BUILDERS[jtype]
        argv = builder(params, job.dir, self.ctx)
        module = JOB_MODULES.get(jtype, DEFAULT_JOB_MODULE)
        cmd = [sys.executable, "-m", module, *argv]

        job.status = "running"
        job.started_at = utcnow_iso()
        job.persist()
        self._emit(job, type="status", phase=jtype, message="started: " + " ".join(argv),
                   data={"cmd": argv})

        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        # Build subprocess environment with credentials from external env file
        subprocess_env = self.env_loader.build_subprocess_env()

        proc = subprocess.Popen(
            cmd,
            cwd=str(self.ctx.project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
            env=subprocess_env,
        )
        job._proc = proc
        log_path = job.dir / "stdout.log"
        with log_path.open("w", encoding="utf-8") as logf:
            assert proc.stdout is not None
            for raw in proc.stdout:
                logf.write(raw)
                logf.flush()
                parsed = parse_line(raw)
                if parsed is None:
                    if raw.strip():
                        self._emit(job, type="log", message=raw.rstrip())
                    continue
                self._emit(job, type=parsed["type"], phase=parsed["phase"],
                           message=parsed["message"], data=parsed["data"])
        proc.wait()
        job.return_code = proc.returncode
        if job._cancelled:
            job.status = "cancelled"
        elif proc.returncode == 0:
            job.status = "completed"
        else:
            job.status = "failed"
            job.error = "exit code " + str(proc.returncode)
        job.finished_at = utcnow_iso()
        result = {"return_code": proc.returncode, "status": job.status, "log": str(log_path)}
        (job.dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        job.persist()
        level = "success" if job.status == "completed" else "error"
        self._emit(job, type="status", phase=jtype, level=level,
                   message="finished: " + job.status, data=result)

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        if job.status != "running" or job._proc is None:
            return {"ok": False, "message": "job not running (status=" + job.status + ")"}
        job._cancelled = True
        proc = job._proc
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            else:
                proc.terminate()
        except Exception as exc:
            return {"ok": False, "message": "cancel failed: " + str(exc)}
        self._emit(job, type="status", level="warning", message="cancel requested")
        return {"ok": True, "message": "cancel requested"}

    def pause_job(self, job_id: str) -> dict[str, Any]:
        return {"ok": False, "message": "pause is not supported for subprocess jobs; use cancel + resume"}

    def resume_job(self, job_id: str) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return self.create_job(job.spec)
