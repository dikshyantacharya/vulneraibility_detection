from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any


class LiveDashboard:
    """Small file-backed live dashboard.

    The runner writes state.json after each meaningful event. The HTML page polls
    state.json every second, so it works without websocket dependencies and keeps
    the project install lightweight on Windows.
    """

    def __init__(self, run_dir: Path, cfg: Any):
        self.run_dir = Path(run_dir)
        self.cfg = cfg
        self.dir = self.run_dir / getattr(cfg, "dirname", "live_dashboard")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.events_path = self.dir / "events.jsonl"
        self.lock = threading.RLock()
        self.actual_host = str(getattr(cfg, "host", "127.0.0.1"))
        self.actual_port = int(getattr(cfg, "port", 8765))
        self.server_root: Path | None = None
        self.server_error: str | None = None
        self.state: dict[str, Any] = {
            "status": "initializing",
            "run_dir": str(self.run_dir),
            "run_name": self.run_dir.name,
            "started_at": time.time(),
            "projects": {},
            "samples": {},
            "api": {
                "enabled": False,
                "current_requests": {},
                "completed_requests": 0,
                "failed_requests": 0,
                "retry_requests": 0,
                "total_wait_seconds_observed": 0.0,
            },
            "metrics_live": {},
            "config": {},
            "recent_events": [],
            "server": {},
        }
        self.server = None
        self.thread = None
        self._write_index()
        self.write_state()
        if getattr(cfg, "serve", False):
            self._start_server()
            self.write_state()

    def url(self) -> str:
        # Short stable URL for the currently running dashboard.  The HTTP
        # handler maps /current/ to <run_dir.name>/<live_dashboard>/index.html.
        return f"http://{self.actual_host}:{self.actual_port}/current/"

    def legacy_url(self) -> str:
        return f"http://{self.actual_host}:{self.actual_port}/{self.run_dir.name}/{self.dir.name}/index.html"

    def url_for_path(self, path: str | Path | None) -> str | None:
        if not path:
            return None
        try:
            p = Path(path).resolve()
            root = (self.server_root or Path.cwd()).resolve()
            rel = p.relative_to(root).as_posix()
            return f"http://{self.actual_host}:{self.actual_port}/{urllib.parse.quote(rel, safe='/._-')}"
        except Exception:
            try:
                return Path(path).resolve().as_uri()
            except Exception:
                return str(path)

    def _start_server(self) -> None:
        host = self.actual_host
        preferred_port = int(getattr(self.cfg, "port", 8765))
        cwd = Path.cwd().resolve()
        run_dir_resolved = self.run_dir.resolve()
        # Serve from the project root when possible so one short HTTP server can
        # expose both outputs/runs/... and cache/codekg/... dashboard artifacts.
        try:
            run_dir_resolved.relative_to(cwd)
            root = cwd
        except Exception:
            root = self.run_dir.parent.resolve()
        self.server_root = root
        live_rel = self.dir.resolve().relative_to(root).as_posix()

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(root), **kwargs)

            def translate_path(self, path):  # noqa: ANN001
                parsed = urllib.parse.urlparse(path)
                clean = parsed.path or "/"
                if clean in {"/", "/current", "/current/"}:
                    clean = f"/{live_rel}/index.html"
                elif clean.startswith("/current/"):
                    suffix = clean[len("/current/"):].lstrip("/") or "index.html"
                    clean = f"/{live_rel}/{suffix}"
                rewritten = urllib.parse.urlunparse(("", "", clean, "", parsed.query, parsed.fragment))
                return super().translate_path(rewritten)

            def log_message(self, format, *args):  # noqa: A002
                pass

            def end_headers(self):
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Access-Control-Allow-Origin", "*")
                super().end_headers()

        last_error = None
        for port in range(preferred_port, preferred_port + 25):
            try:
                self.server = ThreadingHTTPServer((host, port), Handler)
                self.actual_port = port
                self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                self.thread.start()
                self.state["server"] = {"running": True, "host": host, "port": port, "root": str(root), "url": self.url(), "legacy_url": self.legacy_url()}
                return
            except OSError as exc:
                last_error = exc
                continue
        self.server = None
        self.server_error = str(last_error) if last_error else "unknown server start error"
        self.state["server"] = {"running": False, "host": host, "port": preferred_port, "error": self.server_error, "file_url_hint": str(self.dir / "index.html")}

    def close(self) -> None:
        self.event("run.finished", {"status": self.state.get("status")})
        if self.server is not None:
            try:
                self.server.shutdown()
            except Exception:
                pass

    def block_until_interrupted(self) -> None:
        """Keep the dashboard HTTP server alive after the run completes.

        The in-process HTTP server uses a daemon thread; without this block the
        Python process exits and the live URL disappears immediately. This method
        is intended for short exploratory runs where the user wants to inspect
        the dashboard after completion.
        """
        self.event("dashboard.keep_alive", {"url": self.url(), "message": "Dashboard is kept alive; press Ctrl+C in this terminal to stop it."})
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            self.event("dashboard.interrupted", {"url": self.url()})
            self.close()
            raise

    def event(self, kind: str, data: dict[str, Any] | None = None) -> None:
        record = {"time": time.time(), "kind": kind, **(data or {})}
        with self.lock:
            self._apply_event_locked(kind, data or {})
            recent = self.state.setdefault("recent_events", [])
            recent.append(record)
            keep = int(getattr(self.cfg, "keep_recent_events", 500) or 500)
            del recent[:-keep]
            with self.events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.write_state_locked()

    def _apply_event_locked(self, kind: str, data: dict[str, Any]) -> None:
        api = self.state.setdefault("api", {})
        samples = self.state.setdefault("samples", {})
        sample_id = str(data.get("sample_id") or "")

        if kind.startswith("api."):
            api["enabled"] = True
            provider_rate_limit = data.get("provider_rate_limit") or data.get("provider_quota")
            provider_headers_applied = False
            if isinstance(provider_rate_limit, dict):
                # Use the first observed provider quota headers as the baseline
                # for the live run, then project locally for each real request.
                # This avoids a misleading dashboard where provider windows
                # (minute/hour/day/month) jump independently of the requests that
                # this run has actually sent.  The latest exact header snapshot is
                # still retained for debugging/final inspection.
                api["provider_rate_limit_latest_exact"] = provider_rate_limit
                headers_present = bool(provider_rate_limit.get("headers_present"))
                if headers_present and not isinstance(api.get("provider_rate_limit_first"), dict):
                    first = json.loads(json.dumps(provider_rate_limit))
                    first["baseline_note"] = "First provider quota headers observed for this run; subsequent live counts are locally projected per real request."
                    api["provider_rate_limit_first"] = first
                    api["provider_rate_limit"] = first
                    provider_headers_applied = True
                    if isinstance(first.get("usage"), dict):
                        api["provider_usage"] = first.get("usage")
                        api["usage"] = first.get("usage")
                elif headers_present:
                    provider_headers_applied = False
            usage = data.get("usage")
            if isinstance(usage, dict) and any(k in usage for k in ("minute", "hour", "day", "month")):
                api["local_usage"] = usage
                api.setdefault("usage", usage)
            rate_limit = data.get("rate_limit")
            if isinstance(rate_limit, dict):
                api["local_rate_limit"] = rate_limit
                if isinstance(rate_limit.get("usage"), dict):
                    api["local_usage"] = rate_limit.get("usage")
                    api.setdefault("usage", rate_limit.get("usage"))
            if kind == "api.provider_quota_probe":
                first = json.loads(json.dumps(data))
                first["baseline_note"] = "Startup provider quota probe baseline; real requests are projected locally because additional probes can consume quota."
                api["provider_rate_limit_first"] = first
                api["provider_rate_limit"] = first
                if isinstance(first.get("usage"), dict):
                    api["provider_usage"] = first.get("usage")
                    api["usage"] = first.get("usage")
            if kind in {"api.request.done", "api.request.error"} and not provider_headers_applied:
                # Quota probes burn requests on SAIA/GWDG, so the dashboard must
                # not poll for fresh quota. If the model adapter does not expose
                # response headers, project the startup provider snapshot forward
                # locally for every real provider request that completed or errored.
                self._project_provider_quota_after_real_request_locked(api, kind, data)
            if data.get("waited_seconds"):
                api["total_wait_seconds_observed"] = float(api.get("total_wait_seconds_observed") or 0.0) + float(data.get("waited_seconds") or 0.0)
            key = f"{sample_id or 'unknown'}:{data.get('stage') or ''}:{data.get('attempt') or data.get('attempt_number') or ''}"
            if kind in {"api.request.queued", "api.concurrency_waiting", "api.rate_limit_waiting"}:
                if sample_id:
                    samples.setdefault(sample_id, {}).update({
                        "status": "waiting_api" if kind == "api.rate_limit_waiting" else "running",
                        "agent_stage": data.get("stage") or samples.setdefault(sample_id, {}).get("agent_stage"),
                        "api_state": "waiting" if kind == "api.rate_limit_waiting" else "queued",
                        "required_wait_seconds": data.get("required_wait_seconds"),
                    })
                api.setdefault("current_requests", {})[key] = {"state": kind, **data, "updated_at": time.time()}
            elif kind in {"api.request.in_flight", "api.rate_limit_acquired", "api.concurrency_acquired"}:
                if sample_id:
                    samples.setdefault(sample_id, {}).update({
                        "status": "api_in_flight" if kind == "api.request.in_flight" else "running",
                        "agent_stage": data.get("stage") or samples.setdefault(sample_id, {}).get("agent_stage"),
                        "api_state": "in_flight" if kind == "api.request.in_flight" else "acquired",
                    })
                api.setdefault("current_requests", {})[key] = {"state": kind, **data, "updated_at": time.time()}
            elif kind == "api.request.done":
                api["completed_requests"] = int(api.get("completed_requests") or 0) + 1
                api.setdefault("current_requests", {}).pop(key, None)
                if sample_id:
                    samples.setdefault(sample_id, {}).update({
                        "status": "running",
                        "agent_stage": data.get("stage"),
                        "api_state": "done",
                        "last_response_chars": data.get("response_chars"),
                    })
            elif kind == "api.request.retry":
                api["retry_requests"] = int(api.get("retry_requests") or 0) + 1
                if sample_id:
                    samples.setdefault(sample_id, {}).update({"status": "waiting_api", "api_state": "retry_wait", "last_api_retry": data})
            elif kind == "api.request.error":
                api["failed_requests"] = int(api.get("failed_requests") or 0) + 1
                if sample_id:
                    samples.setdefault(sample_id, {}).update({"status": "waiting_api" if data.get("will_retry") else "failed", "api_state": "error", "last_api_error": data.get("error")})
            elif kind == "api.http_post.start":
                if sample_id:
                    samples.setdefault(sample_id, {}).update({"status": "api_in_flight", "api_state": "http_post", "agent_stage": data.get("stage") or samples.setdefault(sample_id, {}).get("agent_stage"), "http_timeout_seconds": data.get("timeout_seconds")})
            elif kind == "api.http_post.done":
                if sample_id:
                    samples.setdefault(sample_id, {}).update({"status": "running", "api_state": "http_done", "last_response_chars": data.get("response_chars"), "last_http_status": data.get("http_status")})
            elif kind == "api.http_post.error":
                if sample_id:
                    samples.setdefault(sample_id, {}).update({"status": "waiting_api" if data.get("will_retry") else "failed", "api_state": "http_error", "last_api_error": data.get("error"), "last_http_status": data.get("http_status")})

        if kind.startswith("model_call.") and sample_id:
            row = samples.setdefault(sample_id, {})
            row["current_model_stage"] = data.get("stage") or row.get("current_model_stage")
            row["agent_stage"] = data.get("stage") or row.get("agent_stage") or "agent_loop"
            row["last_model_event_time"] = time.time()
            if kind == "model_call.prompt_ready":
                row["status"] = "running"
                row["api_state"] = "prompt_ready"
                row["last_prompt_chars"] = data.get("prompt_chars")
                row["last_prompt_ready"] = data
            elif kind == "model_call.start":
                row["status"] = "running"
                row["api_state"] = "calling_model"
                row["last_prompt_chars"] = data.get("prompt_chars")
            elif kind == "model_call.heartbeat":
                row["status"] = "running"
                row["api_state"] = "waiting_model_response"
                row["model_call_elapsed_seconds"] = data.get("elapsed_seconds")
            elif kind == "model_call.error":
                row["status"] = "waiting_api"
                row["api_state"] = "model_error"
                row["last_api_error"] = data.get("error")
                row["model_call_elapsed_seconds"] = data.get("elapsed_seconds")
            elif kind == "model_call.done":
                row["status"] = "running"
                row["api_state"] = "model_call_done"
                row["json_status"] = data.get("json_status")
                row["parse_error"] = data.get("parse_error")
                row["last_response_chars"] = data.get("response_chars")
                usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
                # Keep a live, cumulative per-sample token/cost view so the top
                # dashboard cards and sample table update while a sample is still
                # running, not only after final sample completion.
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    try:
                        row[key] = int(row.get(key) or 0) + int(usage.get(key) or 0)
                    except Exception:
                        pass
                try:
                    row["cost_total_usd"] = float(row.get("cost_total_usd") or 0.0) + float(usage.get("cost_total_usd") or 0.0)
                except Exception:
                    pass
                calls = row.setdefault("model_call_progress", [])
                calls.append({
                    "stage": data.get("stage"),
                    "json_status": data.get("json_status"),
                    "prompt_chars": data.get("prompt_chars"),
                    "response_chars": data.get("response_chars"),
                    "usage": usage,
                    "elapsed_seconds": data.get("elapsed_seconds"),
                })
                del calls[:-20]
            elif kind == "model_call.repair_start":
                row["status"] = "running"
                row["api_state"] = "json_repair"
                row["last_repair_parse_error"] = data.get("parse_error")
            elif kind == "model_call.repair_done":
                row["status"] = "running"
                row["api_state"] = "json_repair_done"
                row["last_repair_parse_error"] = data.get("parse_error")

    @staticmethod
    def _project_provider_quota_after_real_request_locked(api: dict[str, Any], kind: str, data: dict[str, Any]) -> None:
        """Advance provider quota display without making extra HTTP calls.

        SAIA/GWDG exposes quota via response headers, but even invalid quota
        probes consume quota. The dashboard therefore performs at most the
        configured startup probe and then projects that provider snapshot forward
        for each real API request when exact response headers are unavailable.
        """
        provider = api.get("provider_rate_limit")
        if not isinstance(provider, dict) or not isinstance(provider.get("usage"), dict):
            return
        if not provider.get("headers_present") and not provider.get("locally_projected"):
            return
        usage = json.loads(json.dumps(provider.get("usage") or {}))
        changed = False
        for window in ("minute", "hour", "day", "month", "generic"):
            row = usage.get(window)
            if not isinstance(row, dict):
                continue
            remaining = row.get("remaining")
            used = row.get("used")
            try:
                if remaining is not None:
                    row["remaining"] = max(0, int(remaining) - 1)
                    changed = True
            except Exception:
                pass
            try:
                if used is not None:
                    row["used"] = int(used) + 1
                    changed = True
            except Exception:
                pass
            row["source"] = "provider_header_startup_plus_local_projection"
        if not changed:
            return
        projected = json.loads(json.dumps(provider))
        projected["usage"] = usage
        projected["locally_projected"] = True
        projected["headers_present"] = True
        projected["projection_note"] = "Startup/provider response headers are not re-polled because quota probes consume requests; remaining quota is decremented locally for real API request done/error events unless exact response headers arrive."
        projected["last_projected_event_kind"] = kind
        projected["last_projected_sample_id"] = data.get("sample_id")
        projected["last_projected_stage"] = data.get("stage")
        projected["last_projected_at"] = time.time()
        api["provider_rate_limit"] = projected
        api["provider_usage"] = usage
        api["usage"] = usage

    def update_run_metadata(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.state.setdefault("run", {}).update(data)
            self.state.update({k: v for k, v in data.items() if k in {"run_id", "config_path", "config_name", "output_dir"}})
            if isinstance(data.get("config"), dict):
                self.state["config"] = data["config"]
            if isinstance(data.get("config_summary"), dict):
                self.state["config_summary"] = data["config_summary"]
            self.write_state_locked()

    def update_project(self, key: str, data: dict[str, Any]) -> None:
        with self.lock:
            self.state.setdefault("projects", {}).setdefault(key, {}).update(data)
            self.write_state_locked()

    def update_projects_bulk(self, updates: dict[str, dict[str, Any]]) -> None:
        """Update many project rows with a single state.json write."""
        if not updates:
            return
        with self.lock:
            projects = self.state.setdefault("projects", {})
            for key, data in updates.items():
                projects.setdefault(str(key), {}).update(data)
            self.write_state_locked()

    def update_sample(self, sample_id: str, data: dict[str, Any]) -> None:
        with self.lock:
            self.state.setdefault("samples", {}).setdefault(str(sample_id), {}).update(data)
            self.write_state_locked()

    def update_api(self, data: dict[str, Any]) -> None:
        with self.lock:
            api = self.state.setdefault("api", {})
            if isinstance(data.get("provider_rate_limit"), dict):
                api["provider_rate_limit"] = data.get("provider_rate_limit")
                if isinstance(api["provider_rate_limit"].get("usage"), dict):
                    api["provider_usage"] = api["provider_rate_limit"].get("usage")
                    api["usage"] = api["provider_rate_limit"].get("usage")
            if isinstance(data.get("usage"), dict):
                api["local_usage"] = data.get("usage")
                api.setdefault("usage", data.get("usage"))
            api.update({k: v for k, v in data.items() if k not in {"usage", "provider_rate_limit"}})
            self.write_state_locked()

    def update_metrics(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.state.setdefault("metrics_live", {}).update(data)
            self.write_state_locked()

    def set_status(self, status: str) -> None:
        with self.lock:
            self.state["status"] = status
            self.write_state_locked()

    def write_state(self) -> None:
        with self.lock:
            self.write_state_locked()

    def write_state_locked(self) -> None:
        """Persist dashboard state without crashing the pipeline on Windows.

        On Windows, a browser fetch, antivirus scanner, or another reader can
        briefly hold ``state.json``. ``Path.replace``/``os.replace`` is atomic
        when it succeeds, but it can raise ``PermissionError`` while the file is
        locked. The live dashboard must never make classification fail, so this
        method retries with per-thread temporary files and finally records a
        non-fatal dashboard-write error if the lock persists.
        """
        self.state["updated_at"] = time.time()
        self.state["revision"] = int(self.state.get("revision") or 0) + 1
        payload = json.dumps(self.state, indent=2, ensure_ascii=False)
        last_error: str | None = None

        # Use a unique tmp path per write. A fixed state.tmp can itself become
        # a contention point under parallel sample classification on Windows.
        for attempt in range(12):
            tmp = self.dir / f".state.{os.getpid()}.{threading.get_ident()}.{time.monotonic_ns()}.tmp"
            try:
                tmp.write_text(payload, encoding="utf-8")
                os.replace(tmp, self.state_path)
                self.state.get("server", {}).pop("last_write_error", None)
                return
            except PermissionError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
                time.sleep(min(0.02 * (attempt + 1), 0.25))
            except OSError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
                time.sleep(min(0.02 * (attempt + 1), 0.25))

        # Last-resort fallback: do not raise. The dashboard may miss one refresh,
        # but the long-running KG/RAG classification must continue.
        try:
            self.state_path.write_text(payload, encoding="utf-8")
            self.state.get("server", {}).pop("last_write_error", None)
        except Exception as exc:
            self.state.setdefault("server", {})["last_write_error"] = last_error or f"{type(exc).__name__}: {exc}"

    def _write_index(self) -> None:
        html = r"""<!doctype html><html><head><meta charset='utf-8'><title>Live VulnGraphRAG Run</title>
<style>
:root{--bg:#f8fafc;--card:#fff;--line:#e5e7eb;--muted:#6b7280;--text:#111827;--blue:#2563eb}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:18px;color:var(--text);background:var(--bg)}h1,h2,h3{margin:.35rem 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px;box-shadow:0 1px 2px #0001}.pill{display:inline-block;border-radius:999px;padding:2px 8px;background:#e5e7eb;margin:2px}.TP,.TN,.done,.kg_built,.kg_loaded_cache,.usable_repo,.validated_pair_selected{background:#dcfce7}.FP,.FN,.failed,.snapshot_unavailable,.unusable_repo,.validated_pair_rejected{background:#fee2e2}.INVALID,.parse_failed,.inconclusive,.waiting_api,.kg_building,.repo_checking,.candidate_for_validation{background:#fef3c7}.running,.api_in_flight,.kg_loading_cache,.snapshot_preparing{background:#dbeafe}.queued{background:#f3f4f6}table{width:100%;border-collapse:collapse;background:white;margin-top:8px}th,td{border:1px solid var(--line);padding:6px;font-size:13px;vertical-align:top}th{background:#f3f4f6;position:sticky;top:0;z-index:1;cursor:pointer}input,select,button{padding:6px;border:1px solid #d1d5db;border-radius:8px;background:white}button.active{background:#dbeafe;border-color:#93c5fd}a{color:var(--blue);text-decoration:none}.small{font-size:12px;color:var(--muted)}pre{white-space:pre-wrap;max-height:360px;overflow:auto;background:#f3f4f6;padding:8px;border-radius:8px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}.warn{color:#92400e}.bad{color:#991b1b}.ok{color:#047857}.nowrap{white-space:nowrap}.path{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}.bar{height:7px;background:#e5e7eb;border-radius:999px;overflow:hidden}.bar>span{display:block;height:100%;background:#93c5fd}.hidden{display:none}.sectionNote{margin:.25rem 0 .5rem 0;color:var(--muted);font-size:12px}
</style></head><body>
<h1>Live VulnGraphRAG / vckg Run</h1><div id='meta' class='small'></div><div class='grid' id='cards'></div>
<div class='tabs'><button id='tabBtn_samples' onclick="show('samples')">Samples</button><button id='tabBtn_projects' onclick="show('projects')">Projects / KG</button><button id='tabBtn_api' onclick="show('api')">API / Quota</button><button id='tabBtn_metrics' onclick="show('metrics')">Metrics</button><button id='tabBtn_configs' onclick="show('configs')">Configs</button><button id='tabBtn_events' onclick="show('events')">Events</button></div>
<section id='samplesSec'><h2>Samples</h2><div class='sectionNote'>Source-only prediction state. Dataset labels and commit messages are report-only and should not be used by the model.</div><div class='toolbar'><select id='filter'><option value='all'>All</option><option value='queued'>Queued</option><option value='running'>Running</option><option value='waiting_api'>Waiting API</option><option value='api_in_flight'>API in-flight</option><option value='done'>Done</option><option value='failed'>Failed</option><option value='TP'>TP</option><option value='TN'>TN</option><option value='FP'>FP</option><option value='FN'>FN</option><option value='INVALID'>Invalid/Inconclusive</option></select><input id='search' placeholder='search project/function/sample/stage/evidence' size='48'><span id='sampleCount' class='small'></span></div><table><thead><tr><th onclick="sortSamples('sample_id')">Sample</th><th onclick="sortSamples('status')">Status</th><th onclick="sortSamples('error_type')">Outcome</th><th onclick="sortSamples('project')">Project</th><th onclick="sortSamples('function')">Function</th><th onclick="sortSamples('agent_stage')">Agent/API stage</th><th onclick="sortSamples('prediction_is_vulnerable')">Prediction</th><th>Reasoning</th><th onclick="sortSamples('total_tokens')">Tokens/Cost</th><th>Report</th></tr></thead><tbody id='samples'></tbody></table></section>
<section id='projectsSec'><h2>Repository inventory, candidate validation, and KG status</h2><div class='sectionNote'>This table combines cached repository inventory, cached candidate-pair selection, worktree/target validation, and per-commit KG build/cache status. CodeKG dashboards are served from cache/codekg or your configured kg.cache_dir. It is dashboard-only reporting state, not model-visible prediction context.</div><div class='toolbar'><select id='projectFilter'><option value='all'>All rows</option><option value='usable_repo'>Usable repos</option><option value='unusable_repo'>Unusable repos</option><option value='candidate_for_validation'>Candidate pairs</option><option value='validated_pair_selected'>Selected validated pairs</option><option value='kg_building'>KG building</option><option value='kg_loaded_cache'>KG loaded cache</option><option value='kg_built'>KG built</option><option value='snapshot_unavailable'>Snapshot failed</option></select><input id='projectSearch' placeholder='search project/repo/function/path/status' size='54'><select id='projectSort'><option value='inventory_rank'>Inventory rank</option><option value='candidate_rank'>Candidate rank</option><option value='project'>Project</option><option value='status'>Status</option><option value='tree_source_bytes'>Source bytes</option><option value='tree_source_files'>Source files</option><option value='mirror_size_bytes'>Mirror size</option><option value='dataset_num_samples'>Dataset samples</option><option value='num_nodes'>KG nodes</option><option value='num_edges'>KG edges</option><option value='kg_wall_seconds'>KG seconds</option></select><select id='projectDir'><option value='asc'>asc</option><option value='desc'>desc</option></select><span id='projectCount' class='small'></span></div><table><thead><tr><th onclick="sortProjects('inventory_rank')">Rank</th><th onclick="sortProjects('project')">Project</th><th onclick="sortProjects('status')">Status</th><th onclick="sortProjects('repo_status')">Repo</th><th onclick="sortProjects('dataset_num_samples')">Dataset</th><th onclick="sortProjects('tree_source_bytes')">Source size</th><th onclick="sortProjects('mirror_size_bytes')">Mirror</th><th>Candidate / target</th><th onclick="sortProjects('resolved_commit')">Commit</th><th onclick="sortProjects('graph_status')">KG</th><th onclick="sortProjects('num_nodes')">Graph</th><th>Paths</th></tr></thead><tbody id='projects'></tbody></table></section>
<section id='apiSec'><h2>API / Quota</h2><div id='apiCards' class='grid'></div><h3>Provider quota headers</h3><p class='small'>Shown from provider response headers when available on real model responses. Startup quota probes are disabled in the scaling configs because even failed probes can consume quota.</p><pre id='providerRaw'></pre><h3>Current requests / local scheduler</h3><table><thead><tr><th>Key</th><th>State</th><th>Sample</th><th>Stage</th><th>Attempt</th><th>Wait</th></tr></thead><tbody id='currentReq'></tbody></table><h3>Raw API state</h3><pre id='apiRaw'></pre></section>
<section id='metricsSec'><h2>Metrics / decisions</h2><div id='metricCards' class='grid'></div><pre id='metricsRaw'></pre></section>
<section id='configsSec'><h2>Configs</h2><p class='small'>Resolved run configuration used for LLM calls, KG generation, retrieval, agent validation, execution, and dashboard settings.</p><select id='configSel' onchange='renderConfig()'></select><pre id='configRaw'></pre></section>
<section id='eventsSec'><h2>Recent Events</h2><pre id='events'></pre></section>
<script>
let STATE={}, sampleSort='queue_index', sampleDir='asc', projectSort='inventory_rank', projectDir='asc';
function fmt(n,d=2){if(n===undefined||n===null||n==='')return ''; if(typeof n==='number'&&Number.isFinite(n))return n.toFixed(d); return n}
function cls(x){return (x||'').toString().replace(/[^A-Za-z0-9_-]/g,'_')}
function money(x){return '$'+fmt(Number(x||0),4)}
function bytes(x){x=Number(x||0); if(!x)return ''; const u=['B','KB','MB','GB','TB']; let i=0; while(x>=1024&&i<u.length-1){x/=1024;i++;} return fmt(x,i?1:0)+' '+u[i]}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function show(name){for(const id of ['samples','api','projects','configs','events','metrics']){document.getElementById(id+'Sec').style.display=(id===name?'block':'none'); const b=document.getElementById('tabBtn_'+id); if(b)b.classList.toggle('active',id===name)}}
function val(o,k){const v=o?.[k]; if(v===undefined||v===null)return ''; return v}
function cmp(a,b,k,dir){let av=val(a,k), bv=val(b,k); const an=Number(av), bn=Number(bv); if(av!==''&&bv!==''&&!Number.isNaN(an)&&!Number.isNaN(bn)){av=an; bv=bn}else{av=String(av).toLowerCase(); bv=String(bv).toLowerCase()} return (av<bv?-1:av>bv?1:0)*(dir==='desc'?-1:1)}
function renderConfig(){const cfg=STATE.config||{}; const sel=document.getElementById('configSel'); const key=sel.value||'all'; const value=(key==='all'?cfg:(cfg[key]||{})); document.getElementById('configRaw').textContent=JSON.stringify(value,null,2)}
function syncConfigSelect(s){const cfg=s.config||{}; const sel=document.getElementById('configSel'); const prior=sel.value||'all'; const keys=['all',...Object.keys(cfg).sort()]; sel.innerHTML=keys.map(k=>`<option value="${esc(k)}">${esc(k)}</option>`).join(''); sel.value=keys.includes(prior)?prior:'all'; renderConfig()}
let LAST_REVISION=null, LAST_RENDER_FINGERPRINT='';
function stateFingerprint(s){const samples=s.samples||{}; const compact=Object.values(samples).map(v=>[v.sample_id,v.status,v.api_state,v.agent_stage,v.current_model_stage,v.total_tokens,v.cost_total_usd,v.agent_report_rel,v.current_report_stage,v.error_type,v.decision_status].join('|')).sort().join('||'); const api=s.api||{}; return [s.revision||'',s.status||'',compact,api.completed_requests||0,api.failed_requests||0,api.retry_requests||0,Object.keys(api.current_requests||{}).length].join('##')}
async function load(){try{const r=await fetch('state.json?ts='+Date.now(),{cache:'no-store'}); const next=await r.json(); const fp=stateFingerprint(next); if(next.revision!==LAST_REVISION||fp!==LAST_RENDER_FINGERPRINT){STATE=next; LAST_REVISION=next.revision; LAST_RENDER_FINGERPRINT=fp; render(STATE)}}catch(e){document.getElementById('meta').innerHTML='<span class="bad">Waiting for state.json: '+esc(e)+'</span>'}}
function metrics(samples){let out={total:0,done:0,tp:0,tn:0,fp:0,fn:0,invalid:0,tokens:0,cost:0,queued:0,running:0,waiting:0,inflight:0,failed:0}; for(const v of Object.values(samples||{})){out.total++; if(v.status==='queued')out.queued++; if(v.status==='running')out.running++; if(v.status==='waiting_api')out.waiting++; if(v.status==='api_in_flight')out.inflight++; if(v.status==='failed')out.failed++; if(v.status==='done')out.done++; if(v.error_type==='TP')out.tp++; if(v.error_type==='TN')out.tn++; if(v.error_type==='FP')out.fp++; if(v.error_type==='FN')out.fn++; if(v.error_type==='INVALID'||v.decision_status==='parse_failed'||v.decision_status==='inconclusive')out.invalid++; out.tokens+=Number(v.total_tokens||0); out.cost+=Number(v.cost_total_usd||0)} const valid=out.tp+out.tn+out.fp+out.fn; out.acc=(out.tp+out.tn)/Math.max(1,valid); out.prec=out.tp/Math.max(1,out.tp+out.fp); out.rec=out.tp/Math.max(1,out.tp+out.fn); out.f1=2*out.prec*out.rec/Math.max(1e-9,out.prec+out.rec); return out}
function card(k,v,sub=''){return `<div class='card'><b>${esc(k)}</b><br><span style='font-size:23px'>${esc(v)}</span><div class='small'>${esc(sub)}</div></div>`}
function sortSamples(k){sampleSort=k; sampleDir=sampleDir==='asc'?'desc':'asc'; renderSamples(STATE)}
function sortProjects(k){projectSort=k; document.getElementById('projectSort').value=k; projectDir=projectDir==='asc'?'desc':'asc'; document.getElementById('projectDir').value=projectDir; renderProjects(STATE)}
function stageMini(v){const calls=(v.model_call_progress||[]).slice(-6); if(!calls.length)return ''; return '<div class="small">'+calls.map(c=>`${esc(c.stage||'stage')}: ${fmt(c.elapsed_seconds||0)}s, in ${esc((c.usage||{}).prompt_tokens||0)}, out ${esc((c.usage||{}).completion_tokens||0)}, total ${esc((c.usage||{}).total_tokens||0)}`).join('<br>')+'</div>'}
function renderSamples(s){const f=document.getElementById('filter').value; const q=document.getElementById('search').value.toLowerCase(); const rows=Object.values(s.samples||{}).sort((a,b)=>cmp(a,b,sampleSort,sampleDir)).filter(v=>(f==='all'||v.error_type===f||v.status===f||(f==='INVALID'&&(v.error_type==='INVALID'||v.decision_status==='parse_failed'||v.decision_status==='inconclusive')))&&JSON.stringify(v).toLowerCase().includes(q)); document.getElementById('sampleCount').textContent=rows.length+' / '+Object.keys(s.samples||{}).length+' shown'; document.getElementById('samples').innerHTML=rows.map(v=>`<tr><td class='nowrap'>${esc(v.sample_id||'')}</td><td><span class='pill ${cls(v.status)}'>${esc(v.status||'')}</span><br><span class='small'>${esc(v.api_state||'')}</span></td><td><span class='pill ${cls(v.error_type)}'>${esc(v.error_type||'')}</span><br><span class='small'>${esc(v.decision_status||'')}</span></td><td>${esc(v.project||'')}</td><td>${esc(v.function||'')}<br><span class='small path'>${esc(v.filepath||'')}</span></td><td>${esc(v.agent_stage||'')}<br><span class='small'>${esc(v.current_model_stage||'')}</span>${stageMini(v)}</td><td>${v.prediction_is_vulnerable===undefined?'':(v.prediction_is_vulnerable?'vulnerable':'non-vulnerable')}<br>${fmt(v.confidence||0)}</td><td><span class='small'>${esc((v.reasoning_summary||'').slice(0,260))}</span></td><td>${esc(v.total_tokens||0)}<br>${money(v.cost_total_usd||0)}<br><span class='small'>last ${fmt(v.last_model_elapsed_seconds||0)}s</span></td><td>${v.agent_report_url?link(v.agent_report_url,'open'):(v.agent_report_rel?`<a href="${esc(v.agent_report_rel)}" target="_blank" rel="noopener">open</a>`:'')}</td></tr>`).join('')}
function projectMatchesStatus(v,f){if(f==='all')return true; if(f==='usable_repo')return !!v.repo_usable; if(f==='unusable_repo')return v.repo_usable===false; if(f==='kg_built')return v.status==='kg_built'||v.graph_status==='built'; if(f==='kg_loaded_cache')return v.status==='kg_loaded_cache'||v.graph_status==='loaded_cache'; return v.status===f||v.graph_status===f||v.kg_status===f}
function link(url,label){return url?`<a href="${esc(url)}" target="_blank" rel="noopener">${esc(label)}</a>`:''}
function compactPath(path,label){return path?`<span class='small path' title="${esc(path)}">${esc(label)}</span>`:''}
function renderProjects(s){projectSort=document.getElementById('projectSort').value||projectSort; projectDir=document.getElementById('projectDir').value||projectDir; const f=document.getElementById('projectFilter').value; const q=document.getElementById('projectSearch').value.toLowerCase(); let rows=Object.entries(s.projects||{}).map(([k,v])=>({key:k,...v})); rows=rows.filter(v=>projectMatchesStatus(v,f)&&JSON.stringify(v).toLowerCase().includes(q)).sort((a,b)=>cmp(a,b,projectSort,projectDir)); document.getElementById('projectCount').textContent=rows.length+' / '+Object.keys(s.projects||{}).length+' shown'; document.getElementById('projects').innerHTML=rows.map(v=>{const stat=v.status||v.graph_status||v.repo_status||''; const ds=[v.dataset_num_samples!==undefined?`n=${v.dataset_num_samples}`:'',v.dataset_num_vulnerable!==undefined?`v=${v.dataset_num_vulnerable}`:'',v.dataset_num_fixed!==undefined?`f=${v.dataset_num_fixed}`:'',v.dataset_unique_files!==undefined?`files=${v.dataset_unique_files}`:''].filter(Boolean).join(' | '); const src=[bytes(v.tree_source_bytes),v.tree_source_files!==undefined?`${v.tree_source_files} files`:'' ].filter(Boolean).join('<br>'); const cand=[v.candidate_rank?`rank ${v.candidate_rank}`:'',v.function||v.func_name||'',v.filepath||'',v.selected_for_classification?'selected':'',v.pair_valid===false?'rejected':''].filter(Boolean).join('<br>'); const graph=[v.graph_status||v.kg_status||'',v.backend_used?`backend ${v.backend_used}`:'',v.cache_hit?'cache hit':'',v.num_nodes!==undefined?`${v.num_nodes} nodes`:'',v.num_edges!==undefined?`${v.num_edges} edges`:'',v.num_files!==undefined?`${v.num_files} files`:'' ,v.num_functions!==undefined?`${v.num_functions} funcs`:'' ,v.num_statements!==undefined?`${v.num_statements} stmts`:'' ,v.kg_wall_seconds!==undefined&&v.kg_wall_seconds!==null?`${fmt(v.kg_wall_seconds)}s`:'' ].filter(Boolean).join('<br>'); const links=[link(v.dashboard_url,'dashboard'),link(v.manifest_url,'manifest'),link(v.graph_json_url,'graph.json'),link(v.graph_dir_url,'artifacts')].filter(Boolean).join(' · '); const pathHints=[compactPath(v.graph_dir,'kg cache'),compactPath(v.snapshot_path,'worktree'),compactPath(v.mirror_path,'mirror')].filter(Boolean).join('<br>'); return `<tr><td>${esc(v.inventory_rank||'')}</td><td><b>${esc(v.project||v.key||'')}</b><br><span class='small path'>${esc(v.repo_key||'')}</span><br><span class='small'>${esc(v.project_url||'')}</span></td><td><span class='pill ${cls(stat)}'>${esc(stat)}</span></td><td>${esc(v.repo_status||'')}<br><span class='small bad'>${esc((v.repo_error||v.error||'').slice(0,140))}</span></td><td>${esc(ds)}</td><td>${src}</td><td>${bytes(v.mirror_size_bytes)}</td><td class='path'>${cand}</td><td class='path'>${esc((v.resolved_commit||'').slice(0,12))}</td><td>${graph}</td><td>${v.num_nodes!==undefined?esc(v.num_nodes):''}<br>${v.num_edges!==undefined?esc(v.num_edges):''}</td><td class='path'><div class='small'>${links}</div><div>${pathHints}</div></td></tr>`}).join('')}

function renderApi(s){
  const api=s.api||{};
  const provider=api.provider_rate_limit||api.provider_rate_limit_first||{};
  const usage=api.local_usage||api.usage||{};
  const current=api.current_requests||{};
  document.getElementById('apiCards').innerHTML=[
    card('Completed',api.completed_requests||0,'retries '+(api.retry_requests||0)+' | errors '+(api.failed_requests||0)),
    card('Current',Object.keys(current).length,'active/waiting requests'),
    card('Observed wait',fmt(api.total_wait_seconds_observed||0,1)+'s','local scheduler/API waiting'),
    card('Quota source',provider.headers_present?'provider headers':(Object.keys(usage).length?'local usage':'off'), provider.http_status?('HTTP '+provider.http_status):'')
  ].join('');
  document.getElementById('providerRaw').textContent=JSON.stringify(provider||{},null,2);
  document.getElementById('apiRaw').textContent=JSON.stringify(api||{},null,2);
  document.getElementById('currentReq').innerHTML=Object.entries(current).map(([k,v])=>`<tr><td class='path'>${esc(k)}</td><td>${esc(v.state||v.status||'')}</td><td>${esc(v.sample_id||'')}</td><td>${esc(v.stage||'')}</td><td>${esc(v.attempt||'')}</td><td>${fmt(v.waited_seconds||v.wait_seconds||0,1)}s</td></tr>`).join('');
}
function renderMetrics(s,m){
  const live=s.metrics_live||{};
  document.getElementById('metricCards').innerHTML=[
    card('Accuracy',fmt((m.acc||0)*100)+'%','valid TP/TN/FP/FN '+m.tp+'/'+m.tn+'/'+m.fp+'/'+m.fn),
    card('Precision',fmt((m.prec||0)*100)+'%','vulnerable class'),
    card('Recall',fmt((m.rec||0)*100)+'%','vulnerable class'),
    card('F1',fmt((m.f1||0)*100)+'%','vulnerable class'),
    card('Invalid',m.invalid||0,'parse_failed/inconclusive'),
    card('Cost',money(m.cost||0),'live aggregate')
  ].join('');
  document.getElementById('metricsRaw').textContent=JSON.stringify({computed:m, live:live},null,2);
}

function render(s){const m=metrics(s.samples); const api=s.api||{}; const provider=api.provider_rate_limit||{}; const localUsage=api.local_usage||{}; const srv=s.server||{}; const elapsed=Math.max(0,Date.now()/1000-(s.started_at||Date.now()/1000)); const cs=s.config_summary||{}; const quotaSource=(provider.headers_present?'provider headers':(Object.keys(localUsage).length?'local scheduler':'off')); document.getElementById('meta').innerHTML='Status: <b>'+esc(s.status)+'</b> | Run: '+esc(s.run_id||s.run_name||s.run_dir)+' | Config: '+esc(s.config_name||s.config_path||'')+' | Elapsed: '+fmt(elapsed,0)+'s | Updated: '+new Date((s.updated_at||0)*1000).toLocaleString()+' | Server: '+(srv.running?'<span class="ok">running</span>':'<span class="warn">file/static</span>'); document.getElementById('cards').innerHTML=[card('Samples done',m.done+'/'+m.total,'queued '+m.queued+' | running '+m.running+' | API wait '+m.waiting+' | in-flight '+m.inflight+' | failed '+m.failed),card('Valid accuracy',fmt(m.acc*100)+'%','TP/TN/FP/FN '+m.tp+'/'+m.tn+'/'+m.fp+'/'+m.fn),card('Model',cs.model_name||'',(cs.model_backend||'')+' | temp '+fmt(cs.temperature||0,2)+' | max_tokens '+(cs.max_tokens||'')),card('KG',cs.kg_version||'',(cs.kg_scope||'')+' | headers '+(cs.kg_include_headers===undefined?'':cs.kg_include_headers)),card('Projects tracked',Object.keys(s.projects||{}).length,'inventory/candidates/KG'),card('Agent',cs.agent_mode||'','rounds '+(cs.agent_max_rounds||'')+' | evidence '+(cs.max_evidence_items_after_tools||'')),card('Quota source',quotaSource,provider.http_status?('HTTP '+provider.http_status+' | reset '+(provider.reset_seconds??'' )+'s'):''),card('Requests',api.completed_requests||0,'retries '+(api.retry_requests||0)+' | errors '+(api.failed_requests||0)),card('Tokens',m.tokens),card('Cost',money(m.cost))].join(''); renderSamples(s); renderProjects(s); renderApi(s); renderMetrics(s,m); syncConfigSelect(s); document.getElementById('events').textContent=(s.recent_events||[]).slice(-160).reverse().map(e=>new Date(e.time*1000).toLocaleTimeString()+' '+e.kind+' '+JSON.stringify(e)).join('\n')}
document.getElementById('filter').onchange=()=>renderSamples(STATE); document.getElementById('search').oninput=()=>renderSamples(STATE); document.getElementById('projectFilter').onchange=()=>renderProjects(STATE); document.getElementById('projectSearch').oninput=()=>renderProjects(STATE); document.getElementById('projectSort').onchange=()=>renderProjects(STATE); document.getElementById('projectDir').onchange=()=>renderProjects(STATE); show('samples'); setInterval(load,1000); load();
</script></body></html>"""

        (self.dir / "index.html").write_text(html, encoding="utf-8")
