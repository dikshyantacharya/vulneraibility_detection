"""FastAPI control-plane app: REST + WebSocket + SPA static serving.

This is purely additive. It reads existing challenge artifacts (read-only) and
launches the existing CLI commands through the JobManager. It never mutates the
KG store or registry directly.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import requests
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The dashboard requires FastAPI + uvicorn. Install with:\n"
        "    pip install -e \".[dashboard]\"\n"
        "or:  pip install fastapi \"uvicorn[standard]\""
    ) from exc

from .events import DashboardEvent
from .inventory import ChallengeInventory, discover_challenges
from .jobs import JobContext, JobManager
from .kg_presets import preset_options
from .llm_profiles import EnvironmentLoader, LLMProfileManager
from .research import ResearchInventory
from .settings import DashboardSettings

_MISSING_FRONTEND_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>VCKG Dashboard</title>
<style>body{font-family:system-ui,sans-serif;max-width:680px;margin:64px auto;color:#1f2937}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px}
.card{border:1px solid #e5e7eb;border-radius:12px;padding:24px;background:#fff}</style></head>
<body><div class="card"><h1>VCKG Dashboard backend is running ✅</h1>
<p>The React frontend has not been built yet. To build it:</p>
<pre><code>cd frontend
npm install
npm run build</code></pre>
<p>The API is live at <code>/api/dashboard/health</code>.
In development you can instead run the Vite dev server (<code>npm run dev</code>)
which proxies API + WebSocket calls to this backend.</p></div></body></html>"""


class WSManager:
    """Tracks connected websockets and forwards DashboardEvents to them."""

    def __init__(self) -> None:
        self._conns: list[tuple[WebSocket, str | None]] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket, job_id: str | None) -> None:
        await ws.accept()
        self._conns.append((ws, job_id))

    def disconnect(self, ws: WebSocket) -> None:
        self._conns = [(w, j) for (w, j) in self._conns if w is not ws]

    def broadcast(self, event: DashboardEvent) -> None:
        # Called from the JobManager's background thread -> hop to the loop.
        if self._loop is None:
            return
        payload = event.to_dict()
        for ws, job_filter in list(self._conns):
            if job_filter and job_filter != event.job_id:
                continue
            try:
                asyncio.run_coroutine_threadsafe(ws.send_json(payload), self._loop)
            except Exception:
                pass


def _dir_size(path: Path, cap_files: int = 20000) -> int:
    total = 0
    n = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
                n += 1
                if n >= cap_files:
                    break
        except OSError:
            continue
    return total


def create_app(settings: DashboardSettings, settings_path: str | Path | None = None) -> FastAPI:
    app = FastAPI(title="VCKG Student-System Dashboard", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    project_root = Path(settings.project_root).resolve()
    ctx = JobContext(
        project_root=project_root,
        default_config=str(settings.resolve("config_path")),
        default_challenge=str(settings.resolve("challenge_root")),
    )
    jobs = JobManager(
        ctx,
        settings.resolve("jobs_root"),
        external_env_path=settings.external_env_path
    )
    research = ResearchInventory(project_root)

    # Initialize LLM profile manager with environment loader
    llm_env_loader = EnvironmentLoader(settings.external_env_path, project_root)
    llm_profiles = LLMProfileManager(
        profiles_path=project_root / "outputs/dashboard/settings/llm_profiles.yaml",
        env_loader=llm_env_loader
    )

    ws_manager = WSManager()
    jobs.add_global_listener(ws_manager.broadcast)

    _inv_cache: dict[str, ChallengeInventory] = {}

    def inv_for(challenge: str | None) -> ChallengeInventory:
        root = challenge or str(settings.resolve("challenge_root"))
        if root not in _inv_cache:
            _inv_cache[root] = ChallengeInventory(root)
        return _inv_cache[root]

    @app.on_event("startup")
    async def _startup() -> None:
        ws_manager.bind_loop(asyncio.get_running_loop())

    # ---- health / status / config / settings ------------------------
    @app.get("/api/dashboard/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "service": "vckg-dashboard", "version": "0.1.0"}

    @app.get("/api/dashboard/status")
    def status(mode: str = Query("admin")) -> dict[str, Any]:
        inv = inv_for(None)
        active = [j for j in jobs.list_jobs() if j["status"] == "running"]
        out: dict[str, Any] = {
            "challenge_root": str(settings.resolve("challenge_root")),
            "challenge_exists": inv.exists,
            "default_mode": settings.default_mode,
            "active_jobs": len(active),
            "total_jobs": len(jobs.list_jobs()),
        }
        if inv.exists:
            out.update(
                {
                    "projects": len(inv.projects(mode)),
                    "functions": len(inv.functions(mode)),
                    "kgs": len(inv.kgs(mode)),
                    "split_counts": inv.split_counts(),
                    "label_balance": inv.label_balance(mode),
                }
            )
            vr = inv.validation_report()
            if vr is not None:
                out["validation_ok"] = vr.get("ok")
        return out

    @app.get("/api/dashboard/config")
    def get_config() -> dict[str, Any]:
        cfg = settings.resolve("config_path")
        text = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
        return {"config_path": str(cfg), "exists": cfg.exists(), "content": text}

    @app.get("/api/dashboard/settings")
    def get_settings() -> dict[str, Any]:
        return settings.to_dict()

    @app.post("/api/dashboard/settings")
    async def post_settings(request: Request) -> dict[str, Any]:
        patch = await request.json()
        settings.update(patch if isinstance(patch, dict) else {})
        if settings_path:
            settings.save(settings_path)
        _inv_cache.clear()
        return settings.to_dict()

    # ---- LLM provider profiles ----------------------------------------
    @app.get("/api/llm/profiles")
    def list_llm_profiles() -> list[dict[str, Any]]:
        """List all available LLM provider profiles."""
        return llm_profiles.list_profiles()

    @app.get("/api/llm/profiles/{profile_id}")
    def get_llm_profile(profile_id: str) -> dict[str, Any]:
        """Get a specific LLM provider profile (no secrets)."""
        prof = llm_profiles.get_profile(profile_id)
        if not prof:
            raise HTTPException(404, f"profile {profile_id} not found")
        result = prof.to_dict(include_secrets=False)
        # Add credential status
        env = llm_env_loader.load_env_files()
        result["has_api_key"] = bool(prof.api_key_env and env.get(prof.api_key_env))
        result["has_username"] = bool(prof.username_env and env.get(prof.username_env))
        result["has_password"] = bool(prof.password_env and env.get(prof.password_env))
        result["selected_model"] = env.get(prof.default_model_env) or prof.default_model
        return result

    @app.post("/api/llm/profiles/{profile_id}/health")
    def check_llm_health(profile_id: str) -> dict[str, Any]:
        """Check health/connectivity of an LLM provider."""
        return llm_profiles.test_health(profile_id)

    @app.post("/api/llm/profiles/{profile_id}/models")
    def discover_llm_models(profile_id: str) -> dict[str, Any]:
        """Discover available models for an LLM provider."""
        return llm_profiles.discover_models(profile_id)

    @app.post("/api/llm/profiles/{profile_id}/set-active")
    async def set_active_llm_profile(profile_id: str, request: Request) -> dict[str, Any]:
        """Set the active LLM provider for research audit runs."""
        prof = llm_profiles.get_profile(profile_id)
        if not prof:
            raise HTTPException(404, f"profile {profile_id} not found")
        body = await request.json() if request.headers.get("content-length") else {}
        model = body.get("model")
        # Store in settings
        settings.extra["active_llm_profile"] = profile_id
        if model and prof.default_model_env:
            # This would require writing to .env, which we don't do from dashboard
            # Instead, we'd persist to settings but note that actual value comes from env
            settings.extra["active_llm_model"] = model
        if settings_path:
            settings.save(settings_path)
        return {
            "ok": True,
            "active_profile": profile_id,
            "active_model": model,
            "message": "Active profile set (model selection requires environment file update)"
        }

    @app.get("/api/llm/profiles/{profile_id}/secret")
    def get_llm_secret_status(profile_id: str) -> dict[str, Any]:
        """Get credential status for a profile (no actual values)."""
        prof = llm_profiles.get_profile(profile_id)
        if not prof:
            raise HTTPException(404, f"profile {profile_id} not found")
        env = llm_env_loader.load_env_files()
        return {
            "profile_id": profile_id,
            "api_key": "present" if prof.api_key_env and env.get(prof.api_key_env) else "missing",
            "username": "present" if prof.username_env and env.get(prof.username_env) else "missing",
            "password": "present" if prof.password_env and env.get(prof.password_env) else "missing",
        }

    @app.post("/api/llm/test-chat")
    async def test_llm_chat(request: Request) -> dict[str, Any]:
        """Test a simple chat with an LLM provider to verify connectivity and auth."""
        body = await request.json() if request.headers.get("content-length") else {}
        profile_id = body.get("profile_id")
        model = body.get("model")
        prompt = body.get("prompt", "Hello, how are you?")

        if not profile_id or not model:
            raise HTTPException(400, "profile_id and model are required")

        prof = llm_profiles.get_profile(profile_id)
        if not prof:
            raise HTTPException(404, f"profile {profile_id} not found")

        creds = llm_profiles.get_credentials(profile_id)

        try:
            if prof.provider_type == "openai_compatible":
                return _test_openai_compatible_chat(prof, model, prompt, creds)
            elif prof.provider_type == "ollama":
                return _test_ollama_chat(prof, model, prompt, creds)
            else:
                return {"ok": False, "message": f"Unknown provider type: {prof.provider_type}"}
        except Exception as e:
            return {"ok": False, "message": f"Chat test failed: {str(e)}"}

    def _effective_model_config(profile_id: str, model: str) -> Any:
        """Build the exact ModelConfig the audit pipeline would use for this
        profile/model, so the preflight payload matches the real request body
        (including AcademicCloud's minimal-payload compatibility mode)."""
        from vuln_commit_kg.config import ModelConfig
        from student_system_creator.dashboard.jobs import _apply_llm_override

        cfg_dict: dict[str, Any] = {}
        _apply_llm_override(cfg_dict, profile_id, model)
        return ModelConfig.model_validate(cfg_dict.get("model", {}))

    def _test_openai_compatible_chat(prof: Any, model: str, prompt: str, creds: dict[str, str]) -> dict[str, Any]:
        """Test chat with OpenAI-compatible provider using the SAME payload
        construction as the real pipeline (build_chat_payload), so payload
        incompatibility is caught before an audit starts."""
        from vuln_commit_kg.models.openai_compatible import build_chat_payload

        headers = {"Content-Type": "application/json"}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"

        mcfg = _effective_model_config(prof.profile_id, model)
        url = prof.base_url.rstrip("/") + "/chat/completions"
        payload = build_chat_payload(mcfg, prompt)

        try:
            r = requests.post(url, headers=headers, json=payload, timeout=15)
            if r.status_code == 200:
                data = r.json()
                response_text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
                return {
                    "ok": True,
                    "profile_id": prof.profile_id,
                    "model": model,
                    "payload_keys": sorted(payload.keys()),
                    "minimal_payload": bool(getattr(mcfg, "api_minimal_payload", False)),
                    "response": response_text[:200],
                    "message": "Chat test successful",
                }
            else:
                # Surface the actual provider error body, not just "Bad Request".
                return {
                    "ok": False,
                    "profile_id": prof.profile_id,
                    "model": model,
                    "status_code": r.status_code,
                    "payload_keys": sorted(payload.keys()),
                    "provider_message": (r.text or "")[:500],
                    "message": f"HTTP {r.status_code}: {(r.text or '')[:300]}",
                }
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "message": "Chat test timeout",
            }

    def _test_ollama_chat(prof: Any, model: str, prompt: str, creds: dict[str, str]) -> dict[str, Any]:
        """Test chat with Ollama provider."""
        headers = {}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"

        url = prof.base_url.rstrip("/") + "/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 100,
        }

        try:
            r = requests.post(url, headers=headers, json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                response_text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
                return {
                    "ok": True,
                    "profile_id": prof.profile_id,
                    "model": model,
                    "response": response_text[:200],
                    "message": "Chat test successful",
                }
            else:
                return {
                    "ok": False,
                    "profile_id": prof.profile_id,
                    "model": model,
                    "status_code": r.status_code,
                    "message": f"HTTP {r.status_code}",
                }
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "message": "Chat test timeout. Ollama may be unreachable. Check VPN.",
            }

    # ---- inventory --------------------------------------------------
    @app.get("/api/dashboard/projects")
    def projects(mode: str = Query("admin"), challenge: str | None = None) -> list[dict[str, Any]]:
        return inv_for(challenge).projects(mode)

    @app.get("/api/dashboard/projects/{project_id}")
    def project_detail(project_id: str, mode: str = Query("admin")) -> dict[str, Any]:
        for p in inv_for(None).projects(mode):
            if p["project_id"] == project_id:
                return p
        raise HTTPException(404, "unknown project")

    @app.get("/api/dashboard/projects/{project_id}/functions")
    def project_functions(project_id: str, mode: str = Query("admin")) -> list[dict[str, Any]]:
        return [f for f in inv_for(None).functions(mode) if f.get("project") == project_id]

    @app.get("/api/dashboard/functions")
    def functions(mode: str = Query("admin"), challenge: str | None = None) -> list[dict[str, Any]]:
        return inv_for(challenge).functions(mode)

    @app.get("/api/dashboard/kgs")
    def kgs(mode: str = Query("admin"), challenge: str | None = None) -> list[dict[str, Any]]:
        return inv_for(challenge).kgs(mode)

    @app.get("/api/dashboard/kgs/{kg_id}")
    def kg_detail(kg_id: str, mode: str = Query("admin")) -> dict[str, Any]:
        d = inv_for(None).kg_detail(kg_id, mode)
        if d is None:
            raise HTTPException(404, "unknown kg")
        return d

    @app.get("/api/dashboard/kgs/{kg_id}/graph")
    def kg_graph(
        kg_id: str,
        limit: int = Query(400, ge=1, le=3000),
        node_type: str | None = None,
        function: str | None = None,
    ) -> dict[str, Any]:
        inv = inv_for(None)
        gdir = inv.graph_dir(kg_id)
        if gdir is None or not (gdir / "graph.json").exists():
            raise HTTPException(404, "graph artifacts missing")
        data = json.loads((gdir / "graph.json").read_text(encoding="utf-8"))
        nodes = data.get("nodes") or []
        edges = data.get("edges") or []
        node_types = dict(Counter(n.get("type") for n in nodes))
        edge_types = dict(Counter(e.get("type") for e in edges))

        sel = nodes
        if node_type:
            sel = [n for n in sel if n.get("type") == node_type]
        if function:
            sel = [n for n in sel if (n.get("function") == function or n.get("name") == function)]
        # bound by degree desc
        sel = sorted(sel, key=lambda n: n.get("degree", 0), reverse=True)[:limit]
        keep_ids = {n.get("id") for n in sel}
        sub_edges = [e for e in edges if e.get("source") in keep_ids and e.get("target") in keep_ids]
        return {
            "knowledge_graph_id": kg_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_type_distribution": node_types,
            "edge_type_distribution": edge_types,
            "returned_nodes": sel,
            "returned_edges": sub_edges,
            "truncated": len(nodes) > len(sel),
        }

    # ---- jobs -------------------------------------------------------
    @app.get("/api/dashboard/jobs")
    def list_jobs() -> list[dict[str, Any]]:
        return jobs.list_jobs()

    @app.get("/api/dashboard/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = jobs.get_job(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return job.to_dict()

    @app.post("/api/dashboard/jobs")
    async def create_job(request: Request) -> dict[str, Any]:
        body = await request.json()
        jtype = body.get("type")
        params = {k: v for k, v in body.items() if k != "type"}
        try:
            return jobs.create_job({"type": jtype, "params": params})
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/dashboard/jobs/{job_id}/cancel")
    def cancel_job(job_id: str) -> dict[str, Any]:
        try:
            return jobs.cancel_job(job_id)
        except KeyError:
            raise HTTPException(404, "unknown job")

    @app.post("/api/dashboard/jobs/{job_id}/pause")
    def pause_job(job_id: str) -> dict[str, Any]:
        try:
            return jobs.pause_job(job_id)
        except KeyError:
            raise HTTPException(404, "unknown job")

    @app.post("/api/dashboard/jobs/{job_id}/resume")
    def resume_job(job_id: str) -> dict[str, Any]:
        try:
            return jobs.resume_job(job_id)
        except KeyError:
            raise HTTPException(404, "unknown job")

    @app.get("/api/dashboard/jobs/{job_id}/events")
    def job_events(job_id: str) -> list[dict[str, Any]]:
        return jobs.get_events(job_id)

    @app.get("/api/dashboard/jobs/{job_id}/logs")
    def job_logs(job_id: str, tail: int = Query(500, ge=1, le=100000)) -> dict[str, Any]:
        job = jobs.get_job(job_id)
        log_path = (Path(job.dir) if job else jobs.root / job_id) / "stdout.log"
        if not log_path.exists():
            return {"job_id": job_id, "lines": []}
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return {"job_id": job_id, "lines": lines[-tail:], "total": len(lines)}

    # ---- reports ----------------------------------------------------
    @app.get("/api/dashboard/reports/validation")
    def validation_report() -> dict[str, Any]:
        vr = inv_for(None).validation_report()
        return vr or {"ok": None, "message": "no validation report found"}

    @app.get("/api/dashboard/reports/evaluation")
    def evaluation_report() -> dict[str, Any]:
        # Find the most recent evaluate job result + metrics.
        for j in jobs.list_jobs():
            if j["type"] == "evaluate_solution" and j["status"] == "completed":
                out_dir = Path(j["params"].get("out") or (Path(j["dir"]) / "eval_out"))
                metrics = out_dir / "metrics.json"
                if metrics.exists():
                    return {"job_id": j["job_id"], "metrics": json.loads(metrics.read_text(encoding="utf-8"))}
        return {"message": "no completed evaluation found"}

    # ---- disk -------------------------------------------------------
    @app.get("/api/dashboard/disk")
    def disk() -> dict[str, Any]:
        root = Path(settings.project_root).resolve()
        usage = shutil.disk_usage(str(root))
        challenge = settings.resolve("challenge_root")
        out = {
            "drive_total_bytes": usage.total,
            "drive_used_bytes": usage.used,
            "drive_free_bytes": usage.free,
            "drive_percent_used": round(usage.used / usage.total * 100, 1) if usage.total else 0,
        }
        if challenge.exists():
            out["challenge_size_bytes"] = _dir_size(challenge)
        return out

    @app.get("/api/dashboard/challenges")
    def challenges() -> list[dict[str, Any]]:
        return discover_challenges(settings.resolve("outputs_root"))

    @app.get("/api/dashboard/leakage")
    def leakage() -> dict[str, Any]:
        inv = inv_for(None)
        return inv.leakage_check() if inv.exists else {"ok": True, "flagged": [], "checked": 0}

    # ---- research agentic audit ------------------------------------
    @app.get("/api/kg/backends")
    def kg_backends() -> dict[str, Any]:
        """Valid KG backend presets for the UI. Each option carries the actual
        config block written to effective_config.yaml, plus the canonical list
        of allowed kg.backend values so the frontend never sends an invalid one.
        """
        return preset_options()

    @app.get("/api/research/health")
    def research_health() -> dict[str, Any]:
        return {"ok": True, "configs": len(research.list_configs()), "runs": len(research.list_runs())}

    @app.get("/api/research/configs")
    def research_configs() -> list[dict[str, Any]]:
        return research.list_configs()

    @app.get("/api/research/configs/{name}")
    def research_config(name: str) -> dict[str, Any]:
        meta = research.config_meta(name)
        if meta is None:
            raise HTTPException(404, "unknown config")
        return meta

    @app.get("/api/research/candidates")
    def research_candidates(limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
        return research.candidates(limit)

    @app.get("/api/research/runs")
    def research_runs() -> list[dict[str, Any]]:
        return research.list_runs()

    @app.get("/api/research/runs/{run_id}")
    def research_run(run_id: str) -> dict[str, Any]:
        d = research.run_detail(run_id)
        if d is None:
            raise HTTPException(404, "unknown run")
        return d

    @app.get("/api/research/runs/{run_id}/samples")
    def research_run_samples(run_id: str) -> list[dict[str, Any]]:
        return research.list_samples(run_id)

    @app.get("/api/research/runs/{run_id}/samples/{sample_id}")
    def research_sample(run_id: str, sample_id: str) -> dict[str, Any]:
        d = research.sample_detail(run_id, sample_id)
        if d is None:
            raise HTTPException(404, "unknown sample")
        return d

    @app.get("/api/research/runs/{run_id}/samples/{sample_id}/agent-trace")
    def research_trace(run_id: str, sample_id: str) -> dict[str, Any]:
        t = research.agent_trace(run_id, sample_id)
        if t is None:
            raise HTTPException(404, "no trace")
        return t

    @app.get("/api/research/runs/{run_id}/samples/{sample_id}/llm-calls")
    def research_llm_calls(run_id: str, sample_id: str) -> list[dict[str, Any]]:
        return research.model_calls(run_id, sample_id)

    @app.get("/api/research/runs/{run_id}/samples/{sample_id}/kg-queries")
    def research_kg_queries(run_id: str, sample_id: str) -> list[dict[str, Any]]:
        return research.kg_queries(run_id, sample_id)

    @app.get("/api/research/runs/{run_id}/samples/{sample_id}/audit-report")
    def research_report(run_id: str, sample_id: str) -> dict[str, Any]:
        r = research.audit_report(run_id, sample_id)
        if r is None:
            raise HTTPException(404, "no report")
        return r

    @app.get("/api/research/dash/{run_id}/{sample_id}/{rel:path}")
    def research_dashboard_file(run_id: str, sample_id: str, rel: str = "index.html"):
        f = research.dashboard_file(run_id, sample_id, rel or "index.html")
        if f is None:
            raise HTTPException(404, "dashboard file not found")
        return FileResponse(str(f))

    # ---- websockets -------------------------------------------------
    @app.websocket("/ws/dashboard/events")
    async def ws_events(ws: WebSocket) -> None:
        await ws_manager.connect(ws, None)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(ws)

    @app.websocket("/ws/dashboard/jobs/{job_id}")
    async def ws_job(ws: WebSocket, job_id: str) -> None:
        await ws_manager.connect(ws, job_id)
        # Replay history so a refreshed browser catches up immediately.
        for ev in jobs.get_events(job_id):
            try:
                await ws.send_json(ev)
            except Exception:
                break
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(ws)

    # ---- SPA static serving (must be mounted last) ------------------
    dist = settings.resolve("frontend_dist")
    if dist.exists() and (dist / "index.html").exists():
        assets = dist / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(dist / "index.html"))

        @app.get("/{full_path:path}")
        def spa(full_path: str) -> FileResponse:
            candidate = dist / full_path
            if candidate.is_file():
                return FileResponse(str(candidate))
            return FileResponse(str(dist / "index.html"))
    else:
        @app.get("/", response_class=HTMLResponse)
        def missing_frontend() -> str:
            return _MISSING_FRONTEND_HTML

    return app


def run(settings: DashboardSettings, settings_path: str | Path | None = None, reload: bool = False) -> None:
    import uvicorn

    if reload:
        # reload needs an import string; expose a module-level factory.
        import os

        os.environ["VCKG_DASHBOARD_SETTINGS"] = str(settings_path or "")
        uvicorn.run(
            "student_system_creator.dashboard.app:_reload_app",
            host=settings.host,
            port=settings.port,
            reload=True,
            factory=True,
        )
    else:
        app = create_app(settings, settings_path)
        uvicorn.run(app, host=settings.host, port=settings.port)


def _reload_app() -> FastAPI:  # pragma: no cover - used only in --reload mode
    import os

    sp = os.environ.get("VCKG_DASHBOARD_SETTINGS") or None
    settings = DashboardSettings.load(sp)
    return create_app(settings, sp)
