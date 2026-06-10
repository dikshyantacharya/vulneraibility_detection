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
_SECRET_HINTS = ("api_key", "apikey", "token", "secret", "password")


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


def _mask_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        masked = {}
        for k, v in obj.items():
            if any(h in str(k).lower() for h in _SECRET_HINTS):
                masked[k] = "***redacted***"
            else:
                masked[k] = _mask_secrets(v)
        return masked
    if isinstance(obj, list):
        return [_mask_secrets(v) for v in obj]
    return obj


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

    def list_samples(self, run_id: str) -> list[dict[str, Any]]:
        d = self._resolve_run(run_id)
        if not d:
            return []
        out = []
        for sd in self._sample_dirs(d):
            fp = _read_json(sd / "final_prediction.json") or {}
            out.append({
                "sample_id": fp.get("sample_id") or sd.name.split("_")[1] if "_" in sd.name else sd.name,
                "dir": sd.name,
                "function_name": "_".join(sd.name.split("_")[2:]) or None,
                "prediction": "vulnerable" if fp.get("is_vulnerable") else ("safe" if fp.get("is_vulnerable") is False else None),
                "confidence": fp.get("confidence"),
                "decision_status": fp.get("decision_status"),
                "resolved_commit": fp.get("resolved_commit_id"),
                "model_backend": fp.get("model_backend"),
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
