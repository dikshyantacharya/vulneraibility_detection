from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vuln_commit_kg.config import load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Commit-aware KG + LLM vulnerability detection framework.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ["inspect", "validate-targets", "build-kg", "run", "estimate-cost"]:
        p = sub.add_parser(name)
        p.add_argument("--config", required=True, help="Path to YAML config file.")
        p.add_argument("--limit", type=int, default=None, help="Override dataset.sample_limit.")
        p.add_argument("--output-root", default=None, help="Override experiment.output_root.")
        p.add_argument("--model-backend", default=None, choices=["mock", "openai_compatible", "gguf", "hf", "llama_server"], help="Override model.backend.")
        p.add_argument("--sample-ids", default=None, help="Comma-separated sample ids to restrict the run to (dashboard selection).")
        p.add_argument("--function-names", default=None, help="Comma-separated function names to restrict the run to.")
        p.add_argument("--selection-file", default=None, help="JSON file with dataset selection overrides {only_sample_ids, only_function_names, project_include, sample_limit}.")
        if name == "estimate-cost":
            p.add_argument("--completion-tokens-per-call", type=int, default=None, help="Assumed completion budget per model call for pre-flight API cost estimates.")

    p = sub.add_parser("scan-projects", help="Clone-free dataset/project scan before choosing projects to run.")
    p.add_argument("--config", required=True, help="Path to YAML config file. Only dataset/logging/output fields are used.")
    p.add_argument("--fetch-github-size", action="store_true", help="Also query GitHub repository size metadata. Slower and rate-limited.")
    p.add_argument("--github-limit", type=int, default=None, help="Maximum number of GitHub repos for which size is fetched.")
    p.add_argument("--output-root", default=None, help="Override experiment.output_root.")


    p = sub.add_parser("prepare-repos", help="Clone/reuse all dataset repositories and cache persistent repository statistics for scaling selection.")
    p.add_argument("--config", required=True, help="Path to YAML config file.")
    p.add_argument("--limit", type=int, default=None, help="Optional maximum number of unique projects to prepare.")
    p.add_argument("--output-root", default=None, help="Override experiment.output_root.")

    p = sub.add_parser("scan-pairs", help="Clone-free scan for SecVulEval vulnerable/fixed function pairs.")
    p.add_argument("--config", required=True, help="Path to YAML config file. Dataset pair filters are respected.")
    p.add_argument("--limit", type=int, default=50, help="Maximum number of pairs to write/show.")
    p.add_argument("--output-root", default=None, help="Override experiment.output_root.")

    p = sub.add_parser("download-model", help="Download/verify the configured GGUF model; for llama_server configs, also install llama-server when auto-download is enabled.")
    p.add_argument("--config", required=True, help="Path to YAML config file containing model.local_path/repo_id/gguf_filename.")
    p.add_argument("--skip-llama-server", action="store_true", help="Only download the GGUF model, not the llama-server executable.")
    p.add_argument("--output-root", default=None, help="Unused except for config override consistency.")

    p = sub.add_parser("install-llama-server", help="Download and install a prebuilt llama.cpp llama-server into tools/llama.cpp.")
    p.add_argument("--config", required=True, help="Path to YAML config file containing llama-server settings.")
    p.add_argument("--force", action="store_true", help="Re-download/re-extract even if an installed binary already exists.")

    p = sub.add_parser("start-llama-server", help="Start llama.cpp llama-server from Python, avoiding PowerShell execution-policy issues.")
    p.add_argument("--config", required=True, help="Path to YAML config file containing model.local_path/repo_id/gguf_filename.")

    p = sub.add_parser("doctor-llama", help="Check GGUF model path, llama-server binary resolution, and server reachability.")
    p.add_argument("--config", required=True, help="Path to YAML config file containing llama-server settings.")
    p.add_argument("--install-if-missing", action="store_true", help="Install llama-server automatically if not found.")

    p = sub.add_parser("visualize")
    p.add_argument("--run-dir", required=True, help="Existing run directory containing metrics.json and usage_summary.json.")

    p = sub.add_parser("joern-doctor", help="Check whether Joern/joern-parse/joern-export are available for primary C/C++ CPG construction.")
    p.add_argument("--config", default=None, help="Optional config file; kg.joern_* settings are read when provided.")

    p = sub.add_parser("build-project-kg", help="Build a standalone KG for a local C/C++ project snapshot, or automatically build the first curriculum-selected KG when --source is omitted.")
    p.add_argument("--source", default=None, help="Path to a local project checkout/snapshot. If omitted, the configured smallest validated curriculum pair is selected automatically.")
    p.add_argument("--out", required=True, help="Output graph directory for local --source mode, or output root/index directory for automatic curriculum mode.")
    p.add_argument("--config", default=None, help="Config used for automatic curriculum mode when --source is omitted. Defaults to configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml if present.")
    p.add_argument("--project", default=None, help="Project display name.")
    p.add_argument("--project-url", default=None, help="Optional project URL.")
    p.add_argument("--commit", default="local", help="Commit/snapshot identifier for the graph manifest.")
    p.add_argument("--backend", choices=["auto", "lightweight", "heuristic", "joern", "tree-sitter", "treesitter", "tree_sitter"], default="auto", help="CodeKG backend. auto prefers Joern, then tree-sitter, then heuristic fallback.")
    p.add_argument("--joern-home", default=None, help="Optional Joern CLI directory. Equivalent to CODEKG_JOERN_HOME/JOERN_HOME for CodeKG.")
    p.add_argument("--require-joern", action="store_true", help="Fail if Joern is not runnable instead of falling back.")
    p.add_argument("--joern-language", choices=["C", "CPP"], default="C", help="Language passed to Joern when the Joern backend is used.")
    p.add_argument("--joern-timeout", type=int, default=900, help="Joern import/export timeout in seconds for CodeKG.")
    p.add_argument("--no-fallback", action="store_true", help="When backend=joern, fail instead of falling back to heuristic.")
    p.add_argument("--target-function", default=None, help="Optional function to center the generated dashboard on.")
    p.add_argument("--open", action="store_true", help="Open the generated dashboard/index in the default browser.")
    p.add_argument("--serve", action="store_true", help="Serve the output directory over a local HTTP server and open it. Useful when browsers restrict file:// JavaScript.")
    p.add_argument("--port", type=int, default=8788, help="Port for --serve.")

    p = sub.add_parser("view-kg", help="Write an interactive static HTML dashboard for an existing KG cache directory.")
    p.add_argument("--graph-dir", default=None, help="Directory containing nodes.jsonl, edges.jsonl, manifest.json. Defaults to the latest KG cache entry.")
    p.add_argument("--latest", action="store_true", help="Use the latest KG cache entry; implied when --graph-dir is omitted.")
    p.add_argument("--out", default=None, help="Output HTML path. Defaults to <graph-dir>/kg_dashboard.html.")
    p.add_argument("--target-function", default=None, help="Optional target function to center the graph subset.")
    p.add_argument("--open", action="store_true", help="Open the generated dashboard in the default browser.")

    p = sub.add_parser("query-kg", help="Run a structured KG query against an existing graph directory.")
    p.add_argument("--graph-dir", default=None, help="Directory containing nodes.jsonl, edges.jsonl, manifest.json. Defaults to the latest KG cache entry.")
    p.add_argument("--latest", action="store_true", help="Use the latest KG cache entry; implied when --graph-dir is omitted.")
    p.add_argument("--query-json", default=None, help="Full JSON query object.")
    p.add_argument("--kind", default="function_context", help="Query kind if --query-json is not provided.")
    p.add_argument("--target-function", default=None, help="Target function name/qualified name.")
    p.add_argument("--symbols", default="", help="Comma-separated symbols/APIs.")
    p.add_argument("--risk-terms", default="", help="Comma-separated risk/semantic terms.")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--limit", type=int, default=80)
    p.add_argument("--out", default=None, help="Optional JSON output path. Defaults to stdout only.")
    p.add_argument("--write-dashboard", action="store_true", help="Also write/update kg_dashboard.html with the query result embedded.")
    p.add_argument("--open", action="store_true", help="Open kg_dashboard.html after writing it.")
    return parser


def _load_and_override(args) -> tuple:
    cfg = load_config(args.config)
    if getattr(args, "limit", None) is not None and getattr(args, "command", None) not in {"scan-pairs"}:
        cfg.dataset.sample_limit = args.limit
    if getattr(args, "output_root", None) is not None:
        cfg.experiment.output_root = args.output_root
    if getattr(args, "model_backend", None) is not None:
        cfg.model.backend = args.model_backend
    # Dashboard-driven explicit selection (additive; safe no-ops when unset).
    if getattr(args, "selection_file", None):
        import json as _json
        sel = _json.loads(Path(args.selection_file).read_text(encoding="utf-8"))
        for key in ("only_sample_ids", "only_function_names", "project_include", "project_exclude"):
            if sel.get(key) is not None:
                setattr(cfg.dataset, key, list(sel[key]))
        if sel.get("sample_limit") is not None:
            cfg.dataset.sample_limit = int(sel["sample_limit"])
    if getattr(args, "sample_ids", None):
        cfg.dataset.only_sample_ids = [x.strip() for x in args.sample_ids.split(",") if x.strip()]
    if getattr(args, "function_names", None):
        cfg.dataset.only_function_names = [x.strip() for x in args.function_names.split(",") if x.strip()]
    return cfg, Path(args.config)




def _is_graph_dir(path: Path) -> bool:
    return (path / "nodes.jsonl").exists() and (path / "edges.jsonl").exists() and (path / "manifest.json").exists()


def _find_latest_graph_dirs(*, root: str | Path = "cache/kg", version_substring: str = "project_v6_joern_primary_semantic_overlay", limit: int = 2) -> list[Path]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    manifests = [p for p in root_path.rglob("manifest.json") if version_substring in str(p) and _is_graph_dir(p.parent)]
    manifests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    seen: set[str] = set()
    graph_dirs: list[Path] = []
    for manifest in manifests:
        key = str(manifest.parent.resolve())
        if key in seen:
            continue
        seen.add(key)
        graph_dirs.append(manifest.parent)
        if len(graph_dirs) >= limit:
            break
    return graph_dirs


def _resolve_graph_dir(value: str | None) -> Path:
    if value:
        graph_dir = Path(value)
        if not _is_graph_dir(graph_dir):
            raise RuntimeError(f"Graph directory is invalid or incomplete: {graph_dir}")
        return graph_dir
    latest = _find_latest_graph_dirs(limit=1)
    if not latest:
        raise RuntimeError(
            "No --graph-dir was provided and no latest KG cache directory was found. "
            "Run: vckg build-project-kg --out outputs\\kg_inspect\\auto_smallest --backend auto --target-function <function>"
        )
    return latest[0]


def _open_path(path: Path) -> None:
    import webbrowser
    webbrowser.open(path.resolve().as_uri())


def _serve_directory(directory: Path, *, index_name: str, port: int) -> int:
    import functools
    import http.server
    import socketserver
    import webbrowser

    directory = directory.resolve()
    url = f"http://127.0.0.1:{port}/{index_name}"
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"Serving {directory} at http://127.0.0.1:{port}/")
        print(f"Opening {url}")
        webbrowser.open(url)
        print("Press Ctrl+C to stop the local dashboard server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("Dashboard server stopped.")
    return 0


def _safe_html(s: object) -> str:
    import html
    return html.escape(str(s or ""), quote=True)


def _write_kg_dashboard_index(*, out_dir: Path, run_dir: Path | None, dashboards: list[dict], target_function: str | None) -> Path:
    import json
    import shutil

    out_dir.mkdir(parents=True, exist_ok=True)
    dashboard_copy_dir = out_dir / "dashboards"
    dashboard_copy_dir.mkdir(parents=True, exist_ok=True)
    selected_rows: list[dict] = []
    cards: list[str] = []
    for i, d in enumerate(dashboards, start=1):
        graph_dir = Path(str(d.get("graph_dir") or "")) if d.get("graph_dir") else None
        dash = Path(str(d.get("dashboard") or "")) if d.get("dashboard") else None
        rel_dash = "#"
        status_text = _safe_html(d.get("status") or d.get("dashboard_error") or "unknown")
        if dash and dash.exists():
            safe_project = str(d.get("project") or d.get("project_name") or "project").replace("/", "_").replace("\\", "_")
            safe_commit = str(d.get("commit_id") or d.get("resolved_commit") or d.get("resolved_commit_id") or "commit")[:12]
            copied_dash = dashboard_copy_dir / f"{i:02d}_{safe_project}_{safe_commit}_kg_dashboard.html"
            shutil.copyfile(dash, copied_dash)
            rel_dash = copied_dash.relative_to(out_dir).as_posix()
            d = {**d, "dashboard_copy": str(copied_dash)}
        selected_rows.append(d)
        graph_dir_text = _safe_html(graph_dir or d.get("graph_dir") or "")
        cards.append(
            "<li>"
            f"<a class='button' href='{_safe_html(rel_dash)}'>Open KG dashboard</a> "
            f"<code>{_safe_html(d.get('project') or d.get('project_name') or '')}</code> "
            f"<code>{_safe_html(str(d.get('commit_id') or d.get('resolved_commit') or d.get('resolved_commit_id') or '')[:12])}</code> "
            f"nodes={_safe_html(d.get('num_nodes') or d.get('nodes') or '')} "
            f"edges={_safe_html(d.get('num_edges') or d.get('edges') or '')} "
            f"status={status_text}"
            f"<br/><span class='muted'>graph_dir: <code>{graph_dir_text}</code></span>"
            "</li>"
        )
    cards_html = "\n".join(cards) or "<li>No KG dashboards were generated. Check selected_kg_dashboards.json.</li>"
    target_text = _safe_html(target_function or "TARGET_FUNCTION")
    run_text = _safe_html(run_dir or "cache/latest")
    index_path = out_dir / "kg_dashboard_index.html"
    index_html = f"""<!doctype html><html><head><meta charset='utf-8'><title>VCKG KG dashboards</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial;margin:32px;line-height:1.45;color:#111827;background:#f8fafc}}
code{{background:#eef2f7;padding:2px 4px;border-radius:4px}}
li{{margin:14px 0;padding:12px;border:1px solid #e5e7eb;border-radius:10px;background:#fff}}
.muted{{color:#6b7280;font-size:12px}}
.button{{display:inline-block;background:#1d4ed8;color:#fff;text-decoration:none;padding:6px 10px;border-radius:8px;margin-right:8px}}
pre{{background:#0b1020;color:#e5e7eb;padding:12px;border-radius:10px;overflow:auto}}
</style></head><body>
<h1>Automatic curriculum KG inspection</h1>
<p>Source selection: smallest validated vulnerable/fixed function pair from the configured curriculum.</p>
<p>Run directory: <code>{run_text}</code></p>
<ul>{cards_html}</ul>
<h2>Latest-graph commands</h2>
<pre>vckg query-kg --latest --kind function_context --target-function {target_text} --write-dashboard --open
vckg view-kg --latest --target-function {target_text} --open</pre>
</body></html>"""
    index_path.write_text(index_html, encoding="utf-8")
    (out_dir / "selected_kg_dashboards.json").write_text(json.dumps(selected_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "kg_manifests.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in selected_rows) + ("\n" if selected_rows else ""), encoding="utf-8")
    return index_path

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "visualize":
            import json
            from vuln_commit_kg.evaluation.visualize import make_visualizations, save_metric_tables
            from vuln_commit_kg.analysis_outputs.scaling import write_scaling_analysis
            run_dir = Path(args.run_dir)
            metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
            usage = json.loads((run_dir / "usage_summary.json").read_text(encoding="utf-8"))
            save_metric_tables(run_dir, metrics, usage)
            make_visualizations(run_dir, metrics, usage)
            dashboard = write_scaling_analysis(run_dir, metrics=metrics, usage=usage)
            print(f"Visualizations written to {run_dir / 'figures'}")
            print(f"Scaling dashboard written to {dashboard}")
            return 0

        if args.command == "joern-doctor":
            from vuln_commit_kg.config import KGConfig
            from vuln_commit_kg.kg.joern_builder import joern_available
            import shutil
            if args.config:
                kg_cfg = load_config(args.config).kg
            else:
                kg_cfg = KGConfig()
            print(f"joern-parse: {shutil.which(kg_cfg.joern_parse_bin) or 'missing'}")
            print(f"joern-export: {shutil.which(kg_cfg.joern_export_bin) or 'missing'}")
            print(f"joern: {shutil.which(kg_cfg.joern_bin) or 'missing'}")
            print(f"available_for_primary_kg: {joern_available(kg_cfg)}")
            return 0 if joern_available(kg_cfg) else 2

        if args.command == "build-project-kg":
            import logging
            import json
            import shutil
            from vuln_commit_kg.config import KGConfig, load_config
            from vuln_commit_kg.kg.project_graph_builder import ProjectGraphBuilder
            from vuln_commit_kg.kg.graph_store import save_graph, load_graph
            from vuln_commit_kg.kg.exports import export_graph_artifacts
            from vuln_commit_kg.kg.kg_dashboard import write_kg_dashboard

            logger = logging.getLogger("vckg.kg")
            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
            out_dir = Path(args.out)

            if not args.source:
                # Automatic curriculum mode: use the same smallest validated pair
                # selection used by the scaling runs, then build/load only the
                # selected resolved project@commit KGs.
                default_cfgs = [
                    Path("configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml"),
                    Path("configs/44_curriculum_1_function_sequential_qwen397b.yaml"),
                    Path("configs/34_five_pair_cached_inventory_qwen397b.yaml"),
                ]
                cfg_path = Path(args.config) if args.config else next((c for c in default_cfgs if c.exists()), None)
                if cfg_path is None:
                    raise RuntimeError(
                        "No --source was provided and no default curriculum config was found. "
                        "Pass --config configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml "
                        "or pass --source <local worktree/project>."
                    )
                cfg = load_config(str(cfg_path))
                cfg.kg.backend = args.backend
                cfg.kg.version = "project_v6_joern_primary_semantic_overlay"
                cfg.kg.joern_fallback_to_lightweight = not args.no_fallback
                cfg.experiment.output_root = str(out_dir)
                cfg.live_dashboard.enabled = False
                from vuln_commit_kg.orchestration.pipeline import CommitKGPipeline
                pipeline = CommitKGPipeline(cfg, config_path=cfg_path)
                result = pipeline.build_kg_only()

                manifest_path = result.metrics_path
                rows = []
                if manifest_path.exists():
                    for line in manifest_path.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            try:
                                rows.append(json.loads(line))
                            except Exception:
                                pass
                built = [r for r in rows if r.get("graph_dir") and Path(str(r.get("graph_dir"))).exists()]
                dashboards = []
                for i, row in enumerate(built, start=1):
                    graph_dir = Path(str(row["graph_dir"]))
                    try:
                        graph = load_graph(graph_dir)
                        dash = write_kg_dashboard(
                            graph,
                            graph_dir=graph_dir,
                            out_path=graph_dir / "kg_dashboard.html",
                            cfg=cfg.kg,
                            target_function=args.target_function,
                        )
                        dashboards.append({**row, "dashboard": str(dash)})
                    except Exception as exc:
                        dashboards.append({**row, "dashboard_error": str(exc)})

                # If the run did not materialize kg_manifests.jsonl (for example
                # because graph_cache loaded an already-existing cache entry before
                # older code appended manifest rows), fall back to the latest cache
                # entries for this KG version.  This keeps the one-command UX stable.
                if not dashboards:
                    latest_dirs = _find_latest_graph_dirs(limit=2)
                    for graph_dir in latest_dirs:
                        try:
                            graph = load_graph(graph_dir)
                            dash = write_kg_dashboard(
                                graph,
                                graph_dir=graph_dir,
                                out_path=graph_dir / "kg_dashboard.html",
                                cfg=cfg.kg,
                                target_function=args.target_function,
                            )
                            dashboards.append({
                                "status": "latest_cache_fallback",
                                "graph_dir": str(graph_dir),
                                "dashboard": str(dash),
                                "num_nodes": len(graph.nodes),
                                "num_edges": len(graph.edges),
                                **(graph.manifest or {}),
                            })
                        except Exception as exc:
                            dashboards.append({"status": "latest_cache_fallback_failed", "graph_dir": str(graph_dir), "dashboard_error": str(exc)})

                index_path = _write_kg_dashboard_index(
                    out_dir=out_dir,
                    run_dir=result.run_dir,
                    dashboards=dashboards,
                    target_function=args.target_function,
                )
                print(f"Automatic curriculum KG run: {result.run_dir}")
                print(f"KG manifest: {manifest_path}")
                print(f"Dashboard index: {index_path}")
                for d in dashboards:
                    print(f"- graph_dir={d.get('graph_dir')} dashboard={d.get('dashboard') or d.get('dashboard_error')}")
                if args.serve:
                    return _serve_directory(out_dir, index_name="kg_dashboard_index.html", port=args.port)
                if args.open:
                    _open_path(index_path)
                return 0

            source = Path(args.source)
            if not source.exists():
                raise RuntimeError(
                    f"Snapshot path unavailable: {source}. "
                    "Replace C:\\path\\to\\project-or-worktree with a real checkout/worktree path, "
                    "or omit --source to automatically build the smallest curriculum-selected project KG."
                )
            from vuln_commit_kg.kg.codekg_adapter import build_codekg_graph
            kg_cfg = KGConfig(backend=args.backend, version="codekg_explorer_integrated_v1")
            kg_cfg.use_codekg = True
            kg_cfg.joern_home = args.joern_home
            kg_cfg.require_joern = bool(args.require_joern) or bool(args.no_fallback and str(args.backend).lower() == "joern")
            kg_cfg.joern_language = args.joern_language
            kg_cfg.joern_timeout = int(args.joern_timeout or 900)
            kg_cfg.joern_timeout_seconds = int(args.joern_timeout or 900)
            kg_cfg.joern_fallback_to_lightweight = not (args.no_fallback or args.require_joern)
            graph = build_codekg_graph(
                source_dir=source,
                out_dir=out_dir,
                cfg=kg_cfg,
                project=args.project or source.name,
                project_url=args.project_url,
                commit_id=args.commit,
                logger=logger,
            )
            dash = Path(graph.manifest.get("dashboard_path") or (out_dir / "dashboard" / "index.html"))
            print(f"CodeKG written: {out_dir}")
            print(f"Dashboard: {dash}")
            print(f"Query examples: {out_dir / 'query_examples.json'}")
            if args.serve:
                return _serve_directory(out_dir, index_name="dashboard/index.html", port=args.port)
            if args.open:
                _open_path(dash)
            return 0

        if args.command == "view-kg":
            graph_dir = _resolve_graph_dir(args.graph_dir)
            if (graph_dir / "graph.json").exists():
                from codekg.dashboard import rebuild_dashboard_from_graph_dir
                out = rebuild_dashboard_from_graph_dir(graph_dir)
            else:
                from vuln_commit_kg.config import KGConfig
                from vuln_commit_kg.kg.kg_dashboard import write_kg_dashboard
                out = write_kg_dashboard(graph_dir=graph_dir, out_path=args.out, cfg=KGConfig(), target_function=args.target_function)
            print(f"Graph dir: {graph_dir}")
            print(f"KG dashboard written: {out}")
            if args.open:
                _open_path(out)
            return 0

        if args.command == "query-kg":
            import json
            from vuln_commit_kg.config import KGConfig
            from vuln_commit_kg.kg.query_engine import KGQueryEngine
            from vuln_commit_kg.kg.kg_dashboard import write_kg_dashboard

            if args.query_json:
                query = json.loads(args.query_json)
            else:
                query = {
                    "kind": args.kind,
                    "target_function": args.target_function,
                    "symbols": [s.strip() for s in args.symbols.split(",") if s.strip()],
                    "risk_terms": [s.strip() for s in args.risk_terms.split(",") if s.strip()],
                    "depth": args.depth,
                    "limit": args.limit,
                }
            graph_dir = _resolve_graph_dir(args.graph_dir)
            if (graph_dir / "graph.json").exists():
                from codekg.query import GraphQueryEngine
                from codekg.dashboard import rebuild_dashboard_from_graph_dir
                engine = GraphQueryEngine(graph_dir)
                kind = query.pop("kind", args.kind)
                if "symbols" in query and query["symbols"] and not query.get("symbol"):
                    query["symbol"] = query["symbols"][0]
                result = engine.run(kind, **query)
            else:
                engine = KGQueryEngine.from_dir(graph_dir)
                result = engine.run(query)
            text = json.dumps(result, ensure_ascii=False, indent=2)
            print(text)
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(text, encoding="utf-8")
                print(f"Query result written: {args.out}")
            if args.write_dashboard:
                if (graph_dir / "graph.json").exists():
                    out = rebuild_dashboard_from_graph_dir(graph_dir)
                    (graph_dir / "last_query_result.json").write_text(text, encoding="utf-8")
                else:
                    out = write_kg_dashboard(graph=engine.graph, graph_dir=graph_dir, cfg=KGConfig(), target_function=query.get("target_function"), query_result=result)
                print(f"Graph dir: {graph_dir}")
                print(f"KG dashboard written: {out}")
                if args.open:
                    _open_path(out)
            return 0

        cfg, config_path = _load_and_override(args)
        if args.command == "download-model":
            from vuln_commit_kg.models.download import ensure_gguf_model_path

            path = ensure_gguf_model_path(cfg.model)
            print(f"GGUF model ready: {path}")
            if cfg.model.backend == "llama_server" and cfg.model.llama_server_auto_download and not args.skip_llama_server:
                from vuln_commit_kg.models.llama_server_installer import install_llama_server

                installed = install_llama_server(cfg.model)
                print(f"llama-server ready: {installed.binary}")
            return 0

        if args.command == "install-llama-server":
            from vuln_commit_kg.models.llama_server_installer import install_llama_server

            installed = install_llama_server(cfg.model, force=args.force)
            print(f"llama-server ready: {installed.binary}")
            print(f"install dir: {installed.install_dir}")
            if installed.asset_name:
                print(f"asset: {installed.asset_name}")
            return 0

        if args.command == "start-llama-server":
            from vuln_commit_kg.models.llama_server_utils import start_llama_server_foreground
            return int(start_llama_server_foreground(cfg.model))

        if args.command == "doctor-llama":
            from vuln_commit_kg.models.download import ensure_gguf_model_path
            from vuln_commit_kg.models.llama_server_utils import base_url, check_llama_server_ready, resolve_llama_server_binary
            model_path = ensure_gguf_model_path(cfg.model)
            print(f"GGUF model: {model_path}")
            try:
                binary = resolve_llama_server_binary(
                    cfg.model.llama_server_binary,
                    cfg=cfg.model,
                    auto_install=args.install_if_missing,
                )
                print(f"llama-server binary: {binary}")
            except Exception as exc:
                print(str(exc))
                return 2
            ok, msg = check_llama_server_ready(base_url(cfg.model), timeout=2.0)
            print(f"server {base_url(cfg.model)}: {'OK' if ok else 'NOT RUNNING'} ({msg})")
            return 0 if ok else 3

        if args.command in {"run", "estimate-cost"} and cfg.model.backend == "llama_server":
            # Preflight early: ensure the configured GGUF exists/downloads before
            # expensive repo/KG work, and install llama-server automatically when
            # managed mode will need it. External-server mode still checks model
            # presence so the config remains reproducible.
            from vuln_commit_kg.models.download import ensure_gguf_model_path
            model_path = ensure_gguf_model_path(cfg.model)
            print(f"GGUF model ready: {model_path}")
            if cfg.model.server_start and cfg.model.llama_server_auto_download:
                from vuln_commit_kg.models.llama_server_installer import install_llama_server
                installed = install_llama_server(cfg.model)
                print(f"llama-server ready: {installed.binary}")

        from vuln_commit_kg.orchestration.pipeline import CommitKGPipeline
        pipeline = CommitKGPipeline(cfg, config_path=config_path)
        if args.command == "inspect":
            result = pipeline.inspect()
        elif args.command == "scan-projects":
            result = pipeline.scan_projects(
                fetch_github_size=args.fetch_github_size,
                github_limit=args.github_limit,
            )
        elif args.command == "validate-targets":
            result = pipeline.validate_targets()
        elif args.command == "scan-pairs":
            result = pipeline.scan_pairs(limit=args.limit)
        elif args.command == "prepare-repos":
            result = pipeline.prepare_repos(limit=args.limit)
        elif args.command == "build-kg":
            result = pipeline.build_kg_only()
        elif args.command == "run":
            result = pipeline.run()
        elif args.command == "estimate-cost":
            result = pipeline.estimate_cost(assumed_completion_tokens_per_call=args.completion_tokens_per_call)
        else:
            raise ValueError(args.command)
        print(f"Run completed: {result.run_dir}")
        print(f"Primary result: {result.metrics_path}")
        if (
            args.command == "run"
            and getattr(cfg.live_dashboard, "enabled", False)
            and getattr(cfg.live_dashboard, "serve", False)
            and getattr(cfg.live_dashboard, "keep_alive_after_run", False)
            and getattr(pipeline, "live", None) is not None
        ):
            print(f"Live dashboard remains available at: {pipeline.live.url()}")
            print("Press Ctrl+C in this terminal when you are finished inspecting it.")
            pipeline.live.block_until_interrupted()
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
