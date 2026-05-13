from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from .backends import HeuristicBackend, JoernBackend, TreeSitterHybridBackend, detect_java, detect_joern, joern_available, tree_sitter_available
from .dashboard import open_dashboard, rebuild_dashboard_from_graph_dir, write_dashboard
from .exporter import QUERY_EXAMPLES, export_graph, load_graph_dir
from .logging_utils import configure_logging
from .query import GraphQueryEngine

JOERN_LATEST_ZIP_URL = "https://github.com/joernio/joern/releases/latest/download/joern-cli.zip"


def _apply_joern_home(joern_home: Optional[str]) -> None:
    if joern_home:
        os.environ["CODEKG_JOERN_HOME"] = str(Path(joern_home).expanduser().resolve())


def select_backend(name: str, logger, *, strict_joern: bool = False, joern_timeout: int = 900, joern_language: str = "C"):
    name = (name or "auto").lower()
    tools = detect_joern()
    logger.info("Backend requested: %s", name)
    logger.info("Joern availability check: %s", json.dumps(tools))
    if name == "joern":
        return JoernBackend(strict=strict_joern, timeout_seconds=joern_timeout, language=joern_language)
    if name in {"tree-sitter", "treesitter", "tree_sitter"}:
        if not tree_sitter_available():
            logger.warning("tree-sitter optional dependencies are not installed; falling back to heuristic parser.")
            return HeuristicBackend()
        return TreeSitterHybridBackend()
    if name == "heuristic":
        return HeuristicBackend()
    if name == "auto":
        tools_ok = bool(tools.get("joern-parse") and tools.get("joern-export"))
        java_info = detect_java()
        if joern_available():
            logger.info("Selected backend: joern_plus_heuristic")
            return JoernBackend(strict=strict_joern, timeout_seconds=joern_timeout, language=joern_language)
        if tools_ok and not java_info.get("ok"):
            logger.warning("Joern CLI was detected, but Java/JDK is not runnable for Joern: %s", java_info.get("reason"))
        if tree_sitter_available():
            logger.info("Selected backend: tree_sitter_hybrid")
            return TreeSitterHybridBackend()
        logger.warning("Selected heuristic fallback parser because Joern is not runnable and tree-sitter optional dependencies are unavailable.")
        return HeuristicBackend()
    raise SystemExit(f"Unknown backend: {name}")


def cmd_build(args) -> int:
    _apply_joern_home(args.joern_home)
    source = Path(args.source).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    logger = configure_logging(out_dir, verbose=True)
    tools = detect_joern()
    java_info = detect_java()
    if args.require_joern and not joern_available():
        logger.error("--require-joern was set, but Joern is not runnable.")
        logger.error("Detected Joern tools: %s", json.dumps(tools))
        logger.error("Java/JVM check: %s", json.dumps(java_info))
        if not (tools.get("joern-parse") and tools.get("joern-export")):
            logger.error("Fix Joern CLI: codekg install-joern --dest tools")
        if not java_info.get("ok"):
            logger.error("Fix Java first: winget install -e --id EclipseAdoptium.Temurin.19.JDK")
            logger.error("Then close/reopen PowerShell and verify: java -version")
        return 3
    if not source.exists():
        logger.error("Source directory does not exist: %s", source)
        return 2
    if not source.is_dir():
        logger.error("Source path is not a directory: %s", source)
        return 2
    logger.info("Output directory: %s", out_dir)
    backend = select_backend(args.backend, logger, strict_joern=args.require_joern, joern_timeout=args.joern_timeout, joern_language=args.joern_language)
    try:
        graph, diagnostics = backend.build(source, out_dir, logger)
    except RuntimeError as exc:
        logger.error("Build stopped: %s", exc)
        return 4
    diagnostics.counters["files_scanned"] = diagnostics.counters.get("files_scanned") or sum(1 for _ in source.rglob("*") if _.is_file())
    manifest = export_graph(graph, out_dir, source, diagnostics, logger)
    graph_payload = {"nodes": graph.nodes_list(), "edges": graph.edges_list()}
    degree = graph.degree()
    for n in graph_payload["nodes"]:
        n["degree"] = int(degree.get(n["id"], 0))
    dashboard_path = write_dashboard(
        out_dir,
        graph_payload,
        manifest,
        QUERY_EXAMPLES,
        initial_query={"kind": "function_context", "target_function": args.target_function, "depth": 2},
        logger=logger,
    )
    logger.info("Dashboard path: %s", dashboard_path)
    logger.info("Build complete. nodes=%d edges=%d backend=%s", len(graph.nodes), len(graph.edges), manifest.get("backend_used"))
    if args.open:
        logger.info("Opening dashboard in browser: %s", dashboard_path.resolve().as_uri())
        open_dashboard(dashboard_path)
    return 0


def cmd_query(args) -> int:
    graph_dir = Path(args.graph_dir).expanduser()
    engine = GraphQueryEngine(graph_dir)
    result = engine.run(
        args.kind,
        target_function=args.target_function,
        target=args.target,
        depth=args.depth,
        direction=args.direction,
        symbol=args.symbol,
        file=args.file,
        risk_terms=args.risk_terms,
        call_depth=args.call_depth,
        data_depth=args.data_depth,
        include_callers=args.include_callers,
        include_headers=args.include_headers,
        include_globals=args.include_globals,
        include_joern=args.include_joern,
        joern_limit=args.joern_limit,
        joern_edge_limit=args.joern_edge_limit,
        max_nodes=args.max_nodes,
        source_node=args.source_node,
        target_node=args.target_node,
    )
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        print(text)
    if args.write_dashboard:
        loaded = load_graph_dir(graph_dir)
        path = write_dashboard(
            graph_dir,
            loaded["graph"],
            loaded["manifest"],
            loaded["query_examples"],
            initial_query={"kind": args.kind, "target_function": args.target_function, "target": args.target, "depth": args.depth, "direction": args.direction, "symbol": args.symbol, "file": args.file, "source_node": args.source_node, "target_node": args.target_node, "call_depth": args.call_depth, "data_depth": args.data_depth, "include_callers": args.include_callers, "include_headers": args.include_headers, "include_globals": args.include_globals, "include_joern": args.include_joern, "joern_limit": args.joern_limit, "joern_edge_limit": args.joern_edge_limit, "max_nodes": args.max_nodes, "risk_terms": args.risk_terms},
        )
        (graph_dir / "last_query_result.json").write_text(text, encoding="utf-8")
        print(f"Dashboard updated: {path}")
    return 0 if "error" not in result else 1


def cmd_view(args) -> int:
    graph_dir = Path(args.graph_dir).expanduser().resolve()
    path = rebuild_dashboard_from_graph_dir(graph_dir)
    if args.open:
        open_dashboard(path)
    if args.serve:
        handler = partial(SimpleHTTPRequestHandler, directory=str(graph_dir))
        server = ThreadingHTTPServer((args.host, args.port), handler)
        url = f"http://{args.host}:{args.port}/dashboard/index.html"
        print(f"Serving dashboard: {url}")
        if args.open:
            import webbrowser
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
    else:
        print(f"Dashboard: {path}")
    return 0


def _run_version(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else f"returncode={proc.returncode}"
    except Exception as exc:
        return f"error: {exc}"


def cmd_doctor(args) -> int:
    _apply_joern_home(args.joern_home)
    tools = detect_joern()
    java_info = detect_java()
    tools_ok = bool(tools.get("joern-parse") and tools.get("joern-export"))
    java_ok = bool(java_info.get("ok"))
    print("CodeKG doctor")
    print(f"  Python: {sys.executable}")
    print(f"  Platform: {platform.platform()}")
    print(f"  CODEKG_JOERN_HOME: {os.environ.get('CODEKG_JOERN_HOME') or '<not set>'}")
    print(f"  JOERN_HOME: {os.environ.get('JOERN_HOME') or '<not set>'}")
    print(f"  Joern CLI tools detected: {tools_ok}")
    print("  Detected tools:")
    for name, path in tools.items():
        print(f"    {name}: {path or '<missing>'}")
    print("  Java/JVM:")
    print(f"    path: {java_info.get('path') or '<missing>'}")
    print(f"    version: {java_info.get('version') or '<missing>'}")
    print(f"    major: {java_info.get('major') or '<unknown>'}")
    print(f"    ok_for_joern: {java_ok}")
    if java_info.get("reason"):
        print(f"    reason: {java_info.get('reason')}")
    print(f"  tree-sitter packages: {'available' if tree_sitter_available() else '<missing>'}")
    if tools_ok and java_ok:
        print("\nJoern is runnable. Build with:")
        print('  codekg build --source "C:\\Users\\DikshyantAcharya\\Personal\\junk\\rockhopper" --out outputs\\rockhopper_kg --backend auto --joern-home tools\\joern-cli --require-joern --open')
        return 0
    print("\nJoern is not runnable yet.")
    if not tools_ok:
        print("Fix Joern CLI:")
        print("  codekg install-joern --dest tools")
        print("  codekg doctor --joern-home tools\\joern-cli")
    if not java_ok:
        print("Fix Java/JDK on Windows:")
        print("  winget install -e --id EclipseAdoptium.Temurin.19.JDK")
        print("  # then close and reopen PowerShell")
        print("  java -version")
        print("  codekg doctor --joern-home tools\\joern-cli")
    return 1


def cmd_install_joern(args) -> int:
    dest_root = Path(args.dest).expanduser().resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    zip_path = dest_root / "joern-cli.zip"
    final_dir = dest_root / "joern-cli"
    print(f"Downloading Joern CLI from: {JOERN_LATEST_ZIP_URL}")
    print(f"Destination: {dest_root}")
    urllib.request.urlretrieve(JOERN_LATEST_ZIP_URL, zip_path)
    if final_dir.exists() and args.force:
        shutil.rmtree(final_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_root)
    if not final_dir.exists():
        matches = [p for p in dest_root.iterdir() if p.is_dir() and p.name.lower().startswith("joern")]
        if matches:
            final_dir = matches[0]
    os.environ["CODEKG_JOERN_HOME"] = str(final_dir)
    tools = detect_joern(extra_roots=[final_dir])
    print("Detected Joern tools after extraction:")
    for name, path in tools.items():
        print(f"  {name}: {path or '<missing>'}")
    if not (tools.get("joern-parse") and tools.get("joern-export")):
        print("Joern archive was downloaded, but joern-parse/joern-export were not detected.")
        print("On Windows, use WSL if the archive contains Unix shell scripts only.")
        return 1
    java_info = detect_java()
    print("Java/JVM check:")
    print(f"  path: {java_info.get('path') or '<missing>'}")
    print(f"  version: {java_info.get('version') or '<missing>'}")
    print(f"  ok_for_joern: {bool(java_info.get('ok'))}")
    if not java_info.get("ok"):
        print("\nJoern CLI is installed, but Java/JDK is not ready.")
        print("Install JDK 19, close/reopen PowerShell, then rerun doctor:")
        print("  winget install -e --id EclipseAdoptium.Temurin.19.JDK")
        print("  java -version")
        print(f"  codekg doctor --joern-home \"{final_dir}\"")
        return 2
    print("\nJoern installed locally for this project.")
    print(f"Use: codekg build --source <project> --out <out> --backend auto --joern-home \"{final_dir}\" --require-joern --open")
    return 0


def cmd_install_java(args) -> int:
    if not platform.system().lower().startswith("win"):
        print("Automatic Java install is only implemented for Windows/winget.")
        print("Install JDK 19+ with your OS package manager, then run: java -version")
        return 1
    cmd = ["winget", "install", "-e", "--id", args.package_id]
    print("Recommended Joern Java package command:")
    print("  " + " ".join(cmd))
    if not args.run:
        print("Run it manually, or execute: codekg install-java --run")
        return 0
    try:
        proc = subprocess.run(cmd)
        print("\nAfter installation, close and reopen PowerShell, then run:")
        print("  java -version")
        print("  codekg doctor --joern-home tools\\joern-cli")
        return proc.returncode
    except FileNotFoundError:
        print("winget was not found. Install Java manually from Adoptium or Microsoft OpenJDK.")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codekg", description="Standalone C/C++ Code Knowledge Graph Explorer")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="Build a code knowledge graph and dashboard")
    p_build.add_argument("--source", required=True, help="C/C++ project directory")
    p_build.add_argument("--out", required=True, help="Output directory for graph artifacts")
    p_build.add_argument("--backend", default="auto", choices=["auto", "joern", "tree-sitter", "treesitter", "heuristic"], help="Parser backend")
    p_build.add_argument("--joern-home", help="Path to a Joern joern-cli directory. Also available via CODEKG_JOERN_HOME or JOERN_HOME.")
    p_build.add_argument("--require-joern", action="store_true", help="Fail immediately instead of falling back when Joern is unavailable")
    p_build.add_argument("--joern-timeout", type=int, default=900, help="Maximum seconds for each Joern command before it is killed. Default: 900")
    p_build.add_argument("--joern-language", default="C", help="Joern frontend language passed to joern-parse. Default: C for C/C++ projects.")
    p_build.add_argument("--target-function", default="count_rows", help="Function to focus by default in dashboard")
    p_build.add_argument("--open", action="store_true", help="Open generated dashboard in the default browser")
    p_build.set_defaults(func=cmd_build)

    p_query = sub.add_parser("query", help="Run deterministic graph queries")
    p_query.add_argument("--graph-dir", required=True, help="Directory containing graph.json/manifest.json")
    p_query.add_argument("--kind", required=True, choices=["function_context", "call_neighborhood", "semantic_facts", "variable_flow", "risk_slice", "security_context", "vulnerability_context", "evidence_slice", "file_context", "shortest_path", "callers", "callees"])
    p_query.add_argument("--target-function", help="Target function name")
    p_query.add_argument("--target", help="Alias for target function")
    p_query.add_argument("--depth", type=int, default=2)
    p_query.add_argument("--direction", default="both", choices=["in", "out", "both"])
    p_query.add_argument("--symbol", help="Variable/parameter symbol for variable_flow")
    p_query.add_argument("--file", help="File path for file_context")
    p_query.add_argument("--risk-terms", default="pointer,array,bounds,size,copy,read,write,allocation,free,null,return,guard", help="Comma-separated deterministic semantic terms")
    p_query.add_argument("--call-depth", type=int, default=2, help="Recursive in-project callee depth for security_context")
    p_query.add_argument("--data-depth", type=int, default=4, help="Variable/data-flow neighborhood depth for security_context")
    p_query.add_argument("--include-callers", action=argparse.BooleanOptionalAction, default=True, help="Include direct callers in security_context")
    p_query.add_argument("--include-headers", action=argparse.BooleanOptionalAction, default=True, help="Include includes/macros/types/header context in security_context")
    p_query.add_argument("--include-globals", action=argparse.BooleanOptionalAction, default=True, help="Include global/header variables in security_context")
    p_query.add_argument("--include-joern", action=argparse.BooleanOptionalAction, default=True, help="Include imported Joern CPG overlay nodes in security_context")
    p_query.add_argument("--joern-limit", type=int, default=160, help="Maximum Joern overlay nodes to visualize in security_context")
    p_query.add_argument("--joern-edge-limit", type=int, default=500, help="Maximum Joern-internal overlay edges to include in security_context")
    p_query.add_argument("--max-nodes", type=int, default=520, help="Maximum nodes returned/visualized for large security_context slices")
    p_query.add_argument("--source-node", help="Source node id for shortest_path")
    p_query.add_argument("--target-node", help="Target node id for shortest_path")
    p_query.add_argument("--write-dashboard", action="store_true", help="Update dashboard metadata and write last_query_result.json")
    p_query.add_argument("--out", help="Optional JSON output path")
    p_query.set_defaults(func=cmd_query)

    p_view = sub.add_parser("view", help="Open or serve an existing dashboard")
    p_view.add_argument("--graph-dir", required=True)
    p_view.add_argument("--open", action="store_true")
    p_view.add_argument("--serve", action="store_true", help="Start a local HTTP server rooted at graph-dir")
    p_view.add_argument("--host", default="127.0.0.1")
    p_view.add_argument("--port", type=int, default=8765)
    p_view.set_defaults(func=cmd_view)

    p_doctor = sub.add_parser("doctor", help="Check local parser/tool availability")
    p_doctor.add_argument("--joern-home", help="Path to a Joern joern-cli directory")
    p_doctor.set_defaults(func=cmd_doctor)

    p_install = sub.add_parser("install-joern", help="Download latest Joern CLI zip into a local tools folder")
    p_install.add_argument("--dest", default="tools", help="Destination folder. Default: tools")
    p_install.add_argument("--force", action="store_true", help="Delete an existing joern-cli folder before extracting")
    p_install.set_defaults(func=cmd_install_joern)

    p_java = sub.add_parser("install-java", help="Print or run the recommended Windows JDK install command for Joern")
    p_java.add_argument("--package-id", default="EclipseAdoptium.Temurin.19.JDK", help="winget package id. Default: EclipseAdoptium.Temurin.19.JDK")
    p_java.add_argument("--run", action="store_true", help="Run winget install now instead of only printing the command")
    p_java.set_defaults(func=cmd_install_java)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
