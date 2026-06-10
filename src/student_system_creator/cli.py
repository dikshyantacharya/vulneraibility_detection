from __future__ import annotations

import argparse

from .build_challenge import main as build_main
from .evaluator.run_submission import main as eval_main
from .package_raid import main as package_raid_main
from .server.api_server import main as serve_main
from .validate_challenge import main as validate_main


def _run_dashboard(args) -> int:
    from pathlib import Path

    from .dashboard.app import run
    from .dashboard.settings import DashboardSettings

    settings = DashboardSettings.load(args.settings)
    settings.project_root = "."
    settings.config_path = args.config
    if args.challenge:
        settings.challenge_root = args.challenge
    settings.host = args.host
    settings.port = args.port
    if getattr(args, "quiet_access_logs", False):
        settings.quiet_access_logs = True
    Path(args.settings).parent.mkdir(parents=True, exist_ok=True)
    settings.save(args.settings)
    reload = bool(getattr(args, "reload", False)) or args.cmd == "dashboard-dev"
    print(f"Starting VCKG dashboard at http://{settings.host}:{settings.port} (mode default={settings.default_mode})", flush=True)
    run(settings, settings_path=args.settings, reload=reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="student-system-creator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="Build public/private student challenge files from VCKG cache")
    p_build.add_argument("--config", default="student_system_creator/configs/default.yaml")
    p_build.add_argument("--limit", type=int, default=None, help="Temporarily limit selected candidate samples for smoke testing")
    p_build.add_argument("--dry-run", action="store_true", help="Only select/write candidate rows; do not create worktrees or build KGs")
    p_build.add_argument("--backend", choices=["auto", "joern", "heuristic", "tree-sitter", "treesitter", "tree_sitter"], default=None, help="Temporarily override kg.backend from the config")
    p_build.add_argument("--overwrite", action="store_true", help="Delete and recreate the challenge output folder before building")
    p_build.add_argument("--progress-every", type=int, default=1, help="Print compact build progress every N candidate samples")

    p_package = sub.add_parser("package-raid", help="Package a built challenge into a Docker/RAID-ready bundle")
    p_package.add_argument("--challenge", default="outputs/student_challenge/vckg_codekg_student_challenge")
    p_package.add_argument("--out", default="dist/vckg_codekg_raid_bundle")
    p_package.add_argument("--project-root", default=".")
    p_package.add_argument("--overwrite", action="store_true")
    p_package.add_argument("--no-zip", action="store_true")


    p_validate = sub.add_parser("validate-challenge", help="Validate public/private challenge consistency and KG/API retrievability")
    p_validate.add_argument("--challenge", default="outputs/student_challenge/vckg_codekg_student_challenge")
    p_validate.add_argument("--api-base", default=None)
    p_validate.add_argument("--api-key", default="dev-key")
    p_validate.add_argument("--api-timeout", type=float, default=30.0)
    p_validate.add_argument("--limit", type=int, default=None)
    p_validate.add_argument("--repo-worktrees", default=None)
    p_validate.add_argument("--require-api", action="store_true")
    p_validate.add_argument("--require-source-snapshot", action="store_true")
    p_validate.add_argument("--write-report", default=None)
    p_validate.add_argument("--progress-every", type=int, default=10)

    p_serve = sub.add_parser("serve", help="Serve private KG registry as bounded retrieval API")
    p_serve.add_argument("--registry", default="outputs/student_challenge/vckg_codekg_student_challenge/private/kg_registry_private.json")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--api-key", default="dev-key")
    p_serve.add_argument("--require-api-key", action="store_true")
    p_serve.add_argument("--max-nodes", type=int, default=500)
    p_serve.add_argument("--engine-cache-size", type=int, default=8)
    p_serve.add_argument("--slow-query-seconds", type=float, default=10.0)
    p_serve.add_argument("--quiet", action="store_true")

    p_eval = sub.add_parser("evaluate", help="Run a student solution.py through the controlled recursive agent loop")
    p_eval.add_argument("--solution", required=True)
    p_eval.add_argument("--input", required=True)
    p_eval.add_argument("--train", default=None)
    p_eval.add_argument("--labels", default=None)
    p_eval.add_argument("--api-base", default="http://127.0.0.1:8000")
    p_eval.add_argument("--api-key", default="dev-key")
    p_eval.add_argument("--out", default="outputs/student_eval")
    p_eval.add_argument("--limit", type=int, default=None)
    p_eval.add_argument("--max-rounds", type=int, default=5)
    p_eval.add_argument("--max-queries-per-round", type=int, default=2)
    p_eval.add_argument("--max-queries-per-sample", type=int, default=8)
    p_eval.add_argument("--max-nodes-per-query", type=int, default=500)
    p_eval.add_argument("--timeout-per-sample-seconds", type=int, default=120)
    p_eval.add_argument("--query-timeout-seconds", type=int, default=30)
    p_eval.add_argument("--quiet", action="store_true")

    p_dash = sub.add_parser("dashboard", help="Start the React control dashboard (REST + WebSocket + UI)")
    p_dash.add_argument("--config", default="student_system_creator/configs/default.yaml")
    p_dash.add_argument("--challenge", default=None, help="Default challenge folder to inspect")
    p_dash.add_argument("--settings", default="outputs/dashboard/settings.json", help="Dashboard settings JSON (created if missing)")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.add_argument("--reload", action="store_true", help="Auto-reload backend on code change (dev)")
    p_dash.add_argument("--quiet-access-logs", action="store_true",
                        help="Suppress routine access logs for health/jobs/disk/ws (errors still log)")

    p_dash_dev = sub.add_parser("dashboard-dev", help="Start the dashboard backend with auto-reload for frontend dev (Vite proxies to it)")
    p_dash_dev.add_argument("--config", default="student_system_creator/configs/default.yaml")
    p_dash_dev.add_argument("--challenge", default=None)
    p_dash_dev.add_argument("--settings", default="outputs/dashboard/settings.json")
    p_dash_dev.add_argument("--host", default="127.0.0.1")
    p_dash_dev.add_argument("--port", type=int, default=8080)

    args, rest = parser.parse_known_args(argv)
    if args.cmd in ("dashboard", "dashboard-dev"):
        return _run_dashboard(args)
    if args.cmd == "build":
        build_args = ["--config", args.config, "--progress-every", str(args.progress_every)]
        if args.limit is not None:
            build_args += ["--limit", str(args.limit)]
        if args.dry_run:
            build_args.append("--dry-run")
        if args.backend:
            build_args += ["--backend", args.backend]
        if args.overwrite:
            build_args.append("--overwrite")
        build_args += list(rest)
        return build_main(build_args)

    if args.cmd == "package-raid":
        package_args = ["--challenge", args.challenge, "--out", args.out, "--project-root", args.project_root]
        if args.overwrite:
            package_args.append("--overwrite")
        if args.no_zip:
            package_args.append("--no-zip")
        package_args += list(rest)
        return package_raid_main(package_args)


    if args.cmd == "validate-challenge":
        validate_args = ["--challenge", args.challenge, "--api-key", args.api_key, "--api-timeout", str(args.api_timeout), "--progress-every", str(args.progress_every)]
        if args.api_base:
            validate_args += ["--api-base", args.api_base]
        if args.limit is not None:
            validate_args += ["--limit", str(args.limit)]
        if args.repo_worktrees:
            validate_args += ["--repo-worktrees", args.repo_worktrees]
        if args.require_api:
            validate_args.append("--require-api")
        if args.require_source_snapshot:
            validate_args.append("--require-source-snapshot")
        if args.write_report:
            validate_args += ["--write-report", args.write_report]
        validate_args += list(rest)
        return validate_main(validate_args)

    if args.cmd == "serve":
        serve_args = [
            "--registry", args.registry,
            "--host", args.host,
            "--port", str(args.port),
            "--api-key", args.api_key,
            "--max-nodes", str(args.max_nodes),
            "--engine-cache-size", str(args.engine_cache_size),
            "--slow-query-seconds", str(args.slow_query_seconds),
        ]
        if args.require_api_key:
            serve_args.append("--require-api-key")
        if args.quiet:
            serve_args.append("--quiet")
        serve_args += list(rest)
        return serve_main(serve_args)

    if args.cmd == "evaluate":
        eval_args = [
            "--solution", args.solution,
            "--input", args.input,
            "--api-base", args.api_base,
            "--api-key", args.api_key,
            "--out", args.out,
            "--max-rounds", str(args.max_rounds),
            "--max-queries-per-round", str(args.max_queries_per_round),
            "--max-queries-per-sample", str(args.max_queries_per_sample),
            "--max-nodes-per-query", str(args.max_nodes_per_query),
            "--timeout-per-sample-seconds", str(args.timeout_per_sample_seconds),
            "--query-timeout-seconds", str(args.query_timeout_seconds),
        ]
        if args.train:
            eval_args += ["--train", args.train]
        if args.labels:
            eval_args += ["--labels", args.labels]
        if args.limit is not None:
            eval_args += ["--limit", str(args.limit)]
        if args.quiet:
            eval_args.append("--quiet")
        eval_args += list(rest)
        return eval_main(eval_args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
