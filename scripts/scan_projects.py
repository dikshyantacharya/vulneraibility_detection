#!/usr/bin/env python
"""Clone-free project scanner for SecVulEval.

Examples:
  python scripts/scan_projects.py --config configs/08_scan_projects.yaml
  python scripts/scan_projects.py --config configs/08_scan_projects.yaml --fetch-github-size --github-limit 50
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vuln_commit_kg.cli import main


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/08_scan_projects.yaml")
    parser.add_argument("--fetch-github-size", action="store_true")
    parser.add_argument("--github-limit", type=int, default=None)
    args = parser.parse_args()
    cli_args = ["scan-projects", "--config", args.config]
    if args.fetch_github_size:
        cli_args.append("--fetch-github-size")
    if args.github_limit is not None:
        cli_args += ["--github-limit", str(args.github_limit)]
    raise SystemExit(main(cli_args))
