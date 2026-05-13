from __future__ import annotations
import argparse, shutil
from pathlib import Path

def copytree_merge(src: Path, dst: Path) -> None:
    for p in src.rglob("*"):
        rel = p.relative_to(src); target = dst / rel
        if p.is_dir(): target.mkdir(parents=True, exist_ok=True)
        else: target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(p, target)

def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--project-root", required=True); ap.add_argument("--yes", action="store_true"); args = ap.parse_args()
    project = Path(args.project_root).resolve(); overlay = Path(__file__).resolve().parents[1]
    if not project.exists(): raise SystemExit(f"Project root does not exist: {project}")
    if not args.yes:
        confirm = input(f"Copy agentic overlay into {project}? [y/N] ").strip().lower()
        if confirm != "y": raise SystemExit("Cancelled.")
    copytree_merge(overlay / "src" / "vckg_agentic_proof", project / "vckg_agentic_proof")
    copytree_merge(overlay / "configs", project / "configs")
    print(f"Copied package to: {project / 'vckg_agentic_proof'}")
    print("Next: wire run_agentic_proof_pipeline into your existing agent call site. See INTEGRATION_SNIPPET.md.")
if __name__ == "__main__": main()
