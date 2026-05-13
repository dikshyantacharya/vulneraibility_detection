from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .hashing import safe_name


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def make_run_dir(output_root: str | Path, experiment_name: str) -> Path:
    run_dir = Path(output_root) / f"{timestamp()}__{safe_name(experiment_name, 60)}"
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "figures").mkdir(exist_ok=True)
    (run_dir / "tables").mkdir(exist_ok=True)
    return run_dir
