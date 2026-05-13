from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__", "node_modules",
    "build", "dist", "cmake-build-debug", "cmake-build-release", ".venv", "venv",
}
SKIP_FILE_SUFFIXES = {".min.js", ".map"}
MAX_FILE_BYTES_DEFAULT = 5_000_000


@dataclass
class DiscoveredFiles:
    source_files: List[Path]
    skipped: List[dict]


def discover_source_files(root: Path, max_file_bytes: int = MAX_FILE_BYTES_DEFAULT) -> DiscoveredFiles:
    root = root.resolve()
    source_files: List[Path] = []
    skipped: List[dict] = []
    for path in root.rglob("*"):
        rel = str(path.relative_to(root)) if path != root else "."
        if path.is_dir():
            continue
        parts = set(path.relative_to(root).parts[:-1])
        if parts.intersection(SKIP_DIR_NAMES):
            skipped.append({"path": rel, "reason": "inside skipped directory"})
            continue
        if any(str(path).endswith(suffix) for suffix in SKIP_FILE_SUFFIXES):
            skipped.append({"path": rel, "reason": "skipped suffix"})
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": rel, "reason": f"stat failed: {exc}"})
            continue
        if size > max_file_bytes:
            skipped.append({"path": rel, "reason": f"file too large ({size} bytes)"})
            continue
        source_files.append(path)
    source_files.sort(key=lambda p: str(p.relative_to(root)).lower())
    return DiscoveredFiles(source_files=source_files, skipped=skipped)
