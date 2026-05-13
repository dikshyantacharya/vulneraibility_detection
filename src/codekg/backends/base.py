from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from ..graph_store import GraphStore


@dataclass
class BuildDiagnostics:
    backend_requested: str
    backend_used: str
    joern_available: bool = False
    joern_tools: Dict[str, str | None] = field(default_factory=dict)
    tree_sitter_available: bool = False
    parse_errors: List[dict] = field(default_factory=list)
    skipped_files: List[dict] = field(default_factory=list)
    quality_warnings: List[dict] = field(default_factory=list)
    counters: Dict[str, int] = field(default_factory=dict)
    parser_confidence: str = "unknown"
    tool_versions: Dict[str, Any] = field(default_factory=dict)


class Backend(ABC):
    name = "base"

    @abstractmethod
    def build(self, source_dir: Path, out_dir: Path, logger) -> tuple[GraphStore, BuildDiagnostics]:
        raise NotImplementedError
