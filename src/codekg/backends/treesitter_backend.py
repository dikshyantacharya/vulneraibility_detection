from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from .heuristic import HeuristicBackend


def tree_sitter_available() -> bool:
    return importlib.util.find_spec("tree_sitter") is not None and importlib.util.find_spec("tree_sitter_language_pack") is not None


class TreeSitterHybridBackend(HeuristicBackend):
    """Tree-sitter-aware entry point with safe heuristic internals.

    The dashboard/schema are stable even when tree-sitter grammar packages are absent.
    When installed, this backend records availability and uses the same deterministic
    extraction pass for statements/semantic overlays. This keeps the initial Rockhopper
    workflow robust and allows future replacement of function extraction with full CST
    traversal without changing CLI or dashboard artifacts.
    """

    name = "tree_sitter_hybrid"

    def __init__(self) -> None:
        super().__init__(backend_label="tree_sitter_hybrid")

    def build(self, source_dir: Path, out_dir: Path, logger):
        graph, diagnostics = super().build(source_dir, out_dir, logger)
        diagnostics.tree_sitter_available = tree_sitter_available()
        diagnostics.parser_confidence = "medium" if diagnostics.tree_sitter_available else diagnostics.parser_confidence
        diagnostics.tool_versions["tree_sitter"] = "available" if diagnostics.tree_sitter_available else None
        if diagnostics.tree_sitter_available:
            logger.info("tree-sitter packages detected; using tree_sitter_hybrid backend label with deterministic extraction/export schema")
        return graph, diagnostics
