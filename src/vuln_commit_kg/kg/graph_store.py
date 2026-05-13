from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from vuln_commit_kg.logging_utils import ProgressMeter, log_kv
from vuln_commit_kg.utils.jsonl import read_jsonl, to_jsonable, write_json, write_jsonl


@dataclass
class KGNode:
    id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class KGEdge:
    source: str
    target: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProjectGraph:
    nodes: list[KGNode] = field(default_factory=list)
    edges: list[KGEdge] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)

    def node_by_id(self) -> dict[str, KGNode]:
        return {n.id: n for n in self.nodes}

    def out_edges(self, node_id: str, edge_type: str | None = None) -> list[KGEdge]:
        return [e for e in self.edges if e.source == node_id and (edge_type is None or e.type == edge_type)]

    def in_edges(self, node_id: str, edge_type: str | None = None) -> list[KGEdge]:
        return [e for e in self.edges if e.target == node_id and (edge_type is None or e.type == edge_type)]

    def nodes_of_type(self, node_type: str) -> list[KGNode]:
        return [n for n in self.nodes if n.type == node_type]


def _write_jsonl_progress(
    path: Path,
    rows: Iterable[Any],
    *,
    logger: logging.Logger | None,
    label: str,
    total: int | None,
    log_every: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    progress = ProgressMeter(logger, total, label, log_every=log_every) if logger else None
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(to_jsonable(row), ensure_ascii=False) + "\n")
            if progress:
                progress.update()
    if progress:
        progress.finish(extra=f"file={path}")


def save_graph(
    graph: ProjectGraph,
    path: str | Path,
    *,
    logger: logging.Logger | None = None,
    log_every: int = 5000,
) -> None:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if logger:
        log_kv(
            logger,
            "KG save",
            output_dir=path,
            nodes=len(graph.nodes),
            edges=len(graph.edges),
            manifest="manifest.json",
        )
    _write_jsonl_progress(
        path / "nodes.jsonl",
        graph.nodes,
        logger=logger,
        label="kg.save.nodes",
        total=len(graph.nodes),
        log_every=log_every,
    )
    _write_jsonl_progress(
        path / "edges.jsonl",
        graph.edges,
        logger=logger,
        label="kg.save.edges",
        total=len(graph.edges),
        log_every=log_every,
    )
    write_json(path / "manifest.json", graph.manifest)
    if logger:
        logger.info("KG save complete | dir=%s", path)


def load_graph(path: str | Path, logger: logging.Logger | None = None, log_every: int = 10000) -> ProjectGraph:
    path = Path(path)
    if logger:
        log_kv(logger, "KG load", input_dir=path)
    node_rows = read_jsonl(path / "nodes.jsonl")
    if logger:
        logger.info("kg.load.nodes: %s loaded from %s", len(node_rows), path / "nodes.jsonl")
    edge_rows = read_jsonl(path / "edges.jsonl")
    if logger:
        logger.info("kg.load.edges: %s loaded from %s", len(edge_rows), path / "edges.jsonl")
    nodes = [KGNode(**row) for row in node_rows]
    edges = [KGEdge(**row) for row in edge_rows]
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if logger:
        logger.info("KG load complete | nodes=%s edges=%s", len(nodes), len(edges))
    return ProjectGraph(nodes=nodes, edges=edges, manifest=manifest)
