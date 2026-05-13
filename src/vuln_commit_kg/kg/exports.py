from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.utils.jsonl import to_jsonable, write_json

from .graph_store import ProjectGraph
from .query_engine import LLM_QUERY_PROMPT, QUERY_CONTRACT, QUERY_EXAMPLES


def export_graph_artifacts(graph: ProjectGraph, out_dir: str | Path, cfg: KGConfig | None = None) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, str] = {}
    if cfg is None or getattr(cfg, "storage_export_csv", True):
        artifacts.update(_export_csv(graph, out))
    if cfg is None or getattr(cfg, "storage_export_graphml", True) or getattr(cfg, "save_graphml", False):
        p = _export_graphml(graph, out)
        if p:
            artifacts["graphml"] = str(p)
    if cfg is None or getattr(cfg, "storage_export_query_examples", True):
        query_doc = {
            "llm_query_contract": QUERY_CONTRACT,
            "llm_query_prompt": LLM_QUERY_PROMPT,
            "examples": QUERY_EXAMPLES,
        }
        write_json(out / "kg_query_contract.json", query_doc)
        artifacts["query_contract"] = str(out / "kg_query_contract.json")
    stats = {
        "num_nodes": len(graph.nodes),
        "num_edges": len(graph.edges),
        "node_types": _counts(n.type for n in graph.nodes),
        "edge_types": _counts(e.type for e in graph.edges),
        "manifest": graph.manifest,
        "artifacts": artifacts,
    }
    write_json(out / "kg_stats.json", stats)
    artifacts["stats"] = str(out / "kg_stats.json")
    return artifacts


def _counts(values):
    out: dict[str, int] = {}
    for v in values:
        out[str(v)] = out.get(str(v), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def _export_csv(graph: ProjectGraph, out: Path) -> dict[str, str]:
    nodes_path = out / "nodes.csv"
    edges_path = out / "edges.csv"
    with nodes_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "type", "properties_json"])
        w.writeheader()
        for n in graph.nodes:
            w.writerow({"id": n.id, "type": n.type, "properties_json": json.dumps(to_jsonable(n.properties), ensure_ascii=False)})
    with edges_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["source", "target", "type", "properties_json"])
        w.writeheader()
        for e in graph.edges:
            w.writerow({"source": e.source, "target": e.target, "type": e.type, "properties_json": json.dumps(to_jsonable(e.properties), ensure_ascii=False)})
    return {"nodes_csv": str(nodes_path), "edges_csv": str(edges_path)}


def _export_graphml(graph: ProjectGraph, out: Path) -> Path | None:
    try:
        import networkx as nx
        g = nx.MultiDiGraph()
        for n in graph.nodes:
            attrs = {"type": n.type}
            for k, v in (n.properties or {}).items():
                attrs[str(k)] = _graphml_value(v)
            g.add_node(n.id, **attrs)
        for idx, e in enumerate(graph.edges):
            attrs = {"type": e.type}
            for k, v in (e.properties or {}).items():
                attrs[str(k)] = _graphml_value(v)
            g.add_edge(e.source, e.target, key=str(idx), **attrs)
        path = out / "graph.graphml"
        nx.write_graphml(g, path)
        return path
    except Exception:
        return None


def _graphml_value(v: Any) -> str | int | float | bool:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return "" if v is None else v
    return json.dumps(to_jsonable(v), ensure_ascii=False)[:4000]
