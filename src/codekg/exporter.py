from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx

from .graph_store import GraphStore
from .models import Edge, Node


QUERY_EXAMPLES = [
    {
        "name": "Security retrieval slice for count_rows",
        "kind": "security_context",
        "args": {
            "target_function": "count_rows",
            "depth": 3,
            "call_depth": 3,
            "data_depth": 4,
            "include_callers": True,
            "include_headers": True,
            "include_globals": True,
            "include_joern": True,
            "risk_terms": ["pointer", "array", "bounds", "size", "copy", "read", "write", "allocation", "free", "null", "return", "guard"],
        },
        "dashboard_query": "security_context(target_function=count_rows, depth=3, call_depth=3, data_depth=4, include_callers=true, include_headers=true, include_globals=true, include_joern=true, risk_terms=[pointer,array,bounds,size,copy,read,write,allocation,free,null,return,guard])",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind security_context --target-function count_rows --depth 3 --call-depth 3 --data-depth 4 --include-callers --include-headers --include-globals --include-joern --risk-terms pointer,array,bounds,size,copy,read,write,allocation,free,null,return,guard --write-dashboard",
    },
    {
        "name": "Function context for count_rows",
        "kind": "function_context",
        "args": {"target_function": "count_rows", "depth": 2},
        "dashboard_query": "function_context(target_function=count_rows, depth=2)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind function_context --target-function count_rows --depth 2 --write-dashboard",
    },
    {
        "name": "Call neighborhood for count_rows",
        "kind": "call_neighborhood",
        "args": {"target_function": "count_rows", "direction": "both", "depth": 2},
        "dashboard_query": "call_neighborhood(target_function=count_rows, direction=both, depth=2)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind call_neighborhood --target-function count_rows --direction both --depth 2 --write-dashboard",
    },
    {
        "name": "Semantic facts for count_rows",
        "kind": "semantic_facts",
        "args": {"target_function": "count_rows"},
        "dashboard_query": "semantic_facts(target_function=count_rows)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind semantic_facts --target-function count_rows --write-dashboard",
    },
    {
        "name": "Variable flow for raw in count_rows",
        "kind": "variable_flow",
        "args": {"target_function": "count_rows", "symbol": "raw", "depth": 4},
        "dashboard_query": "variable_flow(target_function=count_rows, symbol=raw, depth=4)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind variable_flow --target-function count_rows --symbol raw --depth 4 --write-dashboard",
    },
    {
        "name": "Risk/semantic slice for count_rows",
        "kind": "risk_slice",
        "args": {"target_function": "count_rows", "risk_terms": ["pointer", "size", "bounds", "null", "copy"]},
        "dashboard_query": "risk_slice(target_function=count_rows, risk_terms=[pointer,size,bounds,null,copy])",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind risk_slice --target-function count_rows --risk-terms pointer,size,bounds,null,copy --write-dashboard",
    },
    {
        "name": "File context",
        "kind": "file_context",
        "args": {"file": "ragged_array.c", "depth": 2},
        "dashboard_query": "file_context(file=ragged_array.c, depth=2)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind file_context --file ragged_array.c --write-dashboard",
    },
    {
        "name": "Callers of count_rows",
        "kind": "callers",
        "args": {"target_function": "count_rows"},
        "dashboard_query": "callers(target_function=count_rows)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind callers --target-function count_rows --write-dashboard",
    },
    {
        "name": "Callees of count_rows",
        "kind": "callees",
        "args": {"target_function": "count_rows"},
        "dashboard_query": "callees(target_function=count_rows)",
        "cli": "codekg query --graph-dir outputs\\rockhopper_kg --kind callees --target-function count_rows --write-dashboard",
    },
]


def graph_to_networkx(graph: GraphStore) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for node in graph.nodes.values():
        attrs = node.to_dict()
        node_id = attrs.pop("id")
        attrs["node_type"] = attrs.pop("type")
        for key, value in list(attrs.items()):
            if isinstance(value, (dict, list)):
                attrs[key] = json.dumps(value, ensure_ascii=False)
            if value is None:
                attrs[key] = ""
        g.add_node(node_id, **attrs)
    for edge in graph.edges.values():
        attrs = edge.to_dict()
        source = attrs.pop("source")
        target = attrs.pop("target")
        edge_id = attrs.pop("id")
        attrs["edge_type"] = attrs.pop("type")
        for key, value in list(attrs.items()):
            if isinstance(value, (dict, list)):
                attrs[key] = json.dumps(value, ensure_ascii=False)
            if value is None:
                attrs[key] = ""
        g.add_edge(source, target, key=edge_id, id=edge_id, **attrs)
    return g


def export_graph(
    graph: GraphStore,
    out_dir: Path,
    source_dir: Path,
    diagnostics,
    logger,
    dashboard_html: Optional[str] = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    nodes = graph.nodes_list()
    edges = graph.edges_list()
    degree = graph.degree()

    for n in nodes:
        n["degree"] = int(degree.get(n["id"], 0))

    with (out_dir / "nodes.jsonl").open("w", encoding="utf-8") as f:
        for n in nodes:
            f.write(json.dumps(n, ensure_ascii=False) + "\n")
    with (out_dir / "edges.jsonl").open("w", encoding="utf-8") as f:
        for e in edges:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    graph_payload = {"nodes": nodes, "edges": edges}
    (out_dir / "graph.json").write_text(json.dumps(graph_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    nx_graph = graph_to_networkx(graph)
    graphml_path = out_dir / "graph.graphml"
    gexf_path = out_dir / "graph.gexf"
    try:
        nx.write_graphml(nx_graph, graphml_path)
    except Exception as exc:
        logger.warning("GraphML export failed: %s", exc)
        graphml_path.write_text(f"GraphML export failed: {exc}\n", encoding="utf-8")
    try:
        nx.write_gexf(nx_graph, gexf_path)
    except Exception as exc:
        logger.warning("GEXF export failed: %s", exc)
        gexf_path.write_text(f"GEXF export failed: {exc}\n", encoding="utf-8")

    node_type_counts = dict(Counter(n["type"] for n in nodes))
    edge_type_counts = dict(Counter(e["type"] for e in edges))
    manifest = {
        "project_name": source_dir.resolve().name,
        "source_path": str(source_dir.resolve()),
        "backend_requested": diagnostics.backend_requested,
        "backend_used": diagnostics.backend_used,
        "joern_available": diagnostics.joern_available,
        "joern_tools": diagnostics.joern_tools,
        "tree_sitter_available": diagnostics.tree_sitter_available,
        "files_scanned": diagnostics.counters.get("files_scanned", None),
        "source_files_parsed": node_type_counts.get("File", 0),
        "number_of_nodes": len(nodes),
        "number_of_edges": len(edges),
        "node_type_counts": node_type_counts,
        "edge_type_counts": edge_type_counts,
        "parse_errors": diagnostics.parse_errors,
        "skipped_files": diagnostics.skipped_files,
        "quality_warnings": diagnostics.quality_warnings,
        "quality_metrics": {
            "unresolved_calls": diagnostics.counters.get("unresolved_calls", 0),
            "known_external_call_edges": diagnostics.counters.get("known_external_call_edges", 0),
            "duplicate_looking_names": diagnostics.counters.get("duplicate_looking_names", 0),
            "orphan_statements": diagnostics.counters.get("orphan_statements", 0),
            "nodes_without_source_lines": diagnostics.counters.get("nodes_without_source_lines", 0),
            "semantic_facts_generated_from_comments": diagnostics.counters.get("semantic_facts_generated_from_comments", 0),
            "self_call_artifacts": diagnostics.counters.get("self_call_artifacts", 0),
            "parser_confidence_level": diagnostics.parser_confidence,
            "joern_imported_files": diagnostics.counters.get("joern_imported_files", 0),
            "joern_imported_nodes": diagnostics.counters.get("joern_imported_nodes", 0),
            "joern_imported_edges": diagnostics.counters.get("joern_imported_edges", 0),
            "joern_overlay_edges": diagnostics.counters.get("joern_overlay_edges", 0),
            "fields": diagnostics.counters.get("fields", 0),
            "field_accesses": diagnostics.counters.get("field_accesses", 0),
            "shadowed_global_name_suppressed": diagnostics.counters.get("shadowed_global_name_suppressed", 0),
            "field_name_global_suppressed": diagnostics.counters.get("field_name_global_suppressed", 0),
            "indirect_calls": diagnostics.counters.get("indirect_calls", 0),
        },
        "extraction_counters": diagnostics.counters,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_versions": diagnostics.tool_versions,
        "artifacts": {
            "nodes_jsonl": "nodes.jsonl",
            "edges_jsonl": "edges.jsonl",
            "graph_json": "graph.json",
            "graphml": "graph.graphml",
            "gexf": "graph.gexf",
            "build_log": "build.log",
            "query_examples": "query_examples.json",
            "dashboard": "dashboard/index.html",
        },
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "query_examples.json").write_text(json.dumps(QUERY_EXAMPLES, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Exported nodes: %s", out_dir / "nodes.jsonl")
    logger.info("Exported edges: %s", out_dir / "edges.jsonl")
    logger.info("Exported graph JSON: %s", out_dir / "graph.json")
    logger.info("Exported GraphML: %s", graphml_path)
    logger.info("Exported GEXF: %s", gexf_path)
    logger.info("Exported manifest: %s", out_dir / "manifest.json")
    return manifest


def load_graph_dir(graph_dir: Path) -> dict:
    graph_dir = graph_dir.resolve()
    graph_path = graph_dir / "graph.json"
    manifest_path = graph_dir / "manifest.json"
    query_examples_path = graph_dir / "query_examples.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    query_examples = json.loads(query_examples_path.read_text(encoding="utf-8")) if query_examples_path.exists() else QUERY_EXAMPLES
    return {"graph": graph, "manifest": manifest, "query_examples": query_examples}
