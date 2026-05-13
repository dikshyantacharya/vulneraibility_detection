from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .graph_store import KGEdge, KGNode, ProjectGraph, load_graph


QUERY_CONTRACT = {
    "schema_name": "VCKGQuery",
    "description": "LLM-generated query contract for inspecting the code knowledge graph.",
    "fields": {
        "kind": "function_context | node_neighborhood | free_text | risk_paths | guards | calls | semantic_facts | source_to_sink",
        "target_function": "function name or qualified name, for example count_rows",
        "symbols": ["optional variable/API names such as raw, length, itemsize"],
        "risk_terms": ["optional semantic terms such as pointer, bounds, memcpy, allocation"],
        "depth": "integer neighborhood depth, default 2",
        "limit": "maximum number of nodes/results, default 80",
    },
    "required_output": "Return only JSON matching this contract; no markdown.",
}

QUERY_EXAMPLES = [
    {
        "name": "target function neighborhood",
        "query": {"kind": "function_context", "target_function": "count_rows", "depth": 2, "limit": 120},
    },
    {
        "name": "pointer/size semantic facts for target function",
        "query": {"kind": "semantic_facts", "target_function": "count_rows", "risk_terms": ["pointer", "size", "bounds"], "limit": 80},
    },
    {
        "name": "guards around length/raw/itemsize",
        "query": {"kind": "guards", "target_function": "count_rows", "symbols": ["raw", "length", "itemsize"], "limit": 80},
    },
    {
        "name": "risk-oriented search",
        "query": {"kind": "risk_paths", "target_function": "count_rows", "risk_terms": ["dereference", "pointer", "read"], "depth": 2, "limit": 100},
    },
]

LLM_QUERY_PROMPT = """You are generating a query for a C/C++ code knowledge graph.
Return only one JSON object matching this schema:
{
  "kind": "function_context | node_neighborhood | free_text | risk_paths | guards | calls | semantic_facts | source_to_sink",
  "target_function": "name or qualified name of the target function",
  "symbols": ["optional variable or API names"],
  "risk_terms": ["optional semantic terms"],
  "depth": 2,
  "limit": 80
}
Use function_context to inspect the target function, semantic_facts for pointer/size/guard facts, guards for candidate safety checks, calls for caller/callee context, and risk_paths for source-to-risk evidence.
"""


def node_to_dict(n: KGNode) -> dict[str, Any]:
    return {"id": n.id, "type": n.type, **(n.properties or {})}


def edge_to_dict(e: KGEdge) -> dict[str, Any]:
    props = dict(e.properties or {})
    return {"source": e.source, "target": e.target, "type": e.type, "properties": props}


class KGQueryEngine:
    def __init__(self, graph: ProjectGraph):
        self.graph = graph
        self.node_map = graph.node_by_id()
        self.out = {}
        self.inc = {}
        for e in graph.edges:
            self.out.setdefault(e.source, []).append(e)
            self.inc.setdefault(e.target, []).append(e)

    @classmethod
    def from_dir(cls, graph_dir: str | Path) -> "KGQueryEngine":
        return cls(load_graph(graph_dir))

    def run(self, query: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(query, str):
            query = json.loads(query)
        kind = (query.get("kind") or "free_text").lower()
        limit = int(query.get("limit") or 80)
        depth = int(query.get("depth") or 2)
        target_function = query.get("target_function")
        symbols = [str(s).lower() for s in query.get("symbols") or []]
        risk_terms = [str(s).lower() for s in query.get("risk_terms") or []]

        if kind == "function_context":
            seeds = self._find_functions(target_function)
            return self._neighborhood(seeds, depth=depth, limit=limit, query=query)
        if kind == "node_neighborhood":
            node_id = query.get("node_id")
            seeds = [node_id] if node_id in self.node_map else self._find_functions(target_function)
            return self._neighborhood(seeds, depth=depth, limit=limit, query=query)
        if kind == "guards":
            nodes = self._filter_nodes(target_function, symbols, risk_terms + ["guard", "bound", "check", "limit", "size"])
            nodes = [n for n in nodes if self._node_text(n).lower().find("if") >= 0 or "BOUNDS_CHECK" in self._node_text(n)] or nodes
            return self._result(nodes[:limit], self._incident_edges(nodes[:limit]), query)
        if kind == "semantic_facts":
            nodes = [n for n in self.graph.nodes if n.type == "SemanticFact"]
            nodes = self._within_function_or_text(nodes, target_function)
            terms = risk_terms + symbols
            if terms:
                nodes = [n for n in nodes if any(t in self._node_text(n).lower() for t in terms)]
            return self._result(nodes[:limit], self._incident_edges(nodes[:limit]), query)
        if kind == "calls":
            seeds = self._find_functions(target_function)
            edges = [e for e in self.graph.edges if e.type in {"CALLS", "FUNCTION_CALLS_FUNCTION", "FUNCTION_CALLS_NAME", "STATEMENT_CALLS"} and (e.source in seeds or e.target in seeds)]
            nodes = [self.node_map[x] for e in edges for x in (e.source, e.target) if x in self.node_map]
            return self._result(_unique_nodes(nodes)[:limit], edges[:limit * 3], query)
        if kind in {"risk_paths", "source_to_sink"}:
            terms = risk_terms + symbols + ["risk", "pointer", "dereference", "copy", "read", "bounds"]
            nodes = self._filter_nodes(target_function, symbols, terms)
            seeds = self._find_functions(target_function)
            if seeds:
                nbh = self._collect_ids(seeds, depth=depth)
                nodes = [n for n in nodes if n.id in nbh]
            return self._result(nodes[:limit], self._incident_edges(nodes[:limit]), query)
        # free_text
        terms = symbols + risk_terms + [str(query.get("text") or "").lower()]
        terms = [t for t in terms if t]
        nodes = [n for n in self.graph.nodes if terms and any(t in self._node_text(n).lower() for t in terms)]
        return self._result(nodes[:limit], self._incident_edges(nodes[:limit]), query)

    def _find_functions(self, target: str | None) -> list[str]:
        if not target:
            return []
        t = target.lower()
        out = []
        for n in self.graph.nodes:
            if n.type.lower() in {"function", "method", "joernnode"}:
                props = n.properties or {}
                text = " ".join(str(props.get(k, "")) for k in ["name", "qualified_name", "signature", "FULL_NAME", "METHOD_FULL_NAME", "CODE"])
                if t in text.lower():
                    out.append(n.id)
        return out

    def _collect_ids(self, seeds: list[str], *, depth: int) -> set[str]:
        seen = set(seeds)
        frontier = set(seeds)
        for _ in range(max(0, depth)):
            nxt = set()
            for nid in frontier:
                for e in self.out.get(nid, []) + self.inc.get(nid, []):
                    if e.source not in seen:
                        nxt.add(e.source)
                    if e.target not in seen:
                        nxt.add(e.target)
            seen |= nxt
            frontier = nxt
        return seen

    def _neighborhood(self, seeds: list[str], *, depth: int, limit: int, query: dict[str, Any]) -> dict[str, Any]:
        ids = list(self._collect_ids(seeds, depth=depth))[:limit]
        idset = set(ids)
        nodes = [self.node_map[i] for i in ids if i in self.node_map]
        edges = [e for e in self.graph.edges if e.source in idset and e.target in idset]
        return self._result(nodes, edges, query)

    def _filter_nodes(self, target_function: str | None, symbols: list[str], terms: list[str]) -> list[KGNode]:
        nodes = self._within_function_or_text(self.graph.nodes, target_function)
        terms = [t for t in terms if t]
        if not terms:
            return nodes
        return [n for n in nodes if any(t in self._node_text(n).lower() for t in terms)]

    def _within_function_or_text(self, nodes: list[KGNode], target_function: str | None) -> list[KGNode]:
        if not target_function:
            return list(nodes)
        t = target_function.lower()
        result = []
        for n in nodes:
            props = n.properties or {}
            if t in str(props.get("function") or props.get("name") or props.get("qualified_name") or props.get("METHOD_FULL_NAME") or props.get("CODE") or "").lower():
                result.append(n)
        return result

    def _incident_edges(self, nodes: list[KGNode]) -> list[KGEdge]:
        ids = {n.id for n in nodes}
        return [e for e in self.graph.edges if e.source in ids or e.target in ids]

    def _node_text(self, n: KGNode) -> str:
        props = n.properties or {}
        return " ".join(str(v) for v in [n.id, n.type, props.get("text"), props.get("code"), props.get("CODE"), props.get("name"), props.get("qualified_name"), props.get("fact_type"), props.get("description"), props.get("evidence_text")] if v is not None)

    def _result(self, nodes: list[KGNode], edges: list[KGEdge], query: dict[str, Any]) -> dict[str, Any]:
        node_ids = {n.id for n in nodes}
        useful_edges = [e for e in edges if e.source in node_ids or e.target in node_ids]
        return {
            "query": query,
            "nodes": [node_to_dict(n) for n in _unique_nodes(nodes)],
            "edges": [edge_to_dict(e) for e in useful_edges],
            "counts": {"nodes": len(_unique_nodes(nodes)), "edges": len(useful_edges)},
        }


def _unique_nodes(nodes: list[KGNode]) -> list[KGNode]:
    seen = set(); out = []
    for n in nodes:
        if n.id not in seen:
            out.append(n); seen.add(n.id)
    return out
