from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from codekg.query import GraphQueryEngine
from vuln_commit_kg.kg.codekg_adapter import _engine_kwargs, normalize_codekg_result, parse_codekg_query_object


class RegistryError(Exception):
    pass


class KGChallengeRegistry:
    def __init__(self, registry_path: str | Path, *, engine_cache_size: int = 8):
        self.registry_path = Path(registry_path).resolve()
        self.root = self.registry_path.parent
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.entries: dict[str, dict[str, Any]] = data.get("entries") or {}
        self.engine_cache_size = max(0, int(engine_cache_size or 0))
        self._engine_cache: OrderedDict[str, GraphQueryEngine] = OrderedDict()
        self._engine_lock = threading.Lock()

    def get(self, kg_id: str) -> dict[str, Any]:
        entry = self.entries.get(kg_id)
        if not entry:
            raise RegistryError(f"unknown knowledge_graph_id: {kg_id}")
        return entry

    def graph_dir(self, kg_id: str) -> Path:
        entry = self.get(kg_id)
        raw = Path(str(entry.get("graph_dir") or ""))
        path = raw if raw.is_absolute() else self.root / raw
        if not (path / "graph.json").exists():
            raise RegistryError(f"graph artifacts missing for {kg_id}: {path}")
        return path

    def public_metadata(self, kg_id: str) -> dict[str, Any]:
        e = self.get(kg_id)
        return {
            "knowledge_graph_id": kg_id,
            "project": e.get("project"),
            "filepath": e.get("filepath"),
            "function_name": e.get("function_name"),
            "split": e.get("split"),
            "resolved_commit_prefix": str(e.get("resolved_commit") or "")[:12],
        }

    def engine(self, kg_id: str) -> tuple[GraphQueryEngine, bool, float]:
        """Return a cached GraphQueryEngine, with (engine, cache_hit, load_seconds)."""
        t0 = time.time()
        if self.engine_cache_size <= 0:
            return GraphQueryEngine(self.graph_dir(kg_id)), False, time.time() - t0
        with self._engine_lock:
            cached = self._engine_cache.get(kg_id)
            if cached is not None:
                self._engine_cache.move_to_end(kg_id)
                return cached, True, time.time() - t0
        engine = GraphQueryEngine(self.graph_dir(kg_id))
        with self._engine_lock:
            self._engine_cache[kg_id] = engine
            self._engine_cache.move_to_end(kg_id)
            while len(self._engine_cache) > self.engine_cache_size:
                self._engine_cache.popitem(last=False)
        return engine, False, time.time() - t0


def compact_result(result: dict[str, Any], diagnostics: dict[str, Any], *, query: dict[str, Any], kg_id: str) -> dict[str, Any]:
    sub = result.get("subgraph") or {}
    nodes = list(sub.get("nodes") or result.get("nodes") or [])
    edges = list(sub.get("edges") or result.get("edges") or [])

    def node_text(n: dict[str, Any]) -> str:
        attrs = n.get("attrs") or {}
        parts = []
        for key in ["code", "label", "name", "function", "file"]:
            if n.get(key):
                parts.append(str(n.get(key)))
        for key in ["description", "evidence_text", "source_text", "fact_type"]:
            if attrs.get(key):
                parts.append(str(attrs.get(key)))
        return "\n".join(dict.fromkeys(parts))[:1000]

    snippets = []
    for n in nodes[:80]:
        text = node_text(n)
        if not text:
            continue
        snippets.append({
            "node_id": n.get("id"),
            "type": n.get("type"),
            "file": n.get("file"),
            "function": n.get("function") or (n.get("name") if n.get("type") == "Function" else query.get("target_function")),
            "line_start": n.get("line_start"),
            "line_end": n.get("line_end"),
            "text": text,
        })
        if len(snippets) >= 25:
            break
    return {
        "schema_version": 1,
        "kg_id": kg_id,
        "query": query,
        "created_at": time.time(),
        "retrieved_node_count": diagnostics.get("retrieved_node_count", len(nodes)),
        "retrieved_edge_count": diagnostics.get("retrieved_edge_count", len(edges)),
        "important_functions": diagnostics.get("important_functions", [])[:25],
        "important_variables": diagnostics.get("important_variables", [])[:40],
        "semantic_fact_count": diagnostics.get("semantic_fact_count"),
        "guard_like_fact_count": diagnostics.get("guard_like_fact_count"),
        "node_type_counts": diagnostics.get("node_type_counts") or {},
        "edge_type_counts": diagnostics.get("edge_type_counts") or {},
        "evidence_summary": diagnostics.get("evidence_summary"),
        "source_snippets": snippets,
        "node_ids": [str(n.get("id")) for n in nodes if n.get("id")][:300],
        "edge_ids": [str(e.get("id")) for e in edges if e.get("id")][:600],
    }


def run_registry_query(
    registry: KGChallengeRegistry,
    kg_id: str,
    query_payload: dict[str, Any],
    *,
    max_nodes: int = 500,
    allowed_kinds: set[str] | None = None,
) -> dict[str, Any]:
    query = parse_codekg_query_object(query_payload)
    if allowed_kinds and query.get("kind") not in allowed_kinds:
        raise ValueError(f"unsupported query kind: {query.get('kind')}")
    query["max_nodes"] = min(int(query.get("max_nodes") or max_nodes), int(max_nodes))
    entry = registry.get(kg_id)
    target = entry.get("function_name")
    if query.get("target_function") and target and str(query.get("target_function")) != str(target):
        raise ValueError(f"kg_id {kg_id} is bound to target_function={target!r}")
    query.setdefault("target_function", target)

    t0 = time.time()
    engine, engine_cache_hit, engine_load_seconds = registry.engine(kg_id)
    result = engine.run(query["kind"], **_engine_kwargs(query))
    diagnostics = normalize_codekg_result(result, query=query, graph_dir=engine.graph_dir)
    if result.get("error"):
        raise RuntimeError(str(result.get("error")))
    out = compact_result(result, diagnostics, query=query, kg_id=kg_id)
    out["timing"] = {
        "total_seconds": round(time.time() - t0, 3),
        "engine_load_seconds": round(engine_load_seconds, 3),
        "engine_cache_hit": bool(engine_cache_hit),
    }
    return out
