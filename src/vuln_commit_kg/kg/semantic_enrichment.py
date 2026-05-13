from __future__ import annotations

import re
from typing import Any

from vuln_commit_kg.utils.hashing import stable_hash

from .graph_store import KGEdge, KGNode, ProjectGraph


_POINTER_ADVANCE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\+\+|--|\+=|-=|=\s*\1\s*[+\-])")
_POINTER_DEREF_RE = re.compile(r"(?:\*\s*([A-Za-z_]\w*)\b|\b([A-Za-z_]\w*)\s*\[\s*[^\]]+\s*\])")
_SIZE_ARITH_RE = re.compile(r"\b([A-Za-z_]\w*(?:len|size|count|n|num|rows|cols|bytes)[A-Za-z_0-9]*)\b.*?[+\-*/%].*?\b([A-Za-z_]\w*|\d+)\b", re.I)
_BOUNDS_RE = re.compile(r"\b(if|while|assert)\s*\([^\)]*(?:<|<=|>|>=|==|!=)[^\)]*(?:len|size|count|n|num|end|limit|capacity|bounds?|rows?|cols?)[^\)]*\)", re.I)
_ALLOC_RE = re.compile(r"\b(malloc|calloc|realloc|new)\s*\(", re.I)
_COPY_RE = re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|memcpy|memmove|strncpy|snprintf|read|recv|fread)\s*\(", re.I)
_ERROR_GUARD_RE = re.compile(r"\b(if|assert)\s*\([^\)]*(?:NULL|nullptr|<\s*0|==\s*0|!\s*[A-Za-z_]|errno|error|fail|invalid)[^\)]*\)", re.I)


FACT_DEFINITIONS = {
    "POINTER_ADVANCE": "Pointer-like variable is advanced or decremented.",
    "POINTER_DEREFERENCE": "Pointer or array-like variable is dereferenced/indexed.",
    "SIZE_ARITHMETIC": "Length/size/count-like value participates in arithmetic.",
    "BOUNDS_CHECK": "Statement appears to check a size, limit, count, bound, or capacity.",
    "ALLOCATION_SIZE": "Allocation statement may connect size arithmetic to memory extent.",
    "RAW_COPY_OR_READ": "Raw copy/read/write API appears in the statement.",
    "ERROR_OR_NULL_GUARD": "Statement appears to guard error/null/invalid cases.",
}


def enrich_project_graph(graph: ProjectGraph, *, mode: str = "heuristic") -> ProjectGraph:
    """Add semantic proof-oriented overlays on top of any imported code graph.

    This is intentionally conservative. It does not claim a full compiler proof;
    it creates explicit, queryable hints that the agent can ask for and that the
    visualization can show: pointer movement, dereference, length arithmetic,
    guard checks, and raw copy/read APIs. A future SVF/PhASAR backend can replace
    or augment these heuristic facts while keeping the same edge vocabulary.
    """
    if not graph.nodes:
        return graph

    existing_nodes = {n.id for n in graph.nodes}
    existing_edges = {(e.source, e.target, e.type, tuple(sorted((e.properties or {}).items()))) for e in graph.edges}

    def add_node(node: KGNode) -> None:
        if node.id not in existing_nodes:
            graph.nodes.append(node)
            existing_nodes.add(node.id)

    def add_edge(edge: KGEdge) -> None:
        key = (edge.source, edge.target, edge.type, tuple(sorted((edge.properties or {}).items())))
        if key not in existing_edges:
            graph.edges.append(edge)
            existing_edges.add(key)

    statement_nodes = [n for n in graph.nodes if n.type.lower() in {"statement", "call", "callexpression", "joernnode"}]
    added_facts = 0

    for node in statement_nodes:
        props = node.properties or {}
        text = str(props.get("text") or props.get("code") or props.get("CODE") or props.get("name") or "")
        if not text.strip():
            continue
        facts: list[tuple[str, dict[str, Any]]] = []
        if _POINTER_ADVANCE_RE.search(text):
            facts.append(("POINTER_ADVANCE", {"symbols": sorted(set(m.group(1) for m in _POINTER_ADVANCE_RE.finditer(text)))[:12]}))
        deref_symbols = sorted(set((m.group(1) or m.group(2)) for m in _POINTER_DEREF_RE.finditer(text) if (m.group(1) or m.group(2))))
        if deref_symbols:
            facts.append(("POINTER_DEREFERENCE", {"symbols": deref_symbols[:12]}))
        if _SIZE_ARITH_RE.search(text):
            facts.append(("SIZE_ARITHMETIC", {"matches": [m.group(0)[:120] for m in _SIZE_ARITH_RE.finditer(text)][:5]}))
        if _BOUNDS_RE.search(text):
            facts.append(("BOUNDS_CHECK", {"matched_guard": _BOUNDS_RE.search(text).group(0)[:200]}))
        if _ALLOC_RE.search(text):
            facts.append(("ALLOCATION_SIZE", {"api": _ALLOC_RE.search(text).group(1)}))
        if _COPY_RE.search(text):
            facts.append(("RAW_COPY_OR_READ", {"api": _COPY_RE.search(text).group(1)}))
        if _ERROR_GUARD_RE.search(text):
            facts.append(("ERROR_OR_NULL_GUARD", {"matched_guard": _ERROR_GUARD_RE.search(text).group(0)[:200]}))

        for fact_type, fact_props in facts:
            fid = f"semantic:{fact_type}:{stable_hash(node.id + ':' + text + ':' + fact_type, 14)}"
            fact = KGNode(fid, "SemanticFact", {
                "fact_type": fact_type,
                "description": FACT_DEFINITIONS[fact_type],
                "source_node": node.id,
                "relpath": props.get("relpath") or props.get("FILENAME") or props.get("filename"),
                "function": props.get("function") or props.get("METHOD_FULL_NAME") or props.get("methodFullName"),
                "line_start": props.get("line_start") or props.get("LINE_NUMBER") or props.get("lineNumber"),
                "line_end": props.get("line_end") or props.get("LINE_NUMBER_END") or props.get("lineNumberEnd"),
                "evidence_text": text[:700],
                "enrichment_mode": mode,
                **fact_props,
            })
            add_node(fact)
            add_edge(KGEdge(node.id, fid, "HAS_SEMANTIC_FACT", {"fact_type": fact_type, "source": mode}))
            add_edge(KGEdge(fid, node.id, "EVIDENCE_FOR", {"source": "semantic_enrichment"}))
            added_facts += 1

    layers = list(graph.manifest.get("layers") or [])
    if "semantic_enrichment" not in layers:
        layers.append("semantic_enrichment")
    graph.manifest.update({
        "semantic_enrichment_enabled": True,
        "semantic_enrichment_mode": mode,
        "num_semantic_facts": added_facts,
        "layers": layers,
    })
    graph.manifest["num_nodes"] = len(graph.nodes)
    graph.manifest["num_edges"] = len(graph.edges)
    return graph
