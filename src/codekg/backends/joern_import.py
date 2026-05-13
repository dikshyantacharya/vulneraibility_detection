from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from ..graph_store import GraphStore
from ..models import Edge, Node, stable_id

JOERN_EDGE_MAP = {
    "AST": "JOERN_AST",
    "CFG": "JOERN_CFG",
    "CDG": "JOERN_CDG",
    "DDG": "JOERN_DDG",
    "CALL": "JOERN_CALL",
    "CALLS": "JOERN_CALL",
    "REACHING_DEF": "JOERN_REACHING_DEF",
    "REACHING_DEFINITION": "JOERN_REACHING_DEF",
}


def _clean(v):
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    return html.unescape(str(v)).strip()


def _first(attrs: dict, *keys: str):
    lower = {str(k).lower(): k for k in attrs.keys()}
    for k in keys:
        actual = lower.get(k.lower())
        if actual is not None and attrs.get(actual) not in (None, ""):
            return _clean(attrs.get(actual))
    return None


def _to_int(v) -> Optional[int]:
    if v in (None, ""):
        return None
    m = re.search(r"\d+", str(v))
    return int(m.group(0)) if m else None


def _norm_file(value, source_dir: Path) -> Optional[str]:
    if not value:
        return None
    s = str(value).replace("\\", "/")
    root = str(source_dir).replace("\\", "/")
    if s.startswith(root):
        s = s[len(root):].lstrip("/")
    return s or None


def _joern_node_type(label: Optional[str]) -> str:
    # Keep a single public node type so the dashboard can enable/disable the Joern layer easily.
    return "JoernCPGNode"


def _edge_type(label: Optional[str], repr_name: str = "") -> str:
    raw = (label or repr_name or "EDGE").upper().replace("-", "_").replace(" ", "_")
    return JOERN_EDGE_MAP.get(raw, "JOERN_EDGE")


def _register_overlay(graph: GraphStore, joern_id: str, attrs: dict, source_dir: Path) -> int:
    """Connect Joern nodes to normalized CodeKG nodes by function name and/or source line."""
    added = 0
    label = str(_first(attrs, "LABEL", "label", "_label") or "").upper()
    name = _first(attrs, "NAME", "name", "FULL_NAME", "METHOD_FULL_NAME")
    file = _norm_file(_first(attrs, "FILENAME", "filename", "FILE", "file"), source_dir)
    line = _to_int(_first(attrs, "LINE_NUMBER", "lineNumber", "line", "LINE"))
    # Function/method overlay.
    if name and label in {"METHOD", "FUNCTION", "METHOD_PARAMETER_IN", "METHOD_RETURN"}:
        short = str(name).split(".")[-1].split("::")[-1]
        for n in graph.nodes.values():
            if n.type == "Function" and n.name in {name, short}:
                graph.add_edge(Edge(n.id, joern_id, "JOERN_OVERLAY", attrs={"match": "function_name", "joern_label": label}))
                added += 1
                break
    # File/line overlay for statements, facts, and variables.
    if file and line:
        candidates = []
        for n in graph.nodes.values():
            if n.file and (n.file == file or str(n.file).endswith(file) or file.endswith(str(n.file))):
                if n.line_start and n.line_end and int(n.line_start) <= line <= int(n.line_end):
                    candidates.append(n)
        # Prefer executable nodes over file/comment nodes.
        priority = {"Function": 0, "Statement": 1, "Assignment": 1, "ReturnStatement": 1, "Condition": 1, "Loop": 1, "CallExpression": 2, "LocalVariable": 3, "FunctionParameter": 3, "GlobalVariable": 3, "SemanticFact": 4}
        candidates.sort(key=lambda n: priority.get(n.type, 9))
        for n in candidates[:3]:
            graph.add_edge(Edge(n.id, joern_id, "JOERN_OVERLAY", attrs={"match": "file_line", "joern_label": label, "line": line}))
            added += 1
    return added


def _read_graphml(path: Path):
    import networkx as nx
    try:
        return nx.read_graphml(path)
    except Exception:
        return None


def _ingest_graphml(graph: GraphStore, path: Path, source_dir: Path, max_nodes: int, max_edges: int) -> Tuple[int, int, int]:
    g = _read_graphml(path)
    if g is None:
        return 0, 0, 0
    node_map: Dict[str, str] = {}
    added_nodes = added_edges = overlays = 0
    repr_name = path.stem
    for raw_id, attrs in list(g.nodes(data=True))[:max_nodes]:
        attrs = {str(k): _clean(v) for k, v in dict(attrs).items()}
        label = _first(attrs, "LABEL", "label", "_label", "node_label")
        name = _first(attrs, "NAME", "name", "FULL_NAME", "METHOD_FULL_NAME", "CODE", "code") or str(raw_id)
        code = _first(attrs, "CODE", "code")
        file = _norm_file(_first(attrs, "FILENAME", "filename", "FILE", "file"), source_dir)
        line = _to_int(_first(attrs, "LINE_NUMBER", "lineNumber", "line", "LINE"))
        line_end = _to_int(_first(attrs, "LINE_NUMBER_END", "lineNumberEnd", "line_end", "LINE_END")) or line
        jid = stable_id("joern", str(path), raw_id)
        node_map[str(raw_id)] = jid
        graph.add_node(Node(
            id=jid,
            type=_joern_node_type(label),
            label=f"{label or 'CPG'}:{str(name)[:48]}",
            name=str(name)[:200] if name is not None else None,
            file=file,
            line_start=line,
            line_end=line_end,
            code=code,
            attrs={"joern_id": str(raw_id), "joern_label": label, "joern_repr": repr_name, "source_backend": "joern", **attrs},
        ))
        overlays += _register_overlay(graph, jid, attrs, source_dir)
        added_nodes += 1
    for u, v, attrs in list(g.edges(data=True))[:max_edges]:
        sid, tid = node_map.get(str(u)), node_map.get(str(v))
        if not sid or not tid:
            continue
        attrs = {str(k): _clean(vv) for k, vv in dict(attrs).items()}
        label = _first(attrs, "label", "LABEL", "edge_label", "EDGE_LABEL")
        etype = _edge_type(label, repr_name)
        if graph.add_edge(Edge(sid, tid, etype, attrs={"joern_repr": repr_name, "joern_edge_label": label, "source_backend": "joern", **attrs})):
            added_edges += 1
    return added_nodes, added_edges, overlays


def _parse_dot_attrs(text: str) -> dict:
    out = {}
    # Handles label="..." and label=<...> sufficiently for Joern DOT exports.
    for key, val1, val2 in re.findall(r"(\w+)\s*=\s*(?:\"((?:\\.|[^\"])*)\"|<([^>]*)>)", text):
        val = val1 or val2
        val = val.replace('\\"', '"').replace('\\n', '\n')
        out[key] = _clean(re.sub(r"<[^>]+>", " ", val))
    return out


def _ingest_dot(graph: GraphStore, path: Path, source_dir: Path, max_nodes: int, max_edges: int) -> Tuple[int, int, int]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    local_nodes: Dict[str, dict] = {}
    for m in re.finditer(r"^\s*\"?([^\"\s\[;]+)\"?\s*\[(.*?)\]\s*;?\s*$", text, flags=re.M | re.S):
        raw_id = m.group(1)
        attrs = _parse_dot_attrs(m.group(2))
        if raw_id in {"node", "edge", "graph"} or "->" in raw_id:
            continue
        local_nodes[raw_id] = attrs
        if len(local_nodes) >= max_nodes:
            break
    node_map: Dict[str, str] = {}
    repr_name = path.parent.name if path.parent.name != "export" else path.stem
    added_nodes = added_edges = overlays = 0
    for raw_id, attrs in local_nodes.items():
        label_text = _first(attrs, "label", "LABEL") or ""
        # Joern DOT labels often embed the node type as the first token/line.
        label = None
        first_line = str(label_text).splitlines()[0] if label_text else ""
        m = re.match(r"([A-Z_][A-Z0-9_]*)", first_line)
        if m:
            label = m.group(1)
        code = label_text
        name = first_line or raw_id
        jid = stable_id("joern", str(path), raw_id)
        node_map[raw_id] = jid
        graph.add_node(Node(
            id=jid,
            type="JoernCPGNode",
            label=f"{label or 'CPG'}:{str(name)[:48]}",
            name=str(name)[:200],
            code=code,
            attrs={"joern_id": raw_id, "joern_label": label, "joern_repr": repr_name, "source_backend": "joern", **attrs},
        ))
        overlays += _register_overlay(graph, jid, attrs, source_dir)
        added_nodes += 1
    edge_pattern = re.compile(r"^\s*\"?([^\"\s\[]+)\"?\s*->\s*\"?([^\"\s\[]+)\"?\s*(?:\[(.*?)\])?\s*;?\s*$", flags=re.M | re.S)
    for m in edge_pattern.finditer(text):
        if added_edges >= max_edges:
            break
        sid, tid = node_map.get(m.group(1)), node_map.get(m.group(2))
        if not sid or not tid:
            continue
        attrs = _parse_dot_attrs(m.group(3) or "")
        label = _first(attrs, "label", "LABEL")
        etype = _edge_type(label, repr_name)
        if graph.add_edge(Edge(sid, tid, etype, attrs={"joern_repr": repr_name, "joern_edge_label": label, "source_backend": "joern", **attrs})):
            added_edges += 1
    return added_nodes, added_edges, overlays


def ingest_joern_export(graph: GraphStore, export_dir: Path, source_dir: Path, logger, max_nodes: int = 6000, max_edges: int = 24000) -> dict:
    """Import Joern-exported GraphML/DOT artifacts into the normalized dashboard graph.

    Joern export layouts vary by version and command flags. This importer is
    intentionally defensive: it ingests GraphML when available and otherwise DOT
    files, attaches source metadata when present, and creates JOERN_OVERLAY edges
    to normalized CodeKG nodes by function name and file/line evidence.
    """
    stats = {"files": 0, "nodes": 0, "edges": 0, "overlays": 0, "errors": []}
    if not export_dir.exists():
        return stats
    graphml_files = list(export_dir.rglob("*.graphml")) + list(export_dir.rglob("*.xml"))
    dot_files = list(export_dir.rglob("*.dot"))
    files: Iterable[Path] = graphml_files or dot_files
    for path in files:
        if stats["nodes"] >= max_nodes or stats["edges"] >= max_edges:
            break
        try:
            if path.suffix.lower() in {".graphml", ".xml"}:
                n, e, o = _ingest_graphml(graph, path, source_dir, max_nodes - stats["nodes"], max_edges - stats["edges"])
            else:
                n, e, o = _ingest_dot(graph, path, source_dir, max_nodes - stats["nodes"], max_edges - stats["edges"])
            if n or e:
                stats["files"] += 1
                stats["nodes"] += n
                stats["edges"] += e
                stats["overlays"] += o
        except Exception as exc:  # defensive by design; Joern export formats vary
            stats["errors"].append({"file": str(path), "error": str(exc)})
            if logger:
                logger.warning("Failed to ingest Joern export %s: %s", path, exc)
    if logger:
        logger.info("Joern export ingestion: files=%d nodes=%d edges=%d overlays=%d errors=%d", stats["files"], stats["nodes"], stats["edges"], stats["overlays"], len(stats["errors"]))
    return stats
