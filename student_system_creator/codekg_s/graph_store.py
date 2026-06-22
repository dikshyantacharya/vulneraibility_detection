from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Edge, Node


class GraphStore:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, Edge] = {}
        self.name_index: Dict[Tuple[str, str, Optional[str]], str] = {}
        self.node_type_counts: Counter[str] = Counter()
        self.edge_type_counts: Counter[str] = Counter()

    def add_node(self, node: Node) -> str:
        existing = self.nodes.get(node.id)
        if existing:
            # Merge non-empty metadata without destroying earlier evidence.
            for field_name in ("name", "file", "function", "line_start", "line_end", "code"):
                if getattr(existing, field_name) in (None, "") and getattr(node, field_name) not in (None, ""):
                    setattr(existing, field_name, getattr(node, field_name))
            existing.attrs.update({k: v for k, v in node.attrs.items() if v is not None})
            return node.id
        self.nodes[node.id] = node
        self.node_type_counts[node.type] += 1
        if node.name:
            self.name_index[(node.type, node.name, node.file)] = node.id
            self.name_index[(node.type, node.name, None)] = node.id
        return node.id

    def add_edge(self, edge: Edge) -> str:
        if edge.source == edge.target and edge.type not in {"CALLS", "AST_CHILD"}:
            edge.attrs.setdefault("quality_warning", "self_edge")
        if edge.id in self.edges:
            self.edges[edge.id].attrs.update({k: v for k, v in edge.attrs.items() if v is not None})
            return edge.id
        if edge.source not in self.nodes or edge.target not in self.nodes:
            # keep graph consistent; dangling edges are quality issues and not stored
            return ""
        self.edges[edge.id] = edge
        self.edge_type_counts[edge.type] += 1
        return edge.id

    def find_node(self, node_type: str, name: str, file: Optional[str] = None) -> Optional[str]:
        return self.name_index.get((node_type, name, file)) or self.name_index.get((node_type, name, None))

    def nodes_list(self) -> List[dict]:
        return [n.to_dict() for n in self.nodes.values()]

    def edges_list(self) -> List[dict]:
        return [e.to_dict() for e in self.edges.values()]

    def degree(self) -> Counter[str]:
        c: Counter[str] = Counter()
        for e in self.edges.values():
            c[e.source] += 1
            c[e.target] += 1
        return c

    def adjacency(self, edge_types: Optional[Iterable[str]] = None) -> Dict[str, List[str]]:
        allowed = set(edge_types) if edge_types else None
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in self.edges.values():
            if allowed and e.type not in allowed:
                continue
            adj[e.source].append(e.target)
            adj[e.target].append(e.source)
        return adj
