from __future__ import annotations

import json
import re
from collections import Counter, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .exporter import load_graph_dir

CALL_EDGES = {"CALLS", "CALLS_INDIRECT", "STATEMENT_CALLS"}
DATA_EDGES = {
    "FUNCTION_HAS_PARAMETER", "FUNCTION_HAS_LOCAL", "FILE_HAS_GLOBAL", "USES_VARIABLE", "DEFINES_VARIABLE",
    "USES_GLOBAL", "DEFINES_GLOBAL", "DEF_USE", "DATA_DEPENDS_ON", "USES_FIELD", "DEFINES_FIELD", "ACCESSES_FIELD", "HAS_TYPE", "TYPE_HAS_FIELD"
}
CFG_EDGES = {"FUNCTION_HAS_STATEMENT", "CFG_NEXT", "CONTROLS", "RETURNS"}
AST_EDGES = {"AST_CHILD", "FILE_HAS_FUNCTION", "FUNCTION_HAS_STATEMENT", "FUNCTION_HAS_PARAMETER", "FUNCTION_HAS_LOCAL", "FILE_HAS_GLOBAL", "FILE_HAS_TYPE", "TYPE_HAS_FIELD", "HAS_TYPE"}
SEMANTIC_EDGES = {"HAS_SEMANTIC_FACT", "SEMANTICALLY_RELATED"}
FILE_CONTEXT_EDGES = {"PROJECT_HAS_FILE", "FILE_HAS_FUNCTION", "FILE_HAS_TYPE", "FILE_HAS_MACRO", "FILE_HAS_GLOBAL", "FILE_INCLUDES_FILE", "TYPE_HAS_FIELD", "HAS_TYPE", "AST_CHILD"}
JOERN_EDGES = {"JOERN_OVERLAY", "JOERN_AST", "JOERN_CFG", "JOERN_CDG", "JOERN_DDG", "JOERN_CALL", "JOERN_REACHING_DEF", "JOERN_EDGE"}
GUARD_TERMS = {"bounds", "null", "guard", "check", "sanitizer", "error_return", "return", "size"}
DEFAULT_RISK_TERMS = ["pointer", "array", "bounds", "size", "copy", "read", "write", "allocation", "free", "null", "cast", "return", "guard"]


def _truthy(v: object, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


class GraphQueryEngine:
    """Deterministic retrieval engine for code-KG inspection.

    This is intentionally not a vulnerability classifier. It retrieves the source
    evidence needed to inspect a target function: its body, variables, globals,
    headers/macros/types, semantic facts, call sites, in-project callees, callers,
    and Joern CPG overlay nodes where available.
    """

    def __init__(self, graph_dir: Path) -> None:
        loaded = load_graph_dir(graph_dir)
        self.graph_dir = graph_dir
        self.graph = loaded["graph"]
        self.manifest = loaded["manifest"]
        self.query_examples = loaded["query_examples"]
        self.nodes = self.graph.get("nodes", [])
        self.edges = self.graph.get("edges", [])
        self.node_by_id = {n["id"]: n for n in self.nodes}
        self.out_edges: Dict[str, List[dict]] = {n["id"]: [] for n in self.nodes}
        self.in_edges: Dict[str, List[dict]] = {n["id"]: [] for n in self.nodes}
        self.by_type: Dict[str, List[dict]] = {}
        for n in self.nodes:
            self.by_type.setdefault(n.get("type", ""), []).append(n)
        for e in self.edges:
            self.out_edges.setdefault(e["source"], []).append(e)
            self.in_edges.setdefault(e["target"], []).append(e)

    def find_function(self, name: str) -> Optional[dict]:
        if not name:
            return None
        exact = [n for n in self.nodes if n.get("type") == "Function" and n.get("name") == name and n.get("attrs", {}).get("defined") is not False]
        if exact:
            return exact[0]
        loose = [n for n in self.nodes if n.get("type") == "Function" and n.get("name") == name]
        return loose[0] if loose else None

    def find_file(self, path_like: str) -> Optional[dict]:
        if not path_like:
            return None
        path_like_norm = path_like.replace("\\", "/")
        exact = [n for n in self.nodes if n.get("type") == "File" and n.get("name") == path_like_norm]
        if exact:
            return exact[0]
        suffix = [n for n in self.nodes if n.get("type") == "File" and str(n.get("name", "")).endswith(path_like_norm)]
        return suffix[0] if suffix else None

    def neighborhood(self, seeds: Iterable[str], depth: int = 1, edge_types: Optional[Set[str]] = None, direction: str = "both") -> dict:
        seed_list = [s for s in seeds if s in self.node_by_id]
        seen_nodes: Set[str] = set(seed_list)
        seen_edges: Set[str] = set()
        q = deque((s, 0) for s in seed_list)
        while q:
            nid, d = q.popleft()
            if d >= depth:
                continue
            incident: List[dict] = []
            if direction in {"out", "both"}:
                incident.extend(self.out_edges.get(nid, []))
            if direction in {"in", "both"}:
                incident.extend(self.in_edges.get(nid, []))
            for e in incident:
                if edge_types and e.get("type") not in edge_types:
                    continue
                other = e["target"] if e["source"] == nid else e["source"]
                seen_edges.add(e["id"])
                if other not in seen_nodes:
                    seen_nodes.add(other)
                    q.append((other, d + 1))
        return self._subgraph(seen_nodes, seen_edges)

    def _subgraph(self, node_ids: Set[str], edge_ids: Optional[Set[str]] = None) -> dict:
        if edge_ids is None:
            edge_ids = {e["id"] for e in self.edges if e["source"] in node_ids and e["target"] in node_ids}
        clean_edges = [e for e in self.edges if e["id"] in edge_ids and e["source"] in node_ids and e["target"] in node_ids]
        clean_node_ids = set(node_ids)
        for e in clean_edges:
            clean_node_ids.add(e["source"]); clean_node_ids.add(e["target"])
        return {
            "nodes": [self.node_by_id[nid] for nid in clean_node_ids if nid in self.node_by_id],
            "edges": clean_edges,
        }

    def _add_edge(self, e: dict, ids: Set[str], edge_ids: Set[str]) -> None:
        if e and e.get("source") in self.node_by_id and e.get("target") in self.node_by_id:
            ids.add(e["source"]); ids.add(e["target"]); edge_ids.add(e["id"])

    def _function_file(self, fn: dict) -> Optional[dict]:
        for e in self.in_edges.get(fn["id"], []):
            if e["type"] == "FILE_HAS_FUNCTION":
                return self.node_by_id.get(e["source"])
        if fn.get("file"):
            return self.find_file(fn["file"])
        return None

    def _include_file_context(self, file_node: Optional[dict], ids: Set[str], edge_ids: Set[str], include_headers: bool, include_globals: bool) -> None:
        if not file_node:
            return
        ids.add(file_node["id"])
        for e in self.out_edges.get(file_node["id"], []):
            if e["type"] in {"FILE_HAS_TYPE", "FILE_HAS_MACRO"}:
                self._add_edge(e, ids, edge_ids)
            if include_headers and e["type"] == "FILE_INCLUDES_FILE":
                self._add_edge(e, ids, edge_ids)
            if include_globals and e["type"] == "FILE_HAS_GLOBAL":
                self._add_edge(e, ids, edge_ids)
        # If a file-level type is included, include its fields as scope-correct members.
        for nid in list(ids):
            n = self.node_by_id.get(nid)
            if n and n.get("type") in {"Struct/Class", "Type"}:
                for e in self.out_edges.get(nid, []):
                    if e["type"] in {"TYPE_HAS_FIELD", "AST_CHILD"}:
                        tgt = self.node_by_id.get(e.get("target"))
                        if tgt and tgt.get("type") == "Field":
                            self._add_edge(e, ids, edge_ids)
        for e in self.in_edges.get(file_node["id"], []):
            if e["type"] == "PROJECT_HAS_FILE":
                self._add_edge(e, ids, edge_ids)

    def _include_semantic_evidence(self, fn_name: str, ids: Set[str], edge_ids: Set[str], terms: Optional[List[str]] = None) -> None:
        low_terms = [t.lower() for t in (terms or []) if t]
        for n in self.nodes:
            if n.get("type") != "SemanticFact" or n.get("function") != fn_name:
                continue
            hay = json.dumps(n, ensure_ascii=False).lower()
            if low_terms and not any(t in hay for t in low_terms):
                # Guard facts are always useful in a vulnerability-oriented evidence view.
                if not any(t in hay for t in GUARD_TERMS):
                    continue
            ids.add(n["id"])
            src = n.get("attrs", {}).get("source_node_id")
            if src in self.node_by_id:
                ids.add(src)
            for e in self.in_edges.get(n["id"], []) + self.out_edges.get(n["id"], []):
                if e["type"] in SEMANTIC_EDGES:
                    self._add_edge(e, ids, edge_ids)

    def _include_function_body(self, fn: dict, ids: Set[str], edge_ids: Set[str], *, include_globals: bool, include_joern: bool, risk_terms: Optional[List[str]] = None, joern_limit: int = 160, joern_edge_limit: int = 500) -> None:
        ids.add(fn["id"])
        file_node = self._function_file(fn)
        self._include_file_context(file_node, ids, edge_ids, include_headers=True, include_globals=include_globals)
        for e in self.out_edges.get(fn["id"], []):
            if e["type"] in {"FUNCTION_HAS_PARAMETER", "FUNCTION_HAS_LOCAL", "FUNCTION_HAS_STATEMENT", "AST_CHILD", "RETURNS", "CONTROLS", "SEMANTICALLY_RELATED"}:
                self._add_edge(e, ids, edge_ids)
        # Pull statement-level variable edges, CFG order, call expressions, and semantic evidence.
        body_nodes = list(ids)
        for nid in body_nodes:
            n = self.node_by_id.get(nid)
            if not n or n.get("function") != fn.get("name"):
                continue
            for e in self.out_edges.get(nid, []) + self.in_edges.get(nid, []):
                if e["type"] in CFG_EDGES | DATA_EDGES | SEMANTIC_EDGES | {"AST_CHILD", "STATEMENT_CALLS"}:
                    self._add_edge(e, ids, edge_ids)
        self._include_semantic_evidence(fn.get("name"), ids, edge_ids, risk_terms)
        # Globals used by statements inside this function.
        if include_globals:
            for nid in list(ids):
                n = self.node_by_id.get(nid)
                if not n or n.get("function") != fn.get("name"):
                    continue
                for e in self.out_edges.get(nid, []):
                    if e["type"] in {"USES_GLOBAL", "DEFINES_GLOBAL"}:
                        self._add_edge(e, ids, edge_ids)
        if include_joern:
            self._include_joern_overlay(ids, edge_ids, limit=joern_limit, edge_limit=joern_edge_limit)

    def _include_joern_overlay(self, ids: Set[str], edge_ids: Set[str], limit: int = 160, edge_limit: int = 500) -> None:
        """Include a bounded Joern overlay. Raw Joern exports can be dense enough to swamp
        the evidence slice, so the query layer keeps direct overlays first and then
        a small amount of local Joern-internal structure."""
        if limit <= 0:
            return
        overlay_edges = []
        seed_ids = [nid for nid in list(ids) if self.node_by_id.get(nid, {}).get("type") != "JoernCPGNode"]
        for nid in seed_ids:
            for e in self.out_edges.get(nid, []) + self.in_edges.get(nid, []):
                if e["type"] == "JOERN_OVERLAY":
                    other = e["target"] if e["source"] == nid else e["source"]
                    if self.node_by_id.get(other, {}).get("type") == "JoernCPGNode":
                        overlay_edges.append(e)
        overlay_edges.sort(key=lambda e: self._joern_priority(self.node_by_id.get(e["source"]), self.node_by_id.get(e["target"])), reverse=True)
        joern_ids: Set[str] = set()
        for e in overlay_edges:
            other = e["source"] if self.node_by_id.get(e["source"], {}).get("type") == "JoernCPGNode" else e["target"]
            if other not in joern_ids and len(joern_ids) >= limit:
                continue
            joern_ids.add(other)
            self._add_edge(e, ids, edge_ids)
        added = 0
        for nid in list(joern_ids):
            if added >= edge_limit:
                break
            for e in self.out_edges.get(nid, []) + self.in_edges.get(nid, []):
                if added >= edge_limit:
                    break
                if e["type"] in JOERN_EDGES and e["type"] != "JOERN_OVERLAY" and e["source"] in joern_ids and e["target"] in joern_ids:
                    self._add_edge(e, ids, edge_ids)
                    added += 1

    def _joern_priority(self, a: Optional[dict], b: Optional[dict]) -> int:
        n = a if a and a.get("type") == "JoernCPGNode" else b
        hay = json.dumps(n or {}, ensure_ascii=False).lower()
        score = 0
        for term, val in [("method", 8), ("function", 8), ("call", 7), ("identifier", 6), ("local", 6), ("control", 5), ("return", 5), ("assignment", 4), ("operator", 4), ("literal", 1)]:
            if term in hay:
                score += val
        return score

    def _trim_ids_for_visualization(self, ids: Set[str], edge_ids: Set[str], target_id: str, max_nodes: int) -> tuple[Set[str], Set[str]]:
        priority = sorted(ids, key=lambda nid: self._node_score_for_slice(self.node_by_id.get(nid), target_id), reverse=True)
        kept = set(priority[:max_nodes])
        kept.add(target_id)
        edge_by_id = {e["id"]: e for e in self.edges}
        kept_edges = {eid for eid in edge_ids if (edge_by_id.get(eid, {}).get("source") in kept and edge_by_id.get(eid, {}).get("target") in kept)}
        return kept, kept_edges

    def _node_score_for_slice(self, n: Optional[dict], target_id: str) -> int:
        if not n:
            return 0
        if n.get("id") == target_id:
            return 10000
        t = n.get("type") or ""
        table = {
            "Function": 220, "FunctionParameter": 180, "LocalVariable": 180, "GlobalVariable": 180, "Field": 170,
            "Condition": 150, "Loop": 150, "ReturnStatement": 150, "Assignment": 150, "CallExpression": 150, "Statement": 140,
            "SemanticFact": 140, "File": 110, "Include": 100, "Macro": 100, "Type": 100, "Struct/Class": 100,
            "JoernCPGNode": 50,
        }
        deg = len(self.out_edges.get(n.get("id"), [])) + len(self.in_edges.get(n.get("id"), []))
        return table.get(t, 20) + min(40, deg)

    def function_context(self, target_function: str, depth: int = 2) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        result = self.neighborhood([fn["id"]], depth=depth, direction="both")
        return self._with_meta(result, "function_context", {"target_function": target_function, "depth": depth})

    def call_neighborhood(self, target_function: str, direction: str = "both", depth: int = 2) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        result = self.neighborhood([fn["id"]], depth=depth, edge_types=CALL_EDGES, direction=direction)
        return self._with_meta(result, "call_neighborhood", {"target_function": target_function, "direction": direction, "depth": depth})

    def semantic_facts(self, target_function: str) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        ids = {fn["id"]}; edge_ids: Set[str] = set()
        self._include_semantic_evidence(target_function, ids, edge_ids, None)
        result = self._subgraph(ids, edge_ids)
        return self._with_meta(result, "semantic_facts", {"target_function": target_function})

    def variable_flow(self, target_function: str, symbol: str, depth: int = 3) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        var_nodes = [n for n in self.nodes if n.get("function") == target_function and n.get("name") == symbol and n.get("type") in {"LocalVariable", "FunctionParameter", "GlobalVariable", "Field"}]
        if not var_nodes:
            # If not local, try global/header variables with same symbol.
            var_nodes = [n for n in self.nodes if n.get("name") == symbol and n.get("type") == "GlobalVariable"]
        if not var_nodes:
            return self._empty(f"symbol not found near {target_function}: {symbol}")
        result = self.neighborhood([n["id"] for n in var_nodes], depth=depth, edge_types=DATA_EDGES | {"FUNCTION_HAS_STATEMENT", "FILE_HAS_GLOBAL"}, direction="both")
        return self._with_meta(result, "variable_flow", {"target_function": target_function, "symbol": symbol, "depth": depth})

    def risk_slice(self, target_function: str, risk_terms: List[str]) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        terms = [t.lower() for t in (risk_terms or DEFAULT_RISK_TERMS)]
        ids = {fn["id"]}; edge_ids: Set[str] = set()
        self._include_function_body(fn, ids, edge_ids, include_globals=True, include_joern=False, risk_terms=terms)
        # Keep only target function, evidence statements, calls, variables, and matching semantic facts.
        keep_types = {"Function", "FunctionParameter", "LocalVariable", "GlobalVariable", "Field", "Struct/Class", "Statement", "Assignment", "ReturnStatement", "Condition", "Loop", "CallExpression", "SemanticFact"}
        for nid in list(ids):
            n = self.node_by_id.get(nid)
            if not n:
                ids.discard(nid); continue
            hay = json.dumps(n, ensure_ascii=False).lower()
            if n.get("type") == "SemanticFact" and not any(t in hay for t in terms):
                ids.discard(nid)
            elif n.get("type") not in keep_types:
                ids.discard(nid)
        edge_ids = {e["id"] for e in self.edges if e["source"] in ids and e["target"] in ids}
        result = self._subgraph(ids, edge_ids)
        return self._with_meta(result, "risk_slice", {"target_function": target_function, "risk_terms": terms})

    def security_context(
        self,
        target_function: str,
        depth: int = 3,
        call_depth: int = 2,
        data_depth: int = 4,
        include_callers: bool = True,
        include_headers: bool = True,
        include_globals: bool = True,
        include_joern: bool = True,
        joern_limit: int = 160,
        joern_edge_limit: int = 500,
        max_nodes: int = 520,
        risk_terms: Optional[List[str]] = None,
    ) -> dict:
        """Retrieve vulnerability-relevant context without making a vulnerability decision."""
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        risk_terms = risk_terms or DEFAULT_RISK_TERMS
        ids: Set[str] = set(); edge_ids: Set[str] = set()
        functions_seen: Set[str] = set()
        callees_seen: Set[str] = set(); callers_seen: Set[str] = set(); external_seen: Set[str] = set()

        def include_fn(fn_node: dict) -> None:
            functions_seen.add(fn_node.get("name") or fn_node["id"])
            self._include_function_body(fn_node, ids, edge_ids, include_globals=include_globals, include_joern=include_joern, risk_terms=risk_terms, joern_limit=joern_limit, joern_edge_limit=joern_edge_limit)
            if include_headers:
                self._include_file_context(self._function_file(fn_node), ids, edge_ids, include_headers=True, include_globals=include_globals)

        include_fn(fn)
        q = deque([(fn, 0)])
        visited_fn_ids = {fn["id"]}
        while q:
            cur, d = q.popleft()
            if d >= call_depth:
                continue
            for e in self.out_edges.get(cur["id"], []):
                if e["type"] not in {"CALLS", "CALLS_INDIRECT"}:
                    continue
                self._add_edge(e, ids, edge_ids)
                target = self.node_by_id.get(e["target"])
                if not target:
                    continue
                # Include call-site statement if the builder knows it.
                via = e.get("attrs", {}).get("via_statement")
                if via in self.node_by_id:
                    ids.add(via)
                if e["type"] == "CALLS_INDIRECT":
                    # A scoped callable variable/function pointer is evidence, but it is
                    # not an external or unresolved function.
                    ids.add(target["id"])
                    continue
                if target.get("type") == "Function" and target.get("attrs", {}).get("defined") is not False:
                    callees_seen.add(target.get("name") or target["id"])
                    include_fn(target)
                    if target["id"] not in visited_fn_ids:
                        visited_fn_ids.add(target["id"])
                        q.append((target, d + 1))
                else:
                    external_seen.add(target.get("name") or target.get("label") or target["id"])
        if include_callers:
            for e in self.in_edges.get(fn["id"], []):
                if e["type"] == "CALLS":
                    src = self.node_by_id.get(e["source"])
                    self._add_edge(e, ids, edge_ids)
                    if src and src.get("type") == "Function" and src.get("attrs", {}).get("defined") is not False:
                        callers_seen.add(src.get("name") or src["id"])
                        include_fn(src)

        # Extra data-flow expansion from already selected variables/statements.
        data_seeds = [nid for nid in ids if self.node_by_id.get(nid, {}).get("type") in {"FunctionParameter", "LocalVariable", "GlobalVariable", "Field", "Statement", "Assignment", "ReturnStatement", "Condition", "Loop"}]
        data_sub = self.neighborhood(data_seeds[:250], depth=min(max(data_depth, 1), 6), edge_types=DATA_EDGES | {"FUNCTION_HAS_STATEMENT", "CFG_NEXT", "HAS_SEMANTIC_FACT"}, direction="both")
        for n in data_sub["nodes"]:
            ids.add(n["id"])
        for e in data_sub["edges"]:
            edge_ids.add(e["id"])
        if include_joern:
            self._include_joern_overlay(ids, edge_ids, limit=joern_limit, edge_limit=joern_edge_limit)

        full_node_count, full_edge_count = len(ids), len(edge_ids)
        if max_nodes and len(ids) > max_nodes:
            ids, edge_ids = self._trim_ids_for_visualization(ids, edge_ids, fn["id"], max_nodes)
        result = self._subgraph(ids, edge_ids)
        result.setdefault("meta", {})["full_node_count"] = full_node_count
        result.setdefault("meta", {})["full_edge_count"] = full_edge_count
        result.setdefault("meta", {})["visual_trimmed"] = full_node_count > len(ids)
        evidence = self._summarize_security_context(result, target_function, callees_seen, callers_seen, external_seen, risk_terms)
        out = self._with_meta(result, "security_context", {
            "target_function": target_function,
            "depth": depth,
            "call_depth": call_depth,
            "data_depth": data_depth,
            "include_callers": include_callers,
            "include_headers": include_headers,
            "include_globals": include_globals,
            "include_joern": include_joern,
            "joern_limit": joern_limit,
            "joern_edge_limit": joern_edge_limit,
            "max_nodes": max_nodes,
            "risk_terms": risk_terms,
        })
        out["evidence_summary"] = evidence
        out["full_node_count"] = full_node_count
        out["full_edge_count"] = full_edge_count
        out["visual_trimmed"] = full_node_count > len(ids)
        return out

    def _summarize_security_context(self, subgraph: dict, target_function: str, callees: Set[str], callers: Set[str], external: Set[str], terms: List[str]) -> dict:
        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])
        node_types = Counter(n.get("type") for n in nodes)
        edge_types = Counter(e.get("type") for e in edges)
        facts = [n for n in nodes if n.get("type") == "SemanticFact"]
        guards = [n for n in facts if any(t in json.dumps(n, ensure_ascii=False).lower() for t in GUARD_TERMS)]
        variables = sorted({n.get("name") for n in nodes if n.get("type") in {"FunctionParameter", "LocalVariable", "GlobalVariable", "Field"} and n.get("name")})
        functions = sorted({n.get("name") for n in nodes if n.get("type") == "Function" and n.get("name")})
        joern_nodes = [n for n in nodes if n.get("type") == "JoernCPGNode"]
        return {
            "target_function": target_function,
            "retrieved_functions": functions,
            "in_project_callees_followed": sorted(callees),
            "callers_included": sorted(callers),
            "external_or_unresolved_calls_included": sorted(external),
            "variables_included": variables[:100],
            "semantic_fact_count": len(facts),
            "guard_like_fact_count": len(guards),
            "joern_overlay_nodes": len(joern_nodes),
            "node_type_counts": dict(node_types),
            "edge_type_counts": dict(edge_types),
            "risk_terms": terms,
            "note": "Retrieval evidence only. This query does not classify the function as vulnerable or safe.",
        }

    def file_context(self, file: str, depth: int = 2) -> dict:
        fnode = self.find_file(file)
        if not fnode:
            return self._empty(f"file not found: {file}")
        result = self.neighborhood([fnode["id"]], depth=depth, direction="both")
        return self._with_meta(result, "file_context", {"file": file, "depth": depth})

    def callers(self, target_function: str) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        ids = {fn["id"]}; edge_ids = set()
        for e in self.in_edges.get(fn["id"], []):
            if e["type"] in {"CALLS", "CALLS_INDIRECT"}:
                ids.add(e["source"]); edge_ids.add(e["id"])
        return self._with_meta(self._subgraph(ids, edge_ids), "callers", {"target_function": target_function})

    def callees(self, target_function: str) -> dict:
        fn = self.find_function(target_function)
        if not fn:
            return self._empty(f"function not found: {target_function}")
        ids = {fn["id"]}; edge_ids = set()
        for e in self.out_edges.get(fn["id"], []):
            if e["type"] in {"CALLS", "CALLS_INDIRECT"}:
                ids.add(e["target"]); edge_ids.add(e["id"])
        return self._with_meta(self._subgraph(ids, edge_ids), "callees", {"target_function": target_function})

    def shortest_path(self, source_node: str, target_node: str) -> dict:
        if source_node not in self.node_by_id or target_node not in self.node_by_id:
            return self._empty("source or target node not found")
        q = deque([source_node]); prev = {source_node: None}; prev_edge = {}
        while q:
            nid = q.popleft()
            if nid == target_node:
                break
            for e in self.out_edges.get(nid, []) + self.in_edges.get(nid, []):
                other = e["target"] if e["source"] == nid else e["source"]
                if other not in prev:
                    prev[other] = nid; prev_edge[other] = e["id"]; q.append(other)
        if target_node not in prev:
            return self._empty("no path found")
        ids = set(); edge_ids = set(); cur = target_node
        while cur:
            ids.add(cur)
            if cur in prev_edge: edge_ids.add(prev_edge[cur])
            cur = prev[cur]
        return self._with_meta(self._subgraph(ids, edge_ids), "shortest_path", {"source_node": source_node, "target_node": target_node})

    def run(self, kind: str, **kwargs) -> dict:
        kind = (kind or "").strip().lower()
        if kind == "function_context":
            return self.function_context(kwargs.get("target_function") or kwargs.get("target"), int(kwargs.get("depth") or 2))
        if kind == "call_neighborhood":
            return self.call_neighborhood(kwargs.get("target_function") or kwargs.get("target"), kwargs.get("direction") or "both", int(kwargs.get("depth") or 2))
        if kind == "semantic_facts":
            return self.semantic_facts(kwargs.get("target_function") or kwargs.get("target"))
        if kind == "variable_flow":
            return self.variable_flow(kwargs.get("target_function") or kwargs.get("target"), kwargs.get("symbol"), int(kwargs.get("depth") or 3))
        if kind == "risk_slice":
            terms = kwargs.get("risk_terms") or []
            if isinstance(terms, str): terms = [x.strip() for x in terms.split(",") if x.strip()]
            return self.risk_slice(kwargs.get("target_function") or kwargs.get("target"), terms)
        if kind in {"security_context", "vulnerability_context", "evidence_slice"}:
            terms = kwargs.get("risk_terms") or DEFAULT_RISK_TERMS
            if isinstance(terms, str): terms = [x.strip() for x in terms.split(",") if x.strip()]
            return self.security_context(
                kwargs.get("target_function") or kwargs.get("target"),
                depth=int(kwargs.get("depth") or 3),
                call_depth=int(kwargs.get("call_depth") or kwargs.get("callDepth") or 2),
                data_depth=int(kwargs.get("data_depth") or kwargs.get("dataDepth") or 4),
                include_callers=_truthy(kwargs.get("include_callers"), True),
                include_headers=_truthy(kwargs.get("include_headers"), True),
                include_globals=_truthy(kwargs.get("include_globals"), True),
                include_joern=_truthy(kwargs.get("include_joern"), True),
                joern_limit=int(kwargs.get("joern_limit") or kwargs.get("joernLimit") or 160),
                joern_edge_limit=int(kwargs.get("joern_edge_limit") or kwargs.get("joernEdgeLimit") or 500),
                max_nodes=int(kwargs.get("max_nodes") or kwargs.get("maxNodes") or 520),
                risk_terms=terms,
            )
        if kind == "file_context":
            return self.file_context(kwargs.get("file"), int(kwargs.get("depth") or 2))
        if kind == "callers":
            return self.callers(kwargs.get("target_function") or kwargs.get("target"))
        if kind == "callees":
            return self.callees(kwargs.get("target_function") or kwargs.get("target"))
        if kind == "shortest_path":
            return self.shortest_path(kwargs.get("source_node"), kwargs.get("target_node"))
        return self._empty(f"unsupported query kind: {kind}")

    @staticmethod
    def parse_query_text(text: str) -> Tuple[str, Dict[str, object]]:
        """Parse dashboard-style query text into a deterministic query invocation."""
        raw = (text or "").strip()
        if not raw:
            return "security_context", {}
        kind = "security_context"
        args: Dict[str, object] = {}
        m = re.match(r"\s*([A-Za-z_][\w]*)\s*\((.*)\)\s*$", raw, flags=re.S)
        if m:
            kind = m.group(1)
            body = m.group(2)
            for part in re.split(r",\s*(?![^\[]*\])", body):
                if not part.strip():
                    continue
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = k.strip().strip("- ")
                    v = v.strip().strip('"\'')
                    if v.startswith("[") and v.endswith("]"):
                        args[k] = [x.strip().strip('"\'') for x in v[1:-1].split(",") if x.strip()]
                    else:
                        args[k] = v
                else:
                    args.setdefault("target_function", part.strip().strip('"\''))
            return kind, args
        # key=value text or natural-ish text.
        for k, v in re.findall(r"([A-Za-z_][\w-]*)\s*=\s*([\w./\\:-]+)", raw):
            args[k.replace("-", "_")] = v
        if "target_function" not in args and "function" not in args and "target" not in args:
            words = re.findall(r"[A-Za-z_]\w*", raw)
            for w in words:
                if w not in {"show", "retrieve", "context", "vulnerability", "security", "for", "function", "target", "with", "called", "calls"}:
                    args["target_function"] = w
                    break
        if "function" in args and "target_function" not in args:
            args["target_function"] = args.pop("function")
        return kind, args

    def _with_meta(self, subgraph: dict, kind: str, args: dict) -> dict:
        return {
            "kind": kind,
            "args": args,
            "node_count": len(subgraph.get("nodes", [])),
            "edge_count": len(subgraph.get("edges", [])),
            "subgraph": subgraph,
        }

    def _empty(self, message: str) -> dict:
        return {"error": message, "node_count": 0, "edge_count": 0, "subgraph": {"nodes": [], "edges": []}}
