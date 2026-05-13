from __future__ import annotations

import re

from vuln_commit_kg.config import RetrievalConfig
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_store import KGNode, ProjectGraph

from .evidence import EvidenceItem, EvidencePack
from .target_locator import TargetLocator


def _strip_c_comments_and_literals(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.S)
    text = re.sub(r"//.*", " ", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


class EvidenceRetriever:
    def __init__(self, cfg: RetrievalConfig):
        self.cfg = cfg
        self.locator = TargetLocator()

    def retrieve(self, graph: ProjectGraph, sample: SecVulEvalSample) -> EvidencePack:
        target, diag = self.locator.locate(graph, sample)
        pack = EvidencePack(
            sample_id=sample.sample_id,
            target_node_id=target.id if target else None,
            target_found=target is not None,
            retrieval_diagnostics=diag,
        )
        if not target:
            pack.summary = "Target function was not found in the project KG; evidence falls back to dataset function body only."
            pack.items.append(
                EvidenceItem(
                    evidence_id="E_TARGET_BODY",
                    kind="target_body_fallback",
                    text=sample.func_body,
                    function=sample.func_name,
                    relpath=sample.filepath,
                    score=0.5,
                )
            )
            return pack

        nodes = graph.node_by_id()
        target_props = target.properties
        pack.summary = (
            f"Target function: {target_props.get('name')} in {target_props.get('relpath')} "
            f"lines {target_props.get('line_start')}-{target_props.get('line_end')}."
        )
        ev_id = 1

        # Target statements.
        stmt_edges = graph.out_edges(target.id, "FUNCTION_HAS_STATEMENT")
        stmt_nodes = [nodes[e.target] for e in stmt_edges if e.target in nodes]
        for stmt in stmt_nodes[: self.cfg.top_k_statements]:
            props = stmt.properties
            score = 1.0
            kind = "target_statement"
            if props.get("risk_hits"):
                kind = "target_risk_statement"
                score = 2.0
            elif props.get("is_safety"):
                kind = "target_safety_statement"
                score = 1.3
            pack.items.append(self._item(ev_id, kind, stmt, score))
            ev_id += 1

        added_ids = {i.node_id for i in pack.items}

        # High-value source-only path evidence that can be missed by the first top-k
        # statements in long target functions. This is especially important for
        # upload/configuration read loops where exploitability depends on bounds,
        # counters, and post-read writes rather than a single risky API name.
        for stmt in self._target_security_path_statements(stmt_nodes):
            if stmt.id in added_ids:
                continue
            pack.items.append(self._item(ev_id, "target_upload_or_bounds_path_statement", stmt, 1.75))
            added_ids.add(stmt.id)
            ev_id += 1

        for definition in self._macro_definitions_for_target(graph, stmt_nodes):
            if definition.id in added_ids:
                continue
            pack.items.append(self._definition_item(ev_id, definition, 1.95))
            added_ids.add(definition.id)
            ev_id += 1

        # Risk statements inside target first, then project-wide risk if risk_first.
        risk_stmts = [s for s in stmt_nodes if s.properties.get("risk_hits")]
        for stmt in risk_stmts[: self.cfg.top_k_risk]:
            if stmt.id in added_ids:
                continue
            pack.items.append(self._item(ev_id, "risk_statement", stmt, 2.0))
            added_ids.add(stmt.id)
            ev_id += 1

        # Nearby safety statements.
        safety_stmts = [s for s in stmt_nodes if s.properties.get("is_safety")]
        for stmt in safety_stmts[: self.cfg.top_k_safety]:
            if stmt.id in added_ids:
                continue
            pack.items.append(self._item(ev_id, "safety_statement", stmt, 1.3))
            added_ids.add(stmt.id)
            ev_id += 1

        # Direct callees.
        for edge in graph.out_edges(target.id, "FUNCTION_CALLS_FUNCTION")[: self.cfg.top_k_callees]:
            callee = nodes.get(edge.target)
            if not callee or callee.id == target.id:
                continue
            props = callee.properties
            pack.items.append(
                EvidenceItem(
                    evidence_id=f"E{ev_id}",
                    kind="callee_function",
                    node_id=callee.id,
                    relpath=props.get("relpath"),
                    function=props.get("name"),
                    line_start=props.get("line_start"),
                    line_end=props.get("line_end"),
                    text=f"{props.get('signature')}\n{props.get('body_preview', '')[:1200]}",
                    score=1.1,
                    scope="callee",
                    match_type="call_graph_name_resolution",
                    metadata={"callee_name": edge.properties.get("callee_name")},
                )
            )
            ev_id += 1

        # Callers.
        for edge in graph.in_edges(target.id, "FUNCTION_CALLS_FUNCTION")[: self.cfg.top_k_callers]:
            caller = nodes.get(edge.source)
            if not caller or caller.id == target.id:
                continue
            props = caller.properties
            pack.items.append(
                EvidenceItem(
                    evidence_id=f"E{ev_id}",
                    kind="caller_function",
                    node_id=caller.id,
                    relpath=props.get("relpath"),
                    function=props.get("name"),
                    line_start=props.get("line_start"),
                    line_end=props.get("line_end"),
                    text=f"{props.get('signature')}\n{props.get('body_preview', '')[:1200]}",
                    score=0.9,
                    scope="caller",
                    match_type="call_graph_name_resolution",
                    metadata={"call_edge": edge.type},
                )
            )
            ev_id += 1

        if self.cfg.strategy == "risk_first":
            project_risks = [n for n in graph.nodes_of_type("Statement") if n.properties.get("risk_hits")]
            for stmt in project_risks[: self.cfg.top_k_risk]:
                if stmt.id in added_ids:
                    continue
                pack.items.append(self._item(ev_id, "project_risk_statement", stmt, 0.7))
                added_ids.add(stmt.id)
                ev_id += 1

        pack.retrieval_diagnostics.update(
            {
                "num_items": len(pack.items),
                "num_target_statements": len(stmt_nodes),
                "num_target_risk_statements": len(risk_stmts),
                "num_target_safety_statements": len(safety_stmts),
                "num_source_only_definition_nodes": len([n for n in graph.nodes if n.type in {"MacroDefinition", "GlobalDefinition"}]),
            }
        )
        return pack

    @staticmethod
    def _target_security_path_statements(stmt_nodes: list[KGNode]) -> list[KGNode]:
        patterns = [
            r"\bcontentlen\b",
            r"\bsockgetlinebuf\s*\(",
            r"\bdecodeurl\s*\(",
            r"\bfprintf\s*\(",
            r"\bbuf\s*\[[^\]]+\]\s*=\s*(?:0|'\\0')",
            r"\bl\s*(?:\+=|=\s*l\s*\+)",
            r"\bLINESIZE\b",
            r"\bsizeof\b",
            r"\bfgets\s*\(",
        ]
        compiled = [re.compile(p, re.I) for p in patterns]
        out: list[KGNode] = []
        for stmt in stmt_nodes:
            text = str(stmt.properties.get("text") or "")
            if any(p.search(text) for p in compiled):
                out.append(stmt)
        return out[:40]

    @staticmethod
    def _macro_definitions_for_target(graph: ProjectGraph, stmt_nodes: list[KGNode]) -> list[KGNode]:
        """Return macro/global definitions relevant to target code, preferring same file.

        The previous version treated every uppercase token, including tokens from
        string literals, as a macro candidate and returned many unrelated RETURN
        definitions from other files. This source-only ranking keeps the actual
        definition close to the target file first and emits at most a small set of
        shadowing candidates.
        """
        if not stmt_nodes:
            return []
        target_relpath = str(stmt_nodes[0].properties.get("relpath") or "")
        text = _strip_c_comments_and_literals("\n".join(str(s.properties.get("text") or "") for s in stmt_nodes))
        terms = set(re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b", text))
        if not terms:
            return []
        size_like = {t for t in terms if any(k in t for k in ["SIZE", "LEN", "MAX", "MIN", "LIMIT", "BUFFER", "BUF"])}
        selected: list[KGNode] = []
        for term in sorted(terms, key=lambda x: (0 if x in size_like else 1, x)):
            defs = [n for n in graph.nodes if n.type in {"MacroDefinition", "GlobalDefinition"} and str(n.properties.get("name") or "") == term]
            if not defs:
                continue
            defs.sort(key=lambda n: (
                0 if str(n.properties.get("relpath") or "") == target_relpath else 1,
                0 if str(n.properties.get("relpath") or "").endswith(".h") else 1,
                int(n.properties.get("line_start") or 10**9),
            ))
            # Keep the best definition and, for size-like constants, one extra
            # shadowing candidate if it differs across files. This is useful for
            # C macro ambiguity without overwhelming the prompt.
            selected.append(defs[0])
            if term in size_like and len(defs) > 1:
                extra = next((d for d in defs[1:] if str(d.properties.get("text") or "") != str(defs[0].properties.get("text") or "")), None)
                if extra is not None:
                    selected.append(extra)
            if len(selected) >= 16:
                break
        return selected[:16]

    @staticmethod
    def _definition_item(idx: int, node: KGNode, score: float) -> EvidenceItem:
        props = node.properties
        kind = "macro_definition" if node.type == "MacroDefinition" else "global_definition"
        return EvidenceItem(
            evidence_id=f"E{idx}",
            kind=kind,
            node_id=node.id,
            relpath=props.get("relpath"),
            function=None,
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=props.get("text", ""),
            score=score,
            scope="project_global",
            matched_symbol=props.get("name"),
            match_type="source_only_definition_for_target_macro",
            trust="high",
            metadata={"wanted_category": "definition", "value": props.get("value"), "node_type": node.type},
        )

    @staticmethod
    def _item(idx: int, kind: str, node: KGNode, score: float) -> EvidenceItem:
        props = node.properties
        return EvidenceItem(
            evidence_id=f"E{idx}",
            kind=kind,
            node_id=node.id,
            relpath=props.get("relpath"),
            function=props.get("function"),
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=props.get("text", ""),
            score=score,
            scope="target_function",
            match_type="deterministic_target_neighborhood",
            metadata={"risk_hits": props.get("risk_hits", []), "calls": props.get("calls", []), "identifiers": props.get("identifiers", [])},
        )
