from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Any

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_store import KGNode, ProjectGraph
from vuln_commit_kg.retrieval.evidence import EvidenceItem, EvidencePack
from vuln_commit_kg.retrieval.target_locator import TargetLocator
from vuln_commit_kg.kg.codekg_adapter import (
    NEW_CODEKG_QUERY_KINDS,
    execute_codekg_query,
    graph_dir_from_project_graph,
    parse_codekg_query_object,
)

PLACEHOLDER_VALUES = {
    "symbol",
    "target variable",
    "target_variable",
    "target variable or api name",
    "concrete_identifier_or_api",
    "concrete_identifier_from_target_function",
    "specific_identifier_or_check",
    "function or api name",
    "bounds/null/auth check",
    "callee definition",
}

ALLOC_CALLS = {"malloc", "calloc", "realloc", "myalloc", "mystrdup", "strdup", "new"}
FREE_CALLS = {"free", "myfree", "delete"}
WRITE_CALLS = {
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove", "fgets", "gets", "scanf", "sscanf", "fscanf", "sockgetlinebuf",
    "decodeurl", "printuserlist", "printiplist", "printportlist",
}
SINK_CALLS = WRITE_CALLS | {"fprintf", "printf", "printstr", "stdpr", "write", "send"}
DEFAULT_VARIABLE_WANTED = ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime"]
BUNDLE_QUERY_TYPE_ALIASES = {
    "buffer_write_bundle", "input_validation_bundle", "callee_summary_bundle",
    "global_state_bundle", "macro_definition_bundle", "global_definition_bundle",
    "integer_overflow_bundle", "format_string_bundle", "path_traversal_bundle",
    "lifetime_ownership_bundle", "caller_input_bundle",
}
UPLOAD_PATH_TERMS = {"contentlen", "sockgetlinebuf", "decodeurl", "fprintf", "LINESIZE"}


@dataclass
class KGToolResult:
    round_index: int
    query_index: int
    query_type: str
    query: str
    reason: str | None = None
    status: str = "ok"
    items: list[EvidenceItem] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    source: str = "model_generated"
    query_object: dict[str, Any] = field(default_factory=dict)
    tool_parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "query_index": self.query_index,
            "query_type": self.query_type,
            "query": self.query,
            "reason": self.reason,
            "status": self.status,
            "items": [self._item_to_dict(i) for i in self._flatten_items(self.items)],
            "diagnostics": self.diagnostics,
            "source": self.source,
            "query_object": self.query_object,
            "tool_parameters": self.tool_parameters,
        }

    @classmethod
    def _flatten_items(cls, values: Any) -> list[Any]:
        # Defensive normalization: bundle expanders must return flat EvidenceItem
        # lists, but older/failed paths may accidentally return nested tuples/lists.
        # Reporting must never crash a run because of a malformed tool result.
        if values is None:
            return []
        if isinstance(values, (list, tuple)):
            out: list[Any] = []
            for value in values:
                # A common buggy shape was (items, diagnostics). Keep the item side
                # and ignore dict diagnostics here because diagnostics are stored separately.
                if isinstance(value, dict):
                    continue
                out.extend(cls._flatten_items(value))
            return out
        return [values]

    @staticmethod
    def _item_to_dict(item: Any) -> dict[str, Any]:
        if hasattr(item, "model_dump"):
            return item.model_dump(mode="json")
        if isinstance(item, dict):
            return item
        return {"serialization_error": f"unexpected evidence item type: {type(item).__name__}", "repr": repr(item)[:500]}


class KGToolExecutor:
    """Deterministic, auditable KG query executor.

    Important behavior for API-readiness:
    - target-function scope and exact identifier matching are the default;
    - variable queries return category-balanced evidence slices, not only first hits;
    - wanted_evidence is executable and reported in diagnostics;
    - optional source_line resolves lexical variable binding where possible;
    - returned evidence includes file/function/line/scope/match/trust metadata.
    """

    def __init__(self, max_items_per_query: int = 6, max_text_chars: int = 900):
        self.max_items_per_query = max_items_per_query
        self.max_text_chars = max_text_chars
        self.locator = TargetLocator()

    def execute_many(
        self,
        *,
        graph: ProjectGraph,
        sample: SecVulEvalSample,
        queries: list[dict[str, Any]],
        round_index: int,
        evidence_id_prefix: str = "Q",
        query_source: str = "model_generated",
    ) -> list[KGToolResult]:
        results: list[KGToolResult] = []
        target, target_diag = self.locator.locate(graph, sample)
        for qidx, query_obj in enumerate(queries, start=1):
            qtype = str(query_obj.get("query_type") or query_obj.get("type") or "search").lower()
            if qtype in BUNDLE_QUERY_TYPE_ALIASES:
                query_obj = dict(query_obj)
                query_obj["query_type"] = "evidence_bundle"
                query_obj.setdefault("bundle_type", "global_state_bundle" if qtype in {"macro_definition_bundle", "global_definition_bundle"} else qtype)
                query_obj.setdefault("query", query_obj.get("bundle_type"))
                qtype = "evidence_bundle"
            query = str(query_obj.get("query") or query_obj.get("name") or "").strip()
            reason = query_obj.get("reason")
            source = str(query_obj.get("_source") or query_source or "model_generated")
            public_query_object = {k: v for k, v in query_obj.items() if k != "_source"}
            tool_parameters = self._tool_parameters(query_obj, round_index, qidx)
            try:
                if graph_dir_from_project_graph(graph) is not None:
                    codekg_query = self._as_codekg_query(query_obj, sample=sample, qtype=qtype, query=query)
                    items, diagnostics = execute_codekg_query(
                        graph,
                        codekg_query,
                        prefix=f"{evidence_id_prefix}{round_index}.{qidx}",
                        max_items=max(8, self.max_items_per_query * 4),
                        max_text_chars=self.max_text_chars,
                    )
                    diagnostics.update({"target_found": target is not None, "target_diag": target_diag})
                    status = "ok" if items else ("error" if diagnostics.get("error") else "no_results")
                    results.append(
                        KGToolResult(
                            round_index=round_index,
                            query_index=qidx,
                            query_type=str(codekg_query.get("kind") or qtype),
                            query=json.dumps(codekg_query, ensure_ascii=False),
                            reason=str(reason) if reason is not None else None,
                            status=status,
                            items=items,
                            diagnostics=diagnostics,
                            source=source,
                            query_object=codekg_query,
                            tool_parameters={**tool_parameters, "codekg_query": codekg_query, "dashboard_path": diagnostics.get("dashboard_path")},
                        )
                    )
                    continue
                valid_error = self._semantic_query_error(query_obj)
                if valid_error:
                    results.append(
                        KGToolResult(
                            round_index=round_index,
                            query_index=qidx,
                            query_type=qtype,
                            query=query,
                            reason=str(reason) if reason is not None else None,
                            status="invalid_query",
                            items=[],
                            diagnostics={"error": valid_error, "target_found": target is not None, "target_diag": target_diag},
                            source=source,
                            query_object=public_query_object,
                            tool_parameters=tool_parameters,
                        )
                    )
                    continue
                items, diagnostics = self._execute_one(
                    graph=graph,
                    sample=sample,
                    target=target,
                    query_type=qtype,
                    query=query,
                    query_obj=query_obj,
                    prefix=f"{evidence_id_prefix}{round_index}.{qidx}",
                )
                diagnostics.update({"target_found": target is not None, "target_diag": target_diag})
                status = "ok" if items else "no_results"
                if diagnostics.get("missing_wanted_evidence"):
                    status = "partial" if items else "no_results"
                results.append(
                    KGToolResult(
                        round_index=round_index,
                        query_index=qidx,
                        query_type=qtype,
                        query=query,
                        reason=str(reason) if reason is not None else None,
                        status=status,
                        items=items,
                        diagnostics=diagnostics,
                        source=source,
                        query_object=public_query_object,
                        tool_parameters={**tool_parameters, **{k: v for k, v in diagnostics.items() if k in {"wanted_evidence", "missing_wanted_evidence", "category_counts", "source_line_file"}}},
                    )
                )
            except Exception as exc:
                results.append(
                    KGToolResult(
                        round_index=round_index,
                        query_index=qidx,
                        query_type=qtype,
                        query=query,
                        reason=str(reason) if reason is not None else None,
                        status="error",
                        items=[],
                        diagnostics={"error": str(exc), "target_found": target is not None, "target_diag": target_diag},
                        source=source,
                        query_object=public_query_object,
                        tool_parameters=tool_parameters,
                    )
                )
        return results


    def _as_codekg_query(self, query_obj: dict[str, Any], *, sample: SecVulEvalSample, qtype: str, query: str) -> dict[str, Any]:
        """Normalize either the new CodeKG contract or legacy KG tool objects.

        Once the integrated graph is a CodeKG graph, all retrieval goes through
        CodeKG's deterministic query engine. Legacy evidence-bundle objects are
        mapped conservatively to source-grounded CodeKG retrieval slices so old
        fallback paths remain usable without reintroducing the old name-only KG.
        """
        raw_kind = str(query_obj.get("kind") or query_obj.get("query_type") or query_obj.get("type") or "").strip().lower()
        qtext = str(query_obj.get("query") or query or "").strip()
        query_text = str(query_obj.get("query_text") or "").strip()
        executable_text = qtext if re.match(r"^[A-Za-z_]\w*\s*\(", qtext) else (query_text if re.match(r"^[A-Za-z_]\w*\s*\(", query_text) else "")
        if raw_kind in NEW_CODEKG_QUERY_KINDS or executable_text:
            # If a deterministic CodeKG function-call query is present, parse it
            # directly.  Legacy wrappers often carry query_type=guard/risk/search;
            # those labels must not override the executable function-call form.
            base = dict(query_obj)
            if executable_text:
                base["query"] = executable_text
            base.setdefault("target_function", sample.func_name)
            return parse_codekg_query_object(base, defaults={"target_function": sample.func_name})

        symbols = []
        for key in ["symbol", "query"]:
            val = str(query_obj.get(key) or "").strip()
            if val and val not in symbols and val not in BUNDLE_QUERY_TYPE_ALIASES:
                symbols.append(val)
        for key in ["suspect_symbols", "suspect_callees"]:
            for val in query_obj.get(key) or []:
                sval = str(val).strip()
                if sval and sval not in symbols:
                    symbols.append(sval)
        risk_terms = [str(x).strip() for x in (query_obj.get("risk_terms") or []) if str(x).strip()]
        wanted = [str(x).strip() for x in (query_obj.get("wanted_evidence") or []) if str(x).strip()]
        risk_terms.extend([w for w in wanted if w not in risk_terms])

        if raw_kind in {"caller", "callers"}:
            return parse_codekg_query_object({"kind": "callers", "target_function": sample.func_name})
        if raw_kind in {"callee", "callees", "call"}:
            return parse_codekg_query_object({"kind": "call_neighborhood", "target_function": sample.func_name, "direction": "out", "call_depth": 2})
        if raw_kind in {"variable", "type", "global"} and symbols:
            return parse_codekg_query_object({"kind": "variable_flow", "target_function": sample.func_name, "symbol": symbols[0], "data_depth": 4})
        if raw_kind in {"semantic_facts"}:
            return parse_codekg_query_object({"kind": "semantic_facts", "target_function": sample.func_name})

        payload = {
            "kind": "evidence_slice",
            "target_function": sample.func_name,
            "target_statement": qtext if raw_kind in {"statement", "statements", "search", "risk", "sink", "safety", "guard", "guards", "check", "checks"} else None,
            "relation_depth": 4,
            "data_depth": 4,
            "control_depth": 3,
            "call_depth": 2,
            "include_headers": True,
            "include_globals": True,
            "include_joern": True,
            "max_nodes": 520,
            "risk_terms": [x for x in list(dict.fromkeys(risk_terms + symbols)) if x],
        }
        return parse_codekg_query_object(payload)

    def _tool_parameters(self, query_obj: dict[str, Any], round_index: int, query_index: int) -> dict[str, Any]:
        return {
            "round_index": round_index,
            "query_index": query_index,
            "query_type": str(query_obj.get("query_type") or ""),
            "query": str(query_obj.get("query") or ""),
            "bundle_type": query_obj.get("bundle_type"),
            "symbol": query_obj.get("symbol"),
            "suspect_symbols": query_obj.get("suspect_symbols") or [],
            "suspect_callees": query_obj.get("suspect_callees") or [],
            "sink_lines": query_obj.get("sink_lines") or [],
            "scope": self._query_scope(query_obj),
            "match": str(query_obj.get("match") or query_obj.get("match_type") or "exact_identifier"),
            "wanted_evidence": self._wanted_evidence(query_obj),
            "source_line": query_obj.get("source_line"),
            "source_line_end": query_obj.get("source_line_end"),
            "max_items_per_query_config": self.max_items_per_query,
        }

    @staticmethod
    def _semantic_query_error(query_obj: dict[str, Any]) -> str | None:
        q = str(query_obj.get("query") or "").strip()
        q_norm = re.sub(r"\s+", "_", q.lower())
        if not q:
            return "empty query"
        if q_norm in PLACEHOLDER_VALUES or "concrete_identifier" in q_norm or "specific_project_evidence" in q_norm:
            return "placeholder query copied from schema"
        if q.lower().startswith(("select ", "insert ", "update ", "delete ", "with ")):
            return "SQL-like query is not allowed"
        return None

    def _execute_one(
        self,
        *,
        graph: ProjectGraph,
        sample: SecVulEvalSample,
        target: KGNode | None,
        query_type: str,
        query: str,
        query_obj: dict[str, Any],
        prefix: str,
    ) -> tuple[list[EvidenceItem], dict[str, Any]]:
        diagnostics: dict[str, Any] = {"wanted_evidence": self._wanted_evidence(query_obj)}
        if not target:
            return [], diagnostics
        scope = self._query_scope(query_obj)
        exact = str(query_obj.get("match") or query_obj.get("match_type") or "exact_identifier").lower() != "substring"

        if query_type in {"evidence_bundle", "bundle"}:
            items, bundle_diag = self._evidence_bundle_query(graph, target, query, prefix, query_obj=query_obj)
            diagnostics.update(bundle_diag)
            return items, diagnostics
        if query_type in {"guard_dominance", "dominance"}:
            items, guard_diag = self._guard_dominance_query(graph, target, query, prefix, query_obj=query_obj)
            diagnostics.update(guard_diag)
            return items, diagnostics
        if query_type in {"callee", "callees", "call"}:
            return self._callee_query(graph, target, query, prefix, exact=exact), diagnostics
        if query_type in {"caller", "callers"}:
            return self._caller_query(graph, target, query, prefix), diagnostics
        if query_type in {"variable", "type", "global"}:
            if query_type == "global" or (query.isupper() and query not in {v.properties.get("name") for v in self._target_variables(graph, target)}):
                items = self._global_or_macro_query(graph, target, query, prefix, exact=True, query_obj=query_obj)
                diagnostics["category_counts"] = self._category_counts(items) or {"global_or_macro": len(items)}
                return items, diagnostics
            items, var_diag = self._variable_query(graph, target, query, prefix, query_obj=query_obj, scope=scope, exact=exact)
            diagnostics.update(var_diag)
            return items, diagnostics
        if query_type in {"safety", "guard", "guards", "check", "checks"}:
            return self._safety_query(graph, target, query, prefix, exact=exact), diagnostics
        if query_type in {"risk", "sink", "sinks", "danger", "dangerous_api"}:
            return self._risk_query(graph, target, query, prefix, exact=exact), diagnostics
        if query_type in {"statement", "statements", "search"}:
            return self._statement_query(graph, target, query, prefix, scope=scope, exact=exact), diagnostics
        return self._statement_query(graph, target, query, prefix, scope="target_function", exact=True), diagnostics


    def _evidence_bundle_query(
        self,
        graph: ProjectGraph,
        target: KGNode,
        query: str,
        prefix: str,
        *,
        query_obj: dict[str, Any],
    ) -> tuple[list[EvidenceItem], dict[str, Any]]:
        """Expand an LLM-requested investigation bundle into concrete KG evidence.

        The LLM chooses the hypothesis and bundle type; this method performs
        deterministic, bounded retrieval so prompts stay compact and evidence is
        grounded in file/function/line metadata.
        """
        bundle_type = str(query_obj.get("bundle_type") or query or "").strip().lower()
        symbol = str(query_obj.get("symbol") or "").strip()
        suspect_symbols = [str(x).strip() for x in (query_obj.get("suspect_symbols") or []) if str(x).strip()]
        suspect_callees = [str(x).strip() for x in (query_obj.get("suspect_callees") or []) if str(x).strip()]
        if not symbol:
            # Prefer a concrete symbol from query text only when it is not the bundle name.
            q_symbols = [t for t in self._query_symbols(query) if t.lower() not in {"buffer_write_bundle", "input_validation_bundle", "callee_summary_bundle", "global_state_bundle", "bundle"}]
            symbol = q_symbols[0] if q_symbols else (suspect_symbols[0] if suspect_symbols else "")
        diagnostics: dict[str, Any] = {"bundle_type": bundle_type, "symbol": symbol, "suspect_symbols": suspect_symbols, "suspect_callees": suspect_callees}
        items: list[EvidenceItem] = []
        seen: set[tuple[str | None, int | None, str]] = set()

        def add_many(new_items: list[EvidenceItem]) -> None:
            for item in new_items:
                key = (item.node_id, item.line_start, item.text)
                if key in seen:
                    continue
                seen.add(key)
                item.evidence_id = f"{prefix}.{len(items) + 1}"
                items.append(item)

        # Main variable-centered bundles.
        variable_like = {
            "buffer_write_bundle", "input_validation_bundle", "integer_overflow_bundle",
            "format_string_bundle", "path_traversal_bundle", "lifetime_ownership_bundle",
        }
        if bundle_type in variable_like and symbol:
            wanted = self._wanted_evidence(query_obj)
            if not wanted:
                wanted = ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime"]
            vq = dict(query_obj)
            vq.update({"query_type": "variable", "query": symbol, "wanted_evidence": wanted})
            var_items, var_diag = self._variable_query(graph, target, symbol, prefix, query_obj=vq, scope="target_function", exact=True)
            diagnostics["variable_slice"] = var_diag
            add_many(var_items)
            # Retrieve macro/global definitions for size-like tokens appearing in the slice.
            size_terms = self._size_terms_from_items(var_items)
            diagnostics["size_terms"] = size_terms[:12]
            for term in size_terms[:6]:
                add_many(self._global_or_macro_query(graph, target, term, prefix, exact=True, query_obj=query_obj)[:3])
            if self._target_has_upload_path(graph, target) and bundle_type in {"buffer_write_bundle", "input_validation_bundle", "integer_overflow_bundle"}:
                upload_items = self._upload_config_path_query(graph, target, symbol or query, prefix)
                diagnostics["upload_config_path_items"] = len(upload_items)
                add_many(upload_items)
            # Summarize callees involved in writes/sinks/output args.
            callee_names = self._callee_terms_from_items(var_items)
            for callee in list(dict.fromkeys(suspect_callees + callee_names))[:8]:
                add_many(self._callee_query(graph, target, callee, prefix, exact=True)[:2])
        elif bundle_type == "callee_summary_bundle":
            for callee in list(dict.fromkeys([symbol] + suspect_callees + self._query_symbols(query)))[:8]:
                if callee:
                    add_many(self._callee_query(graph, target, callee, prefix, exact=True)[:2])
        elif bundle_type == "global_state_bundle":
            terms = list(dict.fromkeys([symbol] + suspect_symbols + self._query_symbols(query)))[:12]
            for term in terms:
                if term:
                    add_many(self._global_or_macro_query(graph, target, term, prefix, exact=True, query_obj=query_obj)[:4])
        elif bundle_type == "caller_input_bundle":
            add_many(self._caller_query(graph, target, query, prefix)[: self.max_items_per_query])
        else:
            # Generic bundle fallback: risk/safety around the named symbol plus callees.
            if symbol:
                add_many(self._risk_query(graph, target, symbol, prefix, exact=True)[:6])
                add_many(self._safety_query(graph, target, symbol, prefix, exact=True)[:6])
            for callee in suspect_callees[:6]:
                add_many(self._callee_query(graph, target, callee, prefix, exact=True)[:2])

        diagnostics["bundle_item_count"] = len(items)
        diagnostics["category_counts"] = self._category_counts(items)
        return items[: max(18, self.max_items_per_query * 5)], diagnostics

    def _guard_dominance_query(
        self,
        graph: ProjectGraph,
        target: KGNode,
        query: str,
        prefix: str,
        *,
        query_obj: dict[str, Any],
    ) -> tuple[list[EvidenceItem], dict[str, Any]]:
        # Lightweight dominance approximation: return guard/check statements that
        # appear before each cited sink/risk line and mention the symbol, size macro,
        # loop counter, sizeof, or length variable. It does not claim compiler-grade CFG dominance.
        symbol = str(query_obj.get("symbol") or "").strip()
        if not symbol:
            syms = self._query_symbols(query)
            symbol = syms[-1] if syms else ""
        sink_lines_raw = query_obj.get("sink_lines") or []
        sink_lines: list[int] = []
        for x in sink_lines_raw:
            try:
                sink_lines.append(int(x))
            except Exception:
                pass
        if not sink_lines:
            for stmt in self._target_statements(graph, target):
                text = str(stmt.properties.get("text") or "")
                if symbol and self._text_has_identifier(text, symbol) and (stmt.properties.get("risk_hits") or set(stmt.properties.get("calls") or []) & SINK_CALLS):
                    if stmt.properties.get("line_start"):
                        sink_lines.append(int(stmt.properties["line_start"]))
        items: list[EvidenceItem] = []
        for stmt in self._target_statements(graph, target):
            line = int(stmt.properties.get("line_start") or 0)
            text = str(stmt.properties.get("text") or "")
            if sink_lines and not any(line <= s for s in sink_lines):
                continue
            if bool(stmt.properties.get("is_safety")) or self._guard_or_bound_for_symbol(text, symbol):
                item = self._statement_item(prefix, len(items)+1, "tool_guard_dominance_candidate", stmt, 1.55, matched_symbol=symbol or None, match_type="approx_preceding_guard", category="guard_dominance")
                item.metadata["guard_dominance_note"] = "approximate: preceding guard/check candidate, not compiler CFG dominance"
                items.append(item)
            if len(items) >= max(self.max_items_per_query, 10):
                break
        return items, {"symbol": symbol, "sink_lines": sink_lines, "dominance_method": "approx_preceding_guard_not_full_cfg", "category_counts": self._category_counts(items)}

    @staticmethod
    def _category_counts(items: list[EvidenceItem]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            cat = str((item.metadata or {}).get("wanted_category") or item.kind)
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    @staticmethod
    def _size_terms_from_items(items: list[EvidenceItem]) -> list[str]:
        terms: list[str] = []
        for item in items:
            for tok in re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b|\bsizeof\b", item.text or ""):
                if tok not in terms:
                    terms.append(tok)
        return terms

    @staticmethod
    def _callee_terms_from_items(items: list[EvidenceItem]) -> list[str]:
        terms: list[str] = []
        for item in items:
            md = item.metadata or {}
            for call in md.get("calls") or []:
                if call not in terms and call not in {"if", "while", "for", "switch", "return", "sizeof"}:
                    terms.append(str(call))
            for call in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", item.text or ""):
                if call not in terms and call not in {"if", "while", "for", "switch", "return", "sizeof"}:
                    terms.append(call)
        return terms

    def _query_scope(self, query_obj: dict[str, Any]) -> str:
        scope = query_obj.get("scope") or "target_function"
        if isinstance(scope, dict):
            return str(scope.get("kind") or scope.get("scope") or "target_function")
        return str(scope or "target_function")

    @staticmethod
    def _wanted_evidence(query_obj: dict[str, Any]) -> list[str]:
        raw = query_obj.get("wanted_evidence") or []
        if isinstance(raw, str):
            raw = [raw]
        out: list[str] = []
        aliases = {
            "definitions": "allocation",
            "definition": "allocation",
            "defs": "allocation",
            "guards": "bounds_checks",
            "checks": "bounds_checks",
            "guard": "bounds_checks",
            "bound_checks": "bounds_checks",
            "risk": "sinks",
            "risks": "sinks",
            "sink": "sinks",
            "free": "lifetime",
            "frees": "lifetime",
        }
        for item in raw:
            norm = re.sub(r"[^a-z0-9_]+", "_", str(item).strip().lower()).strip("_")
            norm = aliases.get(norm, norm)
            if norm and norm not in out:
                out.append(norm)
        return out

    def _target_statements(self, graph: ProjectGraph, target: KGNode) -> list[KGNode]:
        nodes = graph.node_by_id()
        return [nodes[e.target] for e in graph.out_edges(target.id, "FUNCTION_HAS_STATEMENT") if e.target in nodes]

    def _target_variables(self, graph: ProjectGraph, target: KGNode) -> list[KGNode]:
        nodes = graph.node_by_id()
        out = []
        for e in graph.out_edges(target.id, "DECLARES"):
            n = nodes.get(e.target)
            if n and n.type in {"LocalVariable", "Parameter"}:
                out.append(n)
        return out

    def _callee_query(self, graph: ProjectGraph, target: KGNode, query: str, prefix: str, *, exact: bool) -> list[EvidenceItem]:
        nodes = graph.node_by_id()
        items: list[EvidenceItem] = []
        for edge in graph.out_edges(target.id, "FUNCTION_CALLS_FUNCTION"):
            callee_name = str(edge.properties.get("callee_name") or "")
            if query and not self._symbol_match(callee_name, query, exact=True):
                continue
            node = nodes.get(edge.target)
            if node and node.id != target.id:
                items.append(self._function_item(prefix, len(items) + 1, "tool_callee", node, score=1.5, matched_symbol=callee_name, match_type="callee_exact_name"))
            if len(items) >= self.max_items_per_query:
                return items
        if not items:
            for stmt in self._target_statements(graph, target):
                if query in (stmt.properties.get("calls") or []):
                    items.append(self._statement_item(prefix, len(items) + 1, "tool_call_site", stmt, score=1.3, matched_symbol=query, match_type="target_call_site", category="callee_callsite"))
        return items

    def _caller_query(self, graph: ProjectGraph, target: KGNode, query: str, prefix: str) -> list[EvidenceItem]:
        nodes = graph.node_by_id()
        items: list[EvidenceItem] = []
        for edge in graph.in_edges(target.id, "FUNCTION_CALLS_FUNCTION"):
            node = nodes.get(edge.source)
            if node and node.id != target.id:
                items.append(self._function_item(prefix, len(items) + 1, "tool_caller", node, score=1.0, matched_symbol=query or target.properties.get("name"), match_type="caller_graph"))
            if len(items) >= self.max_items_per_query:
                break
        return items

    def _variable_query(
        self,
        graph: ProjectGraph,
        target: KGNode,
        query: str,
        prefix: str,
        *,
        query_obj: dict[str, Any],
        scope: str,
        exact: bool,
    ) -> tuple[list[EvidenceItem], dict[str, Any]]:
        diagnostics: dict[str, Any] = {}
        wanted = self._wanted_evidence(query_obj) or list(DEFAULT_VARIABLE_WANTED)
        diagnostics["wanted_evidence"] = wanted
        source_line_file = self._source_line_to_file_line(query_obj, target)
        if source_line_file is not None:
            diagnostics["source_line_file"] = source_line_file

        target_stmts_all = self._target_statements(graph, target)
        declarations = self._variable_declaration_statements(target_stmts_all, query)
        target_vars = [v for v in self._target_variables(graph, target) if str(v.properties.get("name")) == query]
        if exact and scope == "target_function" and not declarations and not target_vars:
            return [], {**diagnostics, "missing_wanted_evidence": wanted, "category_counts": {}}

        declaration_lines = sorted({int(x.properties.get("line_start") or 0) for x in declarations if x.properties.get("line_start")} | {int(v.properties.get("line_start") or 0) for v in target_vars if v.properties.get("line_start")})
        selected_decl_line = self._selected_declaration_line(declarations, target_vars, source_line_file)
        scoped_stmts = self._statements_for_variable_scope(target_stmts_all, query, selected_decl_line, source_line_file)
        if not scoped_stmts:
            scoped_stmts = [s for s in target_stmts_all if self._text_has_identifier(str(s.properties.get("text") or ""), query)]

        buckets: dict[str, list[EvidenceItem]] = {k: [] for k in ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime", "uses"]}
        seen_keys: set[tuple[str | None, int | None, str]] = set()

        def add(cat: str, item: EvidenceItem) -> None:
            key = (item.node_id, item.line_start, item.text)
            if key in seen_keys:
                return
            seen_keys.add(key)
            item.metadata["wanted_category"] = cat
            item.metadata["variable_instance"] = {
                "symbol": query,
                "selected_declaration_line": selected_decl_line,
                "all_declaration_lines": declaration_lines,
                "source_line_file": source_line_file,
                "scope_policy": "nearest_lexical_declaration_before_source_line" if source_line_file is not None else "first_visible_declaration_with_shadowing_warning",
            }
            if len(declaration_lines) > 1:
                item.metadata["shadowed_variable_instances"] = True
            if cat not in buckets:
                buckets[cat] = []
            buckets[cat].append(item)

        # Variable node/declaration items. If source_line points into a shadowed local, prefer statement declaration over function-level anchor.
        for v in target_vars:
            vline = v.properties.get("line_start")
            if selected_decl_line is None or vline == selected_decl_line:
                add("declaration", self._variable_item(prefix, 0, v, matched_symbol=query, category="declaration"))
        for stmt in declarations:
            if selected_decl_line is None or stmt.properties.get("line_start") == selected_decl_line:
                add("declaration", self._statement_item(prefix, 0, "tool_variable_declaration_statement", stmt, score=1.65, matched_symbol=query, match_type="lexical_exact_identifier_target_scope", category="declaration"))

        for stmt in scoped_stmts:
            cats = self._variable_statement_categories(stmt, query)
            for cat in cats:
                kind = {
                    "allocation": "tool_variable_allocation_or_definition",
                    "writes": "tool_variable_write",
                    "bounds_checks": "tool_variable_bound_or_guard",
                    "sinks": "tool_variable_sink_or_risk",
                    "lifetime": "tool_variable_lifetime",
                    "uses": "tool_variable_use",
                }.get(cat, "tool_variable_use")
                score = {
                    "allocation": 1.60,
                    "writes": 1.85,
                    "bounds_checks": 1.55,
                    "sinks": 1.90,
                    "lifetime": 1.25,
                    "uses": 1.20,
                }.get(cat, 1.20)
                add(cat, self._statement_item(prefix, 0, kind, stmt, score=score, matched_symbol=query, match_type="lexical_exact_identifier_target_scope", category=cat))

        ordered_categories = [c for c in wanted if c in buckets]
        for c in ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime", "uses"]:
            if c not in ordered_categories:
                ordered_categories.append(c)
        budgets = {
            "declaration": 2,
            "allocation": 3,
            "writes": 8,
            "bounds_checks": 6,
            "sinks": 8,
            "lifetime": 3,
            "uses": 4,
        }
        max_total = max(self.max_items_per_query, 18 if {"writes", "sinks", "bounds_checks"} & set(wanted) else 12)
        items: list[EvidenceItem] = []
        for cat in ordered_categories:
            for item in buckets.get(cat, [])[: budgets.get(cat, 3)]:
                if len(items) >= max_total:
                    break
                # assign stable evidence id after category balancing
                item.evidence_id = f"{prefix}.{len(items) + 1}"
                items.append(item)
            if len(items) >= max_total:
                break

        present = {cat for cat, vals in buckets.items() if vals}
        missing = [cat for cat in wanted if cat not in present]
        diagnostics["category_counts"] = {cat: len(vals) for cat, vals in buckets.items() if vals}
        diagnostics["missing_wanted_evidence"] = missing
        diagnostics["selected_declaration_line"] = selected_decl_line
        diagnostics["all_declaration_lines"] = declaration_lines
        diagnostics["shadowed_variable_instances"] = len(declaration_lines) > 1
        diagnostics["lexical_binding"] = "source_line_selected_declaration" if source_line_file is not None else "first_visible_declaration_with_shadowing_warning"

        if len(items) < max_total and scope in {"project", "project_global", "global"}:
            start_idx = len(items)
            for node in graph.nodes:
                if node.type != "Statement":
                    continue
                if node.properties.get("function") == target.properties.get("name") and node.properties.get("relpath") == target.properties.get("relpath"):
                    continue
                if self._text_has_identifier(str(node.properties.get("text") or ""), query):
                    item = self._statement_item(prefix, 0, "tool_project_exact_identifier", node, score=0.7, matched_symbol=query, match_type="exact_identifier_project_scope", category="project_use")
                    item.evidence_id = f"{prefix}.{len(items) + 1}"
                    items.append(item)
                if len(items) >= max_total:
                    break
            if len(items) > start_idx:
                diagnostics["project_scope_extra_items"] = len(items) - start_idx
        return items, diagnostics

    def _source_line_to_file_line(self, query_obj: dict[str, Any], target: KGNode) -> int | None:
        val = query_obj.get("source_line") or query_obj.get("line")
        if val is None:
            return None
        try:
            line = int(val)
        except Exception:
            return None
        start = int(target.properties.get("line_start") or 0)
        end = int(target.properties.get("line_end") or 0)
        if start and end and start <= line <= end:
            return line
        if start and line > 0 and line <= max(1, end - start + 1):
            return start + line - 1
        return line

    def _variable_declaration_statements(self, statements: list[KGNode], query: str) -> list[KGNode]:
        out = []
        for stmt in statements:
            text = str(stmt.properties.get("text") or "")
            defs = set(stmt.properties.get("defines_variables") or [])
            if query in defs or self._looks_like_declaration_of(text, query):
                out.append(stmt)
        return out

    def _selected_declaration_line(self, declarations: list[KGNode], var_nodes: list[KGNode], source_line_file: int | None) -> int | None:
        lines: list[int] = []
        for v in var_nodes:
            if v.properties.get("line_start"):
                lines.append(int(v.properties["line_start"]))
        for stmt in declarations:
            if stmt.properties.get("line_start"):
                lines.append(int(stmt.properties["line_start"]))
        lines = sorted(set(lines))
        if not lines:
            return None
        if source_line_file is None:
            return lines[0]
        before = [x for x in lines if x <= source_line_file]
        return before[-1] if before else lines[0]

    def _statements_for_variable_scope(self, statements: list[KGNode], query: str, decl_line: int | None, source_line_file: int | None) -> list[KGNode]:
        if decl_line is None:
            return [s for s in statements if self._text_has_identifier(str(s.properties.get("text") or ""), query)]
        # Stop at the next redeclaration of the same name when analyzing an earlier binding.
        # For a later/shadowed binding, stop at the first closing-brace statement after
        # the declaration. This is not a full C scope analysis, but it prevents the
        # most harmful mix-up between outer and inner `buf` variables.
        next_decl = None
        for stmt in statements:
            line = int(stmt.properties.get("line_start") or 0)
            text = str(stmt.properties.get("text") or "")
            if line <= decl_line:
                continue
            if self._looks_like_declaration_of(text, query):
                next_decl = line
                break
        out = []
        shadowed_binding = source_line_file is not None and source_line_file >= decl_line and any(
            int(s.properties.get("line_start") or 0) < decl_line and self._looks_like_declaration_of(str(s.properties.get("text") or ""), query)
            for s in statements
        )
        for stmt in statements:
            line = int(stmt.properties.get("line_start") or 0)
            text = str(stmt.properties.get("text") or "")
            if line < decl_line:
                continue
            if line > decl_line and self._looks_like_declaration_of(text, query):
                break
            if next_decl is not None and line >= next_decl:
                break
            if shadowed_binding and line > decl_line and text.strip().startswith("}"):
                break
            if self._text_has_identifier(text, query):
                out.append(stmt)
        return out

    def _variable_statement_categories(self, stmt: KGNode, query: str) -> list[str]:
        text = str(stmt.properties.get("text") or "")
        calls = set(stmt.properties.get("calls") or [])
        has_symbol = self._text_has_identifier(text, query)
        cats: list[str] = []
        if query in set(stmt.properties.get("defines_variables") or []) or self._assignment_to_symbol(text, query):
            if calls & ALLOC_CALLS or "=" in text:
                cats.append("allocation")
        if self._write_to_symbol(text, query) or (has_symbol and calls & WRITE_CALLS):
            cats.append("writes")
        if bool(stmt.properties.get("is_safety")) or self._guard_or_bound_for_symbol(text, query):
            cats.append("bounds_checks")
        if (has_symbol and bool(stmt.properties.get("risk_hits"))) or (has_symbol and calls & SINK_CALLS):
            cats.append("sinks")
        if calls & FREE_CALLS or re.search(r"\b(?:free|myfree)\s*\(\s*" + re.escape(query) + r"\b", text):
            cats.append("lifetime")
        if not cats and self._text_has_identifier(text, query):
            cats.append("uses")
        # Stable order and de-dup.
        ordered = []
        for cat in ["allocation", "writes", "bounds_checks", "sinks", "lifetime", "uses"]:
            if cat in cats and cat not in ordered:
                ordered.append(cat)
        return ordered

    @staticmethod
    def _looks_like_declaration_of(text: str, symbol: str) -> bool:
        pattern = r"(^|[;{]\s*)\s*(?:const\s+|volatile\s+|static\s+|extern\s+|register\s+|unsigned\s+|signed\s+|struct\s+\w+\s+|enum\s+\w+\s+|union\s+\w+\s+|[A-Za-z_]\w*\s+)+(?:[\*\s]+)" + re.escape(symbol) + r"\b(?:\s*\[[^\]]*\])?\s*(?:=|;|,)"
        return re.search(pattern, text.replace("\n", " ")) is not None

    @staticmethod
    def _assignment_to_symbol(text: str, symbol: str) -> bool:
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])\s*(?:\[[^\]]*\])?\s*=", text) is not None

    @staticmethod
    def _write_to_symbol(text: str, symbol: str) -> bool:
        sym = re.escape(symbol)
        patterns = [
            r"\b" + sym + r"\s*\[[^\]]+\]\s*=",
            r"\*\s*" + sym + r"\s*=",
            r"\b(?:sprintf|snprintf|vsprintf|vsnprintf|strcpy|strncpy|strcat|strncat|memcpy|memmove|fgets|gets|scanf|sscanf|fscanf|sockgetlinebuf|decodeurl|printuserlist|printiplist|printportlist)\s*\([^;\n]*\b" + sym + r"\b",
        ]
        return any(re.search(p, text) for p in patterns)

    @staticmethod
    def _guard_or_bound_for_symbol(text: str, symbol: str) -> bool:
        if not re.search(r"\b(?:if|while|for)\s*\(", text):
            return False
        return bool(re.search(r"\b" + re.escape(symbol) + r"\b|\bLINESIZE\b|\bsizeof\b|\bcontentlen\b|\bi\b\s*(?:<|>|<=|>=)", text))

    def _safety_query(self, graph: ProjectGraph, target: KGNode, query: str, prefix: str, *, exact: bool) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        terms = self._query_symbols(query)
        for stmt in self._target_statements(graph, target):
            text = str(stmt.properties.get("text") or "")
            is_safety = bool(stmt.properties.get("is_safety")) or any(t in text for t in ["LINESIZE", "sizeof", "contentlen"])
            matches_term = any(self._text_has_identifier(text, t) for t in terms)
            if is_safety and (matches_term or not terms):
                items.append(self._statement_item(prefix, len(items) + 1, "tool_safety_or_guard", stmt, 1.45, matched_symbol=terms[0] if terms else None, match_type="target_safety_exact_identifier" if terms else "target_safety_general", category="bounds_checks"))
            if len(items) >= self.max_items_per_query:
                return items
        return items

    def _risk_query(self, graph: ProjectGraph, target: KGNode, query: str, prefix: str, *, exact: bool) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        terms = self._query_symbols(query)
        for stmt in self._target_statements(graph, target):
            risk = bool(stmt.properties.get("risk_hits")) or bool(set(stmt.properties.get("calls") or []) & SINK_CALLS)
            text = str(stmt.properties.get("text") or "")
            matches_term = any(self._text_has_identifier(text, t) or t in (stmt.properties.get("calls") or []) for t in terms)
            if risk and (matches_term or not terms):
                items.append(self._statement_item(prefix, len(items) + 1, "tool_risk_or_sink", stmt, 1.8, matched_symbol=terms[0] if terms else None, match_type="target_risk_exact_identifier" if terms else "target_risk_general", category="sinks"))
            if len(items) >= self.max_items_per_query:
                return items
        return items


    def _target_has_upload_path(self, graph: ProjectGraph, target: KGNode) -> bool:
        text = "\n".join(str(s.properties.get("text") or "") for s in self._target_statements(graph, target))
        return any(term in text for term in UPLOAD_PATH_TERMS)

    def _upload_config_path_query(self, graph: ProjectGraph, target: KGNode, query: str, prefix: str) -> list[EvidenceItem]:
        """Return source-only evidence for upload/config read-loop reasoning."""
        items: list[EvidenceItem] = []
        categories = [
            ("case_or_branch", re.compile(r"\bcase\b.*['\"]?U['\"]?|\bupload\b", re.I)),
            ("contentlen_declaration_or_parse", re.compile(r"\bcontentlen\b.*(?:=|atoi|atol|strtol|Content-Length|content-length|Contentlength)|(?:int|unsigned|long|size_t)\s+contentlen\b", re.I)),
            ("contentlen_cap_or_guard", re.compile(r"\b(?:if|while|for)\s*\([^\n;]*\bcontentlen\b|\bcontentlen\b[^\n;]*(?:LINESIZE|sizeof|MAX|LIMIT|<|>|<=|>=)", re.I)),
            ("loop_condition", re.compile(r"\b(?:while|for)\s*\([^\n;]*(?:\bl\b|\bi\b)[^\n;]*\bcontentlen\b|\bcontentlen\b[^\n;]*(?:\bl\b|\bi\b)", re.I)),
            ("read_bound_expression", re.compile(r"\bsockgetlinebuf\s*\([^;]*", re.I)),
            ("post_read_nul_write", re.compile(r"\bbuf\s*\[[^\]]+\]\s*=\s*0\b|\bbuf\s*\[[^\]]+\]\s*=\s*'\\0'", re.I)),
            ("decode_or_transform", re.compile(r"\bdecodeurl\s*\(", re.I)),
            ("file_or_output_write", re.compile(r"\bfprintf\s*\(|\bfwrite\s*\(|\bwrite\s*\(", re.I)),
            ("loop_progress", re.compile(r"\bl\s*(?:\+=|=\s*l\s*\+)|\bi\s*=|\bi\s*[<>]=?", re.I)),
            ("size_macro_use", re.compile(r"\bLINESIZE\b|\bsizeof\b", re.I)),
        ]
        selected_nodes: list[tuple[str, KGNode]] = []
        target_stmts = self._target_statements(graph, target)
        for category, pattern in categories:
            per_category_limit = 4 if category in {"contentlen_cap_or_guard", "read_bound_expression", "post_read_nul_write", "loop_condition"} else 2
            count = 0
            for stmt in target_stmts:
                text = str(stmt.properties.get("text") or "")
                if pattern.search(text):
                    selected_nodes.append((category, stmt))
                    count += 1
                    if count >= per_category_limit:
                        break
        # Preserve source order after category collection, but avoid duplicates.
        seen: set[tuple[str, int | None, str]] = set()
        selected_nodes.sort(key=lambda cs: int(cs[1].properties.get("line_start") or 0))
        for category, stmt in selected_nodes:
            key = (stmt.id, stmt.properties.get("line_start"), category)
            if key in seen:
                continue
            seen.add(key)
            item = self._statement_item(prefix, len(items) + 1, "tool_upload_config_path", stmt, 1.9, matched_symbol=query or None, match_type="upload_config_path_keyword", category=category)
            item.metadata["bundle_focus"] = "upload_config_path_source_only"
            items.append(item)
            if len(items) >= max(24, self.max_items_per_query * 4):
                break
        return items

    def _global_or_macro_query(self, graph: ProjectGraph, target: KGNode | None, query: str, prefix: str, *, exact: bool, query_obj: dict[str, Any] | None = None) -> list[EvidenceItem]:
        """Return macro/global definitions before ordinary uses, ranked by target context."""
        terms = self._query_symbols(query) or [query]
        items: list[EvidenceItem] = []
        target_rel = str(target.properties.get("relpath") or "") if target else ""
        source_line_file = self._source_line_to_file_line(query_obj or {}, target) if target is not None else None

        definitions: list[KGNode] = []
        for node in graph.nodes:
            if node.type not in {"MacroDefinition", "GlobalDefinition"}:
                continue
            name = str(node.properties.get("name") or "")
            if any(self._symbol_match(name, t, exact=True) if exact else self._symbol_match(name, t, exact=False) for t in terms):
                definitions.append(node)

        def rank_def(node: KGNode) -> tuple[int, int, int, int, str]:
            rel = str(node.properties.get("relpath") or "")
            line = int(node.properties.get("line_start") or 10**9)
            same_file = 0 if target_rel and rel == target_rel else 1
            before_source = 0 if source_line_file is not None and line <= source_line_file else 1
            headerish = 0 if rel.endswith((".h", ".hpp", ".hh")) else 1
            distance = abs((source_line_file or line) - line)
            return (same_file, before_source, headerish, distance, rel)

        definitions.sort(key=rank_def)
        seen_defs: set[str] = set()
        for node in definitions:
            name = str(node.properties.get("name") or "")
            rel = str(node.properties.get("relpath") or "")
            text = str(node.properties.get("text") or "")
            key = f"{name}:{rel}:{text}"
            if key in seen_defs:
                continue
            seen_defs.add(key)
            kind = "tool_macro_definition" if node.type == "MacroDefinition" else "tool_global_definition"
            item = self._definition_item(prefix, len(items) + 1, kind, node, matched_symbol=name, match_type="definition_exact_identifier" if exact else "definition_substring")
            item.metadata["definition_rank"] = {
                "target_relpath": target_rel,
                "same_file": bool(target_rel and rel == target_rel),
                "source_line_file": source_line_file,
                "note": "definitions are sorted same-file/before-source before other project definitions",
            }
            if len(definitions) > 1:
                item.metadata["shadowing_or_multiple_definitions"] = True
            items.append(item)
            # For exact macro lookups, return the best same-file definition plus at most
            # one alternate project definition. This avoids flooding prompts with unrelated
            # RETURN definitions while preserving ambiguity for constants like LINESIZE.
            if len(items) >= min(self.max_items_per_query, 2 if exact else self.max_items_per_query):
                break

        # After definitions, include target-local uses, then project uses, so the model sees both value and context.
        use_items: list[EvidenceItem] = []
        if target:
            for node in self._target_statements(graph, target):
                text = str(node.properties.get("text") or "")
                if any(self._text_has_identifier(text, t) if exact else t.lower() in text.lower() for t in terms):
                    use_items.append(self._statement_item(prefix, len(items) + len(use_items) + 1, "tool_global_or_macro_use", node, score=1.1, matched_symbol=terms[0], match_type="target_use_after_definition", category="global_or_macro_use"))
                if len(items) + len(use_items) >= self.max_items_per_query:
                    break
        if len(items) + len(use_items) < self.max_items_per_query:
            for node in graph.nodes:
                if node.type != "Statement":
                    continue
                if target and node.properties.get("function") == target.properties.get("name") and node.properties.get("relpath") == target.properties.get("relpath"):
                    continue
                text = str(node.properties.get("text") or "")
                if any(self._text_has_identifier(text, t) if exact else t.lower() in text.lower() for t in terms):
                    use_items.append(self._statement_item(prefix, len(items) + len(use_items) + 1, "tool_global_or_macro_use", node, score=0.65, matched_symbol=terms[0], match_type="project_use_after_definition", category="global_or_macro_use"))
                if len(items) + len(use_items) >= self.max_items_per_query:
                    break
        return items + use_items[: max(0, self.max_items_per_query - len(items))]

    def _statement_query(self, graph: ProjectGraph, target: KGNode | None, query: str, prefix: str, *, scope: str, exact: bool, kind: str = "tool_statement") -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        nodes = self._target_statements(graph, target) if target and scope != "project" else [n for n in graph.nodes if n.type == "Statement"]
        terms = self._query_symbols(query) or [query]
        for node in nodes:
            text = str(node.properties.get("text") or "")
            if any(self._text_has_identifier(text, t) if exact else (t.lower() in text.lower()) for t in terms):
                sc = 1.2 if target and node.properties.get("function") == target.properties.get("name") and node.properties.get("relpath") == target.properties.get("relpath") else 0.7
                items.append(self._statement_item(prefix, len(items) + 1, kind, node, score=sc, matched_symbol=terms[0], match_type="exact_identifier" if exact else "substring", category="statement"))
            if len(items) >= self.max_items_per_query:
                break
        return items

    @staticmethod
    def _query_symbols(query: str) -> list[str]:
        return [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", query or "") if len(t) >= 2][:8]

    @staticmethod
    def _text_has_identifier(text: str, symbol: str) -> bool:
        if not symbol:
            return False
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])", text) is not None

    @staticmethod
    def _symbol_match(value: str, query: str, *, exact: bool) -> bool:
        return value == query if exact else query.lower() in value.lower()

    def _statement_item(self, prefix: str, idx: int, kind: str, node: KGNode, score: float = 1.0, *, matched_symbol: str | None = None, match_type: str | None = None, category: str | None = None) -> EvidenceItem:
        props = node.properties
        scope = "target_function" if props.get("function") else "project"
        trust = "high" if props.get("relpath") and props.get("function") and props.get("line_start") else "low_missing_location"
        md = {"risk_hits": props.get("risk_hits", []), "calls": props.get("calls", []), "identifiers": props.get("identifiers", [])}
        if category:
            md["wanted_category"] = category
        return EvidenceItem(
            evidence_id=f"{prefix}.{idx}",
            kind=kind,
            node_id=node.id,
            relpath=props.get("relpath"),
            function=props.get("function"),
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=str(props.get("text", ""))[: self.max_text_chars],
            score=score,
            scope=scope,
            matched_symbol=matched_symbol,
            match_type=match_type,
            trust=trust,
            metadata=md,
        )


    def _definition_item(self, prefix: str, idx: int, kind: str, node: KGNode, *, matched_symbol: str | None = None, match_type: str | None = None) -> EvidenceItem:
        props = node.properties
        md = {
            "wanted_category": "definition",
            "name": props.get("name"),
            "value": props.get("value"),
            "qualified_name": props.get("qualified_name"),
            "node_type": node.type,
        }
        return EvidenceItem(
            evidence_id=f"{prefix}.{idx}",
            kind=kind,
            node_id=node.id,
            relpath=props.get("relpath"),
            function=None,
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=str(props.get("text", ""))[: self.max_text_chars],
            score=1.95,
            scope="project_global",
            matched_symbol=matched_symbol,
            match_type=match_type,
            trust="high" if props.get("relpath") and props.get("line_start") else "medium",
            metadata=md,
        )

    def _function_item(self, prefix: str, idx: int, kind: str, node: KGNode, score: float = 1.0, *, matched_symbol: str | None = None, match_type: str | None = None) -> EvidenceItem:
        props = node.properties
        body = str(props.get("body_preview", ""))[: self.max_text_chars]
        sig = str(props.get("signature", ""))
        return EvidenceItem(
            evidence_id=f"{prefix}.{idx}",
            kind=kind,
            node_id=node.id,
            relpath=props.get("relpath"),
            function=props.get("name"),
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=(sig + "\n" + body).strip(),
            score=score,
            scope="callee" if "callee" in kind else "caller" if "caller" in kind else "function",
            matched_symbol=matched_symbol,
            match_type=match_type,
            trust="high" if props.get("relpath") and props.get("line_start") else "medium",
            metadata={"qualified_name": props.get("qualified_name"), "parameters": props.get("parameters", [])},
        )

    def _variable_item(self, prefix: str, idx: int, node: KGNode, *, matched_symbol: str, category: str | None = None) -> EvidenceItem:
        props = node.properties
        md = {"qualified_name": props.get("qualified_name"), "node_type": node.type}
        if category:
            md["wanted_category"] = category
        return EvidenceItem(
            evidence_id=f"{prefix}.{idx}",
            kind="tool_variable_declaration",
            node_id=node.id,
            relpath=props.get("relpath"),
            function=props.get("function"),
            line_start=props.get("line_start"),
            line_end=props.get("line_end"),
            text=f"{node.type} {props.get('name')} declared in {props.get('function')} at {props.get('relpath')}:{props.get('line_start')}",
            score=1.7,
            scope="target_function",
            matched_symbol=matched_symbol,
            match_type="exact_identifier_target_scope",
            trust="high",
            metadata=md,
        )


def merge_tool_results_into_evidence(evidence: EvidencePack, results: list[KGToolResult], max_total_items: int = 120) -> EvidencePack:
    existing_ids = {item.evidence_id for item in evidence.items}
    for result in results:
        for item in KGToolResult._flatten_items(result.items):
            if not isinstance(item, EvidenceItem):
                continue
            if item.evidence_id not in existing_ids and len(evidence.items) < max_total_items:
                evidence.items.append(item)
                existing_ids.add(item.evidence_id)
    evidence.retrieval_diagnostics.setdefault("agent_tool_results", []).extend([r.to_dict() for r in results])
    evidence.retrieval_diagnostics["num_items_after_agent_tools"] = len(evidence.items)
    return evidence
