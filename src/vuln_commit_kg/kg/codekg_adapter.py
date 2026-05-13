from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from vuln_commit_kg.kg.graph_store import KGEdge, KGNode, ProjectGraph
from vuln_commit_kg.retrieval.evidence import EvidenceItem


NEW_CODEKG_QUERY_KINDS = {
    "security_context",
    "evidence_slice",
    "function_context",
    "call_neighborhood",
    "variable_flow",
    "semantic_facts",
    "file_context",
    "shortest_path",
    "risk_slice",
    "callers",
    "callees",
}

_QUERY_LIMITS = {
    "depth": (0, 6),
    "relation_depth": (0, 6),
    "call_depth": (0, 5),
    "data_depth": (0, 6),
    "control_depth": (0, 6),
    "joern_limit": (0, 500),
    "joern_edge_limit": (0, 1500),
    "max_nodes": (1, 1200),
}

_ALLOWED_PARAMS: dict[str, set[str]] = {
    "security_context": {
        "kind", "target", "target_function", "depth", "call_depth", "data_depth",
        "include_callers", "include_headers", "include_globals", "include_joern",
        "joern_limit", "joern_edge_limit", "max_nodes", "risk_terms", "reason", "hypothesis_id",
    },
    "evidence_slice": {
        "kind", "target", "target_function", "target_statement", "depth", "relation_depth",
        "call_depth", "data_depth", "control_depth", "include_defs", "include_uses",
        "include_guards", "include_callees", "include_callers", "include_headers",
        "include_globals", "include_joern", "joern_limit", "joern_edge_limit", "max_nodes",
        "risk_terms", "reason", "hypothesis_id",
    },
    "function_context": {"kind", "target", "target_function", "depth", "reason", "hypothesis_id"},
    "call_neighborhood": {"kind", "target", "target_function", "direction", "depth", "call_depth", "reason", "hypothesis_id"},
    "variable_flow": {"kind", "target", "target_function", "symbol", "depth", "data_depth", "reason", "hypothesis_id"},
    "semantic_facts": {"kind", "target", "target_function", "risk_terms", "reason", "hypothesis_id"},
    "file_context": {"kind", "file", "depth", "reason", "hypothesis_id"},
    "shortest_path": {"kind", "source_node", "target_node", "reason", "hypothesis_id"},
    "risk_slice": {"kind", "target", "target_function", "risk_terms", "reason", "hypothesis_id"},
    "callers": {"kind", "target", "target_function", "reason", "hypothesis_id"},
    "callees": {"kind", "target", "target_function", "reason", "hypothesis_id"},
}


def normalize_backend_name(name: str | None) -> str:
    raw = (name or "auto").strip().lower()
    if raw in {"lightweight", "fallback", "source", "source_only"}:
        return "heuristic"
    if raw in {"tree_sitter", "treesitter"}:
        return "tree-sitter"
    if raw in {"auto", "joern", "heuristic", "tree-sitter"}:
        return raw
    return "auto"


def build_codekg_graph(
    *,
    source_dir: Path,
    out_dir: Path,
    cfg: Any,
    project: str | None,
    project_url: str | None,
    commit_id: str | None,
    logger: Any,
) -> ProjectGraph:
    """Build CodeKG artifacts and return a pipeline-compatible ProjectGraph.

    CodeKG remains the source of truth on disk. The returned ProjectGraph is a
    compatibility view used by the existing target locator, evidence pack, and
    audit loop.
    """
    from codekg.cli import _apply_joern_home, select_backend
    from codekg.dashboard import write_dashboard
    from codekg.exporter import QUERY_EXAMPLES, export_graph
    from codekg.logging_utils import configure_logging
    from codekg.backends import detect_java, detect_joern, joern_available, tree_sitter_available

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joern_home = getattr(cfg, "joern_home", None)
    if joern_home:
        _apply_joern_home(str(joern_home))
    requested = normalize_backend_name(getattr(cfg, "backend", "auto"))
    require_joern = bool(getattr(cfg, "require_joern", False)) or (
        requested == "joern" and not bool(getattr(cfg, "joern_fallback_to_lightweight", True))
    )
    joern_timeout = int(getattr(cfg, "joern_timeout_seconds", getattr(cfg, "joern_timeout", 900)) or 900)
    joern_language = str(getattr(cfg, "joern_language", "C") or "C")

    codekg_logger = configure_logging(out_dir, verbose=False)
    codekg_logger.propagate = False
    tools = detect_joern()
    java_info = detect_java()
    if require_joern and not joern_available():
        raise RuntimeError(
            "CodeKG require_joern=true but Joern is not runnable. "
            f"tools={tools} java={java_info} joern_home={os.environ.get('CODEKG_JOERN_HOME') or os.environ.get('JOERN_HOME')}"
        )
    backend = select_backend(
        requested,
        codekg_logger,
        strict_joern=require_joern,
        joern_timeout=joern_timeout,
        joern_language=joern_language,
    )
    graph, diagnostics = backend.build(Path(source_dir), out_dir, codekg_logger)
    diagnostics.counters["files_scanned"] = diagnostics.counters.get("files_scanned") or sum(
        1 for p in Path(source_dir).rglob("*") if p.is_file()
    )
    manifest = export_graph(graph, out_dir, Path(source_dir), diagnostics, codekg_logger)
    manifest.update(
        {
            "kg_version": "codekg_explorer_integrated_v1",
            "project": project,
            "project_url": project_url,
            "commit_id": commit_id,
            "snapshot_path": str(Path(source_dir).resolve()),
            "codekg_graph_dir": str(out_dir.resolve()),
            "dashboard_path": str((out_dir / "dashboard" / "index.html").resolve()),
            "kg_methodology": "CodeKG Explorer builder with Joern/Tree-sitter/heuristic backend selection, scope-aware variable identity, statement occurrence identity, deterministic semantic facts, and static dashboard export.",
            "layers": ["files", "functions", "statements", "variables", "fields", "calls", "CFG", "semantic_facts", "retrieval"],
            "kg_representation_note": "CodeKG graph artifacts are canonical; the in-memory ProjectGraph is a compatibility view for the existing vulnerability-agent workflow.",
            "num_nodes": manifest.get("number_of_nodes"),
            "num_edges": manifest.get("number_of_edges"),
            "num_files": manifest.get("source_files_parsed") or manifest.get("files_scanned"),
            "num_functions": (manifest.get("node_type_counts") or {}).get("Function"),
            "num_statements": sum((manifest.get("node_type_counts") or {}).get(t, 0) for t in ["Statement", "Assignment", "ReturnStatement", "Condition", "Loop", "CallExpression"]),
            "backend": manifest.get("backend_used"),
            "backend_used": manifest.get("backend_used"),
            "backend_requested": manifest.get("backend_requested"),
            "joern_available": manifest.get("joern_available"),
            "java_available": bool(java_info.get("ok")),
            "tree_sitter_available": tree_sitter_available(),
            "fallback_used": str(manifest.get("backend_used") or "").lower().startswith("heuristic"),
        }
    )
    # Re-write enriched manifest after adding pipeline-specific metadata.
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    graph_payload = json.loads((out_dir / "graph.json").read_text(encoding="utf-8"))
    degree = graph.degree()
    for n in graph_payload.get("nodes", []):
        n["degree"] = int(degree.get(n.get("id"), 0))
    write_dashboard(
        out_dir,
        graph_payload,
        manifest,
        QUERY_EXAMPLES,
        initial_query={"kind": "security_context"},
        logger=codekg_logger,
    )
    if logger:
        logger.info(
            "CodeKG build complete | out=%s | backend=%s | nodes=%s | edges=%s | dashboard=%s",
            out_dir,
            manifest.get("backend_used"),
            manifest.get("number_of_nodes"),
            manifest.get("number_of_edges"),
            out_dir / "dashboard" / "index.html",
        )
    return load_codekg_as_project_graph(out_dir)


def load_codekg_as_project_graph(graph_dir: str | Path) -> ProjectGraph:
    graph_dir = Path(graph_dir)
    graph_payload = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
    manifest = json.loads((graph_dir / "manifest.json").read_text(encoding="utf-8"))
    nodes = [_codekg_node_to_project_node(n) for n in graph_payload.get("nodes", [])]
    edges: list[KGEdge] = []
    node_types = {n.id: n.type for n in nodes}
    for e in graph_payload.get("edges", []):
        edge = _codekg_edge_to_project_edge(e)
        edges.append(edge)
        # Backward-compatible aliases for the legacy deterministic evidence retriever.
        if e.get("type") == "CALLS" and node_types.get(e.get("source")) == "Function" and node_types.get(e.get("target")) == "Function":
            attrs = dict(e.get("attrs") or {})
            target_name = next((n.properties.get("name") for n in nodes if n.id == e.get("target")), None)
            if target_name:
                attrs.setdefault("callee_name", target_name)
            edges.append(KGEdge(source=e["source"], target=e["target"], type="FUNCTION_CALLS_FUNCTION", properties=attrs))
        if e.get("type") in {"FUNCTION_HAS_PARAMETER", "FUNCTION_HAS_LOCAL"}:
            edges.append(KGEdge(source=e["source"], target=e["target"], type="DECLARES", properties=dict(e.get("attrs") or {})))
    manifest.setdefault("codekg_graph_dir", str(graph_dir.resolve()))
    manifest.setdefault("dashboard_path", str((graph_dir / "dashboard" / "index.html").resolve()))
    manifest.setdefault("num_nodes", manifest.get("number_of_nodes", len(nodes)))
    manifest.setdefault("num_edges", manifest.get("number_of_edges", len(edges)))
    manifest.setdefault("num_files", manifest.get("source_files_parsed") or manifest.get("files_scanned"))
    manifest.setdefault("num_functions", (manifest.get("node_type_counts") or {}).get("Function"))
    return ProjectGraph(nodes=nodes, edges=edges, manifest=manifest)


def _codekg_node_to_project_node(n: dict[str, Any]) -> KGNode:
    props = dict(n.get("attrs") or {})
    for key in ["label", "name", "file", "function", "line_start", "line_end", "code", "degree"]:
        if key in n and n.get(key) is not None:
            props.setdefault(key, n.get(key))
    if n.get("file") is not None:
        props.setdefault("relpath", str(n.get("file")))
    if n.get("code") is not None:
        props.setdefault("text", str(n.get("code")))
        props.setdefault("body_preview", str(n.get("code"))[:2000])
        if n.get("type") == "Function":
            first = str(n.get("code") or "").splitlines()[0] if str(n.get("code") or "").splitlines() else ""
            props.setdefault("signature", first[:300])
    props.setdefault("codekg_type", n.get("type"))
    return KGNode(id=str(n.get("id")), type=str(n.get("type") or "Unknown"), properties=props)


def _codekg_edge_to_project_edge(e: dict[str, Any]) -> KGEdge:
    props = dict(e.get("attrs") or {})
    if e.get("id") is not None:
        props.setdefault("edge_id", e.get("id"))
    return KGEdge(source=str(e.get("source")), target=str(e.get("target")), type=str(e.get("type") or "UNKNOWN"), properties=props)


def graph_dir_from_project_graph(graph: ProjectGraph) -> Path | None:
    raw = (graph.manifest or {}).get("codekg_graph_dir") or (graph.manifest or {}).get("graph_dir")
    if not raw:
        return None
    p = Path(str(raw))
    return p if p.exists() else None


def parse_codekg_query_object(raw: Any, *, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    defaults = dict(defaults or {})
    if isinstance(raw, str):
        raw_text = raw.strip()
        if not raw_text:
            raise ValueError("empty CodeKG query")
        if raw_text.startswith("{"):
            obj = json.loads(raw_text)
        else:
            kind, args = _parse_function_call_query(raw_text)
            obj = {"kind": kind, **args}
    elif isinstance(raw, dict):
        obj = dict(raw)
        # Some model outputs put the function-call query in the legacy query field.
        qtext = str(obj.get("query") or "").strip()
        if qtext and re.match(r"^[A-Za-z_]\w*\s*\(", qtext):
            parsed_kind, args = _parse_function_call_query(qtext)
            explicit_kind = str(obj.get("kind") or "").strip().lower()
            query_type_kind = str(obj.get("query_type") or "").strip().lower()
            # Function-call text is the most precise form. Legacy wrappers often
            # carry query_type=search/guard/risk, which must not override the
            # parsed CodeKG kind.
            selected_kind = explicit_kind or (query_type_kind if query_type_kind in NEW_CODEKG_QUERY_KINDS else parsed_kind)
            obj = {**obj, "kind": selected_kind, **args}
    else:
        raise ValueError(f"unsupported CodeKG query object type: {type(raw).__name__}")
    if "kind" not in obj and "query_type" in obj:
        obj["kind"] = obj.get("query_type")
    if "kind" not in obj and "type" in obj:
        obj["kind"] = obj.get("type")
    kind = str(obj.get("kind") or "").strip().lower()
    if kind == "vulnerability_context":
        kind = "security_context"
    if not kind:
        kind = "security_context"
    obj["kind"] = kind
    for k, v in defaults.items():
        obj.setdefault(k, v)
    return validate_codekg_query(obj)


def validate_codekg_query(obj: dict[str, Any]) -> dict[str, Any]:
    kind = str(obj.get("kind") or "").strip().lower()
    if kind not in NEW_CODEKG_QUERY_KINDS:
        raise ValueError(f"unsupported CodeKG query kind: {kind}")
    allowed = _ALLOWED_PARAMS.get(kind, {"kind"})
    cleaned = {k: v for k, v in obj.items() if k in allowed or k.startswith("_")}
    cleaned["kind"] = kind
    ignored = sorted(k for k in obj.keys() if k not in cleaned and k not in {"query_type", "query", "type", "bundle_type", "scope", "match", "wanted_evidence"})
    if ignored:
        cleaned["_ignored_params"] = ignored
    for key, (lo, hi) in _QUERY_LIMITS.items():
        if key in cleaned and cleaned[key] is not None and cleaned[key] != "":
            try:
                val = int(cleaned[key])
            except Exception as exc:
                raise ValueError(f"{key} must be an integer") from exc
            cleaned[key] = max(lo, min(hi, val))
    if cleaned.get("direction") not in {None, "in", "out", "both"}:
        raise ValueError("direction must be one of in/out/both")
    for b in ["include_callers", "include_headers", "include_globals", "include_joern", "include_defs", "include_uses", "include_guards", "include_callees"]:
        if b in cleaned:
            cleaned[b] = _truthy(cleaned[b])
    if "risk_terms" in cleaned:
        cleaned["risk_terms"] = _list_of_str(cleaned.get("risk_terms"), max_items=40)
    for required in _required_params(kind):
        if not cleaned.get(required):
            raise ValueError(f"{kind} requires parameter: {required}")
    return cleaned


def execute_codekg_query(graph: ProjectGraph, query_obj: dict[str, Any], *, prefix: str, max_items: int = 10, max_text_chars: int = 900) -> tuple[list[EvidenceItem], dict[str, Any]]:
    from codekg.query import GraphQueryEngine

    graph_dir = graph_dir_from_project_graph(graph)
    if graph_dir is None:
        raise FileNotFoundError("ProjectGraph manifest does not contain a usable codekg_graph_dir")
    query = parse_codekg_query_object(query_obj)
    engine = GraphQueryEngine(graph_dir)
    kind = query["kind"]
    engine_kwargs = _engine_kwargs(query)
    result = engine.run(kind, **engine_kwargs)
    diagnostics = normalize_codekg_result(result, query=query, graph_dir=graph_dir)
    items = codekg_result_to_evidence_items(
        result,
        prefix=prefix,
        query=query,
        max_items=max_items,
        max_text_chars=max_text_chars,
        dashboard_path=str((graph_dir / "dashboard" / "index.html").resolve()),
    )
    return items, diagnostics


def normalize_codekg_result(result: dict[str, Any], *, query: dict[str, Any], graph_dir: Path) -> dict[str, Any]:
    sub = result.get("subgraph") or {}
    nodes = sub.get("nodes") or result.get("nodes") or []
    edges = sub.get("edges") or result.get("edges") or []
    facts = [n for n in nodes if n.get("type") == "SemanticFact"]
    guards = [n for n in facts if any(t in json.dumps(n, ensure_ascii=False).lower() for t in ["guard", "bounds", "null", "check", "return"])]
    statements = [n for n in nodes if n.get("type") in {"Statement", "Assignment", "ReturnStatement", "Condition", "Loop", "CallExpression"}]
    functions = sorted({str(n.get("name")) for n in nodes if n.get("type") == "Function" and n.get("name")})
    variables = sorted({str(n.get("name")) for n in nodes if n.get("type") in {"FunctionParameter", "LocalVariable", "GlobalVariable", "Field"} and n.get("name")})
    return {
        "codekg": True,
        "query": query,
        "error": result.get("error"),
        "retrieved_node_count": result.get("node_count", len(nodes)),
        "retrieved_edge_count": result.get("edge_count", len(edges)),
        "full_node_count": result.get("full_node_count"),
        "full_edge_count": result.get("full_edge_count"),
        "visual_trimmed": result.get("visual_trimmed"),
        "important_functions": functions[:50],
        "important_variables": variables[:100],
        "important_statement_count": len(statements),
        "semantic_fact_count": len(facts),
        "guard_like_fact_count": len(guards),
        "evidence_summary": result.get("evidence_summary"),
        "dashboard_path": str((graph_dir / "dashboard" / "index.html").resolve()),
        "kg_artifacts": str(graph_dir.resolve()),
        "node_type_counts": _count_by(nodes, "type"),
        "edge_type_counts": _count_by(edges, "type"),
    }


def codekg_result_to_evidence_items(result: dict[str, Any], *, prefix: str, query: dict[str, Any], max_items: int, max_text_chars: int, dashboard_path: str | None) -> list[EvidenceItem]:
    sub = result.get("subgraph") or {}
    nodes = list(sub.get("nodes") or result.get("nodes") or [])
    edges = list(sub.get("edges") or result.get("edges") or [])
    ranked = sorted(nodes, key=lambda n: _node_rank(n, query), reverse=True)
    items: list[EvidenceItem] = []
    summary = result.get("evidence_summary") or {}
    if result.get("error"):
        return []
    if summary:
        items.append(
            EvidenceItem(
                evidence_id=f"{prefix}.1",
                kind="codekg_query_summary",
                node_id=None,
                relpath=None,
                function=query.get("target_function") or query.get("target"),
                text=json.dumps(summary, ensure_ascii=False, indent=2)[:max_text_chars],
                score=2.2,
                scope="codekg_retrieval_summary",
                match_type=str(query.get("kind")),
                trust="high",
                metadata={"query": query, "dashboard_path": dashboard_path, "edge_count": len(edges)},
            )
        )
    start_idx = len(items) + 1
    for n in ranked:
        if len(items) >= max_items:
            break
        text = _node_text(n).strip()
        if not text:
            continue
        items.append(
            EvidenceItem(
                evidence_id=f"{prefix}.{start_idx + len(items) - (1 if summary else 0)}",
                kind=f"codekg_{str(n.get('type') or 'node').lower()}",
                node_id=str(n.get("id")),
                relpath=n.get("file"),
                function=n.get("function") or (n.get("name") if n.get("type") == "Function" else query.get("target_function")),
                line_start=_as_int(n.get("line_start")),
                line_end=_as_int(n.get("line_end")),
                text=text[:max_text_chars],
                score=float(_node_rank(n, query)) / 100.0,
                scope="codekg_subgraph",
                matched_symbol=query.get("symbol") or "",
                match_type=str(query.get("kind")),
                trust="high" if n.get("file") or n.get("code") else "medium",
                metadata={"node_type": n.get("type"), "query": query, "dashboard_path": dashboard_path, "attrs": n.get("attrs") or {}},
            )
        )
    return items


def _engine_kwargs(query: dict[str, Any]) -> dict[str, Any]:
    kind = query.get("kind")
    kwargs = dict(query)
    kwargs.pop("kind", None)
    if kind == "evidence_slice":
        # CodeKG's deterministic evidence_slice entry currently uses the same
        # security-context engine, with suspicious statement/risk terms steering
        # result ranking and evidence conversion.
        kwargs.setdefault("depth", kwargs.get("relation_depth") or 4)
        kwargs.setdefault("data_depth", kwargs.get("data_depth") or 4)
        kwargs.setdefault("call_depth", kwargs.get("call_depth") or 2)
    if kind == "call_neighborhood" and "call_depth" in kwargs and "depth" not in kwargs:
        kwargs["depth"] = kwargs["call_depth"]
    if kind == "variable_flow" and "data_depth" in kwargs and "depth" not in kwargs:
        kwargs["depth"] = kwargs["data_depth"]
    return kwargs


def _parse_function_call_query(text: str) -> tuple[str, dict[str, Any]]:
    m = re.match(r"\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$", text, flags=re.S)
    if not m:
        raise ValueError("query text must be a JSON object or function-call style CodeKG query")
    kind = m.group(1)
    body = m.group(2).strip()
    if not body:
        return kind, {}
    args: dict[str, Any] = {}
    for part in _split_top_level_commas(body):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            args[k.strip()] = _parse_value(v.strip())
        else:
            args.setdefault("target_function", _parse_value(part))
    return kind, args


def _split_top_level_commas(body: str) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    quote: str | None = None
    esc = False
    for ch in body:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _parse_value(v: str) -> Any:
    s = v.strip()
    if not s:
        return ""
    low = s.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low in {"none", "null"}:
        return None
    try:
        return ast.literal_eval(s)
    except Exception:
        pass
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s.strip('"\'')


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _list_of_str(v: Any, max_items: int = 40) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        raw = [x.strip() for x in v.split(",")]
    elif isinstance(v, (list, tuple, set)):
        raw = [str(x).strip() for x in v]
    else:
        raw = [str(v).strip()]
    out: list[str] = []
    for item in raw:
        if item and item not in out:
            out.append(item[:80])
        if len(out) >= max_items:
            break
    return out


def _required_params(kind: str) -> list[str]:
    if kind in {"security_context", "evidence_slice", "function_context", "call_neighborhood", "variable_flow", "semantic_facts", "risk_slice", "callers", "callees"}:
        return ["target_function"]
    if kind == "file_context":
        return ["file"]
    if kind == "shortest_path":
        return ["source_node", "target_node"]
    return []


def _node_text(n: dict[str, Any]) -> str:
    attrs = n.get("attrs") or {}
    parts = []
    for key in ["code", "label", "name", "function", "file"]:
        if n.get(key):
            parts.append(str(n.get(key)))
    for key in ["description", "evidence_text", "fact_type", "risk", "guard", "source_text"]:
        if attrs.get(key):
            parts.append(str(attrs.get(key)))
    if not parts and attrs:
        parts.append(json.dumps(attrs, ensure_ascii=False)[:1200])
    return "\n".join(dict.fromkeys(parts))


def _node_rank(n: dict[str, Any], query: dict[str, Any]) -> int:
    t = str(n.get("type") or "")
    score = {
        "Function": 220,
        "FunctionParameter": 190,
        "LocalVariable": 185,
        "GlobalVariable": 180,
        "Field": 175,
        "Condition": 170,
        "Loop": 165,
        "Assignment": 165,
        "ReturnStatement": 160,
        "CallExpression": 160,
        "Statement": 145,
        "SemanticFact": 175,
        "File": 100,
        "JoernCPGNode": 80,
    }.get(t, 50)
    hay = json.dumps(n, ensure_ascii=False).lower()
    for term in _list_of_str(query.get("risk_terms")) + _list_of_str(query.get("symbol")) + _list_of_str(query.get("target_statement")):
        if term.lower() in hay:
            score += 35
    if n.get("code") or (n.get("attrs") or {}).get("evidence_text"):
        score += 15
    return score


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        k = str(row.get(key) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out


def _as_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None and v != "" else None
    except Exception:
        return None
