from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Iterable

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.logging_utils import ProgressMeter, fmt_seconds, log_kv, rss_mb
from vuln_commit_kg.utils.hashing import stable_hash

from .extractors.c_like import extract_functions_from_text
from .extractors.security_patterns import find_risky_calls, is_safety_statement
from .graph_store import KGEdge, KGNode, ProjectGraph, save_graph


class ProjectGraphBuilder:
    """Build a source-only CPG-inspired security KG.

    This implementation remains dependency-light and regex/statement based, but the
    representation is now explicitly layered like a Code Property Graph plus a
    security overlay:
      - core code layer: Project/File/Function/Statement/CallExpression/LocalVariable
      - program-analysis edges: CONTAINS, AST_CHILD, CALLS, DEF_USE, USES/DEFINES_VARIABLE
      - security overlay: SecurityRisk/SafetyCheck with evidence edges

    It is not a full compiler-aware Joern/CodeQL/Clang CPG. The manifest records
    that limitation so reports do not over-claim semantic precision.
    """

    def __init__(self, cfg: KGConfig, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger

    def build(
        self,
        snapshot_path: Path | None,
        project: str | None,
        project_url: str | None,
        commit_id: str | None,
    ) -> ProjectGraph:
        if self.cfg.scope == "disabled":
            return ProjectGraph(manifest={"scope": "disabled"})
        if self.cfg.scope == "function_only_baseline":
            raise ValueError("function_only_baseline should be handled by the orchestration layer per sample.")
        if snapshot_path is None or not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot path unavailable: {snapshot_path}")

        if self.cfg.backend in {"auto", "joern"}:
            from .joern_builder import build_with_joern

            joern_graph = build_with_joern(
                cfg=self.cfg,
                logger=self.logger,
                snapshot_path=snapshot_path,
                project=project,
                project_url=project_url,
                commit_id=commit_id,
            )
            if joern_graph is not None:
                return joern_graph
            if self.cfg.backend == "joern" and not self.cfg.joern_fallback_to_lightweight:
                raise RuntimeError("Joern KG backend was requested, but Joern parsing/export failed and fallback is disabled.")
            self.logger.warning("kg.joern.fallback_to_lightweight | backend=%s", self.cfg.backend)

        start = time.perf_counter()
        log_kv(
            self.logger,
            "KG build start",
            project=project,
            commit=(commit_id[:12] if commit_id else None),
            snapshot=snapshot_path,
            kg_version=self.cfg.version,
            include_file_types=",".join(self.cfg.include_file_types),
            include_headers=self.cfg.include_headers,
            max_files=self.cfg.max_files,
            max_file_bytes=self.cfg.max_file_bytes,
        )

        graph = ProjectGraph()
        project_id = f"project:{stable_hash(project_url or project or 'unknown', 16)}"
        commit_node_id = f"commit:{commit_id or 'unknown'}"
        graph.nodes.append(KGNode(project_id, "Project", {"name": project, "url": project_url}))
        graph.nodes.append(KGNode(commit_node_id, "Commit", {"commit_id": commit_id}))
        graph.edges.append(KGEdge(project_id, commit_node_id, "PROJECT_AT_COMMIT"))

        source_files, discovery_stats = self._discover_source_files(snapshot_path)
        if self.cfg.max_files is not None and len(source_files) > self.cfg.max_files:
            self.logger.info(
                "kg.discover.cap: using first %s eligible source files out of %s because kg.max_files=%s",
                self.cfg.max_files,
                len(source_files),
                self.cfg.max_files,
            )
            source_files = source_files[: self.cfg.max_files]

        log_kv(
            self.logger,
            "KG discovery done",
            eligible_source_files=len(source_files),
            files_scanned=discovery_stats["files_scanned"],
            excluded_by_dir=discovery_stats["excluded_by_dir"],
            excluded_by_suffix=discovery_stats["excluded_by_suffix"],
            elapsed=fmt_seconds(time.perf_counter() - start),
            rss=f"{rss_mb():.1f} MB",
        )

        files_seen = 0
        functions_seen = 0
        statements_seen = 0
        calls_seen = 0
        variables_seen = 0
        macro_definitions_seen = 0
        global_definitions_seen = 0
        skipped_large = 0
        parse_errors = 0
        function_name_index: dict[str, list[str]] = {}
        last_def_by_function_var: dict[tuple[str, str], str] = {}
        progress = ProgressMeter(
            self.logger,
            len(source_files),
            "kg.parse.files",
            log_every=max(1, self.cfg.progress_log_every_files),
            log_every_seconds=self.cfg.progress_log_every_seconds,
        )

        for file_path in source_files:
            relpath = "?"
            try:
                if file_path.stat().st_size > self.cfg.max_file_bytes:
                    skipped_large += 1
                    progress.update(extra=f"skip_large={skipped_large} file={file_path.name}")
                    continue
                relpath = file_path.relative_to(snapshot_path).as_posix()
                file_bytes = file_path.stat().st_size
                file_start = time.perf_counter()
                if self.cfg.log_file_start:
                    self.logger.info(
                        "kg.parse.file_start: %s/%s | file=%s | bytes=%s | rss=%.1f MB",
                        progress.done + 1,
                        len(source_files),
                        relpath,
                        file_bytes,
                        rss_mb(),
                    )
                text = file_path.read_text(encoding="utf-8", errors="ignore")
                funcs = extract_functions_from_text(text, relpath=relpath)
                file_elapsed = time.perf_counter() - file_start
                if file_elapsed >= self.cfg.slow_file_log_seconds:
                    self.logger.warning(
                        "kg.parse.slow_file: file=%s | elapsed=%s | bytes=%s | funcs=%s | rss=%.1f MB",
                        relpath,
                        fmt_seconds(file_elapsed),
                        file_bytes,
                        len(funcs),
                        rss_mb(),
                    )
                files_seen += 1
                file_node = f"file:{relpath}"
                graph.nodes.append(KGNode(file_node, "File", {"relpath": relpath, "bytes": len(text)}))
                graph.edges.append(KGEdge(commit_node_id, file_node, "COMMIT_HAS_FILE"))
                graph.edges.append(KGEdge(commit_node_id, file_node, "CONTAINS"))

                for definition in _extract_file_level_definitions(text, relpath):
                    def_hash = stable_hash(f"{relpath}:{definition['line_start']}:{definition['name']}:{definition['text']}", 12)
                    node_id = f"definition:{definition['node_type']}:{relpath}:{definition['name']}:{definition['line_start']}:{def_hash}"
                    graph.nodes.append(KGNode(node_id, definition["node_type"], definition))
                    graph.edges.append(KGEdge(file_node, node_id, "FILE_HAS_DEFINITION"))
                    graph.edges.append(KGEdge(file_node, node_id, "CONTAINS"))
                    graph.edges.append(KGEdge(commit_node_id, node_id, "COMMIT_HAS_DEFINITION"))
                    if definition["node_type"] == "MacroDefinition":
                        macro_definitions_seen += 1
                    else:
                        global_definitions_seen += 1

                for fn in funcs:
                    if self.cfg.max_functions is not None and functions_seen >= self.cfg.max_functions:
                        break
                    fn_node = f"function:{fn.function_id}"
                    graph.nodes.append(
                        KGNode(
                            fn_node,
                            "Function",
                            {
                                "name": fn.name,
                                "signature": fn.signature,
                                "relpath": relpath,
                                "line_start": fn.line_start,
                                "line_end": fn.line_end,
                                "body_preview": fn.body[:2000],
                                "parameters": fn.parameters,
                                "local_variables": sorted(fn.local_variables.keys()),
                                "qualified_name": f"{relpath}::{fn.name}",
                            },
                        )
                    )
                    graph.edges.append(KGEdge(file_node, fn_node, "FILE_HAS_FUNCTION"))
                    graph.edges.append(KGEdge(file_node, fn_node, "CONTAINS"))
                    function_name_index.setdefault(fn.name, []).append(fn_node)
                    functions_seen += 1

                    # Variable/parameter declaration nodes; this gives exact symbol anchors.
                    for var_name, var_info in sorted(fn.local_variables.items()):
                        var_node = f"var:{relpath}:{fn.name}:{var_name}:{var_info.get('line_start') or fn.line_start}"
                        vtype = "Parameter" if var_info.get("kind") == "parameter" else "LocalVariable"
                        graph.nodes.append(
                            KGNode(
                                var_node,
                                vtype,
                                {
                                    "name": var_name,
                                    "relpath": relpath,
                                    "function": fn.name,
                                    "line_start": var_info.get("line_start") or fn.line_start,
                                    "line_end": var_info.get("line_end") or fn.line_start,
                                    "scope": "target_or_function_local",
                                    "qualified_name": f"{relpath}::{fn.name}::{var_name}",
                                },
                            )
                        )
                        graph.edges.append(KGEdge(fn_node, var_node, "DECLARES"))
                        graph.edges.append(KGEdge(fn_node, var_node, "CONTAINS"))
                        variables_seen += 1

                    variable_node_by_name = {
                        n.properties.get("name"): n.id
                        for n in graph.nodes
                        if n.type in {"LocalVariable", "Parameter"}
                        and n.properties.get("relpath") == relpath
                        and n.properties.get("function") == fn.name
                    }

                    previous_stmt_node: str | None = None
                    for stmt in fn.statements:
                        stmt_node = f"statement:{stmt.statement_id}"
                        risk_hits = [h.__dict__ for h in find_risky_calls(stmt.text)]
                        safety = is_safety_statement(stmt.text)
                        graph.nodes.append(
                            KGNode(
                                stmt_node,
                                "Statement",
                                {
                                    "text": stmt.text,
                                    "relpath": relpath,
                                    "function": fn.name,
                                    "line_start": stmt.line_start,
                                    "line_end": stmt.line_end,
                                    "calls": stmt.calls,
                                    "identifiers": stmt.identifiers,
                                    "defines_variables": stmt.defines_variables,
                                    "uses_variables": stmt.uses_variables,
                                    "risk_hits": risk_hits,
                                    "is_safety": safety,
                                    "qualified_name": f"{relpath}::{fn.name}::{stmt.line_start}:{stable_hash(stmt.text, 10)}",
                                },
                            )
                        )
                        graph.edges.append(KGEdge(fn_node, stmt_node, "FUNCTION_HAS_STATEMENT"))
                        graph.edges.append(KGEdge(fn_node, stmt_node, "AST_CHILD"))
                        graph.edges.append(KGEdge(fn_node, stmt_node, "CONTAINS"))
                        if previous_stmt_node:
                            graph.edges.append(KGEdge(previous_stmt_node, stmt_node, "CFG_NEXT"))
                        previous_stmt_node = stmt_node
                        statements_seen += 1

                        for var in stmt.defines_variables:
                            var_node = variable_node_by_name.get(var)
                            if var_node:
                                graph.edges.append(KGEdge(stmt_node, var_node, "DEFINES_VARIABLE", {"name": var, "match_type": "exact_identifier"}))
                                last_def_by_function_var[(fn_node, var)] = stmt_node
                        for var in stmt.uses_variables:
                            var_node = variable_node_by_name.get(var)
                            if var_node:
                                graph.edges.append(KGEdge(stmt_node, var_node, "USES_VARIABLE", {"name": var, "match_type": "exact_identifier"}))
                                prev_def = last_def_by_function_var.get((fn_node, var))
                                if prev_def and prev_def != stmt_node:
                                    graph.edges.append(KGEdge(prev_def, stmt_node, "DEF_USE", {"variable": var, "match_type": "exact_identifier"}))

                        for call in stmt.calls:
                            call_node = f"call:{stmt.statement_id}:{call}"
                            graph.nodes.append(
                                KGNode(
                                    call_node,
                                    "CallExpression",
                                    {
                                        "name": call,
                                        "statement_id": stmt.statement_id,
                                        "relpath": relpath,
                                        "function": fn.name,
                                        "line_start": stmt.line_start,
                                        "line_end": stmt.line_end,
                                        "code": stmt.text[:500],
                                    },
                                )
                            )
                            graph.edges.append(KGEdge(stmt_node, call_node, "STATEMENT_CALLS"))
                            graph.edges.append(KGEdge(stmt_node, call_node, "AST_CHILD"))
                            graph.edges.append(KGEdge(fn_node, call_node, "FUNCTION_CALLS_NAME", {"callee_name": call}))
                            calls_seen += 1
                            for hit in risk_hits:
                                if hit["value"] == call:
                                    risk_node = f"risk:{hit['value']}:{hit.get('cwe') or 'unknown'}"
                                    graph.nodes.append(KGNode(risk_node, "SecurityRisk", hit))
                                    graph.edges.append(KGEdge(stmt_node, risk_node, "STATEMENT_HAS_RISK"))
                                    graph.edges.append(KGEdge(stmt_node, risk_node, "HAS_RISK"))
                                    graph.edges.append(KGEdge(risk_node, stmt_node, "EVIDENCE_FOR", {"source": "security_overlay"}))
                        if safety:
                            safety_node = f"safety:{stable_hash(stmt.text, 12)}"
                            graph.nodes.append(KGNode(safety_node, "SafetyCheck", {"text": stmt.text[:500], "relpath": relpath, "function": fn.name, "line_start": stmt.line_start, "line_end": stmt.line_end}))
                            graph.edges.append(KGEdge(stmt_node, safety_node, "STATEMENT_HAS_SAFETY_CHECK"))
                            graph.edges.append(KGEdge(safety_node, stmt_node, "EVIDENCE_FOR", {"source": "security_overlay"}))
                progress.update(
                    extra=(
                        f"file={relpath} funcs={functions_seen} stmts={statements_seen} "
                        f"vars={variables_seen} calls={calls_seen} nodes={len(graph.nodes)} edges={len(graph.edges)}"
                    )
                )
            except Exception as exc:
                parse_errors += 1
                self.logger.warning("kg.parse.skip: file=%s error=%s", relpath or file_path, exc)
                progress.update(extra=f"parse_errors={parse_errors} file={Path(relpath).name if relpath else file_path.name}")

        progress.finish(extra=f"files={files_seen} funcs={functions_seen} stmts={statements_seen} skipped_large={skipped_large}")

        self.logger.info("kg.resolve_calls: start | temporary_call_edges=%s", sum(1 for e in graph.edges if e.type == "FUNCTION_CALLS_NAME"))
        resolve_start = time.perf_counter()
        resolved_edges = 0
        for edge in list(graph.edges):
            if edge.type == "FUNCTION_CALLS_NAME":
                callee_name = edge.properties.get("callee_name")
                for target_fn_node in function_name_index.get(callee_name, [])[:20]:
                    graph.edges.append(KGEdge(edge.source, target_fn_node, "FUNCTION_CALLS_FUNCTION", {"callee_name": callee_name}))
                    graph.edges.append(KGEdge(edge.source, target_fn_node, "CALLS", {"callee_name": callee_name, "resolution": "name_based"}))
                    resolved_edges += 1
        self.logger.info("kg.resolve_calls: done | added=%s | elapsed=%s", resolved_edges, fmt_seconds(time.perf_counter() - resolve_start))

        self.logger.info("kg.deduplicate: start | nodes=%s edges=%s", len(graph.nodes), len(graph.edges))
        dedup_start = time.perf_counter()
        seen_nodes = set()
        unique_nodes = []
        for node in graph.nodes:
            if node.id not in seen_nodes:
                unique_nodes.append(node)
                seen_nodes.add(node.id)
        graph.nodes = unique_nodes
        seen_edges = set()
        unique_edges = []
        for edge in graph.edges:
            key = (edge.source, edge.target, edge.type, tuple(sorted((edge.properties or {}).items())))
            if key not in seen_edges:
                unique_edges.append(edge)
                seen_edges.add(key)
        graph.edges = unique_edges
        self.logger.info(
            "kg.deduplicate: done | nodes=%s edges=%s | elapsed=%s",
            len(graph.nodes),
            len(graph.edges),
            fmt_seconds(time.perf_counter() - dedup_start),
        )

        graph.manifest = {
            "project": project,
            "project_url": project_url,
            "commit_id": commit_id,
            "kg_scope": self.cfg.scope,
            "kg_version": self.cfg.version,
            "kg_backend": "lightweight",
            "kg_methodology": "cpg_inspired_source_only_security_overlay",
            "kg_representation_note": (
                "Directed edge-labeled attributed multigraph inspired by Code Property Graphs. "
                "Includes AST-like containment, statement order/CFG_NEXT, call graph, exact identifier variable anchors, "
                "lightweight DEF_USE edges, and security risk/safety overlay. This dependency-light builder is not a full compiler-aware Joern/Clang/CodeQL CPG."
            ),
            "layers": ["core_code", "program_analysis", "security_overlay", "retrieval_evidence"],
            "num_files": files_seen,
            "num_functions": functions_seen,
            "num_statements": statements_seen,
            "num_variables": variables_seen,
            "num_calls": calls_seen,
            "num_macro_definitions": macro_definitions_seen,
            "num_global_definitions": global_definitions_seen,
            "num_nodes": len(graph.nodes),
            "num_edges": len(graph.edges),
            "skipped_large_files": skipped_large,
            "parse_errors": parse_errors,
            "include_file_types": list(self.cfg.include_file_types),
            "include_headers": self.cfg.include_headers,
            "exclude_dirs": list(self.cfg.exclude_dirs),
            "max_files": self.cfg.max_files,
            "max_file_bytes": self.cfg.max_file_bytes,
            "files_scanned": discovery_stats["files_scanned"],
            "excluded_by_dir": discovery_stats["excluded_by_dir"],
            "excluded_by_suffix": discovery_stats["excluded_by_suffix"],
            "seconds": time.perf_counter() - start,
        }
        log_kv(
            self.logger,
            "KG build done",
            files=files_seen,
            functions=functions_seen,
            statements=statements_seen,
            variables=variables_seen,
            macro_definitions=macro_definitions_seen,
            global_definitions=global_definitions_seen,
            calls=calls_seen,
            nodes=len(graph.nodes),
            edges=len(graph.edges),
            skipped_large=skipped_large,
            parse_errors=parse_errors,
            elapsed=fmt_seconds(graph.manifest["seconds"]),
            rss=f"{rss_mb():.1f} MB",
        )
        return graph

    def build_and_save(self, snapshot_path: Path, out_dir: Path, project: str | None, project_url: str | None, commit_id: str | None) -> ProjectGraph:
        graph = self.build(snapshot_path, project, project_url, commit_id)
        if self.cfg.semantic_enrichment_enabled and graph.manifest.get("scope") != "disabled":
            from .semantic_enrichment import enrich_project_graph

            graph = enrich_project_graph(graph, mode=self.cfg.semantic_enrichment_mode)
        save_graph(graph, out_dir, logger=self.logger, log_every=self.cfg.graph_save_log_every)
        try:
            from .exports import export_graph_artifacts

            artifacts = export_graph_artifacts(graph, out_dir, self.cfg)
            graph.manifest.setdefault("storage_artifacts", {}).update(artifacts)
            import json
            (out_dir / "manifest.json").write_text(json.dumps(graph.manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            self.logger.warning("kg.export_artifacts_failed | dir=%s | error=%s", out_dir, exc)
        if self.cfg.visualization_enabled:
            try:
                from .kg_dashboard import write_kg_dashboard

                dashboard = write_kg_dashboard(graph, graph_dir=out_dir, out_path=out_dir / "kg_dashboard.html", cfg=self.cfg)
                self.logger.info("KG dashboard written | report=%s", dashboard)
            except Exception as exc:
                self.logger.warning("kg.dashboard_failed | dir=%s | error=%s", out_dir, exc)
        return graph

    def _discover_source_files(self, root: Path) -> tuple[list[Path], dict[str, int]]:
        extensions = set(self.cfg.include_file_types)
        if not self.cfg.include_headers:
            extensions = {ext for ext in extensions if ext not in {".h", ".hpp", ".hh", ".hxx"}}
        excluded = set(self.cfg.exclude_dirs)
        source_files: list[Path] = []
        stats = {"files_scanned": 0, "excluded_by_dir": 0, "excluded_by_suffix": 0}
        progress = ProgressMeter(self.logger, None, "kg.discover.scan", log_every=2500, log_every_seconds=self.cfg.progress_log_every_seconds)
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            stats["files_scanned"] += 1
            try:
                rel_parts = path.relative_to(root).parts
            except Exception:
                rel_parts = path.parts
            if set(rel_parts) & excluded:
                stats["excluded_by_dir"] += 1
                progress.update(extra=f"eligible={len(source_files)} excluded_dir={stats['excluded_by_dir']}")
                continue
            if path.suffix.lower() not in extensions:
                stats["excluded_by_suffix"] += 1
                progress.update(extra=f"eligible={len(source_files)} excluded_suffix={stats['excluded_by_suffix']}")
                continue
            source_files.append(path)
            progress.update(extra=f"eligible={len(source_files)} last={path.name}")
        progress.finish(extra=f"eligible={len(source_files)} scanned={stats['files_scanned']}")
        source_files.sort(key=lambda p: p.as_posix())
        return source_files, stats

    def _iter_source_files(self, root: Path) -> Iterable[Path]:
        return iter(self._discover_source_files(root)[0])


_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\b(.*)$")
_GLOBAL_CONST_RE = re.compile(
    r"^\s*(?:static\s+)?(?:const\s+)?(?:volatile\s+)?"
    r"(?:unsigned\s+|signed\s+)?(?:long\s+|short\s+)?(?:int|char|size_t|ssize_t|uint\d+_t|int\d+_t|long|short)"
    r"\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=\s*([^;]+);"
)
_ENUM_CONST_RE = re.compile(r"^\s*([A-Z_][A-Z0-9_]{2,})\s*=\s*([^,}]+),?\s*$")


def _extract_file_level_definitions(text: str, relpath: str) -> list[dict]:
    """Extract file-scope macro/global definitions as source-only KG anchors.

    The previous KG represented in-function statements well but missed definitions
    such as `#define LINESIZE ...`, forcing global queries to return arbitrary uses.
    These nodes make macro/global evidence first-class without adding labels, diffs,
    commit messages, or other non-source information.
    """
    out: list[dict] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        m = _DEFINE_RE.match(line)
        if m:
            name = m.group(1)
            value = m.group(2).strip()
            logical = line.rstrip()
            j = idx
            while logical.endswith("\\") and j < len(lines):
                j += 1
                logical = logical[:-1].rstrip() + " " + lines[j - 1].strip()
            out.append(
                {
                    "node_type": "MacroDefinition",
                    "name": name,
                    "value": value,
                    "text": logical.strip(),
                    "relpath": relpath,
                    "line_start": idx,
                    "line_end": j,
                    "function": None,
                    "identifiers": [name],
                    "scope": "file_or_project_global",
                    "qualified_name": f"{relpath}::{name}",
                }
            )
            continue
        cm = _GLOBAL_CONST_RE.match(line)
        if cm:
            name = cm.group(1)
            if not (name.isupper() or name.lower().endswith(("size", "len", "limit", "max", "min"))):
                continue
            out.append(
                {
                    "node_type": "GlobalDefinition",
                    "name": name,
                    "value": cm.group(2).strip(),
                    "text": line.strip(),
                    "relpath": relpath,
                    "line_start": idx,
                    "line_end": idx,
                    "function": None,
                    "identifiers": [name],
                    "scope": "file_or_project_global",
                    "qualified_name": f"{relpath}::{name}",
                }
            )
            continue
        em = _ENUM_CONST_RE.match(line)
        if em:
            name = em.group(1)
            out.append(
                {
                    "node_type": "GlobalDefinition",
                    "name": name,
                    "value": em.group(2).strip(),
                    "text": line.strip(),
                    "relpath": relpath,
                    "line_start": idx,
                    "line_end": idx,
                    "function": None,
                    "identifiers": [name],
                    "scope": "file_or_project_global",
                    "qualified_name": f"{relpath}::{name}",
                }
            )
    return out
