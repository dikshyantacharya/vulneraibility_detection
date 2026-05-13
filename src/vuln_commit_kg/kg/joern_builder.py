from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.logging_utils import fmt_seconds, log_kv, rss_mb
from vuln_commit_kg.utils.hashing import safe_name, stable_hash

from .graph_store import KGEdge, KGNode, ProjectGraph


def joern_available(cfg: KGConfig) -> bool:
    return shutil.which(cfg.joern_parse_bin) is not None and shutil.which(cfg.joern_export_bin) is not None


def build_with_joern(
    *,
    cfg: KGConfig,
    logger: logging.Logger,
    snapshot_path: Path,
    project: str | None,
    project_url: str | None,
    commit_id: str | None,
) -> ProjectGraph | None:
    """Build a ProjectGraph from Joern CPG output when Joern is installed.

    The importer accepts GraphML emitted by joern-export. If the local Joern
    installation exposes a slightly different CLI, the function falls back to a
    second command ordering. If Joern is absent or export parsing fails, return
    None and let the caller use the lightweight builder when configured.
    """
    if not joern_available(cfg):
        logger.warning("kg.joern.unavailable | joern_parse=%s joern_export=%s", cfg.joern_parse_bin, cfg.joern_export_bin)
        return None
    start = time.perf_counter()
    work_root = Path(cfg.joern_work_dir)
    key = safe_name(f"{project or 'project'}_{commit_id or stable_hash(str(snapshot_path), 10)}", 80)
    work = work_root / key
    export_root = work / "export"
    work.mkdir(parents=True, exist_ok=True)
    export_root.mkdir(parents=True, exist_ok=True)
    cpg_bin = work / "cpg.bin"
    log_kv(logger, "KG Joern build start", project=project, commit=(commit_id[:12] if commit_id else None), snapshot=snapshot_path, work_dir=work)

    parse_cmd = [cfg.joern_parse_bin, str(snapshot_path), "--output", str(cpg_bin)]
    ok, parse_out = _run(parse_cmd, timeout=cfg.joern_timeout_seconds)
    if not ok:
        logger.warning("kg.joern.parse_failed | cmd=%s | output=%s", " ".join(parse_cmd), parse_out[-2000:])
        return None

    parsed_graph = None
    export_errors: list[str] = []
    for repr_name in cfg.joern_export_representations:
        out_dir = export_root / safe_name(repr_name, 32)
        out_dir.mkdir(parents=True, exist_ok=True)
        commands = [
            [cfg.joern_export_bin, str(cpg_bin), "--repr", repr_name, "--format", cfg.joern_export_format, "--out", str(out_dir)],
            [cfg.joern_export_bin, "--repr", repr_name, "--format", cfg.joern_export_format, "--out", str(out_dir), str(cpg_bin)],
        ]
        for cmd in commands:
            ok, out = _run(cmd, timeout=cfg.joern_timeout_seconds)
            if not ok:
                export_errors.append(f"{' '.join(cmd)}\n{out[-1000:]}")
                continue
            parsed_graph = _import_exported_graphml(out_dir, logger=logger)
            if parsed_graph and parsed_graph.nodes:
                break
        if parsed_graph and parsed_graph.nodes:
            break
    if not parsed_graph or not parsed_graph.nodes:
        logger.warning("kg.joern.export_unparsed | errors=%s", "\n---\n".join(export_errors)[-4000:])
        return None

    project_id = f"project:{stable_hash(project_url or project or 'unknown', 16)}"
    commit_node_id = f"commit:{commit_id or 'unknown'}"
    parsed_graph.nodes.insert(0, KGNode(project_id, "Project", {"name": project, "url": project_url}))
    parsed_graph.nodes.insert(1, KGNode(commit_node_id, "Commit", {"commit_id": commit_id}))
    parsed_graph.edges.insert(0, KGEdge(project_id, commit_node_id, "PROJECT_AT_COMMIT"))
    parsed_graph.manifest.update({
        "project": project,
        "project_url": project_url,
        "commit_id": commit_id,
        "kg_scope": cfg.scope,
        "kg_version": cfg.version,
        "kg_backend": "joern",
        "kg_methodology": "joern_code_property_graph_primary",
        "kg_representation_note": "Imported from Joern CPG export and normalized into VCKG ProjectGraph. Semantic enrichment may add additional nodes/edges.",
        "joern_work_dir": str(work),
        "joern_cpg_bin": str(cpg_bin),
        "joern_export_dir": str(export_root),
        "layers": ["joern_cpg", "program_analysis", "security_overlay"],
        "num_nodes": len(parsed_graph.nodes),
        "num_edges": len(parsed_graph.edges),
        "seconds": time.perf_counter() - start,
    })
    logger.info("KG Joern build done | nodes=%s edges=%s elapsed=%s rss=%.1f MB", len(parsed_graph.nodes), len(parsed_graph.edges), fmt_seconds(time.perf_counter() - start), rss_mb())
    return parsed_graph


def _run(cmd: list[str], *, timeout: int) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False)
        return p.returncode == 0, p.stdout or ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _import_exported_graphml(out_dir: Path, *, logger: logging.Logger) -> ProjectGraph | None:
    try:
        import networkx as nx
    except Exception as exc:
        logger.warning("kg.joern.networkx_missing | %s", exc)
        return None
    graph = ProjectGraph(manifest={"joern_import_format": "graphml"})
    seen_nodes = set()
    seen_edges = set()
    files = list(out_dir.rglob("*.graphml")) + list(out_dir.rglob("*.xml"))
    for fp in files:
        try:
            g = nx.read_graphml(fp)
        except Exception:
            continue
        for nid, attrs in g.nodes(data=True):
            node_id = f"joern:{nid}"
            if node_id in seen_nodes:
                continue
            props = {str(k): _json_safe(v) for k, v in dict(attrs).items()}
            typ = str(props.get("label") or props.get("LABEL") or props.get("type") or props.get("_label") or "JoernNode")
            # Common Joern labels can be pipe-separated/list-like; keep first readable type.
            if "|" in typ:
                typ = typ.split("|")[0]
            graph.nodes.append(KGNode(node_id, typ, props))
            seen_nodes.add(node_id)
        for u, v, attrs in g.edges(data=True):
            edge = KGEdge(f"joern:{u}", f"joern:{v}", str(attrs.get("label") or attrs.get("LABEL") or attrs.get("type") or "JOERN_EDGE"), {str(k): _json_safe(val) for k, val in dict(attrs).items()})
            key = (edge.source, edge.target, edge.type, tuple(sorted(edge.properties.items())))
            if key not in seen_edges:
                graph.edges.append(edge); seen_edges.add(key)
    if graph.nodes:
        graph.manifest["joern_graphml_files"] = [str(f) for f in files]
        return graph
    return None


def _json_safe(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)
