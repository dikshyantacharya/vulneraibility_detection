from __future__ import annotations

import logging
from pathlib import Path

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.logging_utils import log_kv
from vuln_commit_kg.utils.hashing import safe_name, stable_hash, url_hash

from .graph_store import ProjectGraph, load_graph, save_graph
from .project_graph_builder import ProjectGraphBuilder
from .codekg_adapter import build_codekg_graph, load_codekg_as_project_graph


class GraphCache:
    def __init__(self, cfg: KGConfig, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.root = Path(cfg.cache_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def graph_dir(self, project_url: str | None, project: str | None, commit_id: str | None) -> Path:
        project_key = f"{safe_name(project or project_url or 'unknown_project', 48)}__{url_hash(project_url or project or 'unknown')}"
        commit_key = safe_name(commit_id or "unknown_commit", 48)
        cfg_hash = stable_hash(self.cfg.model_dump(mode="json"), 12)
        return self.root / project_key / commit_key / self.cfg.version / cfg_hash


    # Compatibility helpers for older orchestration paths. New code should call
    # graph_dir()/get_or_build() with separate project and project_url values.
    def key_dir(self, project_or_url: str | None, commit_id: str | None) -> Path:
        return self.graph_dir(project_or_url, None, commit_id)

    def load(self, project_or_url: str | None, commit_id: str | None) -> ProjectGraph | None:
        out_dir = self.key_dir(project_or_url, commit_id)
        if (out_dir / "nodes.jsonl").exists() and (out_dir / "edges.jsonl").exists():
            if (out_dir / "graph.json").exists():
                graph = load_codekg_as_project_graph(out_dir)
                graph.manifest.setdefault("codekg_graph_dir", str(out_dir.resolve()))
                graph.manifest.setdefault("dashboard_path", str((out_dir / "dashboard" / "index.html").resolve()))
                return graph
            return load_graph(out_dir, logger=self.logger, log_every=self.cfg.graph_save_log_every)
        return None

    def save(self, project_or_url: str | None, commit_id: str | None, graph: ProjectGraph) -> Path:
        out_dir = self.key_dir(project_or_url, commit_id)
        save_graph(graph, out_dir, logger=self.logger, log_every=self.cfg.graph_save_log_every)
        return out_dir

    def get_or_build(
        self,
        snapshot_path: Path | None,
        project: str | None,
        project_url: str | None,
        commit_id: str | None,
    ) -> tuple[ProjectGraph, Path, str]:
        out_dir = self.graph_dir(project_url, project, commit_id)
        log_kv(
            self.logger,
            "KG cache check",
            project=project,
            commit=(commit_id[:12] if commit_id else None),
            cache_dir=out_dir,
            force_rebuild=self.cfg.force_rebuild,
            build_if_missing=self.cfg.build_if_missing,
        )
        if not self.cfg.force_rebuild and (out_dir / "nodes.jsonl").exists() and (out_dir / "edges.jsonl").exists():
            if (out_dir / "graph.json").exists():
                graph = load_codekg_as_project_graph(out_dir)
            else:
                graph = load_graph(out_dir, logger=self.logger, log_every=self.cfg.graph_save_log_every)
            graph.manifest.setdefault("codekg_graph_dir", str(out_dir.resolve()))
            graph.manifest.setdefault("dashboard_path", str((out_dir / "dashboard" / "index.html").resolve()))
            return graph, out_dir, "loaded_cache"
        if not self.cfg.build_if_missing:
            raise FileNotFoundError(f"KG cache missing and build_if_missing=false: {out_dir}")
        if snapshot_path is None:
            raise FileNotFoundError("Cannot build KG without a snapshot path")
        use_codekg = bool(getattr(self.cfg, "use_codekg", True))
        if use_codekg:
            graph = build_codekg_graph(
                source_dir=snapshot_path,
                out_dir=out_dir,
                cfg=self.cfg,
                project=project,
                project_url=project_url,
                commit_id=commit_id,
                logger=self.logger,
            )
        else:
            # Compatibility escape hatch for old experiments. The default path is
            # CodeKG and should be used for all new vulnerability-agent runs.
            builder = ProjectGraphBuilder(self.cfg, self.logger)
            graph = builder.build_and_save(snapshot_path, out_dir, project, project_url, commit_id)
        return graph, out_dir, "built"
