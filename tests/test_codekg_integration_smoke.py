from __future__ import annotations

from pathlib import Path
import logging

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_cache import GraphCache
from vuln_commit_kg.agents.tool_query import KGToolExecutor


def test_codekg_graphcache_and_agent_tool_smoke(tmp_path):
    src = tmp_path / "project"
    src.mkdir()
    (src / "sample.c").write_text(
        """
        int helper(char *p) { if (!p) return -1; return p[0]; }
        int count_rows(char *raw, int length) {
          if (raw == 0) return -1;
          int rows = 0;
          for (int i = 0; i < length; i++) if (raw[i] == '\\n') rows++;
          return helper(raw) + rows;
        }
        """,
        encoding="utf-8",
    )
    cfg = KGConfig(cache_dir=str(tmp_path / "codekg"), backend="heuristic", use_codekg=True, force_rebuild=True)
    graph, graph_dir, status = GraphCache(cfg, logger=logging.getLogger("test.codekg")).get_or_build(src, "smoke", None, "local")
    assert status == "built"
    assert (graph_dir / "graph.json").exists()
    assert (graph_dir / "dashboard" / "index.html").exists()
    assert graph.manifest.get("backend_used") == "heuristic"

    sample = SecVulEvalSample(
        idx=0,
        sample_id="smoke-0",
        project="smoke",
        filepath="sample.c",
        func_name="count_rows",
        func_body=(src / "sample.c").read_text(encoding="utf-8"),
    )
    result = KGToolExecutor().execute_many(
        graph=graph,
        sample=sample,
        queries=[{"query_type": "security_context", "target_function": "count_rows", "depth": 3}],
        round_index=1,
    )[0]
    assert result.status == "ok"
    assert result.query_type == "security_context"
    assert result.items
    assert result.diagnostics["retrieved_node_count"] > 0
    assert result.diagnostics["dashboard_path"].endswith("dashboard/index.html")
    assert result.diagnostics["query_view_path"].endswith(".json")
    assert Path(result.diagnostics["query_view_path"]).exists()
    assert result.diagnostics["query_view_node_count"] > 0
