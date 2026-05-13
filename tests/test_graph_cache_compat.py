import logging

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.kg.graph_cache import GraphCache
from vuln_commit_kg.kg.graph_store import KGEdge, KGNode, ProjectGraph


def test_graph_cache_legacy_key_dir_save_load_roundtrip(tmp_path):
    cfg = KGConfig(cache_dir=str(tmp_path), version="test_v", build_if_missing=False)
    cache = GraphCache(cfg, logging.getLogger("test_graph_cache"))

    out_dir = cache.key_dir("https://example.com/org/repo.git", "abc123")
    assert tmp_path in out_dir.parents
    assert out_dir.name

    graph = ProjectGraph(
        nodes=[KGNode(id="n1", type="Function", properties={"name": "f"})],
        edges=[KGEdge(source="n1", target="n1", type="self", properties={})],
        manifest={"project": "repo", "commit_id": "abc123"},
    )
    saved_dir = cache.save("https://example.com/org/repo.git", "abc123", graph)
    assert saved_dir == out_dir
    assert (saved_dir / "nodes.jsonl").exists()
    assert (saved_dir / "edges.jsonl").exists()

    loaded = cache.load("https://example.com/org/repo.git", "abc123")
    assert loaded is not None
    assert loaded.nodes[0].id == "n1"
    assert loaded.edges[0].type == "self"
    assert loaded.manifest["commit_id"] == "abc123"


def test_graph_cache_get_or_build_loads_existing_cache_without_builder(tmp_path):
    cfg = KGConfig(cache_dir=str(tmp_path), version="test_v", build_if_missing=False)
    cache = GraphCache(cfg, logging.getLogger("test_graph_cache"))
    out_dir = cache.graph_dir("https://example.com/org/repo.git", "repo", "abc123")
    graph = ProjectGraph(nodes=[KGNode(id="n1", type="Function")], manifest={"prebuilt": True})

    from vuln_commit_kg.kg.graph_store import save_graph

    save_graph(graph, out_dir)
    loaded, loaded_dir, status = cache.get_or_build(
        snapshot_path=None,
        project="repo",
        project_url="https://example.com/org/repo.git",
        commit_id="abc123",
    )
    assert loaded_dir == out_dir
    assert status == "loaded_cache"
    assert loaded.manifest["prebuilt"] is True
