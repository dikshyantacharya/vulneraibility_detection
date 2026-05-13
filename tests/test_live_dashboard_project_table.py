from types import SimpleNamespace

from vuln_commit_kg.analysis_outputs.live_dashboard import LiveDashboard


def test_live_dashboard_bulk_project_rows_written_once(tmp_path):
    cfg = SimpleNamespace(dirname="live_dashboard", serve=False, host="127.0.0.1", port=8765, keep_recent_events=10)
    dash = LiveDashboard(tmp_path / "run", cfg)
    dash.update_projects_bulk({
        "repo_a": {"project": "a", "status": "usable_repo", "tree_source_bytes": 10},
        "repo_b": {"project": "b", "status": "kg_building", "tree_source_bytes": 20},
    })
    assert dash.state["projects"]["repo_a"]["project"] == "a"
    assert dash.state["projects"]["repo_b"]["status"] == "kg_building"
    html = (dash.dir / "index.html").read_text(encoding="utf-8")
    assert "Repository inventory, candidate validation, and KG status" in html
    assert "projectSort" in html
