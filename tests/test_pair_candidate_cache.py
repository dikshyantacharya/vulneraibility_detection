from vuln_commit_kg.config import DatasetConfig
from vuln_commit_kg.data.pair_candidates import read_pair_candidate_cache, write_pair_candidate_cache
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.orchestration.pipeline import CommitKGPipeline
from vuln_commit_kg.config import AppConfig, ExperimentConfig, LiveDashboardConfig, LoggingConfig


def _sample(idx, project, url, vulnerable, fixed_idx=None, body="int f(){return 0;}"):
    return SecVulEvalSample(
        sample_id=str(idx),
        idx=idx,
        project=project,
        project_url=url,
        filepath="src/file.c",
        commit_id=f"commit{idx}",
        is_vulnerable=vulnerable,
        func_name="f",
        func_body=body,
        fixed_func_idx=fixed_idx,
    )


def test_pair_candidate_cache_is_sorted_by_cached_inventory_and_readable(tmp_path):
    samples = [
        _sample(1, "large", "https://example.com/large.git", True, fixed_idx=2, body="x" * 50),
        _sample(2, "large", "https://example.com/large.git", False, body="y" * 50),
        _sample(3, "small", "https://example.com/small.git", True, fixed_idx=4, body="x"),
        _sample(4, "small", "https://example.com/small.git", False, body="y"),
    ]
    from vuln_commit_kg.repos.repo_manager import RepoManager

    inventory_rows = [
        {
            "repo_key": RepoManager.repo_key("https://example.com/large.git", "large"),
            "repo_usable": True,
            "tree_source_bytes": 10_000,
            "tree_source_files": 100,
            "mirror_size_bytes": 50_000,
            "mirror_path": "/cache/large.git",
        },
        {
            "repo_key": RepoManager.repo_key("https://example.com/small.git", "small"),
            "repo_usable": True,
            "tree_source_bytes": 10,
            "tree_source_files": 1,
            "mirror_size_bytes": 100,
            "mirror_path": "/cache/small.git",
        },
    ]

    summary = write_pair_candidate_cache(samples, DatasetConfig(), cache_dir=tmp_path, inventory_rows=inventory_rows)
    assert summary["rows"] == 2

    rows = read_pair_candidate_cache(tmp_path / "pair_candidates_smallest_first.jsonl")
    assert [row["project"] for row in rows] == ["small", "large"]
    assert rows[0]["usable_repo"] is True
    assert rows[0]["vulnerable_sample_id"] == "3"
    assert rows[0]["fixed_sample_id"] == "4"
    assert (tmp_path / "pair_candidates_by_project.json").exists()


def test_pipeline_loads_cached_pair_candidates_without_rebuilding_raw_pairs(tmp_path):
    samples = [
        _sample(1, "project_a", "https://example.com/a.git", True, fixed_idx=2),
        _sample(2, "project_a", "https://example.com/a.git", False),
        _sample(3, "project_b", "https://example.com/b.git", True, fixed_idx=4),
        _sample(4, "project_b", "https://example.com/b.git", False),
    ]
    write_pair_candidate_cache(samples, DatasetConfig(), cache_dir=tmp_path)

    cfg = AppConfig(
        experiment=ExperimentConfig(name="test_cached_pairs", output_root=str(tmp_path / "runs")),
        dataset=DatasetConfig(
            validation_aware_pair_selection=True,
            validated_pair_limit=1,
            candidate_pair_limit=1,
            use_cached_pair_candidates=True,
            validation_candidate_order="cached_smallest_first",
            pair_candidate_cache_path=str(tmp_path / "pair_candidates_smallest_first.jsonl"),
            require_project_url=True,
        ),
        live_dashboard=LiveDashboardConfig(enabled=False),
        logging=LoggingConfig(rich=False),
    )
    pipeline = CommitKGPipeline(cfg)
    selected = pipeline._load_validation_aware_pair_candidates(samples)

    assert [s.sample_id for s in selected] == ["1", "2"]
    summary_path = pipeline.run_dir / "candidate_pairs_for_validation_summary.json"
    assert summary_path.exists()
    assert "loaded_from_pair_candidate_cache" in summary_path.read_text(encoding="utf-8")


def test_pair_candidate_cache_excludes_unusable_inventory_rows(tmp_path):
    samples = [
        _sample(1, "bad", "https://example.com/bad.git", True, fixed_idx=2),
        _sample(2, "bad", "https://example.com/bad.git", False),
        _sample(3, "good", "https://example.com/good.git", True, fixed_idx=4),
        _sample(4, "good", "https://example.com/good.git", False),
    ]
    from vuln_commit_kg.repos.repo_manager import RepoManager

    inventory_rows = [
        {"repo_key": RepoManager.repo_key("https://example.com/bad.git", "bad"), "repo_usable": False, "repo_status": "clone_failed"},
        {"repo_key": RepoManager.repo_key("https://example.com/good.git", "good"), "repo_usable": True, "tree_source_bytes": 1, "tree_source_files": 1},
    ]
    summary = write_pair_candidate_cache(samples, DatasetConfig(), cache_dir=tmp_path, inventory_rows=inventory_rows)
    rows = read_pair_candidate_cache(tmp_path / "pair_candidates_smallest_first.jsonl")
    assert summary["rows"] == 1
    assert rows[0]["project"] == "good"


def test_cached_pair_loader_keeps_one_pair_per_project(tmp_path):
    samples = [
        _sample(1, "same", "https://example.com/same.git", True, fixed_idx=2),
        _sample(2, "same", "https://example.com/same.git", False),
        SecVulEvalSample(sample_id="3", idx=3, project="same", project_url="https://example.com/same.git", filepath="src/other.c", commit_id="c3", is_vulnerable=True, func_name="g", func_body="int g(){return 1;}", fixed_func_idx=4),
        SecVulEvalSample(sample_id="4", idx=4, project="same", project_url="https://example.com/same.git", filepath="src/other.c", commit_id="c4", is_vulnerable=False, func_name="g", func_body="int g(){return 2;}"),
        _sample(5, "other", "https://example.com/other.git", True, fixed_idx=6),
        _sample(6, "other", "https://example.com/other.git", False),
    ]
    write_pair_candidate_cache(samples, DatasetConfig(), cache_dir=tmp_path)
    cfg = AppConfig(
        experiment=ExperimentConfig(name="test_cached_pair_diversity", output_root=str(tmp_path / "runs")),
        dataset=DatasetConfig(
            validation_aware_pair_selection=True,
            validated_pair_limit=2,
            candidate_pair_limit=10,
            use_cached_pair_candidates=True,
            validation_candidate_one_pair_per_project=True,
            validation_candidate_order="cached_smallest_first",
            pair_candidate_cache_path=str(tmp_path / "pair_candidates_smallest_first.jsonl"),
        ),
        live_dashboard=LiveDashboardConfig(enabled=False),
        logging=LoggingConfig(rich=False),
    )
    pipeline = CommitKGPipeline(cfg)
    selected = pipeline._load_validation_aware_pair_candidates(samples)
    assert [s.project for s in selected] == ["other", "other", "same", "same"] or [s.project for s in selected] == ["same", "same", "other", "other"]
    assert len(selected) == 4
