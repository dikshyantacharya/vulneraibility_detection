import time

from vuln_commit_kg.config import ValidationCacheConfig
from vuln_commit_kg.repos.validation_cache import CommitValidationCache


def test_validation_cache_reuses_negative_result(tmp_path):
    cfg = ValidationCacheConfig(cache_dir=str(tmp_path), filename="validation.jsonl")
    cache = CommitValidationCache(cfg)
    cache.record(
        repo_key="repo",
        commit="deadbeef",
        sample_id="1",
        filepath="src/a.c",
        function="f",
        status="invalid_reference",
        error="fatal: invalid reference",
    )

    hit = cache.get_negative(repo_key="repo", commit="deadbeef", sample_id="1", filepath="src/a.c", function="f")
    assert hit is not None
    assert hit["status"] == "invalid_reference"

    reloaded = CommitValidationCache(cfg)
    hit2 = reloaded.get_negative(repo_key="repo", commit="deadbeef", sample_id="1", filepath="src/a.c", function="f")
    assert hit2 is not None
    assert hit2["error"] == "fatal: invalid reference"


def test_validation_cache_can_expire_negative_result(tmp_path):
    cfg = ValidationCacheConfig(cache_dir=str(tmp_path), filename="validation.jsonl", retry_invalid_after_days=0)
    cache = CommitValidationCache(cfg)
    cache.record(
        repo_key="repo",
        commit="deadbeef",
        sample_id="1",
        filepath="src/a.c",
        function="f",
        status="invalid_reference",
        timestamp=time.time() - 10,
    )
    assert cache.get_negative(repo_key="repo", commit="deadbeef", sample_id="1", filepath="src/a.c", function="f") is None


def test_validation_cache_does_not_reuse_stale_registered_worktree_failure(tmp_path):
    cfg = ValidationCacheConfig(cache_dir=str(tmp_path), filename="validation.jsonl")
    cache = CommitValidationCache(cfg)
    cache.record(
        repo_key="repo",
        commit="deadbeef",
        sample_id="1",
        filepath="src/a.c",
        function="f",
        status="low_similarity",
        validation_status="file_missing",
        similarity=0.0,
        error="fatal: 'cache/worktrees/repo/deadbeef' is a missing but already registered worktree; use 'add -f' to override",
    )

    assert cache.get_negative(repo_key="repo", commit="deadbeef", sample_id="1", filepath="src/a.c", function="f") is None
