import logging
import subprocess
from pathlib import Path

from vuln_commit_kg.config import DatasetConfig, SnapshotConfig
from vuln_commit_kg.data.sample_selector import choose_smallest_pair, select_samples
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.repos.commit_resolver import CommitResolver
from vuln_commit_kg.repos.repo_manager import RepoStatus
from vuln_commit_kg.repos.target_validator import TargetValidator


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return result.stdout.strip()


def test_smallest_pair_selection_uses_fixed_func_idx():
    vul = SecVulEvalSample(
        sample_id="10", idx=10, project="tiny", project_url="https://github.com/example/tiny",
        filepath="a.c", commit_id="abc", is_vulnerable=True, func_name="f", func_body="int f(){return 0;}", fixed_func_idx=11,
    )
    fixed = SecVulEvalSample(
        sample_id="11", idx=11, project="tiny", project_url="https://github.com/example/tiny",
        filepath="a.c", commit_id="abc", is_vulnerable=False, func_name="f", func_body="int f(){return 1;}", fixed_func_idx=11,
    )
    other = SecVulEvalSample(
        sample_id="1", idx=1, project="big", project_url="https://github.com/example/big",
        filepath="b.c", commit_id="def", is_vulnerable=True, func_name="g", func_body="int g(){return 0;}", fixed_func_idx=None,
    )
    cfg = DatasetConfig(sample_selection="smallest_vuln_fixed_pair", sample_limit=None)
    selected = select_samples([other, vul, fixed], cfg, seed=1)
    assert [s.idx for s in selected] == [10, 11]
    pair = choose_smallest_pair([other, vul, fixed], cfg)
    assert pair.vulnerable_idx == 10
    assert pair.fixed_idx == 11


def test_secvuleval_patch_resolution_matches_parent_and_patch(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    vulnerable_body = "int f(int x) {\n    return x + 1;\n}\n"
    fixed_body = "int f(int x) {\n    if (x < 0) return 0;\n    return x + 1;\n}\n"
    (repo / "a.c").write_text(vulnerable_body, encoding="utf-8")
    _git(repo, "add", "a.c")
    _git(repo, "commit", "-m", "vulnerable")
    parent_commit = _git(repo, "rev-parse", "HEAD")

    (repo / "a.c").write_text(fixed_body, encoding="utf-8")
    _git(repo, "add", "a.c")
    _git(repo, "commit", "-m", "fix vulnerability")
    patch_commit = _git(repo, "rev-parse", "HEAD")

    mirror = tmp_path / "repo.git"
    _git(tmp_path, "clone", "--mirror", str(repo), str(mirror))

    logger = logging.getLogger("test")
    resolver = CommitResolver(SnapshotConfig(commit_resolution="secvuleval_patch"), logger)
    status = RepoStatus(project_url=str(repo), repo_key="repo", mirror_path=str(mirror), status="reused_existing_mirror")
    vul_sample = SecVulEvalSample(
        sample_id="1", idx=1, project="repo", project_url=str(repo), filepath="a.c", commit_id=patch_commit,
        is_vulnerable=True, func_name="f", func_body=vulnerable_body, fixed_func_idx=2,
    )
    fixed_sample = SecVulEvalSample(
        sample_id="2", idx=2, project="repo", project_url=str(repo), filepath="a.c", commit_id=patch_commit,
        is_vulnerable=False, func_name="f", func_body=fixed_body, fixed_func_idx=2,
    )

    vul_candidates = resolver.candidates(status, vul_sample)
    fixed_candidates = resolver.candidates(status, fixed_sample)
    assert vul_candidates[0].label == "pre_fix_parent_for_vulnerable"
    assert vul_candidates[0].commit_id == parent_commit
    assert fixed_candidates[0].label == "patch_commit_for_fixed"
    assert fixed_candidates[0].commit_id == patch_commit

    # Validate directly on checked-out repository states without invoking remote clone.
    _git(repo, "checkout", parent_commit)
    vul_validation = TargetValidator(logger).validate(repo, vul_sample)
    assert vul_validation.body_similarity > 0.98
    _git(repo, "checkout", patch_commit)
    fixed_validation = TargetValidator(logger).validate(repo, fixed_sample)
    assert fixed_validation.body_similarity > 0.98
