import logging
from pathlib import Path

from vuln_commit_kg.config import RepoConfig
from vuln_commit_kg.repos.git_runner import GitError, GitResult
from vuln_commit_kg.repos.repo_manager import RepoStatus
from vuln_commit_kg.repos.snapshot_manager import SnapshotManager


class FakeGit:
    def __init__(self, worktree: Path):
        self.worktree = worktree
        self.calls = []
        self.failed_once = False

    def run(self, args, cwd=None, check=True):
        self.calls.append(list(args))
        joined = " ".join(str(a) for a in args)
        if "worktree add" in joined and not self.failed_once:
            self.failed_once = True
            raise GitError(GitResult(
                cmd=["git", *map(str, args)],
                cwd=None,
                returncode=128,
                stdout="",
                stderr="fatal: 'cache/worktrees/repo/deadbeef' is a missing but already registered worktree; use 'add -f' to override",
            ))
        if "worktree add" in joined:
            self.worktree.mkdir(parents=True, exist_ok=True)
            (self.worktree / ".git").write_text("gitdir: fake\n", encoding="utf-8")
        return GitResult(cmd=["git", *map(str, args)], cwd=None, returncode=0, stdout="", stderr="")


def test_snapshot_manager_recovers_deleted_but_registered_worktree(tmp_path):
    cfg = RepoConfig(
        cache_dir=str(tmp_path / "repos"),
        worktree_dir=str(tmp_path / "worktrees"),
        prune_stale_worktrees=True,
        force_recreate_registered_worktree=True,
    )
    repo_key = "repo"
    commit = "deadbeef" * 5
    worktree = Path(cfg.worktree_dir) / repo_key / commit[:48]
    mgr = SnapshotManager(cfg, logging.getLogger("test"), tmp_path / "run")
    fake_git = FakeGit(worktree)
    mgr.git = fake_git

    status = mgr.ensure_snapshot(RepoStatus("https://example/repo.git", repo_key, str(tmp_path / "repos" / "repo.git"), "reused_existing_mirror"), commit)

    assert status.status == "created_worktree_after_prune"
    assert Path(status.worktree_path).joinpath(".git").exists()
    assert any("worktree" in c and "prune" in c for c in fake_git.calls)
    assert any("--force" in c and "add" in c for c in fake_git.calls)
