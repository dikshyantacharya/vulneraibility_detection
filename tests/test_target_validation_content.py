import logging
from pathlib import Path

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.repos.target_validator import TargetValidator


def test_token_sequence_exact_ignores_whitespace_and_comments(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text(
        "int f(int x) {\n    // repository comment\n    if (x < 0) { return 0; }\n    return x + 1;\n}\n",
        encoding="utf-8",
    )
    sample = SecVulEvalSample(
        sample_id="1",
        idx=1,
        project="repo",
        project_url="",
        filepath="a.c",
        commit_id="abc",
        is_vulnerable=False,
        func_name="f",
        func_body="int f ( int x ){ if(x<0){return 0;} return x+1; }",
    )
    validation = TargetValidator(logging.getLogger("test"), artifact_root=tmp_path / "artifacts").validate(
        repo, sample, candidate_commit_id="abc", candidate_label="unit"
    )
    assert validation.status == "match_exact"
    assert validation.body_similarity == 1.0
    assert validation.token_sequence_exact
    assert validation.artifact_dir
    assert (Path(validation.artifact_dir) / "side_by_side.html").exists()
