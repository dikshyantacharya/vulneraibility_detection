from vuln_commit_kg.evaluation.statement import split_gold_statements


def test_split_gold_statements():
    assert split_gold_statements("a();\nb();") == ["a();", "b();"]
