from vuln_commit_kg.agents.json_parse import parse_and_validate_with_normalization
from vuln_commit_kg.agents.schemas import PosthocCommitAuditResponse


def test_truncated_json_object_is_closed_for_report_schema():
    text = '{"semantic_alignment":"aligned","factual_findings":["one","two"],"audit_conclusion":"cut off'
    obj, parsed, notes = parse_and_validate_with_normalization(text, PosthocCommitAuditResponse)
    assert parsed.semantic_alignment == "aligned"
    assert parsed.factual_findings[:2] == ["one", "two"]
    assert parsed.audit_conclusion.startswith("cut off")
