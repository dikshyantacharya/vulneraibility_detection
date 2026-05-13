from vuln_commit_kg.agents.json_parse import parse_and_validate_with_normalization
from vuln_commit_kg.agents.schemas import RiskHypothesisResponse, FinalDecisionResponse


def test_bundle_query_type_is_mechanically_normalized_without_llm_repair():
    raw = '''{
      "risk_hypotheses": [{"id": "H1", "kind": "buffer_overflow"}],
      "kg_queries": [{
        "query_type": "callee_summary_bundle",
        "query": "sockgetlinebuf",
        "reason": "Need callee semantics",
        "scope": "adminchild"
      }]
    }'''
    obj, parsed, notes = parse_and_validate_with_normalization(raw, RiskHypothesisResponse)
    assert parsed.kg_queries[0].query_type == "evidence_bundle"
    assert parsed.kg_queries[0].bundle_type == "callee_summary_bundle"
    assert obj["kg_queries"][0]["scope"] == "target_function"
    assert notes


def test_decision_status_alias_is_normalized():
    raw = '''{
      "is_vulnerable": false,
      "confidence": 0.8,
      "primary_vulnerability_type": null,
      "vuln_statements": [],
      "evidence_used": ["E1"],
      "confirmed_hypotheses": [],
      "ruled_out_hypotheses": ["H1"],
      "unresolved_hypotheses": [],
      "decision_status": "not-vulnerable",
      "reasoning_summary": "Bounded by cited evidence."
    }'''
    obj, parsed, notes = parse_and_validate_with_normalization(raw, FinalDecisionResponse)
    assert parsed.decision_status == "non_vulnerable"
    assert obj["decision_status"] == "non_vulnerable"
    assert any("decision_status" in n for n in notes)
