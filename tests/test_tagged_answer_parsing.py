from vuln_commit_kg.agents.json_parse import (
    extract_answer_tag_payload,
    parse_and_validate_tagged_output,
    parse_and_validate_with_normalization,
)
from vuln_commit_kg.agents.schemas import FinalDecisionResponse, RiskHypothesisResponse


def test_answer_tag_payload_is_parsed_not_thinking_text():
    raw = '''<thinking>Public analysis mentions C code { not json } and schema examples.</thinking>
<answer>{
  "risk_hypotheses": [{"id": "H1", "kind": "integer_overflow", "status": "active"}],
  "kg_queries": []
}</answer>'''
    obj, parsed, notes, tag_info, payload = parse_and_validate_tagged_output(raw, RiskHypothesisResponse)
    assert tag_info["answer_tag_complete"] is True
    assert parsed.risk_hypotheses[0].id == "H1"
    assert payload.strip().startswith("{")
    assert any("answer_extraction" in n for n in notes)


def test_incomplete_answer_tag_uses_whole_response_for_repair_source():
    payload, info = extract_answer_tag_payload('<thinking>x</thinking><answer>{"risk_hypotheses": []')
    assert info["answer_tag_found"] is True
    assert info["answer_tag_complete"] is False
    assert payload.startswith("<thinking>")


def test_prose_before_json_skips_c_braces_and_finds_later_json():
    raw = '''Analysis first:
```c
int f(void) { return 0; }
```
Now the JSON:
{
  "risk_hypotheses": [],
  "kg_queries": []
}
'''
    obj, parsed, notes = parse_and_validate_with_normalization(raw, RiskHypothesisResponse)
    assert parsed.risk_hypotheses == []
    assert parsed.kg_queries == []


def test_final_false_decision_clears_forbidden_vulnerability_type():
    raw = '''{
      "is_vulnerable": false,
      "confidence": 0.5,
      "primary_vulnerability_type": "Integer Overflow / Undefined Behavior",
      "vuln_statements": [],
      "evidence_used": ["E14"],
      "confirmed_hypotheses": [],
      "ruled_out_hypotheses": [],
      "unresolved_hypotheses": ["H1", "H2"],
      "upload_path_assessment": {"present": false, "verdict": "not_present", "evidence_ids": [], "reason": "No upload path detected", "missing_facts": []},
      "decision_status": "inconclusive",
      "reasoning_summary": "Risks remain unresolved."
    }'''
    obj, parsed, notes = parse_and_validate_with_normalization(raw, FinalDecisionResponse)
    assert parsed.primary_vulnerability_type is None
    assert parsed.decision_status == "inconclusive"
    assert parsed.upload_path_assessment.verdict == "unresolved"
    assert any("cleared primary_vulnerability_type" in n for n in notes)


def test_tagged_parser_accepts_valid_bare_json_as_provider_fallback():
    raw = '{"risk_hypotheses": [], "kg_queries": []}'
    obj, parsed, notes, tag_info, payload = parse_and_validate_tagged_output(
        raw, RiskHypothesisResponse, require_answer_tag=True
    )
    assert parsed.risk_hypotheses == []
    assert tag_info["extraction"] == "bare_schema_json"
    assert any("bare_schema_json_accepted_missing_tags" in n for n in notes)


def test_tagged_parser_accepts_json_mode_thinking_answer_wrapper():
    raw = '{"thinking":"public notes","answer":{"risk_hypotheses":[],"kg_queries":[]}}'
    obj, parsed, notes, tag_info, payload = parse_and_validate_tagged_output(
        raw, RiskHypothesisResponse, require_answer_tag=True
    )
    assert parsed.risk_hypotheses == []
    assert tag_info["extraction"] == "json_key_answer_wrapper"
    assert tag_info["json_key_answer_found"] is True
    assert any("json_key_answer_wrapper_accepted" in n for n in notes)


def test_tagged_parser_accepts_json_mode_answer_string_wrapper():
    import json

    raw = json.dumps({
        "thinking": "public notes",
        "answer": json.dumps({"risk_hypotheses": [], "kg_queries": []}),
    })
    obj, parsed, notes, tag_info, payload = parse_and_validate_tagged_output(
        raw, RiskHypothesisResponse, require_answer_tag=True
    )
    assert parsed.kg_queries == []
    assert tag_info["extraction"] == "json_key_answer_wrapper"


def test_strict_tagged_parser_accepts_full_thinking_and_answer_wrapper():
    raw = '<thinking>Checked visible code and schema.</thinking><answer>{"risk_hypotheses": [], "kg_queries": []}</answer>'
    obj, parsed, notes, tag_info, payload = parse_and_validate_tagged_output(
        raw, RiskHypothesisResponse, require_answer_tag=True
    )
    assert tag_info["thinking_tag_complete"] is True
    assert tag_info["answer_tag_complete"] is True
    assert parsed.risk_hypotheses == []
    assert payload.strip().startswith("{")
