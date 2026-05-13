from vckg_agentic_proof.parser import parse_json_answer

def test_answer_tag_json():
    raw = '<analysis>x</analysis><answer>{"verdict":"ok"}</answer>'
    assert parse_json_answer(raw).parsed["verdict"] == "ok"

def test_fenced_json_fallback():
    raw = '```json\n{"verdict":"ok"}\n```'
    assert parse_json_answer(raw).parsed["verdict"] == "ok"
