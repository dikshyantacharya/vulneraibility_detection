from __future__ import annotations


def test_code_evidence_prompt_removes_graph_metadata_and_keeps_code():
    from vckg_agentic_proof.prompts import hypothesis_verification_prompt

    sample = {"function": "codingXOR"}
    hypotheses = [
        {
            "hypothesis_id": "HYP-01",
            "title": "Unchecked bufferLength write",
            "risk_summary": "xoredString is written up to bufferLength",
            "required_proof_questions": ["Is bufferLength bounded by the output buffer?"],
        }
    ]
    evidence = [
        {
            "id": "E1",
            "kind": "target_statement",
            "file": "main.c",
            "function": "codingXOR",
            "line_start": 396,
            "line_end": 396,
            "text": "int i;",
            "relation": "target_function",
            "score": 1.0,
        },
        {
            "id": "E4",
            "kind": "target_statement",
            "file": "main.c",
            "function": "codingXOR",
            "line_start": 401,
            "line_end": 401,
            "text": "xoredString[i] = table[keyString[i] & 0xF][(unsigned char)extractedString[i]];",
            "relation": "target_function",
            "score": 1.0,
        },
        {
            "id": "AP3.1.2",
            "kind": "codekg_function",
            "file": "main.c",
            "function": "fillBuffer",
            "line_start": 510,
            "line_end": 522,
            "text": "510 | int fillBuffer(FILE* mainFile, char* extractedString, char* keyString)\n512 | int charactersRead = fread(extractedString, 1, BUFFER_SIZE, mainFile);\n521 | return charactersRead;\n522 | }\nfillBuffer\nmain.c",
            "relation": "codekg_subgraph",
            "score": 2.35,
        },
    ]

    prompt = "\n".join(m["content"] for m in hypothesis_verification_prompt(sample, hypotheses, evidence))
    assert "SOURCE CODE EVIDENCE BUNDLE" in prompt
    assert '"line_start"' not in prompt
    assert '"line_end"' not in prompt
    assert '"score"' not in prompt
    assert "510 |" not in prompt
    assert "int i;" not in prompt
    assert "xoredString[i]" in prompt
    assert "fread(extractedString, 1, BUFFER_SIZE, mainFile)" in prompt
