from vuln_commit_kg.agents.schemas import FinalDecisionResponse


def test_final_decision_accepts_upload_path_assessment():
    parsed = FinalDecisionResponse.model_validate({
        "is_vulnerable": False,
        "confidence": 0.35,
        "primary_vulnerability_type": None,
        "vuln_statements": [],
        "evidence_used": ["E42", "E50"],
        "confirmed_hypotheses": [],
        "ruled_out_hypotheses": ["H_upload"],
        "unresolved_hypotheses": [],
        "upload_path_assessment": {
            "present": True,
            "contentlen_declaration": {"evidence_id": "E8", "value": "unsigned contentlen = 0"},
            "contentlen_cap": {"evidence_id": "E42", "value": "contentlen > LINESIZE*1024 -> 0"},
            "read_size_expression": {"evidence_id": "E50", "value": "min(contentlen-l, LINESIZE-1)"},
            "nul_write": {"evidence_id": "E52", "value": "buf[i] = 0"},
            "decode_and_write_sink": {"evidence_id": "E53,E54", "value": "decodeurl/fprintf"},
            "verdict": "safe",
            "evidence_ids": ["E42", "E50", "E52"],
            "reason": "bounded upload loop",
            "missing_facts": [],
        },
        "decision_status": "non_vulnerable",
        "reasoning_summary": "Upload path is bounded by E42/E50 before E52.",
    })
    assert parsed.upload_path_assessment is not None
    assert parsed.upload_path_assessment.verdict == "safe"
