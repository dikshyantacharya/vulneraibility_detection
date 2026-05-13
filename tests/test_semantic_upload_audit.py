from vuln_commit_kg.agents.semantic_safety import semantic_audit_dict
from vuln_commit_kg.retrieval.evidence import EvidenceItem, EvidencePack


def _pack(lines):
    return EvidencePack(
        sample_id="s",
        items=[EvidenceItem(evidence_id=f"T{i}", kind="tool_upload_config_path", text=line) for i, line in enumerate(lines, 1)],
    )


def test_signed_upload_remaining_index_write_is_unsafe():
    audit = semantic_audit_dict(_pack([
        "int contentlen = 0;",
        "int l=0;",
        "contentlen = atoi(sb);",
        "while((i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '+', conf.timeouts[STRING_S])) > 0){",
        "if(i > (contentlen - l)) i = (contentlen - l);",
        "buf[i] = 0;",
        "decodeurl((unsigned char *)buf, 1);",
        'fprintf(writable, "%s", l? buf : buf + 9);',
    ]))
    assert any(f["kind"] == "signed_upload_remaining_index_write" and f["status"] == "unsafe" for f in audit["findings"])


def test_bounded_upload_read_loop_is_safe():
    audit = semantic_audit_dict(_pack([
        "unsigned contentlen = 0;",
        "unsigned l=0;",
        'sscanf(sb, "%u", &contentlen);',
        "if(contentlen > LINESIZE*1024) contentlen = 0;",
        "while(l < contentlen && (i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, (contentlen - l) > LINESIZE - 1?LINESIZE - 1:contentlen - l, '+', conf.timeouts[STRING_S])) > 0){",
        "buf[i] = 0;",
        "decodeurl((unsigned char *)buf, 1);",
        'fprintf(writable, "%s", l? buf : buf + 9);',
    ]))
    assert any(f["kind"] == "bounded_upload_read_loop" and f["status"] == "safe" for f in audit["findings"])

from vuln_commit_kg.agents.semantic_safety import source_upload_path_audit_from_text


def test_source_upload_path_audit_detects_prefix_and_fixed_patterns():
    pre_fix = """
    int contentlen = 0;
    int l=0;
    contentlen = atoi(sb);
    while((i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '+', conf.timeouts[STRING_S])) > 0){
      if(i > (contentlen - l)) i = (contentlen - l);
      buf[i] = 0;
      decodeurl((unsigned char *)buf, 1);
      fprintf(writable, "%s", l? buf : buf + 9);
    }
    """
    fixed = """
    unsigned contentlen = 0;
    sscanf(sb, "%u", &contentlen);
    if(contentlen > LINESIZE*1024) contentlen = 0;
    unsigned l=0;
    while(l < contentlen && (i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, (contentlen - l) > LINESIZE - 1?LINESIZE - 1:contentlen - l, '+', conf.timeouts[STRING_S])) > 0){
      if(i > (contentlen - l)) i = (contentlen - l);
      buf[i] = 0;
      decodeurl((unsigned char *)buf, 1);
      fprintf(writable, "%s", l? buf : buf + 9);
    }
    """
    assert source_upload_path_audit_from_text(pre_fix)["verdict"] == "unsafe"
    assert source_upload_path_audit_from_text(fixed)["verdict"] == "safe"
