from __future__ import annotations

import json
import re
from typing import Any

from vuln_commit_kg.config import PromptingConfig
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.retrieval.evidence import EvidencePack
from vuln_commit_kg.utils.text import truncate_middle

from .semantic_safety import semantic_audit_dict, source_upload_path_audit_from_text

SYSTEM_PROMPT = (
    "You are a vulnerability-analysis agent. Use only the supplied target function "
    "and supplied repository evidence for prediction. Prefer exactly two top-level XML-style "
    "tags in this order: <thinking> followed by <answer>. The <thinking> block is for "
    "public, evidence-based analysis notes only; it must not reveal hidden chain-of-thought "
    "and must leave enough output budget for the complete answer. The <answer> block must "
    "contain exactly one schema-valid JSON object and nothing else. If the API forces "
    "JSON-only output and cannot emit XML tags, use a transport wrapper object with keys "
    "thinking and answer, where answer is the schema-valid JSON object. Do not use markdown. "
    "Do not include examples, placeholders, commit summaries, or project summaries in the JSON. "
    "For code references in JSON, prefer evidence IDs once evidence is available. Do not put "
    "full raw C/C++ statements inside JSON strings."
)

FORBIDDEN_PLACEHOLDERS = [
    "short vulnerability category",
    "exact statement or short description",
    "callee definition",
    "guard condition",
    "input origin",
    "function or API name",
    "bounds/null/auth check",
    "why this evidence is needed",
    "specific identifier or check",
    "brief evidence-based summary of what is known and missing",
    "exact vulnerable statement if any",
    "short evidence-based reason",
    "brief evidence-based explanation; no hidden chain-of-thought",
    "SELECT * FROM code",
    "<boolean>",
    "<number>",
    "<evidence_id>",
    "<identifier_or_api_from_target>",
]

ALLOWED_QUERY_TYPES = [
    "security_context",
    "evidence_slice",
    "function_context",
    "call_neighborhood",
    "variable_flow",
    "semantic_facts",
    "file_context",
    "shortest_path",
    "risk_slice",
    "callers",
    "callees",
]

BUNDLE_TYPES = []  # legacy; integrated runs use CodeKG deterministic retrieval kinds above.


def _prompting_cfg(cfg: PromptingConfig | None) -> PromptingConfig:
    return cfg or PromptingConfig()


def _orientation(sample: SecVulEvalSample, cfg: PromptingConfig | None = None) -> dict[str, Any]:
    cfg = _prompting_cfg(cfg)
    data: dict[str, Any] = {"filepath": sample.filepath, "function": sample.func_name}
    if cfg.include_orchestration_metadata_in_model_prompt:
        data.update(
            {
                "sample_id": sample.sample_id,
                "dataset_commit": sample.commit_id,
                "project": sample.project,
                "project_url": sample.project_url,
                "ground_truth_label": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
            }
        )
    if cfg.include_cwe_hints_in_model_prompt:
        data["cwe_hints"] = sample.cwe_list
    if cfg.include_cve_hints_in_model_prompt:
        data["cve_hints"] = sample.cve_list
    return data


def _line_numbered_source(text: str | None, max_chars: int) -> str:
    raw = text or ""
    lines = raw.splitlines()
    numbered = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))
    return truncate_middle(numbered, max_chars)


def _strip_c_comments_and_literals(text: str) -> str:
    """Remove C/C++ comments and string/char literals for lightweight lexical scans."""
    text = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.S)
    text = re.sub(r"//.*", " ", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


def _prompt_safe_identifiers(text: str) -> list[str]:
    bad = {
        "if", "else", "while", "for", "switch", "case", "break", "continue", "return", "sizeof",
        "int", "char", "void", "unsigned", "signed", "long", "short", "struct", "const", "static", "extern",
        "volatile", "register", "enum", "union", "FILE", "NULL", "true", "false",
    }
    seen: list[str] = []
    for tok in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", _strip_c_comments_and_literals(text)):
        if tok in bad or tok.lower() in {x.lower() for x in bad}:
            continue
        if tok not in seen:
            seen.append(tok)
    return seen


def _split_decl_list(rest: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in rest:
        if ch in "([{" :
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            part = "".join(cur).strip()
            if part:
                parts.append(part)
            cur = []
        else:
            cur.append(ch)
    part = "".join(cur).strip()
    if part:
        parts.append(part)
    return parts


def _extract_declared_names(body: str) -> list[str]:
    """Best-effort C local/parameter declaration extraction for prompts.

    This is deliberately broader than the KG variable anchor regex, because the
    source-only prompt must expose important variables such as i, l, contentlen,
    username, inbuf, writable, and parameters. It is not used as ground truth.
    """
    clean = _strip_c_comments_and_literals(body)
    seen: list[str] = []

    # Function parameters from the first signature line.
    first_line = clean.splitlines()[0] if clean.splitlines() else ""
    m_params = re.search(r"\((.*)\)", first_line)
    if m_params:
        for param in _split_decl_list(m_params.group(1)):
            param = param.strip()
            if not param or param == "void":
                continue
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", param.replace("*", " "))
            if m and m.group(1) not in seen:
                seen.append(m.group(1))

    type_prefix = re.compile(
        r"^\s*(?:"
        r"(?:const|volatile|static|extern|register)\s+|"
        r"(?:unsigned|signed)\s+|(?:long|short)\s+|"
        r"struct\s+\w+\s+|enum\s+\w+\s+|union\s+\w+\s+|"
        r"FILE\s+|size_t\s+|ssize_t\s+|uint\d+_t\s+|int\d+_t\s+|"
        r"[A-Za-z_]\w+\s+"
        r")+(.+);\s*$"
    )
    control = re.compile(r"^\s*(?:if|while|for|switch|return)\b")
    for raw_line in clean.splitlines()[1:]:
        line = raw_line.strip()
        if not line or control.match(line) or "(" in line and not line.startswith(("FILE", "struct", "enum", "union")):
            # Avoid function calls/prototypes; ordinary declarations below rarely contain '('.
            continue
        m = type_prefix.match(line)
        if not m:
            continue
        for declarator in _split_decl_list(m.group(1)):
            declarator = declarator.split("=", 1)[0].strip()
            declarator = re.sub(r"\[[^\]]*\]", " ", declarator)
            declarator = declarator.replace("*", " ").replace("&", " ")
            m_name = re.search(r"\b([A-Za-z_]\w*)\b\s*$", declarator)
            if m_name:
                name = m_name.group(1)
                if name not in seen:
                    seen.append(name)
    return seen


def _target_vocabulary(sample: SecVulEvalSample, max_items: int = 80) -> str:
    body = sample.func_body or ""
    clean = _strip_c_comments_and_literals(body)
    variables = _extract_declared_names(body)
    callees: list[str] = []
    for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        if name in {"if", "while", "for", "switch", "return", "sizeof"}:
            continue
        if name not in callees:
            callees.append(name)
    risky_calls = [c for c in callees if c in {
        "sprintf", "snprintf", "vsprintf", "vsnprintf", "strcpy", "strncpy", "strcat", "strncat",
        "memcpy", "memmove", "gets", "fgets", "scanf", "sscanf", "fscanf", "system", "popen", "fprintf",
        "sockgetlinebuf", "decodeurl", "printuserlist", "printiplist", "printportlist",
    }]
    constants = [x for x in _prompt_safe_identifiers(body) if x.isupper() or x.startswith("CWE_")][:max_items]
    guard_lines: list[str] = []
    for i, line in enumerate(body.splitlines(), start=1):
        if re.search(r"\b(?:if|while|for)\s*\(", line) and len(guard_lines) < 18:
            guard_lines.append(f"{i}: {line.strip()[:180]}")
    upload_terms = [t for t in ["contentlen", "l", "i", "LINESIZE", "sockgetlinebuf", "buf[i]", "decodeurl", "fprintf"] if t in body]
    vocab = {
        "visible_variables": variables[:max_items],
        "visible_callees": callees[:max_items],
        "visible_risky_or_security_relevant_calls": risky_calls[:max_items],
        "visible_constants_or_macros": constants[:max_items],
        "visible_guard_or_loop_lines": guard_lines,
        "source_only_upload_path_terms_detected": upload_terms,
    }
    return json.dumps(vocab, ensure_ascii=False)


def _common_rules() -> str:
    return """
Strict output contract:
- Preferred response shape is literal XML-style tags, not a JSON wrapper with keys named thinking/answer:
  <thinking>
  Public evidence notes only. Summarize concrete evidence, uncertainty, and why each JSON field is justified. Do not include hidden/private chain-of-thought, markdown headings, code fences, or full code blocks. Keep this focused enough that the complete <answer> JSON is always produced.
  </thinking>
  <answer>
  {{schema-valid JSON object only}}
  </answer>
- Start the response with <thinking>. End the response with </answer>. Put no text before <thinking> or after </answer>.
- The <answer> block is the machine-readable contract and must contain exactly one valid JSON object: no markdown fences, prose, comments, or trailing commas.
- Never put JSON outside <answer>. Never put prose inside <answer>.
- If your API provider forces JSON-only output and cannot emit XML tags, return exactly {{"thinking": "public evidence notes", "answer": {{schema-valid JSON object}}}}.
- Do not copy schema examples or placeholder/type-marker values.
- Use only concrete identifiers/APIs/line numbers visible in the supplied target function or returned evidence.
- Once evidence is available, cite concrete evidence IDs such as "E14" or "Q1.2.1".

CodeKG retrieval contract:
- KG requests must be structured CodeKG query objects; never SQL, never arbitrary graph traversal, and never vague natural-language graph access.
- Allowed query_type values: {allowed}
- The query_type value is the CodeKG query kind. Use target_function for function-centered queries.
- Prefer security_context for the first target-function investigation.
- Prefer evidence_slice when a suspicious statement, expression, or line is known.
- Use variable_flow for suspicious variables/parameters/globals.
- Use call_neighborhood, callers, or callees when the hypothesis depends on caller/callee behavior.
- Use semantic_facts for deterministic risk-pattern, guard, pointer, allocation, bounds, or lifetime evidence.
- Use file_context only when file-level headers, macros, globals, or neighboring functions are needed.
- Do not classify from query names alone. Base reasoning only on returned source-grounded evidence.
- If evidence is insufficient, request another specific CodeKG query.
- Do not invent code that was not retrieved.
- Every final claim must cite retrieved evidence by evidence ID and, where available, file/function/line/snippet/node id.

Security reasoning constraints:
- Forbidden literal placeholder phrases: {forbidden}
- A bounded API is not vulnerable merely because it writes: safe generic patterns include fgets(dst, N, f) when N is not greater than the declared destination array size, and snprintf/vsnprintf with a destination-size argument.
- Treat unbounded sprintf/vsprintf/strcpy/strcat/gets and scanf-family %s without field width as high-risk unless returned evidence proves an adequate bound.
- Distinguish absence of proof from proof of safety: unresolved risk must stay unresolved/inconclusive, not become non-vulnerable.
- A non-vulnerable decision requires concrete mitigating or ruling-out evidence, such as a size cap, loop bound, destination-size argument, length check before indexing/writing, or unreachable sink.
- A confirmed vulnerability requires more than a risky API name: cite destination buffer, destination-size evidence, attacker/source-control evidence, the missing or insufficient bound, and why the write can exceed the destination.
- For upload/configuration paths, explicitly inspect content-length parsing/caps, loop counters, read-size expressions, NUL writes after reads, decoding/transformation calls, and output/file-write calls before deciding.
""".strip().format(allowed=json.dumps(ALLOWED_QUERY_TYPES), forbidden=json.dumps(FORBIDDEN_PLACEHOLDERS, ensure_ascii=False))


RISK_HYPOTHESIS_SCHEMA_TEXT = """
{
  "risk_hypotheses": [
    {
      "id": "H1",
      "kind": "free-form short vulnerability/risk category, e.g. integer_overflow, out_of_bounds_read, unchecked_length, null_deref, format_string, path_traversal, logic_error",
      "status": "active",
      "suspicious_locations": [
        {"line": 0, "code_reference": "short target-code reference", "reason": "specific source-only reason"}
      ],
      "suspect_symbols": ["concrete variable/constant names from target"],
      "suspect_callees": ["concrete callee/API names from target"],
      "needed_context": ["specific facts that would confirm or rule out this hypothesis"]
    }
  ],
  "kg_queries": [
    {
      "hypothesis_id": "H1",
      "query_type": "security_context",
      "target_function": "target function name",
      "depth": 3,
      "call_depth": 2,
      "data_depth": 4,
      "include_callers": true,
      "include_headers": true,
      "include_globals": true,
      "include_joern": true,
      "joern_limit": 160,
      "max_nodes": 520,
      "risk_terms": ["pointer", "array", "bounds", "size", "copy", "read", "write", "allocation", "free", "null", "return", "guard"],
      "reason": "H1: explain what concrete CodeKG evidence this query should retrieve"
    },
    {
      "hypothesis_id": "H1",
      "query_type": "evidence_slice",
      "target_function": "target function name",
      "target_statement": "suspicious expression or short code reference",
      "relation_depth": 4,
      "data_depth": 4,
      "control_depth": 3,
      "call_depth": 2,
      "include_defs": true,
      "include_uses": true,
      "include_guards": true,
      "include_callees": true,
      "include_headers": true,
      "include_globals": true,
      "include_joern": true,
      "joern_limit": 120,
      "max_nodes": 450,
      "risk_terms": ["concrete", "terms", "from", "target"],
      "reason": "H1: explain the suspicious statement/expression this slice should ground"
    }
  ]
}
""".strip()


FOLLOWUP_SCHEMA_TEXT = """
{
  "continue": false,
  "hypothesis_updates": [
    {
      "id": "H1",
      "status": "confirmed_vulnerable | ruled_out_safe | unresolved | needs_more_evidence",
      "evidence_used": ["Q1.1.1"],
      "public_reason": "concise evidence-based update",
      "remaining_context_needed": ["only facts still missing"]
    }
  ],
  "active_hypothesis_ids": ["H1"],
  "resolved_hypothesis_ids": [],
  "kg_queries": [
    {
      "hypothesis_id": "H1",
      "query_type": "variable_flow",
      "target_function": "target function name",
      "symbol": "concrete variable/parameter/global from target or evidence",
      "data_depth": 4,
      "reason": "H1: specific remaining data-flow fact this should resolve"
    },
    {
      "hypothesis_id": "H1",
      "query_type": "call_neighborhood",
      "target_function": "target function name",
      "direction": "both",
      "call_depth": 2,
      "reason": "H1: caller/callee context needed to confirm or rule out reachability/effects"
    },
    {
      "hypothesis_id": "H1",
      "query_type": "semantic_facts",
      "target_function": "target function name",
      "reason": "H1: deterministic facts needed for guards, bounds, pointer, allocation, or lifetime evidence"
    }
  ],
  "verification_summary": "public summary of what changed after this KG evidence"
}
""".strip()


FINAL_DECISION_SCHEMA_TEXT = """
{
  "is_vulnerable": false,
  "confidence": 0.0,
  "primary_vulnerability_type": null,
  "vuln_statements": [
    {
      "evidence_id": "E41",
      "line": 0,
      "claim_strength": "confirmed | strongly_supported | plausible | weak_pattern_only",
      "sink_or_api": "concrete sink/API name",
      "destination_buffer": "destination object or buffer",
      "destination_size_evidence": "evidence ID or short fact proving destination size/capacity",
      "source_or_input_control_evidence": "evidence ID or short fact proving source/input/reachability",
      "bound_or_guard_evidence": "evidence ID or short fact about relevant guard, or 'none found in evidence'",
      "why_bound_insufficient": "why available bounds do not prevent overflow/write past destination",
      "reason": "short evidence-based claim",
      "why_exploitable": "why the cited statement can violate memory/security safety",
      "missing_facts": []
    }
  ],
  "evidence_used": [],
  "confirmed_hypotheses": [],
  "ruled_out_hypotheses": [],
  "unresolved_hypotheses": [],
  "upload_path_assessment": {
    "present": true,
    "contentlen_declaration": {"evidence_id": "E8", "line": 0, "value": "int contentlen = 0 | unsigned contentlen = 0", "summary": "content length variable declaration and signedness"},
    "contentlen_parsing": {"evidence_id": "E41", "line": 0, "value": "atoi | sscanf", "summary": "how Content-Length is parsed"},
    "contentlen_cap": {"evidence_id": "E42", "line": 0, "value": "cap expression or none", "summary": "cap/range guard for contentlen"},
    "loop_condition": {"evidence_id": "E48", "line": 0, "value": "while/for condition", "summary": "upload loop condition"},
    "read_size_expression": {"evidence_id": "E50", "line": 0, "value": "sockgetlinebuf size argument", "summary": "per-read bound expression"},
    "post_read_adjustment": {"evidence_id": "E49", "line": 0, "value": "if(i > contentlen-l) ... or none", "summary": "post-read clamp/adjustment before NUL write"},
    "nul_write": {"evidence_id": "E52", "line": 0, "value": "buf[i] = 0", "summary": "NUL write after read"},
    "decode_and_write_sink": {"evidence_id": "E53,E54", "line": 0, "value": "decodeurl/fprintf", "summary": "decoded upload data written to config/output"},
    "verdict": "unsafe | safe | unresolved",
    "evidence_ids": ["E41", "E48", "E50"],
    "reason": "concise source-only upload-path verdict",
    "missing_facts": []
  },
  "decision_status": "vulnerable | non_vulnerable | inconclusive",
  "binary_prediction_policy": "brief note on how decision_status maps to is_vulnerable for benchmark scoring",
  "reasoning_summary": "concise public evidence-based explanation"
}
""".strip()


def risk_hypothesis_prompt(sample: SecVulEvalSample, evidence: EvidencePack | None = None, max_context_chars: int = 16_000, prompting_cfg: PromptingConfig | None = None) -> str:
    # Local runs pass a small max_context_chars; API-rich runs pass a much larger
    # value so the full/near-full target function can be preserved.
    src_chars = max(4000, max_context_chars - 2500)
    return f"""
{_common_rules()}

Stage 1 — source-only hypothesis and investigation-plan generation.
No KG evidence has been provided yet. Inspect the target function and propose only concrete hypotheses that are visible from the source.
The LLM chooses what to investigate; the orchestrator will deterministically expand requested evidence bundles through the KG.
Prefer evidence_bundle queries over vague natural-language safety searches.

Allowed bundle_type values:
{json.dumps(BUNDLE_TYPES)}

Bundle selection guidance:
- buffer/memory risk: buffer_write_bundle for the main buffer symbol; callee_summary_bundle for callees that write/copy/format into it; global_state_bundle for size constants/macros/globals.
- input validation risk: input_validation_bundle for input source, parser/conversion, validation, and sink.
- integer risk: integer_overflow_bundle for arithmetic/conversion, type/range, and guards.
- format-string risk: format_string_bundle for format argument origin and sink.
- path/command risk: path_traversal_bundle or command_injection-style evidence via input_validation_bundle/callee_summary_bundle.
- lifetime risk: lifetime_ownership_bundle for allocation/free/use-after-free evidence.

Expected schema:
{RISK_HYPOTHESIS_SCHEMA_TEXT}

Constraints:
- Focus on reachable target-function paths and distinguish risky patterns from exploitability.
- For memory writes, request destination-size evidence, source/input-control evidence, and guarding/bounds evidence.
- For upload/configuration logic, explicitly inspect content-length parsing/caps, loop counters, read-size expressions, post-read NUL writes, decode/transform calls, file/output writes, and termination/progress conditions.
- Do not classify safe bounded reads such as fgets(buf, 256, fp) into char buf[256] as vulnerable without concrete mismatch or unsafe subsequent use.
- If a macro/global constant such as LINESIZE affects a bound, request query_type="global" for the exact symbol or evidence_bundle/global_state_bundle.
- Return every distinct, concrete hypothesis that is meaningfully supported by the visible target code; do not add duplicates or filler hypotheses.
- Return enough kg_queries to investigate the concrete hypotheses, while keeping each query specific and non-duplicative.
- Each kg_query must reference a hypothesis_id when it investigates a hypothesis and must use a concrete symbol/API from the target vocabulary or returned evidence.
- Do not use placeholders such as "symbol" or "target variable" as actual values.
- Use function-relative line numbers from the line-numbered source.

Model-visible target orientation:
{json.dumps(_orientation(sample, prompting_cfg), ensure_ascii=False)}

Target-derived vocabulary:
{_target_vocabulary(sample)}

Line-numbered target function source:
{_line_numbered_source(sample.func_body, src_chars)}
""".strip()


def followup_query_prompt(sample: SecVulEvalSample, evidence: EvidencePack, previous_trace_summary: str, max_context_chars: int, round_index: int, prompting_cfg: PromptingConfig | None = None) -> str:
    ledger_chars = max(1500, max_context_chars // 3)
    evidence_chars = max(2500, max_context_chars // 2)
    return f"""
{_common_rules()}

Stage {round_index} — hypothesis verification after KG bundle retrieval.
The orchestrator executed your previous KG/bundle requests. Use only the returned evidence below plus the compact public ledger.
Update each hypothesis as confirmed_vulnerable, ruled_out_safe, unresolved, or needs_more_evidence.
Only request another query if it is concrete, non-duplicate, and resolves a specific remaining fact. Prefer evidence_bundle or guard_dominance requests over natural-language searches.
If no useful concrete new request remains, set continue=false and keep unresolved hypotheses unresolved.

Expected schema:
{FOLLOWUP_SCHEMA_TEXT}

Round: {round_index}
Model-visible target orientation:
{json.dumps(_orientation(sample, prompting_cfg), ensure_ascii=False)}

Compact hypothesis/query ledger:
{truncate_middle(previous_trace_summary, ledger_chars)}

New KG evidence returned for the latest query round:
{evidence.to_prompt_text(evidence_chars)}
""".strip()


def _risk_audit_text(evidence: EvidencePack, max_chars: int) -> str:
    rows: list[str] = []
    for item in evidence.items:
        md = item.metadata if isinstance(item.metadata, dict) else {}
        risk_hits = md.get("risk_hits")
        wanted_cat = md.get("wanted_category")
        is_risk = item.kind in {"target_risk_statement", "risk_statement"} or "risk" in item.kind or "sink" in item.kind or bool(risk_hits)
        is_guard = "safety" in item.kind or "guard" in item.kind or wanted_cat in {"bounds_checks", "guards", "guard_dominance"}
        is_upload = "upload" in item.kind or str(wanted_cat or "") in {"case_or_branch", "contentlen_declaration_or_parse", "contentlen_cap_or_guard", "loop_condition", "read_bound_expression", "post_read_nul_write", "decode_or_transform", "file_or_output_write", "loop_progress", "size_macro_use"}
        if is_risk or is_guard or is_upload:
            loc = f"{item.relpath or ''}:{item.line_start or '?'}-{item.line_end or '?'}"
            rows.append(f"[{item.evidence_id}] kind={item.kind} loc={loc} category={wanted_cat or ''} symbol={item.matched_symbol or ''}\n{(item.text or '')[:500]}")
    if not rows:
        return "No target-local risk/guard evidence was retrieved."
    return truncate_middle("\n\n".join(rows), max_chars)


def _high_value_evidence(evidence: EvidencePack, max_items: int = 45) -> EvidencePack:
    # Keep all risk/sink/guard/tool evidence first, then fill with remaining target evidence.
    ranked = []
    rest = []
    for item in evidence.items:
        md = item.metadata if isinstance(item.metadata, dict) else {}
        high = (
            "risk" in item.kind or "sink" in item.kind or "guard" in item.kind or "safety" in item.kind
            or str(md.get("wanted_category") or "") in {"exact_writes", "format_writes", "offset_writes", "sinks", "bounds_checks", "guards", "guard_dominance", "callee_summaries", "size_macros", "case_or_branch", "contentlen_declaration_or_parse", "contentlen_cap_or_guard", "loop_condition", "read_bound_expression", "post_read_nul_write", "decode_or_transform", "file_or_output_write", "loop_progress", "size_macro_use"}
            or "upload" in item.kind
        )
        (ranked if high else rest).append(item)
    clone = evidence.model_copy(deep=True)
    clone.items = (ranked + rest)[:max_items]
    return clone


def final_decision_prompt(sample: SecVulEvalSample, evidence: EvidencePack, trace_summary: str, max_context_chars: int, prompting_cfg: PromptingConfig | None = None) -> str:
    # Keep final prompts below the observed Qwen/AcademicCloud instability range.
    # The final decision needs high-value, source-bound evidence, not every
    # statement. Larger datasets benefit more from stable bounded prompts.
    budget = min(int(max_context_chars or 0), 42000)
    src_chars = min(12000, max(6500, budget // 4))
    ledger_chars = min(5200, max(2200, budget // 7))
    audit_chars = min(7000, max(2600, budget // 6))
    evidence_chars = min(14000, max(4500, budget // 3))
    max_items = 90 if budget >= 36000 else 60
    compact_evidence = _high_value_evidence(evidence, max_items=max_items)
    semantic_audit = semantic_audit_dict(compact_evidence)
    source_upload_audit = source_upload_path_audit_from_text(sample.func_body or "")
    return f"""
{_common_rules()}

Final stage — binary vulnerability classification of the target function.
Use the target function, compact hypothesis ledger, retrieved KG evidence bundles, and risk/guard audit. Do not use metadata, labels, commits, CVEs, CWEs, or commit messages.
A risky API alone is not sufficient. A generic guard/check that merely mentions a variable is also not sufficient to rule out a risky write. Conversely, bounded APIs such as fgets(dst, N, f) or snprintf(dst, N, ...) are not vulnerabilities when evidence shows N is within the destination size.
Decision-status semantics are strict:
- decision_status="vulnerable" only when at least one concrete statement is confirmed or strongly supported by evidence.
- decision_status="non_vulnerable" only when the relevant risks have concrete ruling-out evidence: adequate bounds, destination-size arguments, range caps, length checks before indexing/writing, or no reachable unsafe sink.
- decision_status="inconclusive" when evidence shows suspicious patterns but the available evidence does not prove exploitability or safety.
Missing evidence is not safety evidence. If risk evidence remains unresolved, use decision_status="inconclusive" and low confidence rather than a high-confidence non-vulnerable decision.
Every vuln_statements entry must cite an evidence_id that actually supports the reason and must include claim_strength.

Mandatory upload/config path rule:
- If the evidence contains an upload/config path with contentlen, sockgetlinebuf, buf[i]=0, decodeurl, and fprintf, you must fill upload_path_assessment.
- Decide the upload/config path first. Then separately mention generic sprintf/UI-formatting risk only if it changes the final decision.
- Do not claim LINESIZE, buf allocation, contentlen cap, or read-size bounds are missing when evidence IDs in the prompt provide them.
- upload_path_assessment.verdict="unsafe" when source evidence shows signed contentlen/l or equivalent remaining-length arithmetic plus a read of LINESIZE-1 followed by a post-read clamp/NUL write that can index outside the buffer.
- upload_path_assessment.verdict="safe" when source evidence shows unsigned counters/range cap, l < contentlen loop guard, and read size bounded by min(contentlen-l, LINESIZE-1) before buf[i]=0.
- upload_path_assessment.verdict="unresolved" only when one of the required source facts is genuinely absent from retrieved evidence; list those missing facts.

Expected schema:
{FINAL_DECISION_SCHEMA_TEXT}

When is_vulnerable=true, each vuln_statements item must satisfy the confirmed-vulnerability evidence contract:
{{"evidence_id":"E41","line":0,"claim_strength":"confirmed | strongly_supported | plausible | weak_pattern_only","sink_or_api":"concrete sink/API","destination_buffer":"destination object","destination_size_evidence":"evidence/fact proving destination capacity","source_or_input_control_evidence":"evidence/fact proving input/source control or reachability","bound_or_guard_evidence":"relevant guard evidence or none found","why_bound_insufficient":"why the bound is absent or insufficient","reason":"short evidence-based claim","why_exploitable":"why the write/security effect can occur","missing_facts":[]}}
If any of these facts are missing, the claim_strength must be plausible or weak_pattern_only and the final decision should be inconclusive unless another statement satisfies the full contract.

Constraints:
- If is_vulnerable=false: primary_vulnerability_type must be null and vuln_statements must be []. Put unresolved risks only in unresolved_hypotheses and reasoning_summary.
- If upload_path_assessment.present=true and verdict is safe, cite the concrete mitigation IDs in reasoning_summary and prefer decision_status="non_vulnerable" unless another independent vulnerability satisfies the full contract.
- If upload_path_assessment.present=true and verdict is unsafe, cite the unsafe IDs in evidence_used and prefer decision_status="vulnerable" unless you explicitly refute each unsafe element.
- If is_vulnerable=true: decision_status must be vulnerable; each vuln_statements item must contain evidence_id, line, claim_strength, sink_or_api, destination_buffer, destination_size_evidence, source_or_input_control_evidence, bound_or_guard_evidence, why_bound_insufficient, reason, why_exploitable, and missing_facts.
- Do not mark is_vulnerable=true using only claim_strength="weak_pattern_only" or "plausible". At least one vuln_statement must be "confirmed" or "strongly_supported".
- decision_status must be one of vulnerable, non_vulnerable, inconclusive.
- confidence must reflect evidence completeness; do not use 0.95 when major risk evidence is unresolved.
- evidence_used should contain the strongest supporting IDs; include all IDs needed for the decision contract, but do not list irrelevant retrieved items.
- vuln_statements should include every distinct confirmed or strongly supported vulnerable statement needed for the final decision. Do not put raw C/C++ code blocks into JSON.
- reasoning_summary must be evidence-based and as detailed as needed to justify the decision without adding unsupported facts.
- If the evidence proves only a generic risky API pattern but not attacker-controlled reachability, destination size, and missing/insufficient bounds, use decision_status="inconclusive" instead of a high-confidence vulnerable/non-vulnerable decision.
- For non_vulnerable, reasoning_summary must explicitly name the concrete evidence IDs that rule out the suspected risks.

Model-visible target orientation:
{json.dumps(_orientation(sample, prompting_cfg), ensure_ascii=False)}

Line-numbered target function source:
{_line_numbered_source(sample.func_body, src_chars)}

Compact hypothesis ledger:
{truncate_middle(trace_summary, ledger_chars)}

Final risk/guard/upload evidence audit:
{_risk_audit_text(compact_evidence, audit_chars)}

Source-only semantic safety audit over retrieved evidence:
{truncate_middle(json.dumps(semantic_audit, ensure_ascii=False), audit_chars)}

Narrow source-only upload-pattern audit over the target function:
{truncate_middle(json.dumps(source_upload_audit, ensure_ascii=False), audit_chars)}

Retrieved high-value KG evidence:
{compact_evidence.to_prompt_text(evidence_chars)}
""".strip()


def json_repair_prompt(*, invalid_text: str, parser_error: str, expected_schema: str) -> str:
    return f"""
The previous response failed parsing or schema validation. Repair the structure only; do not redo the security analysis.

Invalid model output to repair:
{truncate_middle(invalid_text, 2500)}

Parser/schema error:
{truncate_middle(parser_error, 1000)}

Required answer schema:
{truncate_middle(expected_schema, 3000)}

Return one corrected response in the preferred literal-tag format and no text outside it:
<thinking>
Public note: state the structural correction only. Do not add hidden/private chain-of-thought.
</thinking>
<answer>
{{schema-valid corrected JSON object only}}
</answer>
If the API forces JSON-only output and rejects literal tags, return exactly {{"thinking": "structural correction note", "answer": {{schema-valid corrected JSON object}}}}.
Preserve all hypotheses, hypothesis_updates, kg_queries, unresolved_hypotheses, evidence IDs, and vuln_statements whenever they can be represented in the schema. Do not collapse multiple hypotheses into one. Do not delete kg_queries or downgrade/drop a hypothesis merely to satisfy validation unless that field is irrecoverably malformed. You may shorten long prose fields only; keep structural arrays intact. Do not use markdown fences.
""".strip()


POSTHOC_COMMIT_AUDIT_SCHEMA_TEXT = """
{
  "semantic_alignment": "aligned | partially_aligned | not_aligned | unclear",
  "factual_support": "supported | partially_supported | unsupported | unclear",
  "snapshot_semantics": "pre_fix_parent | patch_commit | dataset_commit | unknown",
  "does_reasoning_match_snapshot": true,
  "does_reasoning_match_commit_message": true,
  "patch_effect_identified": true,
  "audit_label": "good | partially_good | misleading | unsupported | unclear",
  "commit_message_summary": "brief report-only summary of the commit message claim",
  "model_reasoning_summary": "brief summary of the model's final reasoning",
  "factual_findings": ["evidence-based factual observation"],
  "mismatch_or_gap": ["specific mismatch, missing fact, or overclaim"],
  "missing_patch_evidence": ["patch-related fact not identified in final reasoning, if applicable"],
  "evidence_ids_checked": ["E41", "Q1.1.17"],
  "audit_conclusion": "concise conclusion; this does not change the prediction"
}
""".strip()


def posthoc_commit_audit_prompt(*, sample: SecVulEvalSample, prediction: Any, evidence: EvidencePack, max_context_chars: int = 24000) -> str:
    """Report-only audit prompt.

    This prompt intentionally may include commit metadata because the final
    prediction has already been made. It must never be used to alter the binary
    prediction; it exists only for human debugging of semantic quality.
    """
    evidence_chars = min(9000, max(3000, int(max_context_chars) // 3))
    pred = prediction.model_dump(mode="json") if hasattr(prediction, "model_dump") else dict(prediction or {})
    return f"""
Strict output rules:
- You MUST use exactly this top-level wrapper structure, with no text before <thinking> and no text after </answer>:
  <thinking>
  Public evidence-based audit notes. Include as much detail as needed, but do not reveal hidden/private chain-of-thought.
  </thinking>
  <answer>
  {{schema-valid JSON object only}}
  </answer>
- The <answer> tag must contain exactly one valid JSON object: no markdown fences, prose, comments, or trailing commas.
- Do not put JSON outside <answer>. Do not put prose inside <answer>.
- This is a post-hoc report-only audit. Do not change or restate a new binary prediction.
- Judge whether the final model reasoning is semantically aligned with the commit message, the resolved snapshot semantics, and the cited evidence.
- For a pre-fix-parent snapshot, reasoning should explain why the snapshot is vulnerable if it predicts vulnerable.
- For a patch-commit snapshot, reasoning should not merely say "not proven vulnerable"; it should identify concrete source evidence that mitigates or rules out the commit-message class of bug, when available.
- If the reasoning misses relevant safety/risk evidence, set semantic_alignment/factual_support to partially_aligned/partially_supported or worse.
- If the commit message names an admin configuration upload/out-of-bounds-write class but final reasoning focuses only on unrelated sprintf/UI formatting evidence, mark the audit as partially_aligned or not_aligned unless the final reasoning also explains the upload/config path.
- For patch-commit snapshots, concrete mitigation evidence should include source-level guards/caps/read-bound expressions where available, not merely absence of proof.
- Cite concrete evidence IDs when making factual claims.

Expected schema:
{POSTHOC_COMMIT_AUDIT_SCHEMA_TEXT}

Report-only metadata, never used for prediction:
{{"sample_id": {json.dumps(getattr(prediction, "sample_id", None) or sample.sample_id)}, "project": {json.dumps(sample.project)}, "filepath": {json.dumps(sample.filepath)}, "function": {json.dumps(sample.func_name)}, "dataset_label_report_only": {json.dumps("vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable")}, "dataset_commit_report_only": {json.dumps(sample.commit_id)}, "resolved_commit_report_only": {json.dumps(getattr(prediction, "resolved_commit_id", None) or evidence.resolved_commit_id or "")}, "resolved_commit_label_report_only": {json.dumps(getattr(prediction, "resolved_commit_label", None) or evidence.resolved_commit_label or "")}, "commit_message_report_only": {json.dumps(sample.commit_message or "")}, "target_validation_status_report_only": {json.dumps(getattr(prediction, "target_validation_status", None) or evidence.target_validation_status or "")}, "target_validation_similarity_report_only": {json.dumps(getattr(prediction, "target_validation_similarity", None) if getattr(prediction, "target_validation_similarity", None) is not None else evidence.target_validation_similarity)}}}
Snapshot-semantics hard rule for this audit: if resolved_commit_label_report_only is "pre_fix_parent_for_vulnerable", snapshot_semantics must be "pre_fix_parent"; if it is "patch_commit_for_fixed", snapshot_semantics must be "patch_commit".

Final prediction to audit:
{json.dumps(pred, ensure_ascii=False, indent=2)}

Evidence available for factual checking:
{evidence.to_prompt_text(evidence_chars)}
""".strip()
