# Agent trace, JSON repair, and prompt privacy

This project now records each agent decision as an explicit, auditable pipeline trace.
For every sample with `agent.save_demo_reports: true`, the run writes an `agent_demos/sample_*/` directory containing:

- `index.html` — human-readable pipeline trace.
- `decision_flow.json` — complete structured trace grouped by dataset setup, KG loading, retrieval, model calls, KG tool calls, final prediction, and report-only evaluation.
- `decision_summary.md` — compact summary.
- `model_calls.jsonl` — one logical model stage per line, including JSON repair attempts.
- `kg_tool_calls.jsonl` — one KG query/tool execution per line.
- `evidence_initial.json` — deterministic evidence before model-requested KG follow-up.
- `evidence_accumulated.json` — evidence after KG tool follow-up.
- `final_prediction.json` — accepted prediction object.
- `prompt_*.txt`, `raw_response_*.txt`, `parsed_response_*.json` — exact prompts, raw outputs, and parse status.
- `repair_prompt_*.txt`, `repair_response_*.txt`, `repair_parsed_*.json` — JSON repair loop artifacts when repair is needed.
- `privacy_scan.json` — checks that answer-leaking orchestration metadata did not appear in model prompts.

## JSON repair loop

Every JSON-producing model call follows this sequence:

1. Send the primary prompt.
2. Save the raw response.
3. Extract JSON from plain text or markdown-fenced output.
4. Validate it with a strict Pydantic schema.
5. If parsing or schema validation fails, send a repair prompt that includes the invalid text, the parser/schema error, and the expected schema.
6. Retry repair up to `agent.max_json_repairs`.
7. If repair still fails, clearly mark the failure and use deterministic fallback KG queries only for KG-query stages.

Fallback KG queries are marked as `fallback_generated`; repaired model queries are marked as `model_generated_after_json_repair`.

## Evidence-ID schemas

Model-visible schemas avoid full raw C statements inside JSON. The model must cite evidence IDs and line numbers:

```json
{
  "evidence_id": "E21",
  "line": 415,
  "reason": "Unbounded sprintf writes into a fixed-size buffer."
}
```

KG query objects must use one of:

```text
callee, caller, safety, risk, statement, variable, type, global, search
```

SQL-like query strings and plain-string query arrays are invalid and trigger the repair loop.

## Prompt privacy controls

The default prompt boundary is strict:

```yaml
prompting:
  include_orchestration_metadata_in_model_prompt: false
  include_cwe_hints_in_model_prompt: false
  include_cve_hints_in_model_prompt: false
```

Report metadata can still show sample IDs, commits, labels, project URLs, and validation artifacts, but the model prompt receives only target source, function/path orientation, evidence IDs, evidence text/locations, and public task instructions.
