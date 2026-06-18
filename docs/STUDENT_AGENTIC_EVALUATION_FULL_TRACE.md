# Student agentic evaluation full trace

This round adds a student-side full-stage `solution.py` and dashboard support for inspecting the student agent loop.

## Student solution

Use:

```text
student_solutions/solution_agentic_research_like.py
```

The solution implements the same high-level stage names as the research audit flow inside the evaluator `step()` contract:

- `01_source_only_hypothesis`
- `02_kg_query_planning`
- `04_hypothesis_verification`
- `04_evidence_gap_iterN`
- `04_hypothesis_verification_iterN`
- `05_counter_evidence_review`
- `05_counter_gap_iterN`
- `06_final_adjudication`
- `final_decision`

The student evaluator still only accepts external actions `query` and `final`, so the internal stages are returned as metadata (`agentic_trace`) and persisted by the evaluator.

## KG API

The evaluator still calls the exact local bounded KG API:

```text
POST /api/v1/kgs/{kg_id}/query
```

with query payloads such as `security_context`, `semantic_facts`, `evidence_slice`, `variable_flow`, and `call_neighborhood`.

## Optional LLM mode

The frontend can pass LLM configuration into the student solution. The solution uses an OpenAI-compatible call to:

```text
{llm_api_base}/chat/completions
```

Use an environment variable for the key, e.g. `STUDENT_LLM_API_KEY`. Labels, commit messages, and sample IDs are not used for prediction.

## Dashboard

Student Agent Audit now reads `traces.json` from the evaluation output directory and displays:

- samples
- final prediction and confidence
- internal agentic stages
- KG query history
- final adjudication JSON
- raw trace JSON

Per-sample reports are downloadable, and the whole evaluation report bundle can be downloaded as a ZIP.
