# Research Agentic Proof Update — Terminal Per-Hypothesis Loop

This patch tightens the research-side LLM + CodeKG vulnerability-detection loop.
It does not modify the Student Challenge pipeline.

## Problem addressed

The previous per-hypothesis implementation could identify that a hypothesis still needed more evidence, generate a follow-up evidence-gap plan, and then move to the next hypothesis when the follow-up queries were duplicate or returned no new evidence. In the downloaded report this made HYP-01 look unfinished: the LLM requested more caller/provenance evidence, but the stage timeline moved on to HYP-02 without a visible terminal closure step.

The report was also difficult to inspect because the main timeline showed only LLM calls. KG retrieval attempts and controller decisions were hidden in later artifacts or not summarized near the top of the text report.

## New behavior

For each hypothesis, the loop now follows this lifecycle:

1. Plan KG queries for the current hypothesis only.
2. Retrieve source-code evidence for that hypothesis.
3. Verify the hypothesis using a source-code evidence bundle.
4. If unresolved, ask an evidence-gap LLM stage for more queryable proof elements.
5. Execute non-duplicate follow-up KG queries.
6. Re-run verification with the expanded evidence bundle.
7. If no new query/evidence is available, run a terminal closure verification stage before moving to the next hypothesis.

A hypothesis now moves to the next hypothesis only after one of these terminal controller reasons is recorded:

- `hypothesis_resolved`
- `hypothesis_confirmed_vulnerability`
- `no_more_evidence_needed`
- `all_queries_duplicate`
- `no_new_evidence_returned`
- `max_iterations_reached`
- `loop_disabled`
- `llm_timeout_gap_analysis`

When a follow-up request cannot add new source-code evidence, the new terminal stage is named like:

```text
04_hypothesis_terminal_verification__HYP-01_iter1
```

This stage receives the current source-code evidence bundle plus a retrieval-status object, and must return the best terminal status for that hypothesis under bounded static evidence.

## Report improvements

The full text report now includes an early `HYPOTHESIS PROGRESS SUMMARY` section with:

- latest status per hypothesis,
- whether the hypothesis was confirmed,
- missing-evidence count,
- supporting/counter evidence IDs,
- controller/retrieval events by hypothesis,
- KG retrieval summary grouped by hypothesis and stage.

This makes it visible whether HYP-01 actually queried more KG evidence, received zero new items, hit duplicate queries, or was re-verified.

## Additional safeguards

- Truncated or JSON-repaired hypotheses with empty `risk_summary` or broken `affected_code_region` are dropped before the per-hypothesis loop, so malformed hypotheses do not waste loop budget.
- `stop_on_confirmed_vulnerability` defaults to true in the research-side adapter and runtime config. Once a complete vulnerability proof is confirmed, later hypotheses are skipped and final adjudication proceeds.
- KG query records now preserve `hypothesis_id`, `query_id`, `agentic_stage`, original `query_text`, returned-item count, status, diagnostics, and item snippets for easier reporting.

## Key modified files

- `src/vckg_agentic_proof/adapter.py`
- `src/vckg_agentic_proof/prompts.py`
- `src/vuln_commit_kg/config.py`
- `src/vuln_commit_kg/orchestration/pipeline.py`
- `src/student_system_creator/dashboard/research.py`
- `tests/test_agentic_architecture_guardrails.py`
