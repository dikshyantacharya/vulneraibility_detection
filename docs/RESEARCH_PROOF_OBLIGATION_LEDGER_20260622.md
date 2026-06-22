# Research Patch: Proof-Obligation Ledger Micro-Steps

Date: 2026-06-22
Scope: research-side `vckg_agentic_proof` / `vuln_commit_kg` agentic proof flow only.

## Purpose

This patch upgrades the agentic vulnerability-detection flow from whole-hypothesis verification to a proof-obligation ledger. The LLM is now used as a small reviewer for one proof question at a time, while the controller maintains the global proof state.

## New lifecycle

1. Generate hypotheses from the target function source.
2. Normalize/deduplicate hypotheses.
3. Process hypotheses sequentially.
4. For each hypothesis:
   - infer a vulnerability family,
   - create proof obligations,
   - run obligation-specific KG queries,
   - build obligation-specific tiny code capsules,
   - call the LLM once per proof obligation,
   - update a structured proof ledger,
   - derive the hypothesis status from the ledger,
   - run local counter-review,
   - only then move to the next hypothesis.
5. Stop early only if a hypothesis reaches accepted confirmed status after local counter-review.

## New files

- `src/vckg_agentic_proof/proof_obligations.py`
- `tests/test_agentic_proof_obligation_ledger.py`

## Modified files

- `src/vckg_agentic_proof/schemas.py`
- `src/vckg_agentic_proof/prompts.py`
- `src/vckg_agentic_proof/code_evidence.py`
- `src/vckg_agentic_proof/adapter.py`
- `src/vuln_commit_kg/orchestration/pipeline.py`
- `src/student_system_creator/dashboard/research.py`

## Important trace stages

The report should now show stages such as:

```text
04_proof_ledger__HYP-01 [start]
03_obligation_retrieval__HYP-01__PO-01 [start/done]
04_proof_obligation__HYP-01__PO-01 [start/done/ledger_update]
04_proof_ledger__HYP-01 [done]
05_counter_evidence_review__HYP-01
05_hypothesis_proof_state__HYP-01
```

The `04_proof_ledger__HYP-* [done]` event contains:

```json
{
  "family": "parser_scaled_pointer_traversal",
  "required_proven": 4,
  "required_total": 4,
  "required_missing": [],
  "status_hint": "complete",
  "derived_status": "confirmed_vulnerability",
  "ledger": { "...": "..." }
}
```

## Vulnerability families currently handled

- `parser_scaled_pointer_traversal`
- `selector_dispatch_or_shift_domain`
- `buffer_extent_or_signed_length`
- `allocation_lifetime`
- `path_file_api_misuse`
- `concurrency_lifecycle`
- `crypto_algorithmic`
- generic memory/bounds fallback

## Why this matters

The previous system still asked the LLM to verify a whole hypothesis over a medium-sized code bundle. That caused the model to ask for irrelevant evidence, such as post-loop raw dereference, instead of recognizing next-iteration parser reads. This patch makes proof obligations explicit and asks the model one narrow question at a time.

## Configuration

New config fields exposed through `AgenticProofConfig` and the pipeline config adapter:

```python
enable_proof_obligation_ledger = True
max_obligations_per_hypothesis = 8
max_queries_per_obligation = 3
```

## Validation performed

```text
python -m compileall -q src/vckg_agentic_proof src/vuln_commit_kg src/student_system_creator/dashboard
PYTHONPATH=src python -m pytest \
  tests/test_agentic_architecture_guardrails.py \
  tests/test_agentic_evidence_curation.py \
  tests/test_agentic_flow_loop.py::TestQueryableGapFallbackQueries \
  tests/test_agentic_proof_obligation_ledger.py -q
```

Result: 31 passed.
