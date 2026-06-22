# Research KG + LLM Architecture Hardening — 2026-06-22

This patch hardens the research-side `agentic_proof` flow for broad use across many C/C++ target functions. It is not a one-function workaround for `count_rows`.

## Main fixes

### 1. CodeKG function-call queries are preserved
The pipeline now preserves executable CodeKG query text such as:

```text
variable_flow(target_function="f", symbol="x", data_depth=4)
security_context(target_function="f", depth=4, call_depth=3)
```

Previously, these could be remapped to coarse legacy query types and reduced to a single variable string, starving the CodeKG retrieval layer and producing zero returned items.

### 2. Query sanitation rejects English proof words
`variable_flow(...)` is now accepted only when its symbol is a real identifier in the target function source. This prevents follow-up queries such as:

```text
variable_flow(target_function="count_rows", symbol="Bit", data_depth=5)
variable_flow(target_function="count_rows", symbol="Caller", data_depth=5)
variable_flow(target_function="count_rows", symbol="Bounds", data_depth=5)
```

### 3. Follow-up query generation is bounded and code-grounded
Automatic follow-up queries now use:

- broad security context,
- caller context,
- callee/helper context,
- semantic facts,
- variable-flow only for real target identifiers,
- evidence slices only for exact expressions named by the verifier.

It no longer expands arbitrary English gap text into dozens of invalid variable queries.

### 4. Per-hypothesis proof gate
A hypothesis cannot remain `confirmed_vulnerability` if its own verification still lists missing evidence. The proof gate downgrades such cases to `plausible_but_unproven` or `insufficient_evidence` and records a `proof_gate` controller event.

The gate checks:

- required proof fields are present,
- cited evidence IDs exist,
- no blocking `missing_evidence` remains,
- input-control proof is not explicitly uncertain.

### 5. Better final report diagnostics
The text report now includes:

- `evidence_strength`,
- `forced_prediction_bool`,
- `why_forced_binary`,
- validator notes / limitations,
- normalization warnings,
- validator modification events,
- KG query status, returned item count, node count, and errors,
- proof-gate controller events.

### 6. Final prediction schema preserves validator fields
`Prediction` now stores agentic-proof validator fields directly, rather than only burying them inside raw JSON:

- `forced_prediction`,
- `forced_prediction_bool`,
- `evidence_strength`,
- `why_forced_binary`,
- `residual_uncertainty`,
- `final_hypothesis_statuses`,
- `normalization_warnings`.

## Validation run in this environment

Passed:

```bash
python -m compileall -q src/vckg_agentic_proof src/vuln_commit_kg src/student_system_creator/dashboard
PYTHONPATH=src python -m pytest tests/test_agentic_architecture_guardrails.py tests/test_agentic_evidence_curation.py -q
```

Result:

```text
23 passed
```

Broader CodeKG integration tests were not run successfully in this uploaded ZIP environment because `vuln_commit_kg.data` is not present in the extracted project context here. That is an existing environment/package-content issue, not caused by this patch.
