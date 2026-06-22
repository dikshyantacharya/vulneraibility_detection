# Research Agentic Proof-Ledger Upgrade — 2026-06-22

This patch upgrades only the research-side LLM + CodeKG vulnerability audit flow.
It keeps the Student Challenge / student-system logic untouched except for report rendering that displays the new research proof-state events.

## Main intent

The LLM is no longer treated as one large global judge. The controller now pushes the system toward a proof-ledger style workflow:

1. Generate source-grounded hypotheses.
2. Retrieve CodeKG evidence per hypothesis.
3. Send small source-code capsules to the LLM rather than a large mixed graph dump.
4. Gate each verification through deterministic proof checks.
5. Run counter-evidence review before any global confirmed-vulnerability stop is accepted.
6. Use final validator logic to distinguish confirmed proof from forced binary benchmark output.

## Important behavioral changes

### 1. No global early stop on raw LLM confirmation

The per-hypothesis loop no longer breaks the whole audit merely because a raw verification stage says `confirmed_vulnerability`.
A confirmation must survive proof-gating and counter-evidence normalization before it can be treated as accepted.
This prevents the failure mode where one hypothesis is temporarily confirmed and later refuted, but the loop has already skipped the remaining hypotheses.

### 2. Counter-review normalizes proof state before final adjudication

A new internal function applies counter-review findings to the hypothesis verification list before Stage 06.
If the defense reviewer recommends `refuted_by_guard`, `refuted_by_caller_constraint`, `refuted_by_patch_or_changed_logic`, `plausible_but_unproven`, or `insufficient_evidence`, then raw confirmations are downgraded or annotated before final adjudication.

### 3. Symbol-kind query routing is stricter

`variable_flow(...)` is now permitted only for target parameters or local variables when target source is available.
Function names, callee names, and typedef/type-like symbols are rejected as variable-flow targets.
Examples rejected before KG execution:

```text
variable_flow(target_function="count_rows", symbol="count_rows", data_depth=5)
variable_flow(target_function="count_rows", symbol="choose_int_read", data_depth=5)
variable_flow(target_function="count_rows", symbol="IntRead", data_depth=5)
```

Valid examples remain:

```text
variable_flow(target_function="count_rows", symbol="length", data_depth=4)
variable_flow(target_function="count_rows", symbol="itemsize", data_depth=4)
variable_flow(target_function="count_rows", symbol="raw_length", data_depth=4)
```

### 4. LLM-visible evidence is now capsule-sized

Per-hypothesis, counter-review, and final-adjudication prompts now receive tiny source-code evidence capsules instead of large evidence bundles.
The LLM still receives enough source code to decide the sub-step, but receives less repeated function/AST noise.

Capsules remove or suppress:

- KG scores
- line-start / line-end fields
- query summaries
- semantic-fact summaries as proof
- standalone local-variable/parameter nodes
- AST suffixes such as `Assignment@67`, `Loop@64`, and `ReturnStatement@75`
- duplicate code blocks where possible

### 5. Parser/pointer traversal proof obligation is more general

The verification prompt no longer requires every scale operand to be attacker-controlled.
For parser pointer/index traversal, the key question is whether the parsed or malformed value is bounded against remaining space and scale before the state advance.
This better covers generic parser bugs such as:

```text
parsed length/count/offset → pointer/index/state advance → missing remaining-bound/overflow guard → later read/write/accept path
```

### 6. Final forced-binary evidence IDs are cleaner

When the final validator forces vulnerable due to an unresolved high-signal local-risk pattern, it now prefers evidence IDs from the unresolved local-risk hypothesis instead of unrelated counter-evidence IDs.
This prevents misleading reports where the final vulnerable decision cites a guard that actually belonged to a different/refuted hypothesis.

## New diagnostics

Reports now include proof-state update events such as:

```text
05_counter_evidence_review [proof_state_update]
05_proof_state [done] { accepted_confirmed_hypotheses: [...] }
```

These make it clear whether a raw confirmed hypothesis survived counter-review.

## Validation run in this environment

Focused research-side validation passed:

```text
PYTHONPATH=src python -m pytest \
  tests/test_agentic_architecture_guardrails.py \
  tests/test_agentic_evidence_curation.py \
  tests/test_agentic_flow_loop.py::TestQueryableGapFallbackQueries -q
```

Result:

```text
29 passed
```

A broader legacy test subset still contains pre-existing failures because some tests import `vuln_commit_kg.data`, which is not present in this uploaded ZIP environment, and some older mocks expect pre-per-hypothesis stage names such as `02_kg_query_planning` instead of the current `02_kg_query_planning__HYP-01` naming.
