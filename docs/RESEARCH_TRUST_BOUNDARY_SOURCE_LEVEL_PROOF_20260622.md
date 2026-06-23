# Research patch: trust-boundary tiers and source-level parser proof

This patch upgrades the research-side agentic vulnerability pipeline after the
latest `count_rows` report.

## Why this patch exists

The previous proof-obligation ledger correctly proved the local parser traversal
chain:

- a parsed value is read from the input buffer,
- that value controls `raw += length * itemsize`,
- no dominating remaining-space/product-overflow guard exists,
- the advanced parser state is reused in a later loop iteration.

However, the hypothesis still ended as `high_signal_incomplete` because the
`trust_boundary_or_external_input` obligation required explicit caller/public
entry-point evidence. In parser/deserializer code, comments and source context
such as `data fed to loads()` are strong source-level trust-boundary evidence,
even when caller reachability remains a stricter exploitability tier.

## Main changes

1. Added `proof_tier` and `trust_boundary_strength` to `HypothesisProofLedger`.
2. Added generic parser/deserializer trust-boundary recognition for source-level
   proof. Examples include load/loads/parse/deserialize/decode/malformed/corrupt
   input context.
3. Kept caller-proven reachability separate from source-level parser context:
   - `confirmed_source_level_vulnerability`
   - `confirmed_reachable_vulnerability`
4. Improved trust-boundary capsule selection so `trust_boundary_or_external_input`
   prefers caller/public parser/load/deserializer code and comments over generic
   loop or pointer snippets.
5. Added explicit retrieval accounting fields to controller events:
   - `kg_returned_items`
   - `accepted_new_evidence_items`
6. Kept `callee_value_range` optional for `parser_scaled_pointer_traversal`; lack
   of concrete reader target bodies remains useful diagnostic uncertainty, but it
   should not block confirmation when the required parser traversal obligations
   are proven.

## Expected effect on the next report

For the `count_rows` case, if the ledger again proves the four local obligations
and sees source-level parser context such as `RaggedArray.loads()`, HYP-01 should
move from:

```text
status_hint = high_signal_incomplete
proof_tier = high_signal_incomplete
```

to:

```text
status_hint = source_level_complete
proof_tier = confirmed_source_level_vulnerability
trust_boundary_strength = source_level
```

The final decision may now show:

```text
decision_status = confirmed_source_level_vulnerable
evidence_strength = confirmed_source_level
```

if no local counter-review refutes the hypothesis.

## Scope

This patch is generic for C/C++ parser/deserializer-style code. It does not use
benchmark labels or commit-message facts to confirm vulnerabilities.
