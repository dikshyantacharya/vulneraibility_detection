# Research Agentic Proof-Ledger Upgrade — 2026-06-22

This patch fixes the proof-obligation semantics exposed by the latest `count_rows` report.

## Main corrections

1. **Negative safety obligations are polarity-aware.**
   Obligations such as `missing_remaining_bound_guard`, `missing_guard_or_invariant`, and `missing_domain_guard` now support the vulnerability when the required guard is absent. A concrete dominating guard is required to refute the hypothesis.

2. **Parser traversal obligations are split more cleanly.**
   The previous `parsed_value_origin` obligation mixed local parsing with attacker control. It is now split into:
   - `parsed_value_from_buffer`
   - `trust_boundary_or_external_input`

3. **Atomic local facts are deterministically reduced.**
   The reducer now recognizes common C/parser facts from source:
   - `length = read(raw)` proves local parsed value from buffer.
   - `raw += length * itemsize` proves scaled state advancement.
   - a loop with `read(raw)` and later `raw += ...` proves next-iteration parser-state use.
   - absence of a product/remaining-space guard supports missing-guard obligations.

4. **The LLM prompt explicitly explains obligation polarity.**
   The micro-verifier is told that for missing-guard obligations, “missing guard” means `proven`, not `refuted`.

5. **Proof-ledger trace now records polarity interpretation.**
   Each obligation ledger update includes:
   - `supports_hypothesis`
   - `refutes_hypothesis`
   - `result_meaning`

6. **Function-pointer/callee-resolution capsules are improved.**
   The `callee_value_range` evidence selector now prioritizes resolver chains and dispatch tables such as:
   - `choose_int_read`
   - `_choose_int_read_write`
   - `int_readers`
   - `ordinal`
   - `list[ordinal]`

## Expected effect on the latest `count_rows` run

The previous report incorrectly treated “no guard exists for `length * itemsize`” as `refuted_by_guard`. With this patch, that obligation should be normalized as vulnerability-supporting evidence. HYP-01 should no longer be marked as refuted merely because the required safety guard is absent.

A clean confirmation may still depend on whether caller/context evidence proves the trust boundary, but the proof ledger should now represent the local parser-traversal chain correctly instead of inverting it.
