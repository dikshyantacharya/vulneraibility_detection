# Research-side proof-tier state alignment patch — 2026-06-23

This patch upgrades the agentic CodeKG + LLM vulnerability-audit architecture after the latest `count_rows` report showed a contradiction:

- the proof-obligation ledger reached `confirmed_source_level_vulnerability`,
- local counter-review downgraded it to `plausible_but_unproven`, and
- final validation emitted `forced_binary_vulnerable / insufficient_static_evidence`.

The fix is to make proof tiers first-class controller state rather than free-text hints.

## Main changes

1. **First-class proof tier fields**
   - `HypothesisVerification` now carries:
     - `proof_tier`
     - `trust_boundary_strength`
     - `accepted_confirmed`
   - Later stages no longer need to scrape these from explanations.

2. **Tier-aware counter-review**
   - `confirmed_source_level_vulnerability` is preserved unless counter-review cites concrete same-operation counter-evidence.
   - Missing stricter caller/I/O evidence may prevent reachable confirmation, but it no longer erases source-level confirmation.

3. **Final validator consumes proof tiers**
   - A source-level confirmed hypothesis maps to:
     - `decision_status = confirmed_source_level_vulnerable`
     - `evidence_strength = confirmed_source_level`
   - A reachable confirmed hypothesis maps to:
     - `decision_status = confirmed_vulnerable`
     - `evidence_strength = confirmed`

4. **Family assignment is hypothesis-first**
   - The controller no longer assigns every hypothesis to `parser_scaled_pointer_traversal` merely because the target source contains `raw += length * itemsize`.
   - New more precise families:
     - `parser_scaled_pointer_traversal`
     - `callee_return_signedness_or_value_range`
     - `selector_shift_domain_or_dispatch_bounds`

5. **Family-specific proof obligations**
   - Signedness/read-return hypotheses require callee/function-pointer resolution and return-range evidence.
   - Selector/shift hypotheses require selector-origin, shift/dispatch-expression, domain-guard, and invalid-selector effect obligations.
   - Parser pointer traversal keeps the proven source-level parser-pointer proof template.

6. **More aggressive deterministic reducers**
   - Missing-guard obligations are normalized after every LLM micro-result.
   - If the LLM says `refuted` while explaining that no dominating guard exists, the controller converts it to vulnerability-supporting `proven`.
   - Obvious C/parser patterns are resolved deterministically when possible.

7. **Prompt alignment**
   - Counter-review now explicitly distinguishes missing stricter reachability evidence from concrete refutation.
   - Final adjudication is told to preserve proof-tier outputs instead of collapsing them into forced binary status.

## Expected effect on the latest count_rows run

HYP-01 should no longer be downgraded by counter-review unless concrete counter-evidence is found. A source-level-complete HYP-01 should remain accepted and should produce:

```text
accepted_confirmed = true
proof_tier = confirmed_source_level_vulnerability
decision_status = confirmed_source_level_vulnerable
evidence_strength = confirmed_source_level
```

For binary benchmark mode, this should stop the per-hypothesis loop after HYP-01. For stricter reachability mode, this still leaves room to continue searching for caller/public-entry proof.
