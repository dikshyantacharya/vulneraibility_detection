# Agentic architecture improvements — pointer-wrap safety and binary forcing

This update addresses a paired pre-fix/post-fix `count_rows` failure pattern where
both samples were predicted vulnerable because unresolved local pointer-arithmetic
risk was forced to the vulnerable class.

## Changes

1. **Deterministic source facts**
   - Adds label-free source facts for pointer-advance operations.
   - Detects saved-base lower-bound guards such as `start = raw` plus `raw >= start`.
   - Detects exact-end success/error-return patterns such as `if (raw == end) return ...; return -1;`.

2. **Validator policy**
   - Rejects “confirmed” proofs whose proof fields still say attacker control is unproven or merely plausible.
   - If all unresolved local risks are pointer-wraparound-like and deterministic source facts show a lower-bound pointer guard plus exact-end error return, forced binary output becomes `fixed/non-vulnerable` rather than defaulting to vulnerable.
   - Confirmed pointer-wraparound claims are rejected when they do not explain how the deterministic guard is bypassed.

3. **CodeKG query normalization**
   - Normalizes LLM aliases such as `direction="incoming"` and `direction="callers"` to CodeKG's accepted `direction="in"`.
   - Normalizes `direction="outgoing"` / `"callees"` to `direction="out"`.

4. **Prompt clarifications**
   - Verification, counter-review, and final-adjudication prompts now explicitly treat deterministic source facts as source-grounded evidence.
   - They clarify that saved-base pointer guards plus exact-end error returns can refute pointer-wraparound traversal hypotheses, but only for that risk class.

## Rationale

The pre-fix `count_rows` version has unchecked pointer advancement and no lower-bound wraparound guard. The post-fix version saves the starting pointer and requires the advanced pointer to remain above it; this is a meaningful source-level guard for the specific overflow-to-lower-address traversal problem described by the patch. The update is generic and does not use labels, commit messages, sample ids, or project metadata in model prompts.
