# Agentic Architecture Round 6: Recall/Precision Balancing

This round addresses the 10-function audit where Round 5 improved several false positives but introduced two false negatives and one remaining false positive.

## Fixes

1. Exact-end parser guard is no longer treated as sufficient safety evidence for pointer wraparound by itself.
   - `raw == end` plus `return -1` is useful, but it only refutes wraparound-to-lower-address traversal when paired with a saved-base lower-bound guard such as `raw >= start`.
   - This prevents vulnerable `count_rows` pre-fix from being marked safe solely because it has an exact-end corruption check.

2. High-signal source patterns can override overconfident safe decisions.
   - If final adjudication says fixed/non-vulnerable but deterministic source facts show an uncovered high-signal pattern, the validator downgrades the safe decision to evidence-incomplete and then forces the binary benchmark prediction according to the high-signal pattern.
   - This is intended to recover vulnerable fixed-size stack-buffer and raw parser pointer-advance cases.

3. Shifted-bounds fixed patch false positive is suppressed more strongly.
   - When `shifted_extra_bounds_guard` is present, remaining `oldpos`, `z`, `origData`, and tuple-control concerns are treated as residual unless separately proven.
   - This prevents the fixed `patch` version from being marked vulnerable for a residual oldpos/z concern after the target extra-block bounds-check patch is present.

## Regression tests

Added tests in `tests/test_agentic_architecture_guardrails.py` for:

- exact-end guard alone does not refute `count_rows` pointer wraparound;
- fixed-size buffer high-signal pattern overrides an overconfident safe decision;
- shifted extra-block bounds guard suppresses the fixed `patch` oldpos/z residual false positive.

## Verification in trimmed sandbox

- `tests/test_agentic_architecture_guardrails.py`: 14/14 passed.
- Modified Python files compiled cleanly.

The broader suite could not be run in the trimmed upload because `src/vuln_commit_kg/data` is intentionally absent.
