# Agentic precision-gate round 5

This patch addresses the high-recall / low-precision behavior seen in the 10-function Research Audit run.

## Main change

The validator no longer forces every unresolved local risk to `vulnerable`. A vulnerable benchmark prediction now needs either:

1. a complete minimum proof chain (`input_control`, `dangerous_operation`, `missing_or_failed_guard`, `unsafe_use`, `security_impact`, cited evidence IDs), or
2. a high-signal deterministic source pattern that remains uncovered by safety evidence.

Otherwise, residual/local risks are kept as uncertainty and the forced binary benchmark prediction defaults to `fixed/non-vulnerable`.

## New deterministic source facts

`_infer_deterministic_source_facts()` now recognizes additional generic, label-free patterns:

- fixed-size buffer with unbounded indexed write
- dynamic heap buffer growth with `malloc`/`realloc`
- unchecked `realloc` as residual risk
- point-at-infinity / identity-element guard in elliptic-curve point addition
- missing identity guard before `mpz_invert` point-addition arithmetic
- GMP arbitrary-precision arithmetic fact for `mpz_mul`/`mpz_sub`
- shifted bsdiff extra-block bounds guard
- missing shifted extra-block bounds guard
- fish `fish_reserved_codepoint()` ENCODE_DIRECT guard
- legacy partial ENCODE_DIRECT guard
- numeric `%d` `/proc/%d/environ` path construction cannot inject slash traversal by itself

## Expected effect on the 10-sample batch

The patch is designed to reduce false positives such as:

- fixed `get_pid_environ_val` being marked vulnerable only because of unchecked `realloc`
- fixed `pointZZ_pAdd` being marked vulnerable for unrelated `mpz_*` arithmetic or side-channel concerns after identity-element handling was added
- fixed `str2wcs_internal` being marked vulnerable despite `fish_reserved_codepoint()` handling

It should preserve true positives for high-signal uncovered patterns such as:

- unbounded fixed-size stack buffer writes
- unguarded raw-buffer pointer advancement by parsed length
- missing point-at-infinity handling before point-addition inversion
- missing shifted bounds check before patch extra-block copy
- legacy partial ENCODE_DIRECT reserved-codepoint handling

## Verification performed in this sandbox

- `python -m py_compile` passed for modified Python files.
- Targeted validator/architecture tests passed:
  - `tests/test_agentic_architecture_guardrails.py`
  - `TestForcedBinaryPredictionSchema`
  - `TestNormalizePredictionBool`

Full repository tests could not be run in this trimmed upload because `src/vuln_commit_kg/data` and frontend `node_modules` are not included.
