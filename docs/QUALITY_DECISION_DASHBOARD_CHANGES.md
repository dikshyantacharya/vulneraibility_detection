# Quality decision and live-dashboard changes

This version keeps the classification prompt source-only for the target snapshot. It does not add patch-delta evidence to model-visible classification.

## Main changes

- Strict tri-state final decisions: `vulnerable`, `non_vulnerable`, `inconclusive`.
- Inconclusive and parse-failed predictions are invalid/abstentions in strict metrics, not true negatives.
- Compatibility metrics are still written separately for comparison with older boolean-only runs.
- Vulnerable statements now include `claim_strength`, `why_exploitable`, and `missing_facts`.
- A vulnerable decision requires at least one `confirmed` or `strongly_supported` vulnerable statement.
- Non-vulnerable decisions require concrete ruling-out evidence; unresolved risks become `inconclusive`.
- Post-hoc commit-message audit is report-only and includes snapshot-semantics checks.
- Privacy scan is now stage-aware: pre-decision prompts are checked separately from post-hoc report-only audit prompts.
- Live dashboard is kept alive after `vckg run` completes when `live_dashboard.keep_alive_after_run: true`; stop it with Ctrl+C.

## Recommended next test

Run:

```powershell
vckg run --config configs/29_one_function_academiccloud_api.yaml
```

Expected behavior:

- The command prints the dashboard URL.
- After metrics are written, the terminal remains open and the dashboard remains available.
- Press Ctrl+C after inspecting the dashboard.
- In `metrics.json`, use `metrics.binary.strict` as the primary metric.
- Inspect `decision_status`; a fixed sample with unresolved risk should now be `inconclusive`, not automatically counted as a true negative.
