# Round 9: Run-level full-flow report bundles

This round adds run-level report ZIP downloads for Research Audit runs.

## New API

`GET /api/research/runs/{run_id}/flow/reports.zip?scope=completed`

Downloads a ZIP containing only per-sample full-flow reports for samples that
have a completed binary prediction (`vulnerable` or `safe`). Running, failed,
skipped, and pending samples are excluded. The bundle includes a `manifest.json`
listing included and excluded samples.

`GET /api/research/runs/{run_id}/flow/reports.zip?scope=all`

Downloads every available per-sample report artifact for the run, including
completed, skipped, failed, running, and partial samples when their sample
directory exists. The bundle includes a `manifest.json` and `README.txt`.

## Dashboard UI

The Research Audit → Runs page now shows two buttons on each run card:

- **Download completed reports ZIP**
- **Download all reports ZIP**

The existing per-sample report downloads remain unchanged.

## Notes

The ZIP generator uses the same sanitized `flow_report()` text as the existing
single-sample download, so secrets remain masked. It does not call the LLM and
does not alter audit artifacts.
