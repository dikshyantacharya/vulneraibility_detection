# Live dashboard and quality-audit upgrade

This version keeps the quality-first agentic setting. It does not reduce `max_rounds`, tool queries, or evidence counts for API runs.

## Main changes

1. **Live dashboard now receives real-time state updates**
   - queued samples
   - running samples
   - API queued/waiting/in-flight/done/error states
   - quota counters from the shared limiter
   - model stage, prompt size, JSON status, parse errors, token/cost updates
   - KG build/load status and graph size
   - report links as soon as a sample finishes

2. **API request coordination remains shared across parallel workers**
   - one shared model object is used in API-parallel mode
   - rate-limit state is persisted under `cache/api_rate_limits`
   - request events are streamed into the dashboard

3. **Final parse failures are no longer treated as ordinary true negatives**
   - final parse failure now receives `decision_status = parse_failed`
   - binary metrics separate valid predictions from invalid/inconclusive predictions
   - `accuracy_all_invalid_as_wrong` is reported for conservative accounting

4. **Agent demo reports now include final reasoning and commit-message audit**
   - final public reasoning summary
   - report-only commit message
   - post-hoc LLM audit checking whether the model reasoning semantically/factually matches the commit message
   - `posthoc_commit_audit.json` artifact

5. **JSON repair was strengthened**
   - repair prompts may shorten oversized arrays instead of preserving impossible/truncated output
   - final prompt asks for at most 12 `evidence_used` IDs and at most 3 vulnerable statements

## Important methodological boundary

The post-hoc commit audit is report-only. It runs after the binary decision and may see commit metadata. It does not change the prediction, metrics, or retrieval.

## Recommended command

```powershell
$env:ACADEMICCLOUD_API_KEY="<your-key>"
vckg run --config configs/29_one_function_academiccloud_api.yaml
```

Open the printed dashboard URL immediately. It polls `state.json` every second, so no manual refresh is needed.
