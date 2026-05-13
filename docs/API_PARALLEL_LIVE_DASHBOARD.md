# API mode, local mode, quotas, and live dashboard

This project now separates local and API execution:

- `agent.prompt_profile: local_budgeted` keeps prompts compact for local llama-server/GGUF context windows.
- `agent.prompt_profile: api_rich` preserves much richer target source, KG evidence, and trace summaries for large-context API models.

AcademicCloud/OpenAI-compatible configs are included:

```powershell
$env:ACADEMICCLOUD_API_KEY="<your key>"
vckg run --config configs/29_one_function_academiccloud_api.yaml
vckg run --config configs/30_smallest_pair_academiccloud_api.yaml
vckg run --config configs/31_two_small_projects_academiccloud_api.yaml
```

API quota scheduling is config-driven:

```yaml
api_quota:
  enabled: true
  requests_per_minute: 10
  requests_per_hour: 200
  requests_per_day: 400
  requests_per_month: 3000
  max_concurrent_requests: 4
```

The scheduler is shared across all parallel sample workers. It persists rolling timestamps in `cache/api_rate_limits/` and does not store API keys. HTTP 429/5xx-like errors are retried with exponential backoff.

The live dashboard is created when the run starts:

```text
outputs/runs/<run>/live_dashboard/index.html
```

With `live_dashboard.serve: true`, the run log also prints a localhost URL. The page polls `state.json` every second and shows project/KG progress, sample progress, TP/FP/TN/FN filtering, API quota usage, tokens, cost, recent events, and links to per-sample agent demos.
