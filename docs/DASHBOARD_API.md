# Dashboard API reference

Base path: `/api/dashboard`. All responses are JSON. The `mode` query parameter
(`admin` | `student`, default `admin`) controls label/registry masking.

## REST endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | liveness `{ok, service, version}` |
| GET | `/status?mode=` | counts, split/label balance, active jobs, validation flag |
| GET | `/config` | resolved config path + raw YAML content |
| GET | `/settings` | current dashboard settings |
| POST | `/settings` | patch + persist settings |
| GET | `/projects?mode=` | projects (smallest→biggest) |
| GET | `/projects/{id}` | one project |
| GET | `/projects/{id}/functions?mode=` | functions in a project |
| GET | `/functions?mode=` | all candidate functions |
| GET | `/kgs?mode=` | registry kg entries |
| GET | `/kgs/{kg_id}?mode=` | one kg entry |
| GET | `/kgs/{kg_id}/graph?limit=&node_type=&function=` | bounded subgraph + type distributions |
| GET | `/jobs` | all jobs (newest first) |
| GET | `/jobs/{id}` | one job |
| POST | `/jobs` | create a job (see below) |
| POST | `/jobs/{id}/cancel` | terminate a running job (taskkill /T on Windows) |
| POST | `/jobs/{id}/pause` | not supported for subprocess jobs (returns `ok:false`) |
| POST | `/jobs/{id}/resume` | relaunch the same spec (build resumes from cache) |
| GET | `/jobs/{id}/events` | structured event history (JSONL replay) |
| GET | `/jobs/{id}/logs?tail=` | raw stdout tail |
| GET | `/reports/validation` | latest validation report |
| GET | `/reports/evaluation` | metrics from the most recent completed evaluation |
| GET | `/disk` | drive usage + challenge folder size |
| GET | `/leakage` | public-id leakage check |
| GET | `/challenges` | discovered built challenge folders |

## Create a job — `POST /api/dashboard/jobs`

```json
{
  "type": "build_challenge",
  "config_path": "student_system_creator/configs/default.yaml",
  "mode": "selected_functions",
  "project_ids": [],
  "sample_ids": ["18127"],
  "limit": 100,
  "backend": "auto",
  "force_rebuild": false,
  "overwrite": false,
  "dry_run": false
}
```

Job types:

| type | runs | notes |
|------|------|-------|
| `build_challenge` / `build_kg` | `build` | overrides merged into an `effective_config.yaml` |
| `validate_challenge` | `validate-challenge` | writes `validation_report.json` into the job dir |
| `evaluate_solution` | `evaluate` | needs `solution`, `input`, optional `labels`, `api_base` |
| `package_raid` | `package-raid` | `out`, `no_zip`, `overwrite` |
| `serve_kg_api` | `serve` | long-running; cancel to stop |
| `inspect_inventory` | (in-process) | fast read-only snapshot |
| `repair_finalize` / `anonymize_ids` / `clean_unreferenced` | — | recognized but run inside `build_challenge`; rejected as standalone with a clear message |

## WebSocket

| Path | Stream |
|------|--------|
| `WS /ws/dashboard/events` | all jobs |
| `WS /ws/dashboard/jobs/{id}` | one job (history replayed on connect) |

### Event schema

```json
{
  "type": "progress | agent_query | kg_ready | status | log",
  "job_id": "20260609_201501_42a7ae",
  "timestamp": "2026-06-09T20:15:01+00:00",
  "phase": "kg_build | evaluation | validation | packaging | ...",
  "level": "info | success | warning | error",
  "message": "raw log line",
  "data": { "processed": 277, "total": 1178, "ready": 237, "eta_seconds": 2262, "rate_per_minute": 23.9 }
}
```

`progress` events carry `processed/total/ready/skipped/failed/vuln/safe/eta_seconds/rate_per_minute/project/function`.
`agent_query` events carry `kind/nodes/edges/engine_cache_hit/time_seconds` parsed from `eval.query.done` / `api.query.done` lines.
