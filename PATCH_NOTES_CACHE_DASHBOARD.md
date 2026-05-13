# Patch: cache/codekg + live dashboard fixes

Changes:
- CodeKG persistent cache now defaults to the repository-level cache tree (`cache/codekg`) instead of `outputs/runs/_codekg_cache`.
- If a config already sets `kg.cache_dir`, that path is honored for persistent CodeKG caches. Your existing `configs/45_...yaml` uses `cache/kg`, so new CodeKG graphs will be stored there unless you change it.
- The live dashboard HTTP server now serves from the project root when possible, so `/current/` can link directly to KG dashboards under `cache/...` and reports under `outputs/runs/...`.
- Fixed frontend crash: `ReferenceError: renderApi is not defined` by restoring `renderApi()` and `renderMetrics()`.
- Sample rows now include `agent_report_url`, so in-progress audit reports can be opened from the live dashboard.

Recommended config:

```yaml
kg:
  cache_mode: persistent
  cache_dir: cache/codekg   # or keep cache/kg if you prefer
  persistent_cache_dir: null
  force_rebuild: false
```

Open the live dashboard at:

```text
http://127.0.0.1:8765/current/
```

Then open `Projects / KG` and click `dashboard` for the relevant project@commit row.
