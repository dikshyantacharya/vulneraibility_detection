# Scaling analysis and projection layer

This layer is intentionally separate from KG design, retrieval parameters, and prompts. It measures the current pipeline as-is, then produces numeric artifacts, figures, and a dashboard for local/API scaling decisions.

## New configs

- `configs/27_two_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml`
  - selects one vulnerable/fixed pair from each of two small projects;
  - runs the current iterative agent;
  - writes per-function agent demos plus a scaling dashboard.
- `configs/28_five_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml`
  - same procedure, but for five small projects.

Both use:

```yaml
dataset:
  sample_selection: smallest_vuln_fixed_pairs_by_project
  project_selection: smallest_dataset
  project_limit: 2   # or 5
```

This gives a controlled calibration path: 2 projects → 5 projects → 50 projects → full dataset.

## Cost configuration

The model config already supports separate input/output prices:

```yaml
model:
  cost:
    input_per_1k_usd: 0.0
    output_per_1k_usd: 0.0
```

For local llama-server runs, keep this at zero or set hypothetical API prices to estimate future cost. When using llama-server/OpenAI-compatible APIs that return usage, provider usage is preferred and `estimated=false` is recorded.

## New run artifacts

Each run now writes:

- `sample_runtime.jsonl` — per-function timing, prediction correctness, tokens, cost, evidence counts, model-call counts, KG-tool counts.
- `project_runtime.jsonl` — per project/snapshot clone status, mirror size, worktree size, KG status, KG wall time, KG cache size, nodes/edges/files/functions/statements.
- `scaling_analysis/index.html` — dashboard with figures, projections, and a filterable prediction browser.
- `scaling_analysis/summary.json` — aggregate runtime, token, cost, and score summary.
- `scaling_analysis/sample_predictions.csv` — one row per target function.
- `scaling_analysis/project_runtime.csv` — one row per project snapshot / KG.
- `scaling_analysis/model_call_usage.csv` — one row per LLM call stage.
- `scaling_analysis/projection_estimates.csv` and `.json` — linear projections for configured sample/project counts.
- `scaling_analysis/figures/*.png` — runtime, project/KG size, token, cost, and projection plots.

The existing per-sample agent reports remain under:

```text
outputs/runs/<run>/agent_demos/sample_<id>_<function>/index.html
```

The new dashboard links to those reports so false positives/false negatives can be inspected manually.

## Suggested local sequence

After starting llama-server, run:

```powershell
vckg run --config configs/27_two_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml
```

Then open:

```text
outputs/runs/<latest-run>/scaling_analysis/index.html
```

After that, scale to five projects:

```powershell
vckg run --config configs/28_five_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml
```

If you later want to refresh plots/dashboard from an existing run:

```powershell
vckg visualize --run-dir outputs/runs/<run>
```

## Interpreting projections

The projections are linear extrapolations from the observed run. They are useful as early budgeting estimates, not as final guarantees. Recalibrate after each scale step because large repositories such as Linux can dominate clone size, KG build time, and cache size.
