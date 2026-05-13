# Local llama-server error fixes and prompt-budgeting changes

This project version fixes the runtime failure pattern seen in the bundle-based agent run:

- `HTTPError: 400 Client Error` from `llama-server` during final decision consistency repair.
- Large prompts after multiple bundle rounds exceeding an 8k context window.
- Model parse/schema failures causing fallback loops with very large repair prompts.
- Samples crashing instead of producing an auditable inconclusive prediction.

## Main fixes

1. **Prompt budgeting**
   - Follow-up prompts now receive compact ledger summaries, not the full trace.
   - Final prompts include only high-value evidence plus a compact risk/guard audit.
   - JSON repair prompts and final consistency-repair prompts are bounded and much smaller.

2. **Graceful model-call error handling**
   - Model/API errors are recorded in `model_calls.jsonl` and the agent trace.
   - A failed model call no longer crashes the sample.
   - If generation fails, the agent returns an inconclusive fallback prediction according to the parse-error policy.

3. **Agentic evidence bundles**
   - Stage 1 now asks the model for hypothesis-driven `evidence_bundle` requests.
   - The orchestrator expands these into deterministic KG evidence slices.
   - Supported bundle concepts include buffer writes, callees, globals/macros, caller context, lifetime, format-string, integer, path/input validation.

4. **New KG cache version**
   - Configs now use `project_v4_agentic_bundle_budgeted_cpg_overlay` to avoid reusing older bundle/KG caches.

## What to check after running

Open:

```text
outputs/runs/<latest>/agent_demos/index.html
```

For each sample, inspect:

- `01_source_only_hypothesis`
- `kg_tool_round_*`
- `bundle_type`, `symbol`, `category_counts`, `returned_evidence_ids`
- `final_decision`
- whether any `model_error` appears in model call artifacts

A local Qwen model may still reason incorrectly, but this version should not crash simply because a repair/final prompt exceeds the local server context.
