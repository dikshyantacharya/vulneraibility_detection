# Agentic-proof reporting and failure-debug improvements

This build updates the agent demo report for `agent.mode: agentic_proof`.

## What changed

- The per-sample agent demo now contains an `Agentic-proof workflow overview` section with one row per real model stage.
- Each row shows stage name, JSON/parse status, parse error, wall time, prompt chars, prompt tokens, completion tokens, total tokens, cost, and a raw-response preview.
- Each LLM stage section now shows:
  - exact model-visible prompt,
  - raw LLM response,
  - extracted public `<analysis>` tag,
  - extracted `<answer>` JSON text,
  - parsed/validated JSON payload,
  - repair prompt/response/parsed result when repair was used,
  - provider raw metadata and usage.
- Agentic-proof parse results are now bridged into the legacy `model_calls.jsonl` report rows, so `raw_agentic_proof_pending_parse` is replaced by `json_ok`, `json_repaired`, or `parse_failed` once the parser has run.
- Failed agentic-proof samples now save a debug report before the exception is re-raised to the pipeline. This report shows the last successful prompt/response and the parse/provider error that caused the sample failure.
- Partial live reports are rewritten after every agentic-proof model call, so the dashboard `open` report link becomes useful while the sample is still running.

## Timing interpretation

Stage `elapsed_seconds` is wall-clock time around the model call. It can include local rate-limit waiting, HTTP/network time, provider queueing/generation, provider timeout, and fallback-model attempts. In sequential runs with no local queue, very long stages are usually provider/server-side delay or fallback after a provider timeout, not KG construction or local parsing.
