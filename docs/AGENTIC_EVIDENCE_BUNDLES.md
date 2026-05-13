
## Local versus API prompt profiles

The agent now supports `agent.prompt_profile`:

- `local_budgeted`: compact prompts for local llama-server / GGUF runs with small context windows such as `n_ctx=8192`.
- `api_rich`: richer prompts for paid API models with larger context windows. This keeps more source, bundle evidence, trace summaries, and repair context.
- `auto`: chooses `local_budgeted` for small-context `llama_server` runs and `api_rich` otherwise.

The two-project local calibration config uses `local_budgeted`. The OpenAI-compatible API template uses `api_rich`.

JSON parsing is also hardened for local models that emit JSON-like text with invalid escapes such as regex fragments. The parser now attempts deterministic salvage before asking the model for repair, and model/API transport errors are recorded instead of crashing a sample.
