# AcademicCloud / SAIA API preflight and model fallback

The AcademicCloud/SAIA API is OpenAI-compatible, but the public model list changes over time. A run can fail with HTTP 404 when the configured model name is no longer exposed by the API even though the `/v1/chat/completions` endpoint itself is correct.

This project now performs an API preflight before the agent loop starts when `model.backend: openai_compatible` and `model.api_preflight: true`.

The preflight:

1. checks that the API key environment variable exists;
2. queries `/v1/models` using both GET and POST, because some SAIA documentation examples use POST;
3. verifies that `model.model_name` is available;
4. falls back to the first available entry from `model.model_fallbacks`;
5. fails early with the available model names if no configured model can be found.

Recommended AcademicCloud config fields:

```yaml
model:
  backend: openai_compatible
  api_base: https://chat-ai.academiccloud.de/v1
  api_key_env: ACADEMICCLOUD_API_KEY
  model_name: qwen3-coder-30b-a3b-instruct
  model_fallbacks:
    - qwen3-coder-30b-a3b-instruct
    - qwen2.5-coder-32b-instruct
    - codestral-22b
    - llama-3.3-70b-instruct
    - meta-llama-3.1-8b-instruct
  api_preflight: true
  request_json_object: false
```

`request_json_object` is disabled for AcademicCloud configs because not every OpenAI-compatible provider supports OpenAI's `response_format={"type":"json_object"}` parameter. The project still requests JSON through the prompt and validates/repairs/parses the response itself.

Before running:

```powershell
$env:ACADEMICCLOUD_API_KEY="your_key_here"
vckg run --config configs/29_one_function_academiccloud_api.yaml
```

If the provider model list changes, edit only `model.model_name` or `model.model_fallbacks` in the config.
