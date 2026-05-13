# API parallel classification threadsafe fix

This patch implements `CommitKGPipeline._classify_one_sample_threadsafe`, which is used when:

```yaml
model:
  backend: openai_compatible
execution:
  parallelize_api_samples: true
  api_classification_max_workers: 4
```

The previous build entered `api.parallel_classification` and attempted to submit this method to the thread pool, but the method was missing. The run stopped with:

```text
ERROR: 'CommitKGPipeline' object has no attribute '_classify_one_sample_threadsafe'
```

The new method mirrors the sequential classification path for one sample while keeping shared JSONL writes behind `self.write_lock`. The shared model object is intentionally reused so the API request limiter coordinates requests across all concurrent samples.

Agent calls inside one function remain sequential because each hypothesis/verification step depends on the previous step. Different samples/functions can run concurrently, subject to the configured API quotas.
