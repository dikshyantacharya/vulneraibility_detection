# Architecture

## Correct unit of context

The target function is **not** the source of the KG. The target function is a query anchor inside a project-level KG built from the repository snapshot at the dataset commit.

```text
sample(project_url, commit_id, filepath, func_name)
  -> bare repo cache
  -> immutable worktree at commit_id
  -> project-level KG cache
  -> target function locator
  -> target-centered evidence pack
  -> agentic LLM classifier
  -> binary-first evaluation
```

## Cache keys

The framework avoids repeated cloning and graph construction.

```text
repo cache:      project_url
worktree cache:  project_url + commit_id
kg cache:        project_url + commit_id + kg.version + kg.config_hash
```

## KG contents in v1

`project_v1_regex_callgraph` creates:

- Project nodes
- Commit nodes
- File nodes
- Function nodes
- Statement nodes
- CallExpression nodes
- SecurityRisk nodes
- SafetyCheck nodes

Edges include:

- `PROJECT_AT_COMMIT`
- `COMMIT_HAS_FILE`
- `FILE_HAS_FUNCTION`
- `FUNCTION_HAS_STATEMENT`
- `STATEMENT_CALLS`
- `FUNCTION_CALLS_NAME`
- `FUNCTION_CALLS_FUNCTION`
- `STATEMENT_HAS_RISK`
- `STATEMENT_HAS_SAFETY_CHECK`

## Agent modes

`single_pass`:

```text
target function + evidence pack -> final JSON prediction
```

`iterative`:

```text
target function + evidence -> structured hypotheses and KG query requests
hypotheses + evidence -> final JSON prediction
```

The project logs structured reasoning artifacts, not private chain-of-thought.

## Model backends

- `mock`: deterministic heuristic backend for smoke tests and cost-free pipeline checks
- `openai_compatible`: any `/chat/completions` API with an environment variable key
- `gguf`: `llama-cpp-python` with optional Hugging Face or direct GGUF download
- `hf`: `transformers` with optional Hugging Face snapshot download

## Evaluation priority

1. Binary classification
2. Statement localization
3. Evidence/reasoning diagnostics
4. Runtime, memory, token, and cost accounting
