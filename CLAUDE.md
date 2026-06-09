# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Vuln Commit KG** is a commit-aware project-level knowledge graph with an agentic LLM framework for detecting vulnerabilities in source code. The system:

1. **Builds project-level KGs**: Uses CodeKG (integrated) or Joern backends to construct whole-project knowledge graphs at specific commits
2. **Retrieves evidence**: Queries KGs to find source-grounded context around target functions
3. **Runs agentic classification**: Uses LLM agents to reason over evidence and classify vulnerability status
4. **Evaluates at scale**: Supports single functions, multiple projects, and dataset-wide runs with cost/timing tracking

The architecture supports multiple LLM backends (OpenAI, local GGUF via llama-server, Hugging Face transformers) and is configured through YAML files for reproducibility and scaling.

## Core Architecture

```
dataset (SecVulEval Arrow) → project selection → repository clone (git worktree)
                          ↓
                    KG build (CodeKG or Joern)
                          ↓
                    evidence retrieval (source-grounded KG queries)
                          ↓
                    agentic LLM classification (reasoning + evidence)
                          ↓
                    evaluation (metrics, artifacts, live dashboard, reports)
```

### Key modules:

- **`src/vuln_commit_kg/`**: Main orchestration, CLI, config, logging
  - `cli.py`: Entry point for `vckg` and `codekg` commands
  - `config.py`: YAML schema and defaults
  - `orchestration/`: Run coordinator, sample resolution, pipeline stages
  - `kg/`: CodeKG builder, extractors, backends (tree-sitter, heuristic, Joern)
  - `retrieval/`: KG query execution, evidence slicing
  - `agents/`: LLM agent loop, JSON repair, structured reasoning
  - `evaluation/`: Metrics, binary classification scoring
  - `repos/`: Git operations, snapshot validation, worktree lifecycle

- **`src/codekg/`**: Vendored CodeKG project for knowledge graph construction, query, and visualization

- **`src/student_system_creator/`**: Challenge generation, student submission evaluation, controlled agent loop

- **`tests/`**: 25+ test files covering extractors, parsers, target validation, agent tracing, KG caching, dataset loading

- **`scripts/`**: Helper utilities for scanning projects, validating challenges, checking configurations

## Common Development Tasks

### Install and setup
```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

pip install -e ".[arrow,dev]"  # arrow for dataset, dev for tests + ruff
pip install -e ".[arrow,hf]"   # Hugging Face transformers models
pip install -e ".[arrow,gguf]" # llama.cpp GGUF support
```

### Run tests
```bash
pytest                           # All tests
pytest tests/test_extractors.py  # Single test file
pytest tests/ -k target_validation  # Filter by keyword
pytest --co                      # List all test functions
```

### Lint and format
```bash
ruff check src/ tests/           # Check style
ruff format src/ tests/          # Auto-format
ruff check --fix src/ tests/     # Fix auto-fixable issues
```

### Validate installation
```powershell
# Quick smoke test (no clone, no real model)
vckg run --config configs/00_smoke_mock.yaml

# Check CodeKG/Joern setup
codekg doctor --joern-home tools\joern-cli
vckg joern-doctor
```

### First real runs (recommended order)
```powershell
vckg run --config configs/01_one_function_project_commit_mock.yaml
vckg run --config configs/02_five_functions_same_project_mock.yaml
vckg validate-targets --config configs/01_one_function_project_commit_mock.yaml  # Before KG build
vckg build-kg --config configs/01_one_function_project_commit_mock.yaml
```

### Build and inspect KGs locally
```powershell
codekg build --source "C:\path\to\project" `
  --out outputs\manual_codekg `
  --backend auto `
  --joern-home tools\joern-cli `
  --open

codekg query --graph-dir outputs\manual_codekg `
  --kind security_context `
  --target-function count_rows `
  --depth 3 `
  --write-dashboard
```

### Inspect live run outputs
Run outputs are written to `outputs/runs/<timestamp>__<experiment_name>/`:
- `resolved_config.yaml`: Full merged config with defaults
- `run.log`: Structured logs (timestamps, progress, errors)
- `samples.jsonl`: Sample metadata and resolution
- `predictions.jsonl`: LLM predictions (binary, raw_reasoning, evidence_summary)
- `evidence_packs.jsonl`: Retrieved KG evidence for each sample
- `agent_traces.jsonl`: Full agent loop traces (prompts, model responses, JSON repair)
- `metrics.json`: Binary classification metrics (TP, FP, FN, TN, F1, precision, recall)
- `figures/`: Confusion matrix, token usage, performance charts
- `agent_demos/`: Interactive HTML reports per sample with full reasoning
- `dashboard/`: Live CodeKG visualization if `open_dashboard: true`

### Student challenge workflow
```bash
# Build a challenge from cached datasets/repos/KGs
student-system-creator build --config student_system_creator/configs/default.yaml

# Serve private CodeKG graphs via API
student-system-creator serve \
  --registry outputs/student_challenge/vckg_codekg_student_challenge/private/kg_registry_private.json \
  --host 127.0.0.1 --port 8000

# Evaluate a student solution against test cases with budget control
student-system-creator evaluate \
  --solution outputs/student_challenge/vckg_codekg_student_challenge/public/student_kit/solution.py \
  --train outputs/student_challenge/vckg_codekg_student_challenge/public/train.csv \
  --input outputs/student_challenge/vckg_codekg_student_challenge/public/test.csv \
  --labels outputs/student_challenge/vckg_codekg_student_challenge/private/test_labels.csv \
  --api-base http://127.0.0.1:8000 \
  --out outputs/student_eval/demo
```

## Configuration and Workflow

Runs are **config-driven**. Most YAML config files are in `configs/`:

- `00_smoke_mock.yaml`: Quickest smoke test
- `01_one_function_project_commit_mock.yaml` - `09_auto_small_project_mock.yaml`: Single/few function/project configs with explicit small projects
- `10_one_function_fast_source_only_mock.yaml`: Headers excluded for speed
- `14_validate_smallest_vuln_fixed_pair.yaml`, `13_smallest_vuln_fixed_pair_mock.yaml`: Minimal vulnerable/fixed pair
- `45_curriculum_*`, `46_curriculum_*`: Full agentic reasoning configs with Joern/Qwen
- `24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml`: 7B Qwen Q8 external server mode
- `27_two_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml`: Scaling analysis dashboard

Key config sections:

```yaml
dataset:
  project_selection: explicit | smallest_dataset | random | first
  project_include: ["didiwiki"]
  project_exclude: ["linux", "Chrome"]

snapshot:
  commit_resolution: secvuleval_patch  # vulnerable rows use patch parent
  on_validation_failure: warn | fail
  body_match_threshold: 0.82

kg:
  use_codekg: true | false
  backend: auto | joern | tree-sitter | heuristic
  joern_home: null | "tools/joern-cli"
  cache_mode: persistent | run_local
  force_rebuild: false

retrieval:
  retrieval_max_nodes: 520
  retrieval_depth: 3
  call_depth: 2
  data_depth: 4
  include_headers: true
  include_globals: true
  include_joern: true

model:
  backend: mock | openai_compatible | gguf | hf | llama_server
  model_name: "gpt-4-mini" | "Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF"
  api_base: "https://api.openai.com/v1"
  api_key_env: "LLM_API_KEY"

prompting:
  include_orchestration_metadata_in_model_prompt: false
  include_cwe_hints_in_model_prompt: false
```

When scaling from a single function to the full dataset, only the config changes—the code path remains the same.

## Key design decisions

1. **Commit resolution semantics**: SecVulEval patch semantics treat vulnerable rows (pre-fix code) and fixed rows (post-fix code) differently. Vulnerable samples use the first parent of the patch commit to ensure the vulnerable code is present.

2. **Source-grounded evidence, not classification**: The KG retriever produces evidence slices; the LLM agent distinguishes retrieved facts from inference vs. missing context.

3. **Structured reasoning traces**: Agent prompts, model responses, JSON repairs, and accepted queries are saved—not hidden in chain-of-thought.

4. **KG backend modularity**: Tree-sitter → Joern → llama-server for local KG inspection, but CodeKG is the integrated default. All backends store artifacts in the same directory layout.

5. **Immutable worktrees for reproducibility**: Each commit is checked out into a worktree and never modified. Clones are bare mirrors; worktrees are created on demand and recovered if interrupted.

## Debugging and observability

- **KG-build progress**: During pipeline runs, console and `run.log` show file discovery, parsing progress, ETA, memory, node/edge counts, and slow-file warnings.

- **Target validation artifacts**: If `on_validation_failure: warn`, mismatches are logged but the run continues. Check `target_validation_artifacts/` for side-by-side comparisons and token-sequence diffs.

- **Agent traces**: Each sample's `agent_demos/sample_<id>/` folder contains all model prompts, responses, JSON repairs, and final parsed queries. Search these to verify privacy (no CVE/CWE hints, no internal URLs if disabled).

- **Failed samples**: `failed_samples.jsonl` ties each failure to a sample_id, project, commit, filepath, and pipeline stage.

- **Live dashboard**: If run on a machine with a browser, `outputs/runs/<run>/dashboard/index.html` or the short URL (e.g. `http://127.0.0.1:8765/current/`) shows project status, KG links, and live progress.

## Joern and CodeKG backends

**Joern (semantic enrichment)**: Place `joern-cli/` in `tools/` and run:
```powershell
vckg joern-doctor
vckg build-project-kg --source C:\path --out outputs\kg --backend joern --target-function count_rows
vckg query-kg --graph-dir outputs\kg --kind semantic_facts --target-function count_rows
```

**CodeKG (integrated default)**: 
```powershell
codekg build --source C:\path --out outputs\kg --backend auto
codekg view --graph-dir outputs\kg --open
```

Both backends cache KGs by default. Force rebuild with `force_rebuild: true` or delete `cache/kg/<project>/<commit>/<kg_version>/<config_hash>`.

## Shared state and cleanup

- **Repository cache**: `cache/repos/bare_mirrors/<project>__*.git` (bare clones, large)
- **KG cache**: `cache/kg/<project>/<commit>/<kg_version>/<config_hash>/` (nodes.jsonl, edges.jsonl, graph artifacts)
- **Worktrees**: `cache/worktrees/<project>__<hash>/` (checked-out snapshots)

To free space after large runs or recover from interrupted clones:
```powershell
Remove-Item -Recurse -Force cache/repos/bare_mirrors/linux__*
rm -rf cache/kg/linux__*
```

## Tokens and cost accounting

Token counts are estimated from config-specified tokenizers:
- **OpenAI APIs**: Use provider `usage` field if returned
- **llama-server**: Fetch `/tokenize` if available, else estimate
- **Hugging Face transformers**: Use tokenizer from actual generation tensors
- **Mock**: Estimate based on character count

For **real Qwen tokenizer without running a model**:
```bash
pip install -e ".[arrow,hf]"
vckg run --config configs/16_smallest_pair_mock_real_qwen_tokenizer.yaml
```

## Windows PowerShell notes

- Line continuation: `` ` `` (backtick)
- Remove directory: `Remove-Item -Recurse -Force path`
- Environment variables: `$env:VAR = "value"`
- Scripts may be unsigned; use `.\student-system-creator.ps1` or `python -m student_system_creator` instead
- Git commands: use `git` directly; no special escaping needed in quotes
