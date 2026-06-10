# Vuln Commit KG + CodeKG Explorer Integration

This package now vendors the standalone `codekg` project and uses it as the default knowledge-graph backend for vulnerability-audit runs. The existing dataset loading, repository/snapshot resolution, LLM reasoning, agent loop, and audit-report workflow are preserved. The old `ProjectGraphBuilder` remains only as an explicit compatibility escape hatch via `kg.use_codekg: false`.

## Control Dashboard (React)

A browser-based control plane for the student-challenge / KG workflow now ships
alongside the CLI. It launches the existing commands as durable, streamed jobs and
adds live progress, a KG explorer, an agent-query audit, validation/evaluation
reports, and admin/student preview modes. All existing CLI commands are unchanged.

```powershell
pip install -e ".[dashboard]"          # FastAPI + uvicorn
cd frontend; npm install; npm run build; cd ..
student-system-creator dashboard --config student_system_creator/configs/default.yaml --port 8080
# open http://127.0.0.1:8080
```

Dev mode (hot-reload): run `student-system-creator dashboard-dev` and, in another
terminal, `cd frontend && npm run dev`. Full docs:
[docs/DASHBOARD.md](docs/DASHBOARD.md),
[docs/DASHBOARD_API.md](docs/DASHBOARD_API.md),
[docs/FRONTEND_DEVELOPMENT.md](docs/FRONTEND_DEVELOPMENT.md),
[docs/ADMIN_WORKFLOW.md](docs/ADMIN_WORKFLOW.md).

## What changed

The vulnerability pipeline now builds CodeKG artifacts under each run directory, normally:

```text
<run_dir>/codekg/<project-key>/<commit>/<kg-version>/<config-hash>/
  nodes.jsonl
  edges.jsonl
  graph.json
  graph.graphml
  graph.gexf
  manifest.json
  query_examples.json
  build.log
  dashboard/index.html
  dashboard/graph_data.json
```

The CodeKG graph is the source of truth. A compatibility view is created in memory so the existing target locator, evidence pack, agent loop, live dashboard, and audit reports can continue to run without rebuilding the pipeline from scratch.

Preserved CodeKG properties include scope-aware variable identity, struct field separation, local/global separation, statement identity by file/function/line/occurrence, deterministic semantic facts, graph quality diagnostics, retrieval slices, and the standalone dashboard.

## Install

```bash
cd <combined-project>
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate

pip install -e ".[arrow,api,dev]"
```

## Optional Joern setup

Place Joern CLI somewhere such as `tools/joern-cli`, then check it with CodeKG:

```bash
codekg doctor --joern-home tools/joern-cli
```

A strict Joern build can be requested with `--require-joern`. Without strict mode, `backend: auto` falls back to tree-sitter if available, then the heuristic C/C++ parser.

## Build and inspect a KG directly

```powershell
codekg build --source "C:\path\to\project" `
  --out outputs\manual_codekg `
  --backend auto `
  --joern-home tools\joern-cli `
  --joern-language C `
  --open

codekg query --graph-dir outputs\manual_codekg `
  --kind security_context `
  --target-function count_rows `
  --depth 3 `
  --call-depth 2 `
  --data-depth 4 `
  --write-dashboard

codekg view --graph-dir outputs\manual_codekg --open
```

The same local-project build is also exposed through `vckg`:

```powershell
vckg build-project-kg --source "C:\path\to\project" `
  --out outputs\manual_codekg `
  --backend auto `
  --joern-home tools\joern-cli `
  --joern-language C `
  --target-function count_rows `
  --open
```

## Run the integrated vulnerability pipeline

Your existing command remains the expected entry point:

```powershell
vckg run --config configs\45_curriculum_1_function_agentic_proof_qwen397b.yaml
```

The relevant config keys are:

```yaml
kg:
  use_codekg: true
  kg_out_dir: codekg
  backend: auto          # auto | joern | tree-sitter | heuristic
  joern_home: null
  require_joern: false
  joern_language: C
  open_dashboard: false

retrieval:
  retrieval_max_nodes: 520
  retrieval_joern_limit: 160
  retrieval_depth: 3
  call_depth: 2
  data_depth: 4
  control_depth: 3
  include_headers: true
  include_globals: true
  include_joern: true
```

The audit/demo report includes the CodeKG dashboard path, artifact directory, backend used, fallback/Joern status, node/edge counts, graph-quality diagnostics, every model-requested KG query, and each source-grounded retrieval summary.

## LLM query contract

The agent prompt now asks for structured CodeKG queries only. Supported forms include:

```text
security_context(target_function="count_rows", depth=3, call_depth=2, data_depth=4, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=520)
evidence_slice(target_function="count_rows", target_statement="length * itemsize", relation_depth=4, data_depth=4, control_depth=3, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=450)
variable_flow(target_function="count_rows", symbol="raw", data_depth=4)
call_neighborhood(target_function="count_rows", direction="both", call_depth=2)
semantic_facts(target_function="count_rows")
function_context(target_function="count_rows", depth=2)
file_context(file="src/example.c")
shortest_path(source_node="<node-id>", target_node="<node-id>")
```

The KG does not classify vulnerabilities. It retrieves source-grounded evidence. Final vulnerability claims must distinguish retrieved evidence, model inference, and missing evidence.

---

# Vuln Commit KG

Commit-aware project-level Knowledge Graph + agentic LLM framework for binary vulnerability detection.

```text
SecVulEval sample -> project_url + commit_id -> repo snapshot -> project-level KG
                 -> target function node -> KG evidence retrieval -> agentic LLM classifier
                 -> binary, statement-level, reasoning/evidence, cost, and runtime evaluation
```

The framework is config-driven so you can start with one function, then scale to five functions, one project, several projects, and eventually the full dataset without changing code.

## What this fixes

The flawed design was:

```text
target function -> local function graph -> LLM decision
```

This project instead builds or loads a **whole-project KG at the exact dataset commit** and treats the target function as a query anchor inside that KG.

## Installation

```bash
cd vuln_commit_kg
python -m venv .venv
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

pip install -e ".[arrow]"
```

Optional extras:

```bash
pip install -e ".[arrow,hf]"      # Hugging Face transformers models
pip install -e ".[arrow,gguf]"    # llama.cpp / GGUF models
pip install -e ".[arrow,tokens]"  # better token counting for OpenAI-compatible models
```

## Dataset setup

Place the SecVulEval Arrow file here:

```text
data/raw/sec_vul_eval-train.arrow
```

Example:

```bash
mkdir -p data/raw
cp /mnt/data/sec_vul_eval-train.arrow data/raw/sec_vul_eval-train.arrow
```

## Stop accidental huge clones

Do **not** let your first real run select the first dataset project blindly. The dataset contains very large projects such as Linux and Chromium. Use one of these safe approaches first.

### 1. Scan projects without cloning

```bash
vckg scan-projects --config configs/08_scan_projects.yaml
```

This writes:

```text
outputs/runs/<timestamp>__scan_projects/project_scan/project_summary.csv
outputs/runs/<timestamp>__scan_projects/project_scan/recommendations.json
```

Optional GitHub size metadata:

```bash
vckg scan-projects --config configs/08_scan_projects.yaml --fetch-github-size --github-limit 50
```

This uses the GitHub repository metadata API, so it can be rate-limited. The default scan is fully clone-free and only uses the dataset.

### 2. Use explicit small-project configs

The real-run configs now use small explicit projects by default:

```text
configs/01_one_function_project_commit_mock.yaml     # shapelib, 1 vulnerable function
configs/02_five_functions_same_project_mock.yaml     # didiwiki, 5 samples
configs/03_one_project_all_functions_mock.yaml       # didiwiki, all available samples
configs/04_multi_project_small_mock.yaml             # small explicit project list
configs/09_auto_small_project_mock.yaml              # automatic smallest eligible project
```

You can change projects directly in YAML:

```yaml
dataset:
  project_include: ["didiwiki"]
  project_selection: explicit
  project_exclude: ["linux", "Chrome", "tensorflow", "Android"]
```

Or let the system choose from the dataset before cloning:

```yaml
dataset:
  project_include: []
  project_selection: smallest_dataset
  project_sort_metric: num_samples
  min_project_samples: 5
  max_project_samples: 20
  require_vulnerable_project: true
  require_safe_project: true
  project_limit: 1
```

Supported `project_selection` values:

```text
first              legacy behavior; first project encountered in dataset
explicit           only use project_include
smallest_dataset   choose projects with the smallest dataset footprint
largest_dataset    choose projects with the largest dataset footprint
random             choose projects randomly after filters
```

Supported `project_sort_metric` values:

```text
num_samples
num_commits
num_files
num_vulnerable
```

## Clone progress and lighter clones

Repository clone now uses safer defaults:

```yaml
repo:
  partial_clone: true
  filter_spec: blob:none
  clone_progress: true
  passthrough_git_output: true
```

This makes Git print progress such as object counting/receiving directly in your terminal. `blob:none` reduces the initial clone size where the remote server supports partial clone. Exact commits are still checked out later; missing blobs are fetched lazily as needed.

If a clone is already stuck on a huge repository, stop it with `Ctrl+C`, delete the partially cloned mirror, and rerun with a small-project config:

```powershell
Remove-Item -Recurse -Force cache\repos\bare_mirrors\linux__*.git
vckg run --config configs/01_one_function_project_commit_mock.yaml
```

## Fastest first run: no cloning, no real model

```bash
vckg run --config configs/00_smoke_mock.yaml
```

This verifies the CLI, configs, logging, output writing, evaluation, visualization, and token accounting.

Outputs are written to:

```text
outputs/runs/<timestamp>__<experiment_name>/
```

Important files:

```text
resolved_config.yaml
run.log
samples.jsonl
predictions.jsonl
evidence_packs.jsonl
agent_traces.jsonl
metrics.json
usage_summary.json
tables/metrics.csv
figures/confusion_matrix.png
figures/binary_metrics.png
figures/token_usage.png
summary.md
```

## First real corrected run

```bash
vckg run --config configs/01_one_function_project_commit_mock.yaml
```

This will:

1. Load one selected SecVulEval sample.
2. Clone/reuse the selected project as a bare mirror.
3. Create/reuse an immutable worktree at `commit_id`.
4. Validate `filepath`, `func_name`, and approximate function body match.
5. Build a project-level KG for that commit.
6. Retrieve target-centered evidence.
7. Run the classifier.
8. Save metrics, debug artifacts, visualizations, timing, memory, and token/cost estimates.

## Scaling from configs

Recommended order:

```text
configs/00_smoke_mock.yaml
configs/08_scan_projects.yaml
configs/01_one_function_project_commit_mock.yaml
configs/02_five_functions_same_project_mock.yaml
configs/03_one_project_all_functions_mock.yaml
configs/04_multi_project_small_mock.yaml
configs/09_auto_small_project_mock.yaml
configs/05_openai_compatible_api.yaml
configs/06_gguf_qwen_coder.yaml
configs/07_hf_model.yaml
```

## API model usage

Set an API key:

```bash
export LLM_API_KEY="..."
# Windows PowerShell:
# $env:LLM_API_KEY="..."
```

Then edit `configs/05_openai_compatible_api.yaml`:

```yaml
model:
  backend: openai_compatible
  api_base: "https://api.openai.com/v1"
  api_key_env: "LLM_API_KEY"
  model_name: "gpt-4.1-mini"
```

The API backend uses `/chat/completions` and logs provider usage if available. If not available, tokens are estimated locally.

## Local GGUF model usage

Example:

```yaml
model:
  backend: gguf
  repo_id: "Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF"
  gguf_filename: "qwen2.5-coder-0.5b-instruct-q4_k_m.gguf"
  local_path: "models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf"
  auto_download: true
```

If `local_path` does not exist and `auto_download: true`, the framework downloads the GGUF file from Hugging Face. You can also use `direct_gguf_url` for a direct download URL.

## Local Hugging Face model usage

Example:

```yaml
model:
  backend: hf
  repo_id: "Qwen/Qwen2.5-Coder-0.5B-Instruct"
  auto_download: true
```

The project loads the tokenizer/model through `transformers`.

## Debugging artifacts

Every major unit writes explicit artifacts:

```text
repo_status.jsonl
target_validation.jsonl
kg_manifests.jsonl
evidence_packs.jsonl
agent_traces.jsonl
predictions.jsonl
failed_samples.jsonl
profile_events.jsonl
usage_events.jsonl
usage_summary.json
```

When something fails, the error is tied to a `sample_id`, `project`, `commit_id`, `filepath`, and pipeline stage.

## Main CLI commands

```bash
vckg inspect --config configs/09_auto_small_project_mock.yaml
vckg scan-projects --config configs/08_scan_projects.yaml
vckg build-kg --config configs/01_one_function_project_commit_mock.yaml
vckg run --config configs/01_one_function_project_commit_mock.yaml
vckg visualize --run-dir outputs/runs/<run>
```

## Notes

- The initial KG extractor is deliberately conservative and dependency-light. It supports C/C++-like projects with regex/brace parsing and security API pattern detection.
- Later you can replace the extractor with Tree-sitter or CodeQL without changing the orchestration layer.
- The system logs structured reasoning traces, not hidden chain-of-thought.

## Upgrading from an earlier ZIP

If you previously extracted v1 or v2 into the same directory, use a clean replacement. Some earlier ZIPs could leave old `src/vuln_commit_kg/data/sample_selector.py` files in place, which causes scanner import errors.

Recommended Windows PowerShell upgrade:

```powershell
# from the parent directory, not inside the old project
Rename-Item vulngraphrag_agent vulngraphrag_agent_old
Expand-Archive vuln_commit_kg_project_v3.zip -DestinationPath .
cd vuln_commit_kg
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[arrow]"
```

If you want to reuse the existing virtual environment, reinstall after extracting v3:

```powershell
pip install -e ".[arrow]" --force-reinstall
```

Quick verification:

```powershell
python - <<'PY'
from vuln_commit_kg.data.sample_selector import ProjectStats, summarize_projects
print('sample_selector OK')
PY
```

## KG-build progress logging

Version 4 adds visible progress for the previously silent KG-build phase. During a real run, you should now see sections like:

```text
KG cache check
KG build start
kg.discover.scan: 2500 | elapsed=5.0s | rate=...
KG discovery done
kg.parse.files: 10/126 (7.9%) | elapsed=... | eta=... | funcs=... stmts=... nodes=... edges=...
kg.resolve_calls: start
kg.resolve_calls: done
kg.deduplicate: start
kg.deduplicate: done
KG save
kg.save.nodes: 5000/18000 (27.8%) | elapsed=... | eta=...
kg.save.edges: 5000/26000 (19.2%) | elapsed=... | eta=...
KG save complete
```

The same information is written to `outputs/runs/<run>/run.log`, so stalled or failed runs are easier to diagnose after the fact.

Control the KG progress frequency from config:

```yaml
kg:
  progress_log_every_files: 10
  progress_log_every_seconds: 5.0
  graph_save_log_every: 5000
```

For very small projects, set `progress_log_every_files: 1`. For large projects, keep it around `25` or `100` to avoid noisy logs.

## KG build observability / avoiding apparent stalls

Version 5 adds explicit KG-builder progress. During graph construction the console and
`outputs/runs/<run>/run.log` now show:

- source discovery progress
- `kg.parse.file_start` before each parsed file
- `kg.parse.files` with percent, ETA, rate, RSS memory, function/statement/node/edge counts
- `kg.parse.slow_file` warnings for slow files
- call-resolution and deduplication stages
- graph-save progress for nodes and edges

For the fastest first real test, use the source-only debug config:

```powershell
vckg run --config configs/10_one_function_fast_source_only_mock.yaml
```

This excludes headers and logs every file. Once that works, move back to:

```powershell
vckg run --config configs/01_one_function_project_commit_mock.yaml
```

Useful KG logging knobs:

```yaml
kg:
  log_file_start: true
  slow_file_log_seconds: 1.0
  progress_log_every_files: 1
  progress_log_every_seconds: 2.0
  include_headers: false   # for quick smoke/debug; true for richer project context
```

If a run was interrupted during KG building, either run with `force_rebuild: true` or delete the
specific incomplete directory under `cache/kg/<project>/<commit>/<kg_version>/<config_hash>`.

## Target validation and commit resolution

If you see a line like this:

```text
target_validation | status=match_approximate | similarity=0.0106
```

that is not a useful match. A similarity near zero usually means one of three things:

1. the dataset commit is a fixing commit and the vulnerable body exists in the parent commit;
2. the target function extractor could not parse the function shape correctly;
3. the dataset metadata points to a file/function that changed substantially.

Use the lightweight validation command before building a KG:

```bash
vckg validate-targets --config configs/01_one_function_project_commit_mock.yaml
```

This writes:

```text
target_validation_candidates.jsonl
target_resolution.jsonl
target_validation.jsonl
target_validation_summary.json
```

The real-run configs use deterministic SecVulEval patch semantics:

```yaml
snapshot:
  commit_resolution: secvuleval_patch
  body_match_threshold: 0.82
```

This does not search history. It applies the dataset rule implied by the dataset card: vulnerable rows are deleted pre-fix code, so they use the first parent of the patch commit; fixed/non-vulnerable rows are added post-fix code, so they use the patch commit itself. The selected commit is logged as:

```text
commit_resolution | sample=... | selected=pre_fix_parent_for_vulnerable:<hash> | status=... | similarity=...
commit_resolution | sample=... | selected=patch_commit_for_fixed:<hash> | status=... | similarity=...
```

Supported modes:

```text
dataset_commit                    use only the dataset commit
secvuleval_patch                  vulnerable rows use the patch commit parent; fixed rows use the patch commit
parent_for_vulnerable             force parent for vulnerable samples, dataset commit otherwise
parent_for_all                    force parent for all samples
```

To find a minimal vulnerable/fixed pair before cloning anything:

```bash
vckg scan-pairs --config configs/15_scan_pairs.yaml --limit 20
vckg validate-targets --config configs/14_validate_smallest_vuln_fixed_pair.yaml
vckg run --config configs/13_smallest_vuln_fixed_pair_mock.yaml
```

For strict experiments, set:

```yaml
snapshot:
  on_validation_failure: fail
```

This stops the run instead of silently classifying a function whose body does not match the selected project snapshot.


## v9 runtime commit logging

For SecVulEval pair runs, each sample has two commit identifiers:

- `dataset_commit_id`: the patch commit stored in the dataset row.
- `resolved_commit_id`: the actual repository snapshot used for KG retrieval. With `snapshot.commit_resolution: secvuleval_patch`, vulnerable rows use the first parent of the patch commit, while fixed/non-vulnerable rows use the patch commit itself.

The run now writes these fields into `predictions.jsonl`, `evidence_packs.jsonl`, `agent_traces.jsonl`, and `usage_events.jsonl`, and prints them in the console under `sample.start`, `sample.graph`, and `retrieval.done`. This avoids confusing the vulnerable pre-fix snapshot with the dataset patch commit.

## v10 validation and real token accounting

Target validation now reports several independent comparisons:

- `raw_similarity`: direct source-text similarity.
- `whitespace_insensitive_similarity`: comments removed and all whitespace removed.
- `token_sequence_similarity`: C/C++ lexical token sequence comparison; comments and whitespace do not affect this score, but identifiers, literals, operators, braces, and statement order do.
- `body_similarity`: the main validation score, equal to the best content/token-sequence score.

When the token sequence or whitespace-insensitive content is identical, status becomes `match_exact` and `body_similarity=1.0`.

Validation artifacts are written under:

```text
outputs/runs/<run_name>/target_validation_artifacts/
```

Each sample/candidate folder contains:

```text
dataset_func_body.c
repo_extracted_func_body.c
side_by_side.txt
side_by_side.html
raw_unified_diff.txt
content_sequence_diff.txt
token_sequence_diff.txt
dataset_content_sequence.txt
repo_content_sequence.txt
dataset_token_sequence.txt
repo_token_sequence.txt
```

For real Qwen tokenizer accounting without running a Qwen model, install the HF extra and run:

```powershell
pip install -e ".[arrow,hf]"
vckg run --config configs/16_smallest_pair_mock_real_qwen_tokenizer.yaml
```

This still uses the mock model for classification, but token counts are computed with the configured Qwen tokenizer. If `model.backend: hf` is used, prompt and completion token counts are taken directly from the actual `transformers` tokenizer/generation tensors. If `model.backend: openai_compatible` returns provider usage, that provider usage is used. If `model.backend: gguf` uses `llama-cpp-python`, token counts are taken from `llama_cpp` tokenization when provider usage is unavailable.

## GGUF via llama-server (recommended for GPU)

This workflow does **not** import `transformers`. It uses a running `llama-server` process and reads real token usage from the server when available. If provider usage is missing, the runner tries llama-server `/tokenize`; if that is unavailable and `estimate_tokens_if_missing: false`, the run fails instead of silently guessing.

1. Install or build `llama-server` from llama.cpp and make sure `llama-server` is on your `PATH`.

2. Download or verify the configured GGUF file:

```powershell
vckg download-model --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

3. Start the server in a separate terminal:

```powershell
.\scripts\start_llama_server_qwen.ps1 -ModelPath models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf -Port 8080 -GpuLayers -1 -Context 8192
```

Linux/macOS:

```bash
./scripts/start_llama_server_qwen.sh models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf
```

4. Run the pair experiment against the server:

```powershell
vckg run --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

Alternative: let the runner start a managed llama-server subprocess:

```powershell
vckg run --config configs/19_smallest_pair_managed_llama_server_qwen_0_5b.yaml
```

The managed mode writes server logs to `outputs/llama_server_qwen_0_5b.log`.

## GGUF + llama-server workflow on Windows

The GGUF model file and the `llama-server.exe` executable are different things.
`vckg download-model` verifies/downloads the `.gguf` file only. You must also have
llama.cpp's `llama-server.exe` available on `PATH`, or point the config to its full path.

PowerShell may block unsigned `.ps1` scripts. The safest way is to use the Python CLI:

```powershell
vckg download-model --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
vckg doctor-llama --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
vckg start-llama-server --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

Run `vckg start-llama-server` in a separate terminal and keep it open. In another terminal:

```powershell
vckg run --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

If `doctor-llama` says it cannot find the executable, either put `llama-server.exe` on PATH or edit the YAML:

```yaml
model:
  llama_server_binary: C:/path/to/llama-server.exe
```

You can also set an environment variable for the current PowerShell session:

```powershell
$env:LLAMA_SERVER_BIN = "C:/path/to/llama-server.exe"
```

A `.cmd` helper is also included and is not affected by PowerShell script-signing rules:

```powershell
.\scripts\start_llama_server_qwen.cmd
```

## Pre-flight token and cost estimation without API calls

Use `estimate-cost` to build/reuse KG evidence and count the prompt tokens before running a paid API.
For Qwen GGUF, start llama-server first so the estimator can use `/tokenize` with the actual local GGUF tokenizer:

```powershell
vckg start-llama-server --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
# second terminal
vckg estimate-cost --config configs/20_estimate_cost_smallest_pair_qwen_llama_tokenizer.yaml
```

This writes:

```text
prompt_token_estimates.jsonl
prompt_token_estimates.csv
cost_estimate_summary.json
```

For closed-source APIs, the exact token count after generation comes from the provider's `usage` field when available. Before generation, any local tokenizer is necessarily a proxy unless it is the same tokenizer used by that provider. The estimator records the method in `tokenization_method` so you can distinguish real provider usage, llama-server tokenization, tiktoken, and character estimates.


## Automatic llama-server installation

For GGUF llama.cpp workflows, the `.gguf` model and `llama-server.exe` are separate files.
If `doctor-llama` reports that the server binary is missing, install it automatically:

```powershell
vckg install-llama-server --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

`vckg download-model` also installs llama-server automatically for llama-server configs unless you pass `--skip-llama-server`:

```powershell
vckg download-model --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
vckg doctor-llama --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
vckg start-llama-server --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
```

The installer distinguishes between the actual executable archive and CUDA runtime/DLL companion archives. For current Windows CUDA llama.cpp releases this means it should choose the `llama-...bin-win-cuda...zip` archive for `llama-server.exe` and, when available, also extract the `cudart-...zip` companion into the same folder. If CUDA package installation still fails on your machine, set `llama_server_package: windows-vulkan` or `windows-cpu` and rerun `vckg install-llama-server --force --config ...`.

The server is installed into `tools/llama.cpp/` by default. You can change the release/package in YAML:

```yaml
model:
  llama_server_package: windows-cuda12   # alternatives: windows-cpu, windows-vulkan, windows-cuda13
  llama_server_install_dir: tools/llama.cpp
```


## Qwen2.5-Coder 7B Q8 GGUF auto-download workflow

This project includes ready-to-run configs for `Qwen2.5-Coder-7B-Instruct-Q8_0.gguf`.
The GGUF file is downloaded automatically from Hugging Face when needed. You do not need to manually place it in `models/`.

External server mode:

```powershell
vckg start-llama-server --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
```

Then in a second terminal:

```powershell
vckg run --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
```

Managed mode, where the pipeline starts llama-server itself:

```powershell
vckg run --config configs/25_smallest_pair_managed_llama_server_qwen7b_q8_agent_demo_strict.yaml
```

The first run downloads both the model and, if missing, the llama-server executable.
Use `vckg doctor-llama --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml` to check the setup.

## Agent trace, JSON repair, and Qwen 7B llama-server demo

The strict agent demo configs now use evidence-ID-only JSON schemas and an explicit JSON repair loop. Every JSON-producing call saves the primary prompt/response, parse result, repair prompts/responses if needed, and the accepted parsed object. KG query provenance is recorded as `model_generated`, `model_generated_after_json_repair`, or `fallback_generated`.

Default prompt privacy is configured under:

```yaml
prompting:
  include_orchestration_metadata_in_model_prompt: false
  include_cwe_hints_in_model_prompt: false
  include_cve_hints_in_model_prompt: false
```

Report metadata can still show labels, sample IDs, project URLs, dataset commits, resolved commits, and validation artifacts, but those fields are not placed in model-visible prompts unless explicitly enabled for a separate experiment.

Recommended Windows PowerShell workflow for the Qwen 7B Q8 smallest-pair demo:

```powershell
vckg download-model --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
vckg install-llama-server --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
vckg doctor-llama --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
vckg start-llama-server --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
```

Then in another terminal:

```powershell
vckg validate-targets --config configs/17_validate_pair_content_exact_artifacts.yaml
vckg run --config configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml
```

Open the generated report at:

```text
outputs/runs/<latest-run>/agent_demos/index.html
```

To verify prompt privacy, inspect each sample's `privacy_scan.json`, or search the saved model prompts:

```powershell
Select-String -Path outputs\runs\<latest-run>\agent_demos\sample_*\prompt_*.txt -Pattern "14569","14570","3b67dc844789dc0f00e934270c7b349bcb547865","d07500687c1a42f73ec5d96a4e1e028af985892f","https://github.com/z3APA3A/3proxy","CVE-","CWE-"
```

See `docs/AGENT_TRACE_AND_JSON_REPAIR.md` for the detailed artifact layout and schema behavior.

## Scaling analysis dashboard

For local calibration before API-scale experiments, use:

```powershell
vckg run --config configs/27_two_small_projects_llama_server_qwen7b_q8_scaling_analysis.yaml
```

Open:

```text
outputs/runs/<latest-run>/scaling_analysis/index.html
```

The dashboard contains per-project clone/KG timing, source and KG sizes, per-function token/cost usage, binary metrics, a filterable prediction browser with links into each agent demo, and linear projections for larger sample/project counts. See `docs/SCALING_ANALYSIS.md`.


## Joern-primary KG backend and standalone KG inspection

This project now supports a Joern-first KG backend with semantic enrichment, CSV/GraphML storage exports, and a standalone interactive KG dashboard. See `docs/JOERN_KG_BACKEND_AND_VISUALIZATION.md`.

Quick commands:

```powershell
vckg joern-doctor
vckg build-project-kg --source C:\path\to\project --out outputs\kg_inspect\project --backend auto --target-function count_rows
vckg query-kg --graph-dir outputs\kg_inspect\project --kind semantic_facts --target-function count_rows --risk-terms pointer,size,bounds --write-dashboard
vckg run --config configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml
```

## CodeKG cache and live dashboard links

The integrated pipeline now uses a persistent CodeKG cache by default:

```yaml
kg:
  cache_mode: persistent
  persistent_cache_dir: outputs/runs/_codekg_cache
  force_rebuild: false
```

This means the same project / resolved commit / graph-build configuration is built once and reused in later runs. The live dashboard is served at the short URL printed by `vckg run`, normally:

```text
http://127.0.0.1:8765/current/
```

Open the **Projects / KG** tab. After each project snapshot finishes building or loading, the table shows compact links named `dashboard`, `manifest`, `graph.json`, and `artifacts`. The `dashboard` link opens the CodeKG Explorer for that exact project/commit snapshot.

To force a fresh CodeKG build for debugging:

```yaml
kg:
  force_rebuild: true
```

To return to per-run CodeKG artifacts:

```yaml
kg:
  cache_mode: run_local
  kg_out_dir: codekg
```

## Student challenge system creator

This project now includes a bounded student challenge generator in `student_system_creator/` and the package `student_system_creator`.

Create a challenge from the existing dataset/repo/KG caches:

```bash
student-system-creator build --config student_system_creator/configs/default.yaml
```

Serve private CodeKG graphs through the challenge API:

```bash
student-system-creator serve --registry outputs/student_challenge/vckg_codekg_student_challenge/private/kg_registry_private.json --host 127.0.0.1 --port 8000
```

Evaluate a student `solution.py` through the controlled recursive agent loop:

```bash
student-system-creator evaluate \
  --solution outputs/student_challenge/vckg_codekg_student_challenge/public/student_kit/solution.py \
  --train outputs/student_challenge/vckg_codekg_student_challenge/public/train.csv \
  --input outputs/student_challenge/vckg_codekg_student_challenge/public/test.csv \
  --labels outputs/student_challenge/vckg_codekg_student_challenge/private/test_labels.csv \
  --api-base http://127.0.0.1:8000 \
  --out outputs/student_eval/demo
```

The student submission contract is intentionally fixed: `solution.py` must define `build_agent(config)`, and the returned agent must implement `step(sample, observation, budget)`. The evaluator controls recursion and KG-query budgets; the student controls query strategy and final reasoning.


## Student System Creator command not found on Windows

After copying the student system creator files into an existing checkout, reinstall the editable package so the console entry point is created in `.venv\Scripts`:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
student-system-creator build --config student_system_creator/configs/default.yaml
```

You can also run it without reinstalling through the included launcher:

```powershell
.\student-system-creator.ps1 build --config student_system_creator/configs/default.yaml
```

or directly with Python:

```powershell
$env:PYTHONPATH="src"
python -m student_system_creator build --config student_system_creator/configs/default.yaml
```
