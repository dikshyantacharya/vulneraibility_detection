# Project Code Knowledge Graph & Agentic LLM for Vulnerability Detection

This repository contains the complete implementation of a vulnerability detection system combining **Project Code Knowledge Graphs (Joern+)** with a **ReAct-style Agentic LLM** and the **RAID challenge** evaluation system.

The framework ingests vulnerability records from the [SecVulEval](https://huggingface.co/datasets/arag0rn/SecVulEval) dataset, downloads the project source code at the specified commit snapshot, constructs a scope-aware knowledge graph, exposes high-level graph query functions, and uses an iterative hypothesis-falsification agent loop to evaluate whether functions are vulnerable.

---

## 1. Project Directory Structure

```text
vulnerability_detection/
├── baseline.py                      # Classical baseline entry point (TF-IDF + Logistic Regression)
├── configs/                         # YAML run configurations (smoke test, single function, pair runs)
│   ├── 00_smoke_mock.yaml           # Quick verification configuration
│   ├── 01_one_function_project_commit_mock.yaml
│   ├── 13_smallest_vuln_fixed_pair_mock.yaml
│   └── 46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml
├── data/                            # Dataset storage
│   └── raw/                         # Raw SecVulEval datasets (Arrow, CSV, Parquet)
├── frontend/                        # Web dashboard interface (React 18 + TypeScript + Vite)
│   ├── package.json                 # Frontend dependencies and scripts
│   ├── src/
│   │   ├── api/                     # Backend API and WebSocket client bindings
│   │   ├── components/              # UI components (DataTable, GraphViewer, etc.)
│   │   └── pages/                   # Views (ResearchRun, KGExplorer, AgentTrace, LLMProviders)
│   └── dist/                        # Compiled production frontend bundle
├── outputs/                         # Run outputs, predictions, traces, and metrics
│   └── runs/                        # Per-run execution directories (<timestamp>__<name>/)
├── scripts/                         # Utility scripts (server launchers, challenge helpers)
│   ├── start_llama_server_qwen.ps1  # Local GGUF llama-server launcher
│   └── student-system-creator.ps1   # RAID challenge system launcher
├── student_solutions/               # Student solutions & reference baseline agent
│   └── solution.py                  # Reference student agent implementation
├── student_system_creator/          # [Student Kit] Distributed to students with APIs & functions
│   ├── api.py                       # Student-facing query client API
│   ├── codekg_s/                    # Graph client utilities for student solutions
│   ├── retrieval_s/                 # Retrieval helper utilities for students
│   └── configs/                     # Student configuration files
├── src/                             # Core Python source packages
│   ├── codekg/                      # Knowledge graph engine and Joern+ backends
│   │   ├── backends/                # Joern, heuristic, and tree-sitter graph extractors
│   │   │   ├── heuristic.py         # Scope-aware variable disambiguation engine
│   │   │   ├── joern.py             # Joern CPG parser execution and discovery
│   │   │   └── joern_import.py      # Joern GraphML export importer and overlay binder
│   │   ├── query.py                 # GraphQueryEngine (high-level KG query primitives)
│   │   ├── dashboard.py             # Standalone SVG/Canvas graph viewer
│   │   └── models.py                # Graph primitives: Node, Edge, stable_id
│   ├── student_system_creator/      # [Internal Test Harness] Used to test & verify student challenges
│   │   ├── build_challenge.py       # Challenge packager & dataset splitter
│   │   ├── dashboard/               # Web dashboard backend (app, jobs, kg_presets)
│   │   ├── evaluator/               # Budget-controlled student solution evaluator
│   │   ├── package_raid.py          # RAID challenge packager
│   │   └── server/                  # Private KG API server hosting challenges
│   └── vuln_commit_kg/              # Main vulnerability audit orchestration pipeline
│       ├── baseline.py              # Classical TF-IDF + Logistic Regression classifier
│       ├── agents/                  # ReAct agent loop, schemas, prompts, reporting
│       │   ├── agent_controller.py  # 3-Stage ReAct falsification controller
│       │   ├── prompts.py           # Structured prompts for hypothesis, falsification, and decision
│       │   ├── schemas.py           # Pydantic data models for hypotheses and predictions
│       │   ├── tool_query.py        # KG tool executor and query mapper
│       │   ├── json_parse.py        # Resilient JSON extraction and self-repair engine
│       │   └── reporting.py         # Interactive HTML demo trace builder
│       ├── data/                    # Dataset ingestion and sample selection
│       │   ├── dataset_loader.py    # SecVulEval dataset loader
│       │   └── schema.py            # Sample data models
│       ├── evaluation/              # Metrics and performance reporting
│       │   ├── binary.py            # Binary classification metrics (Accuracy, Precision, Recall, F1)
│       │   ├── statement.py         # Statement-level localization metrics
│       │   ├── usage.py             # Token consumption and cost tracking
│       │   └── visualize.py         # Confusion matrix and metric plots
│       ├── kg/                      # Knowledge graph adapter and persistent caching
│       ├── repos/                   # Git operations, mirrors, and snapshot worktrees
│       │   ├── commit_resolver.py   # Snapshot resolution based on dataset commit ID
│       │   ├── repo_manager.py      # Bare mirror manager with partial cloning
│       │   ├── snapshot_manager.py  # Immutable worktree creation
│       │   └── target_validator.py  # Function body and token sequence validation
│       └── cli.py                   # Main CLI entry point
├── pyproject.toml                   # Python package build configuration
└── requirements.txt                 # Dependencies
```

---

## 2. Core Modules & Code Guide

This guide provides direct links to the source code files and functions across all major components.

### 2.1 Dataset Ingestion & Snapshot Resolution

The pipeline ingests vulnerability records from the [SecVulEval](https://huggingface.co/datasets/arag0rn/SecVulEval) dataset, downloads the corresponding source repository as a bare mirror, and checks out a snapshot of the repository state based on the commit ID specified in the dataset.

* **Dataset Loading & Schema Normalization:**
  - File: [`src/vuln_commit_kg/data/dataset_loader.py`](src/vuln_commit_kg/data/dataset_loader.py)
  - Key Functions:
    - `load_dataset()`: Ingests dataset files in `.arrow`, `.csv`, `.parquet`, or `.json` format.
    - `_normalize_row()`: Normalizes heterogeneous dataset columns into standard fields.
  - Data Model: [`src/vuln_commit_kg/data/schema.py`](src/vuln_commit_kg/data/schema.py) (`SecVulEvalSample`).

* **Snapshot Resolution:**
  - File: [`src/vuln_commit_kg/repos/commit_resolver.py`](src/vuln_commit_kg/repos/commit_resolver.py)
  - Key Function: `CommitResolver.resolve()`: Resolves the repository snapshot for each sample directly from the commit ID provided in the dataset.

* **Repository Mirrors & Worktrees:**
  - File: [`src/vuln_commit_kg/repos/repo_manager.py`](src/vuln_commit_kg/repos/repo_manager.py)
    - `RepoManager.ensure_mirror()`: Clones the project as a bare Git mirror (`cache/repos/bare_mirrors/`) with partial blobless cloning (`filter_spec: blob:none`).
  - File: [`src/vuln_commit_kg/repos/snapshot_manager.py`](src/vuln_commit_kg/repos/snapshot_manager.py)
    - `SnapshotManager.ensure_worktree()`: Checks out an immutable worktree snapshot (`cache/worktrees/`) at the designated commit ID.
  - File: [`src/vuln_commit_kg/repos/target_validator.py`](src/vuln_commit_kg/repos/target_validator.py)
    - `TargetValidator.validate()`: Compares the function in the checked-out repository with the dataset record using whitespace-insensitive and token-sequence similarity.

---

### 2.2 Knowledge Graph Construction & The Joern+ Parser

Once the repository snapshot is checked out, the project constructs a whole-project Code Knowledge Graph.

* **Joern CPG Extraction:**
  - File: [`src/codekg/backends/joern.py`](src/codekg/backends/joern.py)
    - `JoernBackend.build()`: Runs `joern-parse` on the snapshot directory to produce `cpg.bin`, then invokes `joern-export` to emit GraphML and JSON graph representations.
    - `detect_joern()` and `detect_java()`: Locates Joern and Java runtime environments.
  - File: [`src/codekg/backends/joern_import.py`](src/codekg/backends/joern_import.py)
    - `ingest_joern_export()`: Ingests the Joern CPG and overlays AST, CFG, CDG, DDG, and reaching definition edges onto the graph.
    - `_register_overlay()`: Connects Joern CPG nodes to source-level code nodes by function name and line boundaries.

* **The Joern+ Improvement (Scope-Aware Variable Disambiguation):**
  - Problem: Standard Joern exports often conflate identically named variables occurring in different functions (e.g., a local `len` in function A vs a local `len` in function B) or confuse struct fields (`obj->len`) with local scalar variables.
  - File: [`src/codekg/backends/heuristic.py`](src/codekg/backends/heuristic.py)
    - `resolve_variable()`: Tracks parameter scopes and local declarations per function. A variable lookup checks local declarations and parameters first; it connects to a global node only if no local shadows the name.
    - Scope-Qualified Identifiers: Local variable nodes receive deterministic qualified IDs (`lid = stable_id("local", rel, fn.name, lname, line_start)`) and qualified attributes (`qname = f"{fn.name}::{lname}@L{line_start}"`, `scope_kind="local"`).
    - `extract_types()`: Separates struct, union, and class declarations into distinct `Field` nodes rather than global or local variables.
  - File: [`src/student_system_creator/dashboard/kg_presets.py`](src/student_system_creator/dashboard/kg_presets.py)
    - Defines the `joern_plus` preset (`id="joern_plus"`, `backend="joern"`, `semantic_enrichment_enabled=True`).

* **Graph Data Models:**
  - File: [`src/codekg/models.py`](src/codekg/models.py): Defines `Node`, `Edge`, and deterministic `stable_id()` hashing.

---

### 2.3 High-Level Knowledge Graph Query API

To enable the agentic LLM to inspect relevant code sections without overloading its context window, a set of high-level query functions is provided. These accept parameters such as target function, traversal depth, call depth, and symbol names, and return focused subgraphs.

* **Graph Query Engine:**
  - File: [`src/codekg/query.py`](src/codekg/query.py) (`GraphQueryEngine`)
  - Key Retrieval Functions:
    - `security_context(target_function, depth, call_depth, data_depth, include_callers, include_globals, include_headers, include_joern, max_nodes)`: Returns the neighborhood around the target function including callers, callees, variables, globals, and Joern overlays.
    - `evidence_slice(target_function, target_statement, relation_depth, data_depth, control_depth, call_depth)`: Performs forward and backward slicing around a specific sensitive statement (e.g., buffer writes, memory allocations).
    - `variable_flow(target_function, symbol, depth)`: Traces the definition and data-flow dependencies of a specific variable across statements.
    - `call_neighborhood(target_function, direction, depth)`: Traverses incoming and outgoing call graphs.
    - `callers(target_function, depth)` / `callees(target_function, depth)`: Dedicated directional call graph extraction.
    - `semantic_facts(target_function, risk_terms)`: Retrieves semantic facts such as bounds checks, sanitizers, null checks, and allocation/free operations.
    - `file_context(file, depth)`: Extracts declarations, macros, and includes from the containing file.

* **Execution and Bounding Safety:**
  - File: [`src/vuln_commit_kg/kg/codekg_adapter.py`](src/vuln_commit_kg/kg/codekg_adapter.py)
    - `execute_codekg_query()`: Validates parameters and enforces execution bounds (e.g., maximum depth $\le 6$, maximum nodes $\le 1200$).
  - File: [`src/vuln_commit_kg/agents/tool_query.py`](src/vuln_commit_kg/agents/tool_query.py)
    - `KGToolExecutor.execute_many()`: Dispatches agent queries against the graph and formats results into standardized evidence items.

---

### 2.4 Agentic LLM Architecture (ReAct Hypothesis-Falsification Loop)

The LLM operates as an agent using a ReAct-style reasoning process:

1. **Stage 1 — Source-Only Hypothesis Generation:** The agent receives only the target function source code. It analyzes potential vulnerabilities and generates candidate hypotheses ($H_1, H_2, \dots$) along with the specific evidence required to verify or falsify them.
2. **Stage 2 — Iterative Falsification Loop:** For each iteration:
   - The agent requests specific code sections by calling the high-level Knowledge Graph functions (specifying function, depth, symbol, etc.).
   - The KG returns the requested statements, callers, callees, or data flows.
   - The agent inspects the returned evidence to check if the hypothesis can be **falsified** (e.g., an input check, bounds guard, or caller constraint makes the flaw impossible) or **confirmed**.
   - If the returned evidence is insufficient, the agent marks the hypothesis as `needs_more_evidence` and requests deeper parameters or additional functions.
3. **Stage 3 — Final Adjudication:**
   - If **any** hypothesis is confirmed with grounded proof, the function is declared **vulnerable** (`is_vulnerable = True`).
   - If **all** hypotheses are falsified / ruled out (`ruled_out_safe`), the function is declared **non-vulnerable** (`is_vulnerable = False`).
   - If unresolved hypotheses remain without conclusive proof either way, it is marked **inconclusive**.

* **Controller Implementation:**
  - File: [`src/vuln_commit_kg/agents/agent_controller.py`](src/vuln_commit_kg/agents/agent_controller.py)
    - `AgentController.classify()`: Drives the multi-round hypothesis-falsification loop and final decision synthesis.

* **Prompts & Schemas:**
  - File: [`src/vuln_commit_kg/agents/prompts.py`](src/vuln_commit_kg/agents/prompts.py)
    - `risk_hypothesis_prompt()`: Stage 1 prompt for generating initial hypotheses.
    - `followup_query_prompt()`: Stage 2 prompt for falsification, hypothesis updates, and new KG queries.
    - `final_decision_prompt()`: Stage 3 prompt for final prediction synthesis.
  - File: [`src/vuln_commit_kg/agents/schemas.py`](src/vuln_commit_kg/agents/schemas.py)
    - `RiskHypothesis`, `RiskHypothesisResponse`: Initial hypothesis models.
    - `HypothesisUpdate`, `FollowupResponse`: Status update models (`confirmed_vulnerable`, `ruled_out_safe`, `needs_more_evidence`, `unresolved`).
    - `Prediction`: Final prediction model with cited evidence IDs and confidence score.

* **JSON Parsing & Self-Repair:**
  - File: [`src/vuln_commit_kg/agents/json_parse.py`](src/vuln_commit_kg/agents/json_parse.py)
    - `repair_json_completion()`: Extracts and repairs JSON responses, handling formatting issues and running secondary repair prompts if necessary.

* **Audit Traces & Reporting:**
  - File: [`src/vuln_commit_kg/agents/reporting.py`](src/vuln_commit_kg/agents/reporting.py)
    - `build_agent_demo_report()`: Generates standalone interactive HTML reports (`agent_demos/`) showing every prompt, model response, JSON repair, KG tool result, and hypothesis update.

---

### 2.5 Classical Text-Classification Baseline (TF-IDF + Logistic Regression)

For the classical baseline, the source code of each function is represented using TF–IDF features and classified using Logistic Regression. This provides a deliberately simple text-classification baseline that learns from vulnerable and non-vulnerable training functions without access to repository-level context during inference.

* **Implementation:**
  - File: [`src/vuln_commit_kg/baseline.py`](src/vuln_commit_kg/baseline.py) & root entry point [`baseline.py`](baseline.py)
  - Class: `TfidfLogisticRegressionBaseline`
  - Key Methods:
    - `fit(samples)`: Fits `TfidfVectorizer` (subword/identifier tokenization with n-grams) and trains `LogisticRegression(class_weight="balanced")` on function bodies.
    - `predict_sample(sample)`: Produces a standard `Prediction` instance for a single `SecVulEvalSample`.
    - `predict(samples)`: Generates `Prediction` instances for a batch of samples.
    - `evaluate(samples)`: Computes binary metrics directly via `binary_metrics(samples, preds)`.
    - `save(path)` / `load(path)`: Serializes and deserializes the fitted vectorizer and model using `joblib`.
---

### 2.6 Scientific Evaluation Metrics

The evaluation module scores model predictions against ground truth without metric distortion.

* **Binary Classification Metrics:**
  - File: [`src/vuln_commit_kg/evaluation/binary.py`](src/vuln_commit_kg/evaluation/binary.py)
  - Key Function: `binary_metrics()`
  - Computes: True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN), Accuracy, Precision, Recall, F1-Score, Specificity, and Balanced Accuracy.
  - **Inconclusive & Parse Failure Handling:** Predictions that fail JSON parsing or end as inconclusive are separated into an explicit `invalid_predictions` count and are never silently treated as negative predictions. Also reports `accuracy_all_invalid_as_wrong` for conservative benchmarking.

* **Statement-Level Localization:**
  - File: [`src/vuln_commit_kg/evaluation/statement.py`](src/vuln_commit_kg/evaluation/statement.py)
  - Key Function: `statement_metrics()`: Evaluates statement-level vulnerability localization against ground-truth changed statements.

* **Token & Cost Accounting:**
  - File: [`src/vuln_commit_kg/evaluation/usage.py`](src/vuln_commit_kg/evaluation/usage.py)
  - Key Function: `summarize_usage()`: Tracks prompt tokens, completion tokens, execution time, and financial costs.

* **Metric Visualization:**
  - File: [`src/vuln_commit_kg/evaluation/visualize.py`](src/vuln_commit_kg/evaluation/visualize.py)
  - Key Function: `save_visualisations()`: Generates confusion matrices, metric comparison bar charts, and token usage plots under `outputs/runs/<run_id>/figures/`.

---

### 2.7 Frontend & Dashboard

The project includes an interactive web dashboard providing visual inspection of the dataset, knowledge graph structure, and live agent runs.

> [!NOTE]
> **Disclaimer:** The frontend dashboard was developed with the help of Claude through pair programming.

* **Backend Server:**
  - File: [`src/student_system_creator/dashboard/app.py`](src/student_system_creator/dashboard/app.py): REST and WebSocket API server.
  - File: [`src/student_system_creator/dashboard/jobs.py`](src/student_system_creator/dashboard/jobs.py): Background job manager that runs CLI commands as durable, streamed tasks.

* **Frontend Application (React + TypeScript):**
  - Source Directory: [`frontend/src/`](frontend/src/)
  - Key Views:
    - **Run Audit & Configuration:** [`frontend/src/pages/ResearchRunPage.tsx`](frontend/src/pages/ResearchRunPage.tsx)
      - Select dataset samples and target functions.
      - Select KG backend presets (`joern_plus`, `joern`, `heuristic`, `tree_sitter`).
      - Configure loop budgets: set maximum ReAct iterations per function (`loopMaxIter`) and counter-iteration limits (`loopMaxCounterIter`).
      - Trigger streamed audit jobs with live progress.
    - **LLM Provider Management:** [`frontend/src/pages/LLMProvidersPage.tsx`](frontend/src/pages/LLMProvidersPage.tsx)
      - Configure credentials and select models across multiple providers: OpenAI-compatible APIs, AcademicCloud, local `llama-server` (GGUF), and Hugging Face transformers.
      - Test connectivity and adjust temperature and token limits.
    - **Knowledge Graph Explorer:** [`frontend/src/pages/KGExplorerPage.tsx`](frontend/src/pages/KGExplorerPage.tsx) & [`KGQueryFlowPage.tsx`](frontend/src/pages/KGQueryFlowPage.tsx)
      - Interactive visualization of nodes, edge relationships, AST/CFG links, and Joern overlays.
      - Visualizes the exact subgraphs and traversal paths requested by the agent during each reasoning step.
    - **Agent Trace Inspector:** [`frontend/src/pages/AgentTracePage.tsx`](frontend/src/pages/AgentTracePage.tsx)
      - Step-by-step display of prompts, raw completions, JSON validation states, and the hypothesis ledger.

---

### 2.8 The RAID Challenge Framework

The repository contains two related folders for the **RAID Challenge**:

1. **Root `student_system_creator/` (Student Distribution Kit):**
   - Directory: [`student_system_creator/`](student_system_creator/)
   - This folder is the package provided directly to students. It contains the student-facing APIs ([`api.py`](student_system_creator/api.py)), graph query client libraries ([`codekg_s/`](student_system_creator/codekg_s/)), retrieval utilities ([`retrieval_s/`](student_system_creator/retrieval_s/)), and configuration templates needed for students to build and run their own agents.
2. **Source `src/student_system_creator/` (Internal Author Test & Verification Harness):**
   - Directory: [`src/student_system_creator/`](src/student_system_creator/)
   - This internal harness is used to package the challenge datasets ([`package_raid.py`](src/student_system_creator/package_raid.py), [`build_challenge.py`](src/student_system_creator/build_challenge.py)), host the private KG query API ([`server/`](src/student_system_creator/server/)), and run the evaluation harness ([`evaluator/`](src/student_system_creator/evaluator/)). It is used to test and replicate whether student solutions execute properly when uploaded and receive valid evaluation scores.

* **Reference Solution:**
  - File: [`student_solutions/solution.py`](student_solutions/solution.py): Baseline reference agent demonstrating how student submissions query the graph and return structured predictions.

---

## 3. Quickstart & Execution

### 3.1 Setup

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package with required dependencies (including scikit-learn for baseline)
pip install -e ".[arrow,dashboard,dev]"
pip install scikit-learn
```

### 3.2 Verification Smoke Test

Run the verification smoke test to validate the pipeline, knowledge graph builder, agent loop, and evaluation reporting:

```powershell
vckg run --config configs/00_smoke_mock.yaml
```

### 3.3 Starting the Web Dashboard

Launch the web dashboard to access the user interface:

```powershell
student-system-creator dashboard --config student_system_creator/configs/default.yaml --port 8080
```

Open **`http://127.0.0.1:8080`** in your browser to:
- Browse datasets and functions.
- Configure LLM credentials and models on the **Providers** page.
- Inspect graph structures on the **KG Explorer** page.
- Configure and launch agent audits on the **Research Audit** page.

### 3.4 Running Joern+ and Agentic Audits via CLI

```powershell
# Verify Joern setup
codekg doctor --joern-home tools/joern-cli

# Run an agentic audit on a vulnerable/fixed pair using Joern+ and Qwen
vckg run --config configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml
```

### 3.5 Running the Classical Baseline Smoke Test

```powershell
# Run baseline tests (fit, predict, metrics evaluation)
pytest tests/test_baseline.py
```

### 3.6 Running the Test Suite

```powershell
# Run tests
pytest tests/test_baseline.py tests/test_dashboard.py tests/test_statement_eval.py
```
