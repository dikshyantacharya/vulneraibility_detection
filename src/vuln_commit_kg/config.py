from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ExperimentConfig(BaseModel):
    name: str
    seed: int = 42
    output_root: str = "outputs/runs"
    notes: str | None = None


class DatasetConfig(BaseModel):
    path: str = "data/raw/sec_vul_eval-train.arrow"
    mode: Literal["file", "smoke"] = "file"
    sample_limit: int | None = 1
    sample_selection: Literal["standard", "smallest_vuln_fixed_pair", "smallest_vuln_fixed_pairs_by_project", "explicit_pair"] = "standard"
    explicit_pair_indices: list[int] = Field(default_factory=list)
    # Dashboard-driven explicit selection (additive; empty = no constraint).
    only_sample_ids: list[str] = Field(default_factory=list)
    only_function_names: list[str] = Field(default_factory=list)
    pair_require_same_function: bool = True
    pair_require_same_file: bool = True

    # Validation-aware paired sampling for micro-scaling.  When enabled, the
    # runner oversamples vulnerable/fixed candidate pairs, resolves and
    # validates both snapshots, then keeps only pairs whose target function
    # matches exactly or above snapshot.body_match_threshold.  This prevents
    # function-name-only / 0-similarity cases from reaching KG/LLM stages.
    validation_aware_pair_selection: bool = False
    # When true, only selected sample IDs run exactly as specified (no pair expansion).
    # When false (default), pair expansion runs if validation_aware_pair_selection or
    # sample_selection mode is pair-based. Only enforced if only_sample_ids is non-empty.
    exact_sample_ids_only: bool = False
    validated_pair_limit: int | None = None
    candidate_pair_limit: int | None = None
    candidate_pair_oversample_factor: int = 6
    require_validated_pair_both_sides: bool = True
    # Candidate ordering/filtering for staged scaling.  This is intentionally
    # clone-free: it uses dataset metadata and explicit project filters so the
    # first micro-scaling run does not accidentally clone huge repositories
    # such as Linux.  Later configs can relax these limits.
    validation_candidate_order: Literal["as_found", "dataset_smallest_first", "dataset_largest_first", "cached_smallest_first"] = "dataset_smallest_first"
    use_cached_pair_candidates: bool = False
    pair_candidate_cache_path: str = "cache/repo_inventory/pair_candidates_smallest_first.jsonl"
    build_pair_candidate_cache: bool = False
    validation_candidate_exclude_projects: list[str] = Field(default_factory=list)
    validation_candidate_exclude_project_patterns: list[str] = Field(default_factory=list)
    validation_candidate_max_project_dataset_samples: int | None = None
    validation_candidate_max_unique_files: int | None = None
    validation_candidate_max_pair_function_chars: int | None = None
    # Keep micro-scaling scientifically diverse: select at most one validated
    # vulnerable/fixed pair per project unless a later stress config disables it.
    validation_candidate_one_pair_per_project: bool = True
    # When true, validation-aware selection still validates candidate pairs from
    # small to large, but it is allowed to clone all preselected candidate project
    # mirrors if missing. KG construction remains limited to final selected pairs.
    validation_candidate_clone_mirrors: bool = True
    # In validation-aware scaling runs, process candidate pairs in small-first
    # order and stop as soon as the requested number of valid diverse pairs is
    # found. This avoids validating all oversampled candidates (and avoids
    # repeated worktree attempts for known-bad commits) before KG/LLM work.
    validation_candidate_stream_until_valid_pairs: bool = True

    # Prefer persistent repository inventory produced by `vckg prepare-repos`.
    # This lets later scaling runs choose small, already-cloned, usable projects
    # without re-cloning/re-scanning repositories on every run.
    validation_candidate_use_repo_inventory: bool = True
    validation_candidate_require_repo_inventory_usable: bool = False
    validation_candidate_repo_inventory_sort_metric: Literal[
        "auto", "mirror_size_bytes", "source_bytes", "source_files", "total_files", "dataset_samples"
    ] = "auto"

    project_limit: int | None = None
    project_include: list[str] = Field(default_factory=list)
    project_exclude: list[str] = Field(default_factory=list)
    samples_per_project: int | None = None
    vulnerable_count: int | None = None
    non_vulnerable_count: int | None = None
    shuffle: bool = False
    require_project_url: bool = True
    allow_missing_repo_fields: bool = False

    # Project preselection is intentionally dataset-driven and clone-free.
    # Use project_include for exact control. Use smallest_dataset/largest_dataset/random when
    # you want the runner to choose projects before cloning anything.
    project_selection: Literal[
        "first",
        "explicit",
        "smallest_dataset",
        "largest_dataset",
        "random",
    ] = "first"
    project_sort_metric: Literal["num_samples", "num_commits", "num_files", "num_vulnerable"] = "num_samples"
    min_project_samples: int | None = None
    max_project_samples: int | None = None
    require_vulnerable_project: bool = False
    require_safe_project: bool = False


class RepoConfig(BaseModel):
    enabled: bool = True
    cache_dir: str = "cache/repos/bare_mirrors"
    worktree_dir: str = "cache/worktrees"
    clone_mode: Literal["bare_mirror"] = "bare_mirror"
    fetch_if_exists: bool = False
    use_existing_mirror: bool = True
    clone_if_missing: bool = True
    timeout_seconds: int = 1800
    clean_failed_worktree: bool = True
    skip_if_clone_fails: bool = True
    # If cache/worktrees is manually deleted, bare mirrors can still contain
    # stale worktree registrations. Prune those registrations before/after add
    # failures so missing worktrees are recreated from the cached mirror instead
    # of being treated as target-validation failures.
    prune_stale_worktrees: bool = True
    force_recreate_registered_worktree: bool = True

    # Safer defaults for large repos. A blobless mirror keeps commit history/references
    # but downloads file blobs lazily when a specific worktree needs them.
    partial_clone: bool = True
    filter_spec: str = "blob:none"
    # If an existing mirror was created as a partial/blobless clone and a later
    # config explicitly requests a full clone, set this true to delete and
    # recreate that mirror. Keep false for normal runs to avoid accidental
    # expensive reclones.
    replace_partial_mirror_with_full_clone: bool = False
    clone_progress: bool = True
    passthrough_git_output: bool = True


class RepoInventoryConfig(BaseModel):
    """Persistent repository clone/status/statistics cache.

    `prepare-repos` writes one JSON file per dataset project plus aggregate
    indexes under this directory. Later validation-aware selection can use those
    cached stats to choose small projects first and skip inaccessible/corrupt
    mirrors without recomputing repository statistics.
    """
    enabled: bool = True
    cache_dir: str = "cache/repo_inventory"
    force_refresh: bool = False
    reuse_existing_stats: bool = True
    clone_missing: bool = True
    skip_clone_failures: bool = True
    include_file_types: list[str] = Field(default_factory=lambda: [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"])
    compute_git_tree_stats: bool = True
    compute_commit_count: bool = True
    # Expensive content/function scanning is disabled by default. It is not
    # needed for small-first ordering because tree-level source bytes/files are
    # already cheap and stable. Enable later for deeper offline analysis.
    compute_function_count_approx: bool = False
    max_files_for_function_scan: int = 2000
    max_file_bytes_for_function_scan: int = 400000
    build_pair_candidate_cache: bool = False
    pair_candidate_orderings: list[str] = Field(default_factory=lambda: ["smallest_source_first"])


class ValidationCacheConfig(BaseModel):
    enabled: bool = True
    cache_dir: str = "cache/repo_inventory"
    filename: str = "commit_validation_cache.jsonl"
    reuse_negative_results: bool = True
    retry_invalid_after_days: int | None = None


class SnapshotConfig(BaseModel):
    use_dataset_commit_id: bool = True
    validate_target_function: bool = True

    # Dataset commits in vulnerability datasets are often fixing commits.
    # In that case, the vulnerable function body may match the parent commit,
    # not the raw dataset commit. Keep this explicit and logged.
    commit_resolution: Literal[
        "dataset_commit",
        "secvuleval_patch",
        "parent_for_vulnerable",
        "parent_for_all",
    ] = "dataset_commit"
    parent_depth: int = 1

    require_filepath_exists: bool = True
    require_function_found: bool = False
    body_match_threshold: float = 0.82
    on_validation_failure: Literal["warn_and_continue", "skip", "fail"] = "warn_and_continue"
    # Large dashboard/research sweeps should be able to continue when a dataset
    # row resolves only by function name or otherwise fails strict body matching.
    # When enabled, such samples are recorded as skipped_target_validation and
    # excluded from classification/metrics instead of aborting the whole run.
    skip_target_validation_failures: bool = False
    save_validation_artifacts: bool = True
    validation_artifact_dirname: str = "target_validation_artifacts"

    @field_validator("body_match_threshold")
    @classmethod
    def valid_threshold(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("body_match_threshold must be in [0, 1]")
        return value


class KGConfig(BaseModel):
    scope: Literal["project_snapshot", "function_only_baseline", "disabled"] = "project_snapshot"
    version: str = "codekg_explorer_integrated_v1"

    # KG backend policy for the integrated CodeKG Explorer.
    # auto prefers Joern when runnable, then tree-sitter if installed, then the
    # scope-aware heuristic parser. lightweight remains accepted as a legacy alias
    # for heuristic.
    backend: Literal["auto", "lightweight", "heuristic", "joern", "tree-sitter", "treesitter", "tree_sitter"] = "auto"
    use_codekg: bool = True

    # CodeKG cache policy.  The default is persistent across runs, like the
    # original project-level KG cache: one project/commit/config snapshot is
    # built once and then reused by later runs.  The default location is under
    # the repository-level cache/ tree, alongside repo mirrors, worktrees, and
    # inventory statistics.
    cache_mode: Literal["persistent", "run_local"] = "persistent"
    cache_dir: str = "cache/codekg"
    persistent_cache_dir: str | None = None
    # In run_local mode only, this is resolved relative to the current run dir.
    kg_out_dir: str = "codekg"
    open_dashboard: bool = False
    joern_home: str | None = None
    require_joern: bool = False
    joern_language: Literal["C", "CPP"] = "C"

    build_if_missing: bool = True
    force_rebuild: bool = False
    include_file_types: list[str] = Field(
        default_factory=lambda: [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"]
    )
    exclude_dirs: list[str] = Field(
        default_factory=lambda: [
            ".git", "build", "cmake-build-debug", "cmake-build-release", "node_modules",
            "vendor", "third_party", "external", "dist", "target", "__pycache__"
        ]
    )
    max_files: int | None = 3000
    max_file_bytes: int = 600_000
    max_functions: int | None = None
    save_graphml: bool = False
    progress_log_every_files: int = 25
    progress_log_every_seconds: float = 5.0
    graph_save_log_every: int = 5000
    log_file_start: bool = True
    slow_file_log_seconds: float = 2.0
    # Headers are useful later, but they can be noisy in early debugging.
    # Keep them enabled by default; quick configs may disable them.
    include_headers: bool = True

    # Joern primary CPG integration. The runner expects Joern on PATH or explicit
    # executable paths. It imports Joern output into the existing ProjectGraph
    # interface so the rest of the pipeline, retriever, and dashboards remain
    # compatible.
    joern_parse_bin: str = "joern-parse"
    joern_export_bin: str = "joern-export"
    joern_bin: str = "joern"
    joern_work_dir: str = "cache/joern"
    joern_timeout_seconds: int = 1800
    joern_timeout: int = 900
    joern_export_representations: list[str] = Field(default_factory=lambda: ["cpg14", "all"])
    joern_export_format: str = "graphml"
    joern_fallback_to_lightweight: bool = True
    joern_keep_raw_artifacts: bool = True

    # Semantic enrichment layer added on top of either Joern or lightweight CPG.
    semantic_enrichment_enabled: bool = True
    semantic_enrichment_mode: Literal["heuristic", "svf_optional"] = "heuristic"
    svf_bin: str = "wpa"
    svf_timeout_seconds: int = 1800
    svf_fallback_to_heuristic: bool = True

    # Storage and visualization exports for standalone KG inspection.
    storage_export_graphml: bool = True
    storage_export_csv: bool = True
    storage_export_query_examples: bool = True
    visualization_enabled: bool = True
    visualization_max_nodes: int = 2500
    visualization_max_edges: int = 6000
    visualization_default_neighborhood_depth: int = 2


class RetrievalConfig(BaseModel):
    strategy: Literal["target_neighborhood", "risk_first"] = "target_neighborhood"
    # Defaults for CodeKG query execution requested by the LLM agent.
    retrieval_max_nodes: int = 520
    retrieval_joern_limit: int = 160
    retrieval_depth: int = 3
    call_depth: int = 2
    data_depth: int = 4
    control_depth: int = 3
    include_headers: bool = True
    include_globals: bool = True
    include_joern: bool = True
    top_k_statements: int = 80
    top_k_risk: int = 12
    top_k_safety: int = 10
    top_k_callees: int = 8
    top_k_callers: int = 5
    max_context_chars: int = 16_000
    include_cwe_hint: bool = True
    include_cve_hint: bool = False


class PromptingConfig(BaseModel):
    # Model prompts default to a strict privacy boundary. Orchestration metadata
    # remains available in reports/artifacts but is not placed in model-visible text
    # unless an explicit experiment enables it.
    include_orchestration_metadata_in_model_prompt: bool = False
    include_cwe_hints_in_model_prompt: bool = False
    include_cve_hints_in_model_prompt: bool = False


class AgentConfig(BaseModel):
    enabled: bool = True
    mode: Literal["single_pass", "iterative", "agentic_proof"] = "iterative"
    max_rounds: int = 3
    risk_hypothesis_limit: int = 5
    allow_kg_followup_queries: bool = True
    max_tool_queries_per_round: int = 5
    max_tool_results_per_query: int = 5
    max_evidence_items_after_tools: int = 180
    save_demo_reports: bool = True
    demo_report_dirname: str = "agent_demos"
    save_full_prompts: bool = True
    save_raw_model_outputs: bool = True
    reasoning_trace: Literal["none", "brief_reason", "evidence_summary", "hypothesis_trace", "tool_trace"] = "evidence_summary"
    response_format: Literal["json"] = "json"
    fail_open_on_parse_error: bool = True
    max_json_repairs: int = 2

    # Live/demo reporting controls.  These do not change model-visible prompts.
    # They make per-sample demo pages available while a sample is still running
    # and can hide deterministic pre-agent retrieval tables when the experiment
    # is meant to demonstrate hypothesis-driven KG querying.
    live_partial_demo_reports: bool = True
    demo_report_autorefresh_seconds: float = 2.0
    hide_initial_deterministic_retrieval_in_demo: bool = False
    demo_show_only_kg_tool_evidence: bool = False

    # Quality-first reporting controls. The post-hoc audit is run after the
    # final binary decision and may see report-only commit metadata; it never
    # changes the prediction used for metrics.
    enable_posthoc_commit_audit: bool = True
    posthoc_audit_max_context_chars: int = 24000
    parse_failed_decision_status: str = "parse_failed"

    # Prompt profile controls how much evidence/trace text is placed in prompts.
    # auto: compact for llama-server/GGUF-sized local context, rich for API-style contexts.
    # local_budgeted: aggressively compact prompts and repair prompts for local Qwen/llama-server.
    # api_rich: preserve richer bundle evidence and trace summaries for large-context paid APIs.
    prompt_profile: Literal["auto", "local_budgeted", "api_rich"] = "auto"
    local_source_chars: int = 9000
    local_followup_context_chars: int = 6500
    local_final_context_chars: int = 8500
    local_repair_invalid_chars: int = 2500
    api_source_chars: int = 30000
    api_followup_context_chars: int = 32000
    api_final_context_chars: int = 48000
    api_repair_invalid_chars: int = 8000
    max_repair_schema_chars: int = 7000


class CostConfig(BaseModel):
    input_per_1k_usd: float = 0.0
    output_per_1k_usd: float = 0.0
    currency: str = "USD"


class ModelConfig(BaseModel):
    backend: Literal["mock", "openai_compatible", "gguf", "hf", "llama_server"] = "mock"
    model_name: str | None = None
    repo_id: str | None = None
    revision: str | None = None
    local_path: str | None = None
    auto_download: bool = True
    # GGUF-specific
    gguf_filename: str | None = None
    direct_gguf_url: str | None = None
    n_ctx: int = 8192
    n_gpu_layers: int = -1
    n_threads: int | None = None
    chat_format: str | None = None
    # API-specific / llama-server-specific
    api_base: str | None = None
    api_key_env: str | None = None
    timeout_seconds: int = 120
    # Max HTTP-level retries on transient read timeouts. 0 = no retry.
    # 1 = one retry after the first timeout, then propagate. Only Timeout
    # exceptions are retried; HTTP 4xx/5xx and JSON-parse errors are not.
    llm_retry_on_timeout: int = 1

    # llama-server-specific. The recommended workflow is to start llama-server
    # externally and point server_url at it. Set server_start=true if you want
    # this runner to start a llama-server subprocess for the run.
    server_url: str | None = None
    server_start: bool = False
    llama_server_binary: str = "auto"
    # Automatic llama.cpp server installer. The GGUF model and llama-server executable
    # are separate artifacts. If llama-server is missing, the CLI can download a
    # prebuilt llama.cpp release into tools/llama.cpp and use it automatically.
    llama_server_auto_download: bool = True
    llama_server_download_repo: str = "ggml-org/llama.cpp"
    llama_server_release: str = "latest"
    # Common values: auto, windows-cuda12, windows-cuda13, windows-vulkan,
    # windows-cpu, linux-x64, linux-vulkan, macos-arm64, macos-x64.
    llama_server_package: str = "auto"
    llama_server_install_dir: str = "tools/llama.cpp"
    server_host: str = "127.0.0.1"
    server_port: int = 8080
    server_startup_timeout_seconds: int = 120
    server_extra_args: list[str] = Field(default_factory=list)
    server_log_path: str | None = None
    # Generation
    temperature: float = 0.0
    top_p: float = 1.0
    max_tokens: int = 32768
    stop: list[str] | None = None
    request_json_object: bool = True
    # Optional OpenAI-compatible provider extensions. These are copied as
    # top-level request-body fields, for providers such as vLLM/AcademicCloud
    # that expose vendor-specific controls. Keep empty for strict OpenAI APIs.
    api_extra_body: dict[str, Any] = Field(default_factory=dict)
    # Strict compatibility mode for gateways that reject vendor extensions (e.g.
    # AcademicCloud's chat-completions gateway returns HTTP 400 on unknown body
    # fields such as chat_template_kwargs/response_format). When true, the
    # OpenAI-compatible adapter sends ONLY the universally supported keys
    # (model, messages, temperature, top_p, max_tokens, and stop if set) and
    # ignores api_extra_body / response_format / chat_template_kwargs.
    api_minimal_payload: bool = False
    # Qwen3/AcademicCloud thinking control. The AcademicCloud Qwen 3.5 endpoint
    # returns hidden reasoning in message.reasoning unless the request body
    # includes chat_template_kwargs.enable_thinking=false. When enabled, the
    # OpenAI-compatible adapter injects that flag into every chat completion
    # request and logs the resulting content/reasoning character counts.
    api_disable_thinking: bool = False
    # Older fallback for Qwen3-family models. Kept for compatibility, but the
    # preferred AcademicCloud fix is api_disable_thinking=true rather than
    # appending /no_think to the user prompt.
    api_force_no_think: bool = False
    # OpenAI-compatible API hardening. External providers may change model names
    # or expose /models via GET or POST. Preflight catches those issues before
    # the expensive agent loop starts.
    api_preflight: bool = True
    model_fallbacks: list[str] = Field(default_factory=list)
    # Accounting
    tokenizer_model: str | None = None
    tokenizer_backend: Literal["auto", "hf", "tiktoken", "llama_cpp", "char_estimate"] = "auto"
    estimate_tokens_if_missing: bool = True
    cost: CostConfig = Field(default_factory=CostConfig)




class AgenticProofRuntimeConfig(BaseModel):
    """Optional quality-first agentic proof pipeline controls.

    These fields are used only when ``agent.mode: agentic_proof``.
    The standard iterative agent remains the default for existing configs.
    """
    enabled: bool = False
    answer_tag: str = "answer"
    max_hypotheses: int = 12
    max_queries_per_hypothesis: int = 6
    evidence_limit_per_query: int = 8
    require_counter_evidence: bool = True
    require_minimum_proof_for_vulnerable: bool = True
    consistency_repair_can_upgrade: bool = False
    separate_local_risk_from_confirmed_vulnerability: bool = True
    confidence_policy: str = "evidence_completeness"
    pair_aware_dev_mode: bool = False
    max_tokens_source_only_hypothesis: int = 16384
    max_tokens_kg_query_planning: int = 8192
    max_tokens_hypothesis_verification: int = 16384
    max_tokens_counter_evidence_review: int = 16384
    max_tokens_final_decision: int = 8192
    max_tokens_schema_repair: int = 4096
    max_tokens_evidence_gap_analysis: int = 8192
    iterative_evidence_loop: bool = False
    max_evidence_iterations: int = 3
    max_queries_per_iteration: int = 5
    stop_when_no_new_evidence: bool = True
    stop_when_no_new_queries: bool = True
    stop_when_all_hypotheses_resolved: bool = True
    enable_counter_evidence_loop: bool = False
    max_counter_iterations: int = 2

class APIQuotaConfig(BaseModel):
    """Provider-side quota contract used by the shared request scheduler.

    The local scheduler still protects concurrent calls, but dashboard quota
    display can now prefer provider-supplied HTTP rate-limit headers. SAIA/GWDG
    documents these as x-ratelimit-* headers. Header probes are startup-only by
    default because providers may count even invalid/probe requests.
    """
    enabled: bool = False
    requests_per_minute: int | None = None
    requests_per_hour: int | None = None
    requests_per_day: int | None = None
    requests_per_month: int | None = None
    max_concurrent_requests: int = 1
    state_dir: str = "cache/api_rate_limits"
    safety_margin_seconds: float = 1.0
    retry_max_attempts: int = 4
    # Optional lower cap specifically for socket/read timeouts.  Timeout
    # retries are expensive because each failed attempt can consume the full
    # provider timeout.  When set, the adapter stops retrying the same model
    # after this many timeout attempts and moves to model_fallbacks if present.
    retry_timeout_max_attempts: int | None = None
    retry_initial_delay_seconds: float = 4.0
    retry_max_delay_seconds: float = 120.0
    # If a provider repeatedly returns empty/null content, do not spin through
    # expensive semantic repair prompts. The agent records the failure and uses
    # source-only fallbacks when available.
    retry_empty_response_max_attempts: int = 1
    retry_status_codes: list[int] = Field(default_factory=lambda: [408, 409, 425, 429, 500, 502, 503, 504])

    # Provider header quota display. Set provider_header_probe=off if you do
    # not want even the startup header check. If your provider later exposes
    # response headers through the model adapter, the dashboard also ingests
    # provider_rate_limit events without additional probe calls.
    provider_headers_enabled: bool = True
    provider_header_probe: Literal["off", "startup"] = "startup"
    provider_probe_url: str | None = None

    @field_validator("provider_header_probe", mode="before")
    @classmethod
    def normalize_provider_header_probe(cls, value: Any) -> str:
        if value is False or value is None:
            return "off"
        if value is True:
            return "startup"
        text = str(value).strip().lower()
        if text in {"off", "false", "no", "never", "none", "disabled", "disable"}:
            return "off"
        if text in {"startup", "start", "once", "true", "yes", "enabled", "enable"}:
            return "startup"
        return text

    provider_probe_method: Literal["GET", "POST"] = "GET"
    provider_probe_timeout_seconds: float = 10.0
    provider_header_update_from_responses: bool = True


class ExecutionConfig(BaseModel):
    classification_max_workers: int = 1
    api_classification_max_workers: int = 4
    local_classification_max_workers: int = 1
    parallelize_api_samples: bool = True
    write_live_events: bool = True
    graceful_shutdown_timeout_seconds: float = 5.0


class LiveDashboardConfig(BaseModel):
    enabled: bool = True
    dirname: str = "live_dashboard"
    update_interval_seconds: float = 1.0
    serve: bool = True
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = False
    keep_recent_events: int = 500
    # Keep the HTTP dashboard alive after metrics are written. This makes the
    # live dashboard usable after a short run finishes; stop it with Ctrl+C.
    keep_alive_after_run: bool = True
    update_on_stage_change: bool = True
    stream_agent_events: bool = True
    expose_partial_report_when_running: bool = True
    hide_initial_deterministic_retrieval_evidence: bool = False
    show_accumulated_tokens_and_cost: bool = True


class EvaluationConfig(BaseModel):
    binary: bool = True
    statement_level: bool = True
    reasoning_diagnostics: bool = True
    statement_match_threshold: float = 0.84
    make_visualizations: bool = True
    save_tables: bool = True


class ScalingAnalysisConfig(BaseModel):
    enabled: bool = True
    projection_sample_counts: list[int] = Field(default_factory=lambda: [2, 5, 10, 50, 100, 1000, 25000])
    projection_project_counts: list[int] = Field(default_factory=lambda: [2, 5, 50, 100, 900])
    write_dashboard: bool = True
    note: str | None = None


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    rich: bool = True
    log_every_n_samples: int = 1
    profile_memory: bool = True
    profile_time: bool = True
    show_eta: bool = True
    console_width: int | None = None
    log_every_n_files: int = 25
    log_every_seconds: float = 5.0
    log_graph_save_every: int = 5000


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment: ExperimentConfig
    dataset: DatasetConfig = Field(default_factory=DatasetConfig)
    repo: RepoConfig = Field(default_factory=RepoConfig)
    repo_inventory: RepoInventoryConfig = Field(default_factory=RepoInventoryConfig)
    validation_cache: ValidationCacheConfig = Field(default_factory=ValidationCacheConfig)
    snapshot: SnapshotConfig = Field(default_factory=SnapshotConfig)
    kg: KGConfig = Field(default_factory=KGConfig)
    retrieval: RetrievalConfig = Field(default_factory=RetrievalConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    agentic_proof: AgenticProofRuntimeConfig = Field(default_factory=AgenticProofRuntimeConfig)
    prompting: PromptingConfig = Field(default_factory=PromptingConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    api_quota: APIQuotaConfig = Field(default_factory=APIQuotaConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    live_dashboard: LiveDashboardConfig = Field(default_factory=LiveDashboardConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    scaling_analysis: ScalingAnalysisConfig = Field(default_factory=ScalingAnalysisConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def to_plain_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def load_config(path: str | Path) -> AppConfig:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"Config must be a YAML mapping: {path}")
    return AppConfig.model_validate(raw)


def save_config(config: AppConfig, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config.to_plain_dict(), f, sort_keys=False, allow_unicode=True)
