// Research agentic-audit API client (separate from the student-challenge API).
const BASE = "/api/research";

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, { headers: { "Content-Type": "application/json" }, ...init });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const b = await res.json();
      detail = b.detail || b.error || JSON.stringify(b);
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export interface ConfigMeta {
  name: string;
  path: string;
  dataset_path?: string;
  sample_selection?: string;
  model_backend?: string;
  model_name?: string;
  api_base?: string;
  thinking?: any;
  kg_backend?: string;
  require_joern?: boolean;
  output_root?: string;
  full?: any;
}

export interface Candidate {
  sample_id: string;
  project?: string;
  function_name?: string;
  filepath?: string;
  label?: string;
  repo_key?: string;
  usable_repo?: boolean;
  pair_function_chars?: number;
  tree_total_bytes?: number;
}

export interface ResearchRun {
  run_id: string;
  path: string;
  mtime: number;
  is_job_run: boolean;
  samples: number;
  metrics?: any;
}

export interface ResearchSample {
  sample_id: string;
  dir: string;
  function_name?: string;
  prediction?: string | null;
  prediction_bool?: boolean | null;
  prediction_available?: boolean;
  confidence?: number;
  decision_status?: string;
  resolved_commit?: string;
  model_backend?: string;
  // Admin-only enriched fields
  true_label?: string | null;
  result?: "correct" | "incorrect" | "inconclusive" | "failed" | "unknown" | null;
  error_type?: "tp" | "tn" | "fp" | "fn" | null;
}

export interface KGDashboardCandidate {
  dashboard_index: string;
  graph_dir: string;
  token: string;
  iframe_url: string;
}

export interface KGDashboardInfo {
  exists: boolean;
  graph_dir: string | null;
  dashboard_index: string | null;
  iframe_url: string | null;
  open_url: string | null;
  candidates: KGDashboardCandidate[];
  searched: string[];
  reason?: string;
}

export const research = {
  health: () => http<{ ok: boolean; configs: number; runs: number }>("/health"),
  configs: () => http<{ name: string; path: string }[]>("/configs"),
  configMeta: (name: string) => http<ConfigMeta>(`/configs/${encodeURIComponent(name)}`),
  candidates: (limit = 500) => http<Candidate[]>(`/candidates?limit=${limit}`),
  runs: () => http<ResearchRun[]>("/runs"),
  run: (id: string) => http<any>(`/runs/${encodeURIComponent(id)}`),
  samples: (id: string, mode = "admin") => http<ResearchSample[]>(`/runs/${encodeURIComponent(id)}/samples?mode=${mode}`),
  sample: (run: string, s: string) => http<any>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}`),
  trace: (run: string, s: string) => http<any>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/agent-trace`),
  llmCalls: (run: string, s: string) => http<any[]>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/llm-calls`),
  kgQueries: (run: string, s: string) => http<any[]>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/kg-queries`),
  report: (run: string, s: string) => http<any>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/audit-report`),
  // Old per-sample audit page (agent_demos/sample_x/index.html) — legacy.
  dashboardUrl: (run: string, s: string) =>
    `${BASE}/dash/${encodeURIComponent(run)}/${encodeURIComponent(s)}/index.html`,
  // The high-quality static CodeKG explorer discovered from cache/kg.
  kgDashboard: (run: string, s: string) =>
    http<KGDashboardInfo>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/kg-dashboard`),
  runSummary: (run: string, mode = "admin") =>
    http<RunSummary>(`/runs/${encodeURIComponent(run)}/summary?mode=${mode}`),
  runMetrics: (run: string, mode = "admin") =>
    http<LiveMetrics>(`/runs/${encodeURIComponent(run)}/metrics-live?mode=${mode}`),
  sampleNormalized: (run: string, s: string, mode = "admin") =>
    http<NormalizedSample>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/trace-normalized?mode=${mode}`),
  sampleStages: (run: string, s: string) =>
    http<Stage[]>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/stages`),
  flow: (run: string, s: string) =>
    http<AgentFlow>(`/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/flow`),
  flowReportUrl: (run: string, s: string) =>
    `${BASE}/runs/${encodeURIComponent(run)}/samples/${encodeURIComponent(s)}/flow/report`,
};

export interface RunLLM {
  provider_id?: string;
  provider_name?: string;
  base_url?: string;
  model?: string;
  model_backend?: string;
  temperature?: number;
  max_tokens?: number;
  minimal_payload?: boolean;
}
export interface RunKG {
  preset?: string;
  display_name?: string;
  effective_backend?: string;
  graph_dir?: string;
  dashboard_url?: string;
  dashboard_exists?: boolean;
  reuse_cache?: boolean;
  force_rebuild?: boolean;
}
export interface RunMetrics {
  available?: boolean;
  // Live-computed fields (always present when computed from samples)
  total?: number;
  completed?: number;
  failed?: number;
  inconclusive?: number;
  correct?: number;
  incorrect?: number;
  // Confusion matrix counts
  tp?: number | null;
  fp?: number | null;
  tn?: number | null;
  fn?: number | null;
  // Classification metrics (null when denominator is zero)
  accuracy?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
  specificity?: number | null;
  // Diagnostic for all-inconclusive / no-labels cases
  diagnostic?: string | null;
  // Legacy fields from metrics.json binary section
  n?: number;
}

export interface RunSummary {
  run_id: string;
  config_name?: string;
  status?: string;
  started_at?: string;
  finished_at?: string;
  llm: RunLLM;
  kg: RunKG;
  selection: { exact_sample_ids_only?: boolean; include_pairs?: boolean; sample_ids?: string[] };
  usage?: any;
  samples_requested: number;
  samples_completed: number;
  samples_failed: number;
  samples_pending?: number;
  metrics?: RunMetrics | null;
  metrics_available: boolean;
  metrics_reason?: string;
  metrics_note?: string | null;
}
export interface LiveMetrics {
  available: boolean;
  reason?: string;
  processed?: number;
  single_sample?: boolean;
  tp?: number; tn?: number; fp?: number; fn?: number;
  accuracy?: number; precision?: number; recall?: number; f1?: number;
  vulnerable_recall?: number; safe_recall?: number;
  per_sample?: any[];
}
export interface ChatMessage {
  role: string;
  content: string;
}
export interface Stage {
  index: number;
  stage: string;
  status?: string;
  source?: string;
  prompt?: string | null;
  system?: string | null;
  system_prompt?: string | null;
  user_prompt?: string | null;
  messages?: ChatMessage[] | null;
  legacy_prompt_only?: boolean;
  request_payload_keys?: string[] | null;
  response?: string | null;
  parsed_json?: any;
  prompt_chars?: number | null;
  response_chars?: number | null;
  tokens?: { prompt?: number; completion?: number; total?: number } | null;
  elapsed_seconds?: number | null;
  json_status?: string | null;
  json_expected?: boolean;
  json_valid?: boolean | null;
  repaired_next?: boolean;
  error?: string | null;
  is_repair?: boolean;
  is_planning?: boolean;
  is_final?: boolean;
  finish_reason?: string | null;
  was_truncated?: boolean;
  requested_max_tokens?: number | null;
  effective_max_tokens?: number | null;
}
export interface FlowStage {
  stage?: string | null;
  status?: "pending" | "running" | "completed" | "failed" | "skipped";
  elapsed_seconds?: number | null;
  finish_reason?: string | null;
  was_truncated?: boolean;
  requested_max_tokens?: number | null;
  effective_max_tokens?: number | null;
  prompt_chars?: number | null;
  response_chars?: number | null;
  usage?: { prompt?: number; completion?: number; total?: number; prompt_tokens?: number; completion_tokens?: number; total_tokens?: number } | null;
  error?: string | null;
  // Iteration info parsed from stage name (e.g. "04_evidence_gap_iter2")
  iteration?: number;
  // Full content fields (available after incremental model_calls.jsonl write)
  kind?: string | null;
  system_prompt?: string | null;
  user_prompt?: string | null;
  messages?: { role: string; content: string }[] | null;
  response?: string | null;
  parsed_answer?: any;
  // Parse diagnostics (populated by _enrich_call_parse_result in pipeline.py)
  answer_text?: string | null;
  parse_status?: "valid" | "invalid" | "repaired" | "repair_failed" | "text_only" | "failed" | null;
  parse_error?: string | null;
  validation_error?: string | null;
  repair_status?: string | null;
}

export interface ForcedBinaryDecision {
  /** Always "vulnerable" | "fixed/non-vulnerable" — never null once validator runs */
  forced_prediction?: string | null;
  forced_prediction_bool?: boolean | null;
  /** confirmed_vulnerable | confirmed_non_vulnerable | forced_binary_vulnerable | forced_binary_non_vulnerable */
  decision_status?: string | null;
  /** confirmed | likely | weak | insufficient_static_evidence */
  evidence_strength?: string | null;
  residual_uncertainty?: string[];
  why_forced_binary?: string | null;
  evidence_exhausted?: boolean;
  loop_stop_reason?: string | null;
}

export interface IterationSummary {
  iteration?: number | null;
  phase?: string | null;
  new_evidence_count?: number | null;
  stop_reason?: string | null;
}

export interface AgentFlow {
  sample_id?: string;
  fallback?: boolean;
  iterative_loop_enabled?: boolean;
  loop_stop_reason?: string | null;
  iterations_completed?: number;
  stages: FlowStage[];
  iterations: IterationSummary[];
  total_evidence_items?: number | null;
  initial_evidence_items?: number | null;
}

export interface RunLoopSpec {
  loop_enabled?: boolean;                     // default true for dashboard runs
  enable_counter_evidence_loop?: boolean;     // default = loop_enabled
  max_evidence_iterations?: number;           // default 3
  max_counter_iterations?: number;            // default 2
  max_queries_per_iteration?: number;         // default 5
}

export interface NormalizedSample {
  run_id: string;
  sample_id: string;
  project?: string;
  function?: string;
  filepath?: string;
  status?: string;
  failed?: boolean;
  failed_stage?: string | null;
  last_completed_stage?: string | null;
  error_type?: string | null;
  error_message?: string | null;
  provider_error?: string | null;
  true_label?: string | null;
  prediction?: string | null;
  prediction_available?: boolean;
  confidence?: number | null;
  confidence_available?: boolean;
  correct?: boolean | null;
  decision_status?: string;
  verdict_text?: string | null;
  primary_vulnerability_type?: string;
  parse_error?: string;
  resolved_commit?: string;
  kg_loaded?: boolean;
  initial_retrieval?: boolean;
  kg_queries_count?: number;
  llm: RunLLM;
  kg: RunKG & { nodes?: number | null; edges?: number | null; target_found?: boolean | null };
  usage?: any;
  stages: Stage[];
  kg_queries: any[];
  // Dashboard-display-only — never injected into LLM prompts.
  commit_message?: string | null;
  target_function_source?: string | null;
}
