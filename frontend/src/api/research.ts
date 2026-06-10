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
  confidence?: number;
  decision_status?: string;
  resolved_commit?: string;
  model_backend?: string;
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
  samples: (id: string) => http<ResearchSample[]>(`/runs/${encodeURIComponent(id)}/samples`),
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
};
