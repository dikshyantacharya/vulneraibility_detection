import type {
  DiskInfo,
  Job,
  KgGraph,
  Mode,
  Project,
  FunctionRow,
  StatusSummary,
} from "./types";

const BASE = "/api/dashboard";

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  return httpFull<T>(BASE + path, init);
}

async function httpFull<T>(fullPath: string, init?: RequestInit): Promise<T> {
  const res = await fetch(fullPath, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || body.error || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }

  const contentType = res.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    const text = await res.text();
    throw new Error(
      `Expected JSON from ${fullPath}, got ${contentType}. Preview: ${text.slice(0, 200)}`
    );
  }

  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ ok: boolean; version: string }>("/health"),
  status: (mode: Mode) => http<StatusSummary>(`/status?mode=${mode}`),
  config: () => http<{ config_path: string; exists: boolean; content: string }>("/config"),
  getSettings: () => http<Record<string, any>>("/settings"),
  saveSettings: (patch: Record<string, any>) =>
    http<Record<string, any>>("/settings", { method: "POST", body: JSON.stringify(patch) }),

  projects: (mode: Mode) => http<Project[]>(`/projects?mode=${mode}`),
  projectFunctions: (id: string, mode: Mode) =>
    http<FunctionRow[]>(`/projects/${encodeURIComponent(id)}/functions?mode=${mode}`),
  functions: (mode: Mode) => http<FunctionRow[]>(`/functions?mode=${mode}`),
  kgs: (mode: Mode) => http<FunctionRow[]>(`/kgs?mode=${mode}`),
  kgDetail: (id: string, mode: Mode) =>
    http<FunctionRow>(`/kgs/${encodeURIComponent(id)}?mode=${mode}`),
  kgGraph: (id: string, opts: { limit?: number; node_type?: string; function?: string } = {}) => {
    const q = new URLSearchParams();
    if (opts.limit) q.set("limit", String(opts.limit));
    if (opts.node_type) q.set("node_type", opts.node_type);
    if (opts.function) q.set("function", opts.function);
    return http<KgGraph>(`/kgs/${encodeURIComponent(id)}/graph?${q.toString()}`);
  },

  jobs: () => http<Job[]>("/jobs"),
  job: (id: string) => http<Job>(`/jobs/${id}`),
  createJob: (body: Record<string, any>) =>
    http<Job>("/jobs", { method: "POST", body: JSON.stringify(body) }),
  cancelJob: (id: string) =>
    http<{ ok: boolean; message: string }>(`/jobs/${id}/cancel`, { method: "POST" }),
  resumeJob: (id: string) => http<Job>(`/jobs/${id}/resume`, { method: "POST" }),
  jobEvents: (id: string) => http<any[]>(`/jobs/${id}/events`),
  jobLogs: (id: string, tail = 500) =>
    http<{ job_id: string; lines: string[]; total?: number }>(`/jobs/${id}/logs?tail=${tail}`),

  inventorySummary: (mode: Mode) => http<Record<string, any>>(`/inventory-summary?mode=${mode}`),
  jobFile: (id: string, name: string) =>
    http<{ job_id: string; name: string; content: string }>(`/jobs/${id}/file?name=${encodeURIComponent(name)}`),

  validationReport: () => http<Record<string, any>>("/reports/validation"),
  evaluationReport: () => http<Record<string, any>>("/reports/evaluation"),
  disk: () => http<DiskInfo>("/disk"),
  leakage: () => http<{ ok: boolean; flagged: any[]; checked: number }>("/leakage"),
  challenges: () => http<{ challenge_root: string; name: string }[]>("/challenges"),

  kgBackends: () =>
    httpFull<{
      options: {
        id: string;
        label: string;
        description: string;
        requires_joern: boolean;
        speed: string;
        accuracy: string;
        recommended: boolean;
        effective_backend: string;
        config: Record<string, any>;
        extra_config: Record<string, any>;
      }[];
      allowed_backend_values: string[];
    }>("/api/kg/backends"),

  llmProfiles: () =>
    httpFull<any[]>("/api/llm/profiles"),
  llmHealth: (profileId: string) =>
    httpFull<any>(`/api/llm/profiles/${encodeURIComponent(profileId)}/health`, { method: "POST" }),
  llmDiscoverModels: (profileId: string) =>
    httpFull<any>(`/api/llm/profiles/${encodeURIComponent(profileId)}/models`, { method: "POST" }),
  llmTestChat: (body: { profile_id: string; model: string; prompt: string }) =>
    httpFull<any>("/api/llm/test-chat", { method: "POST", body: JSON.stringify(body) }),
};
