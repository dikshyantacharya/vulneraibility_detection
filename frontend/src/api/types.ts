export type Mode = "admin" | "student";

export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface DashboardEvent {
  type: string;
  job_id: string;
  timestamp: string;
  phase?: string | null;
  level?: string;
  message?: string;
  data?: Record<string, any>;
}

export interface Job {
  job_id: string;
  type: string;
  params: Record<string, any>;
  status: JobStatus;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  return_code?: number | null;
  error?: string | null;
  dir: string;
}

export interface Project {
  project_id: string;
  project: string;
  repo_key?: string;
  project_url?: string;
  function_count: number;
  kg_built: number;
  vuln?: number;
  safe?: number;
  splits: Record<string, number>;
}

export interface FunctionRow {
  knowledge_graph_id: string;
  sample_id?: string;
  project?: string;
  filepath?: string;
  function_name?: string;
  split?: string;
  resolved_commit_prefix?: string;
  target_status?: string;
  label?: number;
}

export interface StatusSummary {
  challenge_root: string;
  challenge_exists: boolean;
  default_mode: Mode;
  active_jobs: number;
  total_jobs: number;
  projects?: number;
  functions?: number;
  kgs?: number;
  split_counts?: Record<string, number>;
  label_balance?: Record<string, number>;
  validation_ok?: boolean | null;
}

export interface GraphNode {
  id: string;
  type?: string;
  label?: string;
  name?: string;
  file?: string;
  function?: string;
  line_start?: number;
  line_end?: number;
  code?: string;
  degree?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  type?: string;
  id?: string;
}

export interface KgGraph {
  knowledge_graph_id: string;
  node_count: number;
  edge_count: number;
  node_type_distribution: Record<string, number>;
  edge_type_distribution: Record<string, number>;
  returned_nodes: GraphNode[];
  returned_edges: GraphEdge[];
  truncated: boolean;
}

export interface DiskInfo {
  drive_total_bytes: number;
  drive_used_bytes: number;
  drive_free_bytes: number;
  drive_percent_used: number;
  challenge_size_bytes?: number;
}
