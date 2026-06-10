import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../state";
import type { DashboardEvent, Job } from "../api/types";

interface QueryRow {
  index: number;
  kind?: string;
  reason?: string;
  nodes?: number;
  edges?: number;
  cacheHit?: boolean;
  time?: number;
  raw: DashboardEvent;
}

export default function AgentAuditPage() {
  const jobsRes = useAsync(() => api.jobs(), []);
  const evalJobs = useMemo(
    () => (jobsRes.data || []).filter((j) => j.type === "evaluate_solution"),
    [jobsRes.data]
  );
  const [jobId, setJobId] = useState<string>("");
  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const [sample, setSample] = useState<string>("");
  const [queryFilter, setQueryFilter] = useState<number | "all">("all");

  useEffect(() => {
    if (!jobId && evalJobs.length) setJobId(evalJobs[0].job_id);
  }, [evalJobs, jobId]);

  useEffect(() => {
    if (!jobId) return;
    api.jobEvents(jobId).then((evs) => setEvents(evs as DashboardEvent[])).catch(() => setEvents([]));
  }, [jobId]);

  const bySample = useMemo(() => {
    const m = new Map<string, QueryRow[]>();
    events
      .filter((e) => e.type === "agent_query")
      .forEach((e) => {
        const d = e.data || {};
        const sid = String(d.sample ?? d.sample_id ?? "unknown");
        const arr = m.get(sid) || [];
        arr.push({
          index: arr.length + 1,
          kind: d.kind || d.query_kind,
          reason: d.reason,
          nodes: d.nodes ?? d.retrieved_node_count,
          edges: d.edges ?? d.retrieved_edge_count,
          cacheHit: d.engine_cache_hit,
          time: d.time_seconds,
          raw: e,
        });
        m.set(sid, arr);
      });
    return m;
  }, [events]);

  const samples = Array.from(bySample.keys());
  useEffect(() => {
    if (!sample && samples.length) setSample(samples[0]);
  }, [samples, sample]);

  const queries = sample ? bySample.get(sample) || [] : [];
  const shownQueries = queryFilter === "all" ? queries : queries.filter((q) => q.index === queryFilter);

  return (
    <div>
      <h1 className="page-title">Agent Audit</h1>
      <p className="page-sub">Agentic query flow (q1, q2, q3 …) reconstructed from evaluation event logs.</p>

      {evalJobs.length === 0 && (
        <div className="banner warn">
          No <code>evaluate_solution</code> jobs found. Run an evaluation first (Evaluation page) to populate the audit.
        </div>
      )}

      <div className="toolbar">
        <select value={jobId} onChange={(e) => { setJobId(e.target.value); setSample(""); }}>
          <option value="">Select evaluation job…</option>
          {evalJobs.map((j: Job) => (
            <option key={j.job_id} value={j.job_id}>{j.job_id} · {j.status}</option>
          ))}
        </select>
        {samples.length > 0 && (
          <select value={sample} onChange={(e) => { setSample(e.target.value); setQueryFilter("all"); }}>
            {samples.map((s) => (
              <option key={s} value={s}>sample {s} ({bySample.get(s)?.length} queries)</option>
            ))}
          </select>
        )}
        {queries.length > 0 && (
          <select value={String(queryFilter)} onChange={(e) => setQueryFilter(e.target.value === "all" ? "all" : Number(e.target.value))}>
            <option value="all">All queries</option>
            {queries.map((q) => (
              <option key={q.index} value={q.index}>q{q.index} {q.kind || ""}</option>
            ))}
          </select>
        )}
      </div>

      {sample && queries.length === 0 && <div className="empty">No agent_query events for this sample.</div>}

      {shownQueries.map((q) => (
        <div className="card" key={q.index} style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8 }}>
            <span className="badge blue">q{q.index}</span>
            <strong>{q.kind || "query"}</strong>
            {q.cacheHit != null && <span className={`badge ${q.cacheHit ? "green" : "gray"}`}>{q.cacheHit ? "cache hit" : "cache miss"}</span>}
            <span style={{ flex: 1 }} />
            <span className="muted">{q.time != null ? `${q.time.toFixed(2)}s` : ""}</span>
          </div>
          {q.reason && <p style={{ marginTop: 0 }}>{q.reason}</p>}
          <dl className="kv">
            <dt>Retrieved nodes</dt><dd>{q.nodes ?? "—"}</dd>
            <dt>Retrieved edges</dt><dd>{q.edges ?? "—"}</dd>
          </dl>
          <pre className="log-viewer" style={{ height: 90, marginTop: 8 }}>{q.raw.message}</pre>
        </div>
      ))}

      {sample && (
        <div className="banner ok" style={{ marginTop: 8 }}>
          Tip: open the <Link to="/kg">KG Explorer</Link> for this sample's graph. Per-query node highlighting on the
          live graph requires the bounded retrieval API (<code>serve</code>) to be running so retrieved node ids are
          available.
        </div>
      )}
    </div>
  );
}
