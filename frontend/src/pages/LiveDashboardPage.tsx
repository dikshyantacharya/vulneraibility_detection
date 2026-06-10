import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { subscribeEvents, subscribeJob } from "../api/websocket";
import { fmtDuration, useAsync } from "../state";
import type { DashboardEvent, Job } from "../api/types";
import JobStatusBadge from "../components/JobStatusBadge";
import LogViewer, { LogLine } from "../components/LogViewer";
import MetricCard from "../components/MetricCard";

interface Progress {
  processed?: number;
  total?: number;
  ready?: number;
  skipped?: number;
  failed?: number;
  vuln?: number;
  safe?: number;
  eta_seconds?: number;
  rate_per_minute?: number;
  project?: string;
  function?: string;
  phase?: string;
}

export default function LiveDashboardPage() {
  const { jobId } = useParams();
  const nav = useNavigate();
  const jobsRes = useAsync(() => api.jobs(), []);
  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const [progress, setProgress] = useState<Progress>({});
  const [job, setJob] = useState<Job | null>(null);
  const seen = useRef(0);

  // pick active or selected job
  const activeJob = useMemo(() => {
    if (jobId) return jobId;
    const running = (jobsRes.data || []).find((j) => j.status === "running");
    return running?.job_id;
  }, [jobId, jobsRes.data]);

  useEffect(() => {
    if (!activeJob) return;
    setEvents([]);
    setProgress({});
    api.job(activeJob).then(setJob).catch(() => {});
    const h = subscribeJob(activeJob, (e) => {
      setEvents((prev) => [...prev.slice(-800), e]);
      if (e.type === "progress" && e.data) {
        setProgress((p) => ({ ...p, ...e.data, phase: e.phase || p.phase }));
      }
      if (e.type === "status" && /finished|error/.test(e.message || "")) {
        api.job(activeJob).then(setJob).catch(() => {});
      }
    });
    return () => h.close();
  }, [activeJob]);

  const logs: LogLine[] = events.map((e) => ({
    text: `${new Date(e.timestamp).toLocaleTimeString()}  ${e.message || JSON.stringify(e.data)}`,
    level: e.level && e.level !== "info" ? e.level : undefined,
  }));
  const errors = events.filter((e) => e.level === "error");
  const recent = [...events].reverse().slice(0, 12);

  const pct = progress.total ? Math.round(((progress.processed || 0) / progress.total) * 100) : 0;

  const cancel = async () => {
    if (activeJob) {
      await api.cancelJob(activeJob);
      api.job(activeJob).then(setJob).catch(() => {});
    }
  };
  const resume = async () => {
    if (activeJob) {
      const j = await api.resumeJob(activeJob);
      nav(`/live/${j.job_id}`);
    }
  };

  return (
    <div>
      <h1 className="page-title">Live Dashboard</h1>
      <p className="page-sub">Real-time progress &amp; logs over WebSocket. History replays on refresh.</p>

      {!activeJob && (
        <div className="card">
          <p className="muted">No running job. Recent jobs:</p>
          <div className="btn-row">
            {(jobsRes.data || []).slice(0, 8).map((j) => (
              <button key={j.job_id} className="btn" onClick={() => nav(`/live/${j.job_id}`)}>
                {j.type} · {j.status}
              </button>
            ))}
            {(jobsRes.data || []).length === 0 && <span className="muted">none yet — start one from Build.</span>}
          </div>
        </div>
      )}

      {activeJob && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
              {job && <JobStatusBadge status={job.status} />}
              <strong>{job?.type}</strong>
              <span className="mono muted">{activeJob}</span>
              {progress.phase && <span className="badge blue">{progress.phase}</span>}
              <span style={{ flex: 1 }} />
              <div className="btn-row">
                <button className="btn danger" disabled={job?.status !== "running"} onClick={cancel}>Cancel</button>
                <button className="btn" onClick={resume}>Resume (relaunch)</button>
              </div>
            </div>
            <div className="progress"><div style={{ width: `${pct}%` }} /></div>
            <div className="muted" style={{ marginTop: 6 }}>
              {progress.processed ?? 0}/{progress.total ?? "?"} ({pct}%)
              {progress.project ? ` · ${progress.project}` : ""}
              {progress.function ? ` / ${progress.function}` : ""}
            </div>
          </div>

          <div className="grid cols-4">
            <MetricCard label="Ready" value={progress.ready ?? "—"} accent="green" />
            <MetricCard label="Skipped" value={progress.skipped ?? "—"} accent="amber" />
            <MetricCard label="Failed" value={progress.failed ?? "—"} accent={progress.failed ? "red" : undefined} />
            <MetricCard label="ETA" value={fmtDuration(progress.eta_seconds)} sub={progress.rate_per_minute ? `${progress.rate_per_minute}/min` : undefined} />
          </div>

          <div className="grid cols-2" style={{ marginTop: 16 }}>
            <div className="card">
              <h3 className="section-title" style={{ marginTop: 0 }}>Live log</h3>
              <LogViewer lines={logs} />
            </div>
            <div className="card">
              <h3 className="section-title" style={{ marginTop: 0 }}>
                Recent events {errors.length > 0 && <span className="badge red">{errors.length} errors</span>}
              </h3>
              <div style={{ maxHeight: 360, overflowY: "auto" }}>
                {recent.map((e, i) => (
                  <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                    <span className={`badge ${e.level === "error" ? "red" : e.type === "agent_query" ? "blue" : "gray"}`}>{e.type}</span>{" "}
                    <span className="mono" style={{ fontSize: 12 }}>{e.message?.slice(0, 110)}</span>
                  </div>
                ))}
                {recent.length === 0 && <span className="muted">waiting for events…</span>}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
