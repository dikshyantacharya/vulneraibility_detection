import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { research, type LiveMetrics } from "../api/research";
import { subscribeJob } from "../api/websocket";
import { fmtDuration, useApp, useDashboard } from "../state";
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
  const { mode } = useApp();
  const { jobs: allJobs } = useDashboard();
  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const [progress, setProgress] = useState<Progress>({});
  const [job, setJob] = useState<Job | null>(null);
  const [metrics, setMetrics] = useState<LiveMetrics | null>(null);
  const seen = useRef(0);

  // Resolve this job's research run_id (dashboard runs live at <job>/runs/<id>)
  // and fetch live classification metrics — admin mode only (uses labels).
  const refetchMetrics = (jid?: string) => {
    if (!jid || mode !== "admin") return;
    research.runs()
      .then((rs) => rs.find((r) => r.is_job_run && r.path.includes(jid)))
      .then((run) => run && research.runMetrics(run.run_id, mode).then(setMetrics))
      .catch(() => {});
  };

  // pick active or selected job (job list comes from the central WS store)
  const activeJob = useMemo(() => {
    if (jobId) return jobId;
    const running = allJobs.find((j) => j.status === "running");
    return running?.job_id;
  }, [jobId, allJobs]);

  useEffect(() => {
    if (!activeJob) return;
    setEvents([]);
    setProgress({});
    setMetrics(null);
    api.job(activeJob).then(setJob).catch(() => {});
    refetchMetrics(activeJob);
    const h = subscribeJob(activeJob, (e) => {
      setEvents((prev) => [...prev.slice(-800), e]);
      if (e.type === "progress" && e.data) {
        setProgress((p) => ({ ...p, ...e.data, phase: e.phase || p.phase }));
      }
      // A completed sample / finished run updates live metrics (no polling).
      if (e.type === "status" || (e.message || "").includes("sample")) {
        if (/finished|error|done|sample/.test(e.message || "")) {
          api.job(activeJob).then(setJob).catch(() => {});
          refetchMetrics(activeJob);
        }
      }
    });
    return () => h.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeJob, mode]);

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
            {allJobs.slice(0, 8).map((j) => (
              <button key={j.job_id} className="btn" onClick={() => nav(`/live/${j.job_id}`)}>
                {j.type} · {j.status}
              </button>
            ))}
            {allJobs.length === 0 && <span className="muted">none yet — start one from Build.</span>}
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

          {/* Live classification metrics (admin mode only — uses labels) */}
          {mode === "admin" && (
            <div style={{ marginTop: 16 }}>
              <div className="section-title">Live classification metrics</div>
              {!metrics || !metrics.available ? (
                <div className="banner warn">
                  {metrics?.reason || "Metrics pending — no completed labeled predictions yet."}
                </div>
              ) : (
                <>
                  {metrics.single_sample && (
                    <div className="banner warn">Single-sample run — metrics are unstable (not statistically meaningful).</div>
                  )}
                  <div className="grid cols-4">
                    <MetricCard label="Processed" value={metrics.processed ?? 0} />
                    <MetricCard label="Accuracy" value={metrics.accuracy != null ? Number(metrics.accuracy).toFixed(2) : "—"} accent="blue" />
                    <MetricCard label="Precision / Recall" value={`${Number(metrics.precision ?? 0).toFixed(2)} / ${Number(metrics.recall ?? 0).toFixed(2)}`} />
                    <MetricCard label="F1" value={metrics.f1 != null ? Number(metrics.f1).toFixed(2) : "—"} accent="green" />
                  </div>
                  <div className="grid cols-2" style={{ marginTop: 8 }}>
                    <div className="card">
                      <h3 className="section-title" style={{ marginTop: 0 }}>Confusion matrix</h3>
                      <table className="cm">
                        <tbody>
                          <tr><td className="muted"></td><td className="muted">pred vuln</td><td className="muted">pred safe</td></tr>
                          <tr><td className="muted">true vuln</td><td><span className="badge green">TP {metrics.tp}</span></td><td><span className="badge red">FN {metrics.fn}</span></td></tr>
                          <tr><td className="muted">true safe</td><td><span className="badge red">FP {metrics.fp}</span></td><td><span className="badge green">TN {metrics.tn}</span></td></tr>
                        </tbody>
                      </table>
                      <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                        Vulnerable recall {Number(metrics.vulnerable_recall ?? 0).toFixed(2)} · Safe recall {Number(metrics.safe_recall ?? 0).toFixed(2)}
                      </div>
                    </div>
                    <div className="card">
                      <h3 className="section-title" style={{ marginTop: 0 }}>Per-sample</h3>
                      <div style={{ maxHeight: 220, overflowY: "auto" }}>
                        <table>
                          <thead><tr><th>Sample</th><th>True</th><th>Pred</th><th>Result</th><th>Conf</th></tr></thead>
                          <tbody>
                            {(metrics.per_sample || []).map((p: any) => (
                              <tr key={p.sample_id}>
                                <td className="mono">{p.sample_id}</td>
                                <td>{p.true_label}</td>
                                <td>{p.prediction}</td>
                                <td>{p.correct ? <span className="badge green">✓</span> : <span className="badge red">✗ {p.outcome}</span>}</td>
                                <td>{p.confidence != null ? `${(p.confidence * 100).toFixed(0)}%` : "—"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

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
