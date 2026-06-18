import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useAsync } from "../state";
import type { Job } from "../api/types";

export default function AgentAuditPage() {
  const jobsRes = useAsync(() => api.jobs(), []);
  const evalJobs = useMemo(
    () => (jobsRes.data || []).filter((j) => j.type === "evaluate_solution"),
    [jobsRes.data]
  );
  const [jobId, setJobId] = useState<string>("");
  const [detail, setDetail] = useState<Record<string, any> | null>(null);
  const [sample, setSample] = useState<string>("");
  const [tab, setTab] = useState<"stages" | "queries" | "final" | "raw">("stages");

  useEffect(() => {
    if (!jobId && evalJobs.length) setJobId(evalJobs[0].job_id);
  }, [evalJobs, jobId]);

  useEffect(() => {
    if (!jobId) return;
    api.evaluationDetail(jobId).then((d) => {
      setDetail(d);
      const first = (d.samples || [])[0]?.sample_id || "";
      setSample((s) => s || first);
    }).catch(() => setDetail(null));
  }, [jobId]);

  const samples = detail?.samples || [];
  const trace = (detail?.traces || []).find((t: any) => String(t.sample_id) === String(sample));
  const agenticTrace = trace?.agentic_trace || [];
  const queries = trace?.query_history || [];
  const answer = trace?.answer || {};

  return (
    <div>
      <h1 className="page-title">Student Agent Audit</h1>
      <p className="page-sub">Inspect the submitted <code>solution.py</code> loop: internal agentic stages, KG queries, final decision, and downloadable reports.</p>

      {evalJobs.length === 0 && (
        <div className="banner warn">
          No <code>evaluate_solution</code> jobs found. Run an evaluation first.
        </div>
      )}

      <div className="toolbar">
        <select value={jobId} onChange={(e) => { setJobId(e.target.value); setSample(""); }}>
          <option value="">Select evaluation job…</option>
          {evalJobs.map((j: Job) => (
            <option key={j.job_id} value={j.job_id}>{j.job_id} · {j.status}</option>
          ))}
        </select>
        {jobId && (
          <a className="btn" href={api.evaluationReportsZipUrl(jobId)}>Download all student reports ZIP</a>
        )}
      </div>

      {detail?.metrics && Object.keys(detail.metrics).length > 0 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <strong>Metrics</strong>
          <dl className="kv" style={{ marginTop: 8 }}>
            <dt>Accuracy / F1</dt><dd>{fmtPct(detail.metrics.accuracy)} / {fmtPct(detail.metrics.f1)}</dd>
            <dt>Precision / Recall</dt><dd>{fmtPct(detail.metrics.precision)} / {fmtPct(detail.metrics.recall)}</dd>
            <dt>TP / FP / FN / TN</dt><dd>{detail.metrics.tp ?? "—"} / {detail.metrics.fp ?? "—"} / {detail.metrics.fn ?? "—"} / {detail.metrics.tn ?? "—"}</dd>
          </dl>
        </div>
      )}

      {samples.length > 0 && (
        <div className="grid cols-2">
          <div className="card">
            <h3 className="section-title" style={{ marginTop: 0 }}>Samples</h3>
            <div style={{ maxHeight: 520, overflow: "auto" }}>
              <table className="data-table">
                <thead><tr><th>Sample</th><th>Fn</th><th>Pred</th><th>Stages</th><th>Queries</th></tr></thead>
                <tbody>
                {samples.map((s: any) => (
                  <tr key={s.sample_id} onClick={() => setSample(String(s.sample_id))} style={{ cursor: "pointer", background: String(sample) === String(s.sample_id) ? "#eef2ff" : undefined }}>
                    <td>{s.sample_id}</td>
                    <td>{s.function_name || "—"}</td>
                    <td>{s.prediction == null ? "—" : s.prediction ? "vuln" : "safe"}</td>
                    <td>{s.agentic_stage_count ?? 0}</td>
                    <td>{s.query_count ?? 0}</td>
                  </tr>
                ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <h3 className="section-title" style={{ margin: 0, flex: 1 }}>Sample {sample || "—"}</h3>
              {jobId && sample && <a className="btn" href={api.evaluationSampleReportUrl(jobId, sample)}>Download report</a>}
            </div>
            {!trace ? <div className="empty">No trace selected.</div> : (
              <>
                <dl className="kv" style={{ marginTop: 10 }}>
                  <dt>Prediction</dt><dd>{answer.prediction == null ? "—" : answer.prediction ? "vulnerable" : "safe/non-vulnerable"}</dd>
                  <dt>Confidence</dt><dd>{typeof answer.confidence === "number" ? `${(answer.confidence * 100).toFixed(1)}%` : "—"}</dd>
                  <dt>Decision status</dt><dd>{answer.decision_status || "—"}</dd>
                  <dt>Stop reason</dt><dd>{trace.stop_reason || "—"}</dd>
                </dl>
                <div className="btn-row" style={{ marginTop: 10 }}>
                  <button className={`btn ${tab === "stages" ? "primary" : ""}`} onClick={() => setTab("stages")}>Stages</button>
                  <button className={`btn ${tab === "queries" ? "primary" : ""}`} onClick={() => setTab("queries")}>KG Queries</button>
                  <button className={`btn ${tab === "final" ? "primary" : ""}`} onClick={() => setTab("final")}>Final</button>
                  <button className={`btn ${tab === "raw" ? "primary" : ""}`} onClick={() => setTab("raw")}>Raw trace</button>
                </div>
                {tab === "stages" && <StageList stages={agenticTrace} />}
                {tab === "queries" && <QueryList queries={queries} />}
                {tab === "final" && <pre className="log-viewer" style={{ height: 360 }}>{JSON.stringify(answer.final_adjudication || trace.final_adjudication || answer, null, 2)}</pre>}
                {tab === "raw" && <pre className="log-viewer" style={{ height: 420 }}>{JSON.stringify(trace, null, 2)}</pre>}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StageList({ stages }: { stages: any[] }) {
  if (!stages?.length) return <div className="empty">No internal agentic_trace metadata was stored. Use the full-stage solution.py.</div>;
  return <div style={{ marginTop: 12 }}>{stages.map((s, i) => (
    <div className="card" key={i} style={{ marginBottom: 8, padding: 12 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span className="badge blue">{i + 1}</span>
        <strong>{s.stage || s.name || "stage"}</strong>
      </div>
      <pre className="log-viewer" style={{ height: 130, marginTop: 8 }}>{JSON.stringify(s.output ?? s, null, 2)}</pre>
    </div>
  ))}</div>;
}

function QueryList({ queries }: { queries: any[] }) {
  if (!queries?.length) return <div className="empty">No KG queries recorded.</div>;
  return <div style={{ marginTop: 12 }}>{queries.map((q, i) => (
    <div className="card" key={i} style={{ marginBottom: 8, padding: 12 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span className="badge green">q{i + 1}</span>
        <strong>{q.query?.kind || "query"}</strong>
        <span className="muted">round {q.round ?? "—"}</span>
      </div>
      {q.reason && <p>{q.reason}</p>}
      <pre className="log-viewer" style={{ height: 110 }}>{JSON.stringify(q.query, null, 2)}</pre>
    </div>
  ))}</div>;
}

function fmtPct(v: any): string {
  if (typeof v !== "number") return "—";
  return v <= 1 ? `${(v * 100).toFixed(1)}%` : v.toFixed(3);
}
