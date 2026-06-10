import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { research, type ResearchRun, type ResearchSample, type RunSummary } from "../api/research";
import { useApp, useAsync } from "../state";

function providerModel(s?: RunSummary): string {
  if (!s) return "—";
  const p = s.llm?.provider_name || s.llm?.model_backend || "—";
  const m = s.llm?.model || "—";
  return `${p} · ${m}`;
}

export default function ResearchRunsPage() {
  const nav = useNavigate();
  const { mode } = useApp();
  const runs = useAsync(() => research.runs(), []);
  const [open, setOpen] = useState<string | null>(null);
  const [samples, setSamples] = useState<ResearchSample[]>([]);
  const [summaries, setSummaries] = useState<Record<string, RunSummary>>({});

  useEffect(() => {
    if (open) research.samples(open).then(setSamples).catch(() => setSamples([]));
  }, [open]);

  // Enrich each run with the real provider/model/KG/metrics summary.
  useEffect(() => {
    (runs.data || []).forEach((r) => {
      if (!summaries[r.run_id]) {
        research.runSummary(r.run_id, mode).then((s) =>
          setSummaries((prev) => ({ ...prev, [r.run_id]: s }))
        ).catch(() => {});
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runs.data, mode]);

  return (
    <div>
      <h1 className="page-title">Research Audit — Runs</h1>
      <p className="page-sub">Past and in-progress agentic audit runs with real provider/model and metrics.</p>
      <button className="btn" onClick={() => { runs.reload(); setSummaries({}); }} style={{ marginBottom: 12 }}>Refresh</button>

      {(runs.data || []).length === 0 && <div className="empty">No runs yet. Start one from Run Audit.</div>}

      {(runs.data || []).map((r: ResearchRun) => {
        const s = summaries[r.run_id];
        const m = s?.metrics;
        return (
          <div className="card" key={r.run_id} style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <button className="btn" onClick={() => setOpen(open === r.run_id ? null : r.run_id)}>
                {open === r.run_id ? "▾" : "▸"}
              </button>
              <strong className="mono">{r.run_id}</strong>
              {s?.status && <span className={`badge ${s.status === "completed" ? "green" : s.status === "failed" ? "red" : s.status === "running" ? "blue" : "gray"}`}>{s.status}</span>}
              {r.is_job_run && <span className="badge blue">dashboard job</span>}
              <span style={{ flex: 1 }} />
              <span className="muted">{new Date(r.mtime * 1000).toLocaleString()}</span>
            </div>

            <dl className="kv" style={{ fontSize: 12, marginTop: 10 }}>
              <dt>LLM</dt><dd><strong>{providerModel(s)}</strong></dd>
              <dt>Server</dt><dd className="mono">{s?.llm?.base_url || "—"}</dd>
              <dt>KG</dt><dd>{s?.kg?.display_name || s?.kg?.preset || "—"} → <span className="mono">{s?.kg?.effective_backend || "—"}</span></dd>
              <dt>Config</dt><dd className="mono">{s?.config_name || "—"}</dd>
              <dt>Samples</dt>
              <dd>
                {s ? `${s.samples_completed}/${s.samples_requested} completed` : `${r.samples} samples`}
                {s?.samples_failed ? ` · ${s.samples_failed} failed` : ""}
                {(s as any)?.samples_pending ? ` · ${(s as any).samples_pending} pending` : ""}
                {s?.selection?.exact_sample_ids_only ? " · exact mode" : ""}
              </dd>
              <dt>Tokens</dt><dd>{s?.usage?.total_tokens ?? "—"} {s?.usage?.cost_total_usd != null ? `· $${Number(s.usage.cost_total_usd).toFixed(4)}` : ""}</dd>
              <dt>Metrics</dt>
              <dd>
                {s && !s.metrics_available ? (
                  <span className="muted">Metrics unavailable: {s.metrics_reason}</span>
                ) : m ? (
                  <>
                    <span className="badge gray">acc {Number(m.accuracy).toFixed(2)}</span>{" "}
                    <span className="badge gray">P {Number(m.precision).toFixed(2)}</span>{" "}
                    <span className="badge gray">R {Number(m.recall).toFixed(2)}</span>{" "}
                    <span className="badge green">F1 {Number(m.f1).toFixed(2)}</span>{" "}
                    <span className="muted">TP {m.tp} · FP {m.fp} · FN {m.fn} · TN {m.tn}</span>
                    {(s as any)?.metrics_note && <span className="badge amber" style={{ marginLeft: 6 }}>{(s as any).metrics_note}</span>}
                  </>
                ) : <span className="muted">—</span>}
              </dd>
            </dl>

            {open === r.run_id && (
              <div className="table-wrap" style={{ marginTop: 12 }}>
                <table>
                  <thead>
                    <tr><th>Sample</th><th>Function</th><th>Prediction</th><th>Confidence</th><th>Status</th><th></th></tr>
                  </thead>
                  <tbody>
                    {samples.map((sm) => (
                      <tr key={sm.sample_id}>
                        <td className="mono">{sm.sample_id}</td>
                        <td>{sm.function_name}</td>
                        <td>
                          {sm.prediction === "vulnerable" ? <span className="badge red">vulnerable</span>
                            : sm.prediction === "safe" ? <span className="badge green">safe</span>
                            : <span className="badge gray">—</span>}
                        </td>
                        <td>{sm.confidence != null ? `${(sm.confidence * 100).toFixed(0)}%` : "—"}</td>
                        <td className="muted">{sm.decision_status || "—"}</td>
                        <td>
                          <a onClick={() => nav(`/research/trace/${r.run_id}/${sm.sample_id}`)} style={{ marginRight: 10, cursor: "pointer" }}>Trace</a>
                          <a onClick={() => nav(`/research/kg/${r.run_id}/${sm.sample_id}`)} style={{ cursor: "pointer" }}>KG flow</a>
                        </td>
                      </tr>
                    ))}
                    {samples.length === 0 && <tr><td colSpan={6} className="empty">No samples in this run.</td></tr>}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
