import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { research, type ResearchRun, type ResearchSample } from "../api/research";
import { useAsync } from "../state";

export default function ResearchRunsPage() {
  const nav = useNavigate();
  const runs = useAsync(() => research.runs(), []);
  const [open, setOpen] = useState<string | null>(null);
  const [samples, setSamples] = useState<ResearchSample[]>([]);

  useEffect(() => {
    if (open) research.samples(open).then(setSamples).catch(() => setSamples([]));
  }, [open]);

  return (
    <div>
      <h1 className="page-title">Research Audit — Runs</h1>
      <p className="page-sub">Past and in-progress agentic audit runs (from <code>outputs/runs</code> and dashboard jobs).</p>
      <button className="btn" onClick={runs.reload} style={{ marginBottom: 12 }}>Refresh</button>

      {(runs.data || []).length === 0 && <div className="empty">No runs yet. Start one from Run Audit.</div>}

      {(runs.data || []).map((r: ResearchRun) => (
        <div className="card" key={r.run_id} style={{ marginBottom: 10 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button className="btn" onClick={() => setOpen(open === r.run_id ? null : r.run_id)}>
              {open === r.run_id ? "▾" : "▸"}
            </button>
            <strong className="mono">{r.run_id}</strong>
            {r.is_job_run && <span className="badge blue">dashboard job</span>}
            <span className="badge gray">{r.samples} samples</span>
            {r.metrics?.f1 != null && <span className="badge green">F1 {Number(r.metrics.f1).toFixed(2)}</span>}
            <span style={{ flex: 1 }} />
            <span className="muted">{new Date(r.mtime * 1000).toLocaleString()}</span>
          </div>

          {open === r.run_id && (
            <div className="table-wrap" style={{ marginTop: 12 }}>
              <table>
                <thead>
                  <tr><th>Sample</th><th>Function</th><th>Prediction</th><th>Confidence</th><th>Status</th><th></th></tr>
                </thead>
                <tbody>
                  {samples.map((s) => (
                    <tr key={s.sample_id}>
                      <td className="mono">{s.sample_id}</td>
                      <td>{s.function_name}</td>
                      <td>
                        {s.prediction === "vulnerable" ? <span className="badge red">vulnerable</span>
                          : s.prediction === "safe" ? <span className="badge green">safe</span>
                          : <span className="badge gray">—</span>}
                      </td>
                      <td>{s.confidence != null ? `${(s.confidence * 100).toFixed(0)}%` : "—"}</td>
                      <td className="muted">{s.decision_status || "—"}</td>
                      <td>
                        <a onClick={() => nav(`/research/trace/${r.run_id}/${s.sample_id}`)} style={{ marginRight: 10 }}>Trace</a>
                        <a onClick={() => nav(`/research/kg/${r.run_id}/${s.sample_id}`)}>KG flow</a>
                      </td>
                    </tr>
                  ))}
                  {samples.length === 0 && <tr><td colSpan={6} className="empty">No samples in this run.</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
