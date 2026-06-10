import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../state";
import MetricCard from "../components/MetricCard";

export default function EvaluationPage() {
  const nav = useNavigate();
  const report = useAsync(() => api.evaluationReport(), []);
  const [form, setForm] = useState({
    solution: "",
    input: "",
    labels: "",
    api_base: "http://127.0.0.1:8000",
    limit: "",
  });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const set = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));
  const m = report.data?.metrics || {};

  const run = async () => {
    setMsg(null);
    if (!form.solution || !form.input) {
      setMsg("solution and input CSV are required.");
      return;
    }
    setBusy(true);
    try {
      const body: Record<string, any> = {
        type: "evaluate_solution",
        solution: form.solution,
        input: form.input,
        api_base: form.api_base,
      };
      if (form.labels) body.labels = form.labels;
      if (form.limit) body.limit = Number(form.limit);
      const job = await api.createJob(body);
      nav(`/live/${job.job_id}`);
    } catch (e: any) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Evaluation</h1>
      <p className="page-sub">Run a student <code>solution.py</code> through the controlled recursive agent loop.</p>

      <div className="grid cols-2">
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Run evaluation</h3>
          <label className="field"><span>solution.py path</span>
            <input type="text" value={form.solution} onChange={(e) => set("solution", e.target.value)} placeholder=".../public/student_kit/solution.py" /></label>
          <label className="field"><span>input CSV (test.csv)</span>
            <input type="text" value={form.input} onChange={(e) => set("input", e.target.value)} placeholder=".../public/test.csv" /></label>
          <label className="field"><span>labels CSV (optional, admin)</span>
            <input type="text" value={form.labels} onChange={(e) => set("labels", e.target.value)} placeholder=".../private/test_labels.csv" /></label>
          <label className="field"><span>API base (running KG serve)</span>
            <input type="text" value={form.api_base} onChange={(e) => set("api_base", e.target.value)} /></label>
          <label className="field"><span>limit (optional)</span>
            <input type="number" value={form.limit} onChange={(e) => set("limit", e.target.value)} /></label>
          {msg && <div className="banner err">{msg}</div>}
          <div className="btn-row">
            <button className="btn primary" disabled={busy} onClick={run}>{busy ? "Starting…" : "Run evaluator"}</button>
          </div>
          <p className="muted" style={{ marginTop: 10 }}>
            Requires the KG retrieval API (<code>serve</code>) to be running at the API base above.
          </p>
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Latest metrics</h3>
          {report.loading ? (
            <div className="empty">Loading…</div>
          ) : Object.keys(m).length === 0 ? (
            <p className="muted">{report.data?.message || "No completed evaluation found."}</p>
          ) : (
            <>
              <div className="grid cols-2">
                <MetricCard label="Accuracy" value={fmtPct(m.accuracy)} accent="blue" />
                <MetricCard label="F1" value={fmtPct(m.f1)} />
                <MetricCard label="Precision" value={fmtPct(m.precision)} />
                <MetricCard label="Recall" value={fmtPct(m.recall)} />
              </div>
              <dl className="kv" style={{ marginTop: 12 }}>
                <dt>TP / FP</dt><dd>{m.tp ?? "—"} / {m.fp ?? "—"}</dd>
                <dt>FN / TN</dt><dd>{m.fn ?? "—"} / {m.tn ?? "—"}</dd>
              </dl>
            </>
          )}
          <button className="btn" onClick={report.reload} style={{ marginTop: 8 }}>Refresh metrics</button>
        </div>
      </div>
    </div>
  );
}

function fmtPct(v: any): string {
  if (typeof v !== "number") return "—";
  return v <= 1 ? `${(v * 100).toFixed(1)}%` : v.toFixed(3);
}
