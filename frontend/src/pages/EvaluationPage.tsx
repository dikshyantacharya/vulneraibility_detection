import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../state";
import MetricCard from "../components/MetricCard";

export default function EvaluationPage() {
  const nav = useNavigate();
  const report = useAsync(() => api.evaluationReport(), []);
  const llmDefaults = useAsync(() => api.studentLlmDefaults(), []);
  const [form, setForm] = useState({
    solution: "student_solutions/solution_agentic_research_like.py",
    train: "outputs/student_challenge/vckg_codekg_student_challenge/public/train.csv",
    train_limit: "",
    input: "outputs/student_challenge/vckg_codekg_student_challenge/public/test.csv",
    labels: "outputs/student_challenge/vckg_codekg_student_challenge/private/test_labels.csv",
    api_base: "http://127.0.0.1:8000",
    api_key: "dev-key-KG",
    limit: "5",
    max_rounds: "10",
    max_queries_per_round: "3",
    max_queries_per_sample: "18",
    max_nodes_per_query: "500",
    timeout_per_sample_seconds: "300",
    llm_enabled: false,
    llm_api_base: "",
    llm_model: "",
    llm_api_key_env: "",
  });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const set = (k: string, v: string | boolean) => setForm((f) => ({ ...f, [k]: v }));

  useEffect(() => {
    const d = llmDefaults.data;
    if (!d) return;
    setForm((f) => ({
      ...f,
      llm_enabled: Boolean(d.llm_enabled),
      llm_api_base: f.llm_api_base || d.llm_api_base || "",
      llm_model: f.llm_model || d.llm_model || "",
      llm_api_key_env: f.llm_api_key_env || d.llm_api_key_env || "",
    }));
  }, [llmDefaults.data]);

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
        api_key: form.api_key,
      };
      if (form.train) body.train = form.train;
      if (form.labels) body.labels = form.labels;
      for (const k of ["limit", "train_limit", "max_rounds", "max_queries_per_round", "max_queries_per_sample", "max_nodes_per_query", "timeout_per_sample_seconds"]) {
        const v = (form as any)[k];
        if (v !== "" && v != null) body[k] = Number(v);
      }
      if (form.llm_enabled) {
        body.llm_enabled = true;
        if (form.llm_api_base) body.llm_api_base = form.llm_api_base;
        if (form.llm_model) body.llm_model = form.llm_model;
        if (form.llm_api_key_env) body.llm_api_key_env = form.llm_api_key_env;
      }
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
      <p className="page-sub">Run a student <code>solution.py</code> through the controlled KG-query loop and inspect its internal agentic trace.</p>

      <div className="grid cols-2">
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Run evaluation</h3>
          <label className="field"><span>solution.py path</span>
            <input type="text" value={form.solution} onChange={(e) => set("solution", e.target.value)} /></label>
          <label className="field"><span>train CSV (optional)</span>
            <input type="text" value={form.train} onChange={(e) => set("train", e.target.value)} /></label>
          <label className="field"><span>train row limit (optional)</span>
            <input type="number" min="0" placeholder="blank = all train rows" value={form.train_limit} onChange={(e) => set("train_limit", e.target.value)} />
            <small className="muted">Use this to fit/test with only the first N training functions.</small>
          </label>
          <label className="field"><span>input CSV (test.csv)</span>
            <input type="text" value={form.input} onChange={(e) => set("input", e.target.value)} /></label>
          <label className="field"><span>labels CSV (optional, admin)</span>
            <input type="text" value={form.labels} onChange={(e) => set("labels", e.target.value)} /></label>
          <div className="grid cols-2">
            <label className="field"><span>API base (running KG serve)</span>
              <input type="text" value={form.api_base} onChange={(e) => set("api_base", e.target.value)} /></label>
            <label className="field"><span>KG API key</span>
              <input type="text" value={form.api_key} onChange={(e) => set("api_key", e.target.value)} /></label>
            <label className="field"><span>limit</span>
              <input type="number" value={form.limit} onChange={(e) => set("limit", e.target.value)} /></label>
            <label className="field"><span>max rounds</span>
              <input type="number" value={form.max_rounds} onChange={(e) => set("max_rounds", e.target.value)} /></label>
            <label className="field"><span>queries / round</span>
              <input type="number" value={form.max_queries_per_round} onChange={(e) => set("max_queries_per_round", e.target.value)} /></label>
            <label className="field"><span>queries / sample</span>
              <input type="number" value={form.max_queries_per_sample} onChange={(e) => set("max_queries_per_sample", e.target.value)} /></label>
            <label className="field"><span>max nodes / query</span>
              <input type="number" value={form.max_nodes_per_query} onChange={(e) => set("max_nodes_per_query", e.target.value)} /></label>
            <label className="field"><span>timeout / sample sec</span>
              <input type="number" value={form.timeout_per_sample_seconds} onChange={(e) => set("timeout_per_sample_seconds", e.target.value)} /></label>
          </div>

          <div className="card soft" style={{ marginTop: 12 }}>
            <h4 className="section-title" style={{ marginTop: 0 }}>Student LLM defaults</h4>
            {llmDefaults.loading ? (
              <p className="muted">Loading LLM defaults…</p>
            ) : llmDefaults.data ? (
              <dl className="kv">
                <dt>Provider</dt><dd>{llmDefaults.data.display_name || llmDefaults.data.profile_id || "—"}</dd>
                <dt>API base</dt><dd className="mono">{llmDefaults.data.llm_api_base || "—"}</dd>
                <dt>Model</dt><dd className="mono">{llmDefaults.data.llm_model || "—"}</dd>
                <dt>API key env</dt><dd className="mono">{llmDefaults.data.llm_api_key_env || "—"} · {llmDefaults.data.llm_api_key_present ? "present" : "missing"}</dd>
                <dt>Env folder</dt><dd className="mono">{llmDefaults.data.env_files_hint || "—"}</dd>
              </dl>
            ) : (
              <p className="muted">No student LLM defaults available.</p>
            )}
            <small className="muted">The browser never receives the API key value. The backend only passes the env var name to solution.py.</small>
          </div>

          <label className="field" style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={form.llm_enabled} onChange={(e) => set("llm_enabled", e.target.checked)} />
            <span>Enable LLM calls inside student solution using the defaults above</span>
          </label>
          {form.llm_enabled && (
            <div className="grid cols-2">
              <label className="field"><span>LLM API base</span>
                <input type="text" value={form.llm_api_base} onChange={(e) => set("llm_api_base", e.target.value)} /></label>
              <label className="field"><span>LLM model</span>
                <input type="text" value={form.llm_model} onChange={(e) => set("llm_model", e.target.value)} /></label>
              <label className="field"><span>LLM API key env</span>
                <input type="text" value={form.llm_api_key_env} onChange={(e) => set("llm_api_key_env", e.target.value)} /></label>
            </div>
          )}
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
              {report.data?.job_id && <a className="btn" href={`/audit`}>Open Student Agent Audit</a>}
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
