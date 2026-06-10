import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../state";

export default function BuildPage() {
  const nav = useNavigate();
  const cfg = useAsync(() => api.config(), []);
  const [form, setForm] = useState({
    config_path: "",
    mode: "all",
    limit: "",
    backend: "",
    force_rebuild: false,
    overwrite: false,
    dry_run: false,
    validate_after: false,
  });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }));

  const submit = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const body: Record<string, any> = {
        type: "build_challenge",
        mode: form.mode,
        force_rebuild: form.force_rebuild,
        overwrite: form.overwrite,
        dry_run: form.dry_run,
      };
      if (form.config_path) body.config_path = form.config_path;
      if (form.limit) body.limit = Number(form.limit);
      if (form.backend) body.backend = form.backend;
      const job = await api.createJob(body);
      if (form.validate_after) {
        // chain a validation right after (independent job; build resumes from cache)
        setMsg(`Build job ${job.job_id} started. Validation queued separately after you confirm completion.`);
      }
      nav(`/live/${job.job_id}`);
    } catch (e: any) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Build / Resume</h1>
      <p className="page-sub">
        Runs <code>student-system-creator build</code> in the backend. Builds resume from the existing KG cache
        automatically — re-running is safe.
      </p>

      <div className="grid cols-2">
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Configuration</h3>
          <label className="field">
            <span>Config file</span>
            <input
              type="text"
              placeholder={cfg.data?.config_path || "student_system_creator/configs/default.yaml"}
              value={form.config_path}
              onChange={(e) => set("config_path", e.target.value)}
            />
          </label>
          <label className="field">
            <span>Mode</span>
            <select value={form.mode} onChange={(e) => set("mode", e.target.value)}>
              <option value="all">All (config-driven)</option>
              <option value="selected_projects">Selected projects (choose on Projects page)</option>
              <option value="selected_functions">Selected functions (choose on Functions page)</option>
              <option value="resume">Resume only (from cache)</option>
            </select>
          </label>
          <label className="field">
            <span>Limit (functions, optional)</span>
            <input type="number" placeholder="e.g. 5 for smoke test" value={form.limit} onChange={(e) => set("limit", e.target.value)} />
          </label>
          <label className="field">
            <span>Backend override</span>
            <select value={form.backend} onChange={(e) => set("backend", e.target.value)}>
              <option value="">(use config)</option>
              <option value="auto">auto (Joern + heuristic)</option>
              <option value="joern">joern</option>
              <option value="heuristic">heuristic</option>
              <option value="tree-sitter">tree-sitter</option>
            </select>
          </label>
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>Options</h3>
          <div className="inline-check">
            <input id="force" type="checkbox" checked={form.force_rebuild} onChange={(e) => set("force_rebuild", e.target.checked)} />
            <label htmlFor="force">Force rebuild KGs (ignore cache)</label>
          </div>
          <div className="inline-check">
            <input id="ow" type="checkbox" checked={form.overwrite} onChange={(e) => set("overwrite", e.target.checked)} />
            <label htmlFor="ow">Overwrite challenge output folder</label>
          </div>
          <div className="inline-check">
            <input id="dry" type="checkbox" checked={form.dry_run} onChange={(e) => set("dry_run", e.target.checked)} />
            <label htmlFor="dry">Dry run (select rows only, no KG build)</label>
          </div>
          <div className="inline-check">
            <input id="va" type="checkbox" checked={form.validate_after} onChange={(e) => set("validate_after", e.target.checked)} />
            <label htmlFor="va">Validate after build</label>
          </div>

          {form.overwrite && (
            <div className="banner warn">⚠ Overwrite deletes and recreates the challenge output folder.</div>
          )}
          {msg && <div className="banner ok">{msg}</div>}

          <div className="btn-row" style={{ marginTop: 16 }}>
            <button className="btn primary" disabled={busy} onClick={submit}>
              {busy ? "Starting…" : "Start build job"}
            </button>
            <button className="btn" onClick={() => nav("/live")}>View jobs</button>
          </div>
        </div>
      </div>
    </div>
  );
}
