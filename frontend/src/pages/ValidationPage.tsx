import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../state";
import MetricCard from "../components/MetricCard";

export default function ValidationPage() {
  const nav = useNavigate();
  const report = useAsync(() => api.validationReport(), []);
  const [busy, setBusy] = useState(false);
  const r = report.data || {};
  const errors: any[] = r.errors || [];
  const warnings: any[] = r.warnings || [];

  const run = async () => {
    setBusy(true);
    try {
      const job = await api.createJob({ type: "validate_challenge" });
      nav(`/live/${job.job_id}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Validation</h1>
      <p className="page-sub">Latest challenge validation report (public/private consistency + KG retrievability).</p>

      <div className="btn-row" style={{ marginBottom: 16 }}>
        <button className="btn primary" disabled={busy} onClick={run}>Run validation</button>
        <button className="btn" onClick={report.reload}>Refresh report</button>
        <a className="btn" href="/api/dashboard/reports/validation" target="_blank" rel="noreferrer">Export JSON</a>
      </div>

      {report.loading ? (
        <div className="empty">Loading…</div>
      ) : r.ok == null ? (
        <div className="banner warn">No validation report found yet. Run validation above.</div>
      ) : (
        <>
          <div className={`banner ${r.ok ? "ok" : "err"}`}>
            {r.ok ? "✓ Validation passed" : "✗ Validation failed"} — {r.checked_rows ?? "?"} rows checked,
            {" "}{r.error_count ?? errors.length} errors, {r.warning_count ?? warnings.length} warnings.
          </div>
          <div className="grid cols-4">
            <MetricCard label="Registry entries" value={r.registry_entries ?? "—"} />
            <MetricCard label="KG folders" value={r.kg_folders ?? "—"} />
            <MetricCard label="Train rows" value={r.train_rows ?? "—"} />
            <MetricCard label="Test rows" value={r.test_rows ?? "—"} />
          </div>

          {errors.length > 0 && (
            <>
              <div className="section-title">Errors</div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>#</th><th>Detail</th></tr></thead>
                  <tbody>
                    {errors.slice(0, 200).map((e, i) => (
                      <tr key={i}><td>{i + 1}</td><td className="mono">{typeof e === "string" ? e : JSON.stringify(e)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {warnings.length > 0 && (
            <>
              <div className="section-title">Warnings</div>
              <div className="table-wrap">
                <table>
                  <tbody>
                    {warnings.slice(0, 200).map((w, i) => (
                      <tr key={i}><td className="mono">{typeof w === "string" ? w : JSON.stringify(w)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
