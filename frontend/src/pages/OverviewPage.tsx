import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { fmtBytes, useApp, useAsync, useDashboard } from "../state";
import MetricCard from "../components/MetricCard";

export default function OverviewPage() {
  const { mode } = useApp();
  const nav = useNavigate();
  // status + leakage are one-time snapshots (no interval). Disk + active-job
  // counts come from the central WebSocket store, not a REST poll.
  const status = useAsync(() => api.status(mode), [mode]);
  const leakage = useAsync(() => api.leakage(), []);
  const { disk, jobs } = useDashboard();
  const s = status.data;
  const activeJobs = jobs.filter((j) => j.status === "running").length;

  return (
    <div>
      <h1 className="page-title">Overview</h1>
      <p className="page-sub">Commit-aware KG &amp; student-challenge control plane.</p>

      {status.error && <div className="banner err">Backend error: {status.error}</div>}
      {s && !s.challenge_exists && (
        <div className="banner warn">
          No built challenge found at <code>{s.challenge_root}</code>. Use the Build page to create one.
        </div>
      )}
      {leakage.data && !leakage.data.ok && (
        <div className="banner err">
          ⚠ Public-id leakage: {leakage.data.flagged.length} id(s) contain vuln/safe/label tokens.
        </div>
      )}

      <div className="grid cols-4">
        <MetricCard label="Projects" value={s?.projects ?? "—"} sub="discovered in registry" accent="blue" />
        <MetricCard label="Functions" value={s?.functions ?? "—"} sub="candidate targets" />
        <MetricCard label="KG graphs" value={s?.kgs ?? "—"} sub="built & registered" />
        <MetricCard
          label="Active jobs"
          value={activeJobs}
          sub={`${jobs.length} total`}
          accent={activeJobs ? "blue" : undefined}
        />
      </div>

      <div className="section-title">Challenge composition</div>
      <div className="grid cols-4">
        <MetricCard label="Train rows" value={s?.split_counts?.train ?? "—"} />
        <MetricCard label="Test rows" value={s?.split_counts?.test ?? "—"} />
        {mode === "admin" ? (
          <>
            <MetricCard label="Vulnerable" value={s?.label_balance?.["1"] ?? "—"} accent="red" />
            <MetricCard label="Safe" value={s?.label_balance?.["0"] ?? "—"} accent="green" />
          </>
        ) : (
          <MetricCard label="Labels" value="hidden" sub="student preview mode" accent="amber" />
        )}
      </div>

      <div className="section-title">Status</div>
      <div className="grid cols-3">
        <MetricCard
          label="Last validation"
          value={s?.validation_ok == null ? "—" : s.validation_ok ? "Passed" : "Failed"}
          accent={s?.validation_ok ? "green" : s?.validation_ok === false ? "red" : undefined}
        />
        <MetricCard
          label="Disk free"
          value={fmtBytes(disk?.drive_free_bytes)}
          sub={`${disk?.drive_percent_used ?? "—"}% used`}
          accent={disk && disk.drive_percent_used > 90 ? "red" : undefined}
        />
        <MetricCard
          label="Public-id leakage"
          value={leakage.data ? (leakage.data.ok ? "Clean" : "Flagged") : "—"}
          sub={`${leakage.data?.checked ?? 0} ids checked`}
          accent={leakage.data ? (leakage.data.ok ? "green" : "red") : undefined}
        />
      </div>

      <div className="section-title">Quick actions</div>
      <div className="btn-row">
        <button className="btn primary" onClick={() => nav("/build")}>Build / Resume</button>
        <button className="btn" onClick={() => nav("/validation")}>Validate</button>
        <button className="btn" onClick={() => nav("/evaluation")}>Evaluate</button>
        <button className="btn" onClick={() => nav("/packaging")}>Package RAID</button>
        <button className="btn" onClick={() => nav("/kg")}>Open KG Explorer</button>
        <button className="btn" onClick={() => status.reload()}>Refresh</button>
      </div>
    </div>
  );
}
