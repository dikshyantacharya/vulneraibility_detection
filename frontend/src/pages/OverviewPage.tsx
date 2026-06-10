import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { fmtBytes, useApp, useAsync, useDashboard } from "../state";
import MetricCard from "../components/MetricCard";

function Bar({ pct, accent }: { pct: number | null | undefined; accent?: string }) {
  const v = Math.max(0, Math.min(100, pct ?? 0));
  return (
    <div className="progress" style={{ marginTop: 6 }} title={pct != null ? `${v}%` : "n/a"}>
      <div style={{ width: `${v}%`, background: accent }} />
    </div>
  );
}

function Help({ text }: { text: string }) {
  return (
    <span title={text} style={{ cursor: "help", color: "var(--muted)", marginLeft: 4 }}>ⓘ</span>
  );
}

export default function OverviewPage() {
  const { mode } = useApp();
  const nav = useNavigate();
  const inv = useAsync(() => api.inventorySummary(mode), [mode]);
  const status = useAsync(() => api.status(mode), [mode]);
  const leakage = useAsync(() => api.leakage(), []);
  const { disk, jobs, refreshDisk } = useDashboard();
  const activeJobs = jobs.filter((j) => j.status === "running").length;

  const d = inv.data || {};
  const dataset = d.dataset || {};
  const repos = d.repos || {};
  const fns = d.functions || {};
  const ch = d.challenge || {};
  const research = d.research || {};

  const refresh = () => {
    inv.reload();
    status.reload();
    refreshDisk();
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <h1 className="page-title" style={{ marginBottom: 0 }}>Overview</h1>
        <span style={{ flex: 1 }} />
        <button className="btn primary" onClick={refresh}>Refresh inventory</button>
      </div>
      <p className="page-sub">End-to-end readiness across the dataset / research-audit and student-challenge workflows.</p>

      {inv.error && <div className="banner err">Inventory error: {inv.error}</div>}
      {leakage.data && !leakage.data.ok && (
        <div className="banner err">⚠ Public-id leakage: {leakage.data.flagged.length} id(s) contain vuln/safe/label tokens.</div>
      )}

      {/* Pipeline */}
      <div className="section-title">Readiness pipeline</div>
      <div className="card" style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", fontSize: 13 }}>
        {[
          `Dataset (${dataset.total_samples ?? "—"})`,
          `Cloned repos (${repos.mirrored_projects ?? "—"}/${repos.dataset_projects ?? "—"})`,
          `Worktrees (${repos.worktrees ?? "—"})`,
          `KG built (${fns.kg_built ?? "—"})`,
          `CodeKG dashboards (${fns.codekg_dashboards ?? "—"})`,
          `Challenge (${ch.exists ? ch.rows ?? 0 : "none"})`,
        ].map((label, i, arr) => (
          <span key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="badge blue">{label}</span>
            {i < arr.length - 1 && <span className="muted">→</span>}
          </span>
        ))}
      </div>

      {/* Dataset inventory */}
      <div className="section-title">Dataset inventory <Help text="From the raw dataset arrow if available, else the pair-candidate cache." /></div>
      <div className="grid cols-4">
        <MetricCard label="Dataset samples" value={dataset.total_samples ?? "—"} sub={dataset.source || ""} accent="blue" />
        <MetricCard label="Unique projects" value={dataset.projects ?? "—"} />
        <MetricCard label="Unique functions" value={dataset.functions ?? "—"} />
        <MetricCard label="Vulnerable / Safe" value={`${dataset.vulnerable ?? "—"} / ${dataset.safe ?? "—"}`} accent="red" />
      </div>

      {/* Repository availability */}
      <div className="section-title">Repository availability <Help text="Mirrors in cache/repos/bare_mirrors, worktrees in cache/worktrees. Reflects the whole dataset, not just challenge projects." /></div>
      <div className="grid cols-4">
        <MetricCard label="Dataset projects" value={repos.dataset_projects ?? "—"} />
        <MetricCard label="Mirrored / cloned" value={repos.mirrored_projects ?? "—"} accent="green" />
        <MetricCard label="Missing / not cloned" value={repos.missing_projects ?? "—"} accent={repos.missing_projects ? "amber" : undefined} />
        <MetricCard label="Worktrees" value={repos.worktrees ?? "—"} sub={`${repos.repo_inventory_records ?? 0} inventory records`} />
      </div>
      <div className="card">
        <div className="muted" style={{ fontSize: 12 }}>Clone coverage {repos.clone_coverage_pct != null ? `${repos.clone_coverage_pct}%` : "—"}</div>
        <Bar pct={repos.clone_coverage_pct} accent="var(--good, #047857)" />
      </div>

      {/* Function analysis readiness */}
      <div className="section-title">Function analysis readiness</div>
      <div className="grid cols-3">
        <MetricCard label="Theoretical analyzable" value={fns.theoretical_analyzable ?? "—"} sub="present in dataset" />
        <MetricCard label="KG-ready (graphs built)" value={fns.kg_built ?? "—"} sub="CodeKG graph exists" accent="green" />
        <MetricCard label="CodeKG dashboards" value={fns.codekg_dashboards ?? "—"} sub="explorer available" />
      </div>

      {/* Student challenge */}
      <div className="section-title">Student challenge inventory <Help text="Separate from the research/dataset numbers above." /></div>
      {ch.exists ? (
        <>
          <div className="grid cols-4">
            <MetricCard label="Challenge rows" value={ch.rows ?? "—"} />
            <MetricCard label="Train rows" value={ch.train_rows ?? "—"} />
            <MetricCard label="Test rows" value={ch.test_rows ?? "—"} />
            <MetricCard label="Private KG entries" value={ch.registry_entries ?? "—"} />
          </div>
          <div className="grid cols-3">
            <MetricCard
              label="Validation"
              value={ch.validation_ok == null ? "—" : ch.validation_ok ? "Passed" : "Failed"}
              accent={ch.validation_ok ? "green" : ch.validation_ok === false ? "red" : undefined}
            />
            {mode === "admin" && (
              <>
                <MetricCard label="Vulnerable (label=1)" value={ch.label_balance?.["1"] ?? "—"} accent="red" />
                <MetricCard label="Safe (label=0)" value={ch.label_balance?.["0"] ?? "—"} accent="green" />
              </>
            )}
            {mode !== "admin" && <MetricCard label="Labels" value="hidden" sub="student preview" accent="amber" />}
          </div>
        </>
      ) : (
        <div className="banner warn">No built student challenge found.</div>
      )}

      {/* Research activity */}
      <div className="section-title">Research audit activity</div>
      <div className="grid cols-4">
        <MetricCard label="Total runs" value={research.total_runs ?? 0} />
        <MetricCard label="Running" value={activeJobs} accent={activeJobs ? "blue" : undefined} />
        <MetricCard label="Failed runs" value={research.failed ?? 0} accent={research.failed ? "red" : undefined} />
        <MetricCard label="Last run" value={research.last_run_time ? new Date(research.last_run_time * 1000).toLocaleDateString() : "—"} sub={research.last_model || ""} />
      </div>
      {(research.last_provider || research.last_model) && (
        <div className="card muted" style={{ fontSize: 12 }}>
          Last: <strong>{research.last_provider || "—"}</strong> · {research.last_model || "—"} · KG {research.last_kg_backend || "—"}
        </div>
      )}

      {/* Storage */}
      <div className="section-title">Storage <Help text="Disk uses the WebSocket-throttled value; press Refresh to recompute." /></div>
      <div className="grid cols-3">
        <MetricCard
          label="Disk free"
          value={fmtBytes(disk?.drive_free_bytes)}
          sub={`${disk?.drive_percent_used ?? "—"}% used`}
          accent={disk && disk.drive_percent_used > 90 ? "red" : undefined}
        />
        <MetricCard label="Active jobs" value={activeJobs} sub={`${jobs.length} total`} accent={activeJobs ? "blue" : undefined} />
        <MetricCard
          label="Public-id leakage"
          value={leakage.data ? (leakage.data.ok ? "Clean" : "Flagged") : "—"}
          sub={`${leakage.data?.checked ?? 0} ids checked`}
          accent={leakage.data ? (leakage.data.ok ? "green" : "red") : undefined}
        />
      </div>

      <div className="section-title">Quick actions</div>
      <div className="btn-row">
        <button className="btn primary" onClick={() => nav("/research")}>Run research audit</button>
        <button className="btn" onClick={() => nav("/research/runs")}>Audit runs</button>
        <button className="btn" onClick={() => nav("/build")}>Build challenge</button>
        <button className="btn" onClick={() => nav("/kg")}>KG Explorer</button>
      </div>
    </div>
  );
}
