import { fmtBytes, useApp, useDashboard } from "../state";

const CONN_LABEL: Record<string, string> = {
  connected: "WebSocket connected",
  connecting: "WebSocket connecting…",
  reconnecting: "WebSocket reconnecting…",
  disconnected: "WebSocket disconnected — manual refresh",
};

export default function TopBar() {
  const { mode, setMode } = useApp();
  const { health, disk, jobs, connection, refreshSnapshot } = useDashboard();
  const active = jobs.filter((j) => j.status === "running").length;
  const apiOk = health?.ok ?? null;
  const connClass =
    connection === "connected" ? "green" : connection === "disconnected" ? "red" : "amber";

  return (
    <div className="topbar">
      <span className={`badge ${mode === "admin" ? "amber" : "blue"}`}>
        {mode === "admin" ? "🔓 Admin mode" : "🎓 Student preview"}
      </span>
      <button
        className="btn"
        onClick={() => setMode(mode === "admin" ? "student" : "admin")}
        title="Toggle admin / student-preview data masking"
      >
        Switch to {mode === "admin" ? "student" : "admin"}
      </button>
      <span className="spacer" />
      {active > 0 && (
        <span className="badge blue">
          <span className="dot" /> {active} active job{active > 1 ? "s" : ""}
        </span>
      )}
      {disk && (
        <span className="muted" title="Free disk on project drive">
          💾 {fmtBytes(disk.drive_free_bytes)} free ({disk.drive_percent_used}% used)
        </span>
      )}
      <span className={`badge ${connClass}`} title={CONN_LABEL[connection]}>
        <span className="dot" /> {CONN_LABEL[connection]}
      </span>
      {connection !== "connected" && (
        <button className="btn" onClick={refreshSnapshot} title="Manual refresh (REST)">
          Refresh
        </button>
      )}
      <span className={`badge ${apiOk === false ? "red" : apiOk ? "green" : "gray"}`}>
        <span className="dot" /> API {apiOk === false ? "down" : apiOk ? "online" : "…"}
      </span>
    </div>
  );
}
