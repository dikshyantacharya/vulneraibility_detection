import { useEffect, useState } from "react";
import { api } from "../api/client";
import { fmtBytes, useApp } from "../state";
import type { DiskInfo } from "../api/types";

export default function TopBar() {
  const { mode, setMode } = useApp();
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [disk, setDisk] = useState<DiskInfo | null>(null);
  const [active, setActive] = useState(0);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        await api.health();
        const [d, jobs] = await Promise.all([api.disk(), api.jobs()]);
        if (!alive) return;
        setApiOk(true);
        setDisk(d);
        setActive(jobs.filter((j) => j.status === "running").length);
      } catch {
        if (alive) setApiOk(false);
      }
    };
    poll();
    const t = setInterval(poll, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

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
      <span className={`badge ${apiOk === false ? "red" : apiOk ? "green" : "gray"}`}>
        <span className="dot" /> API {apiOk === false ? "down" : apiOk ? "online" : "…"}
      </span>
    </div>
  );
}
