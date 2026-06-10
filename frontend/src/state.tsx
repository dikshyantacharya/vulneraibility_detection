import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import type { DiskInfo, Job, Mode } from "./api/types";
import { api } from "./api/client";
import { subscribeDashboard, type ConnStatus, type DashboardSocket } from "./api/websocket";

interface AppState {
  mode: Mode;
  setMode: (m: Mode) => void;
}

const Ctx = createContext<AppState>({ mode: "admin", setMode: () => {} });

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<Mode>(
    (localStorage.getItem("vckg.mode") as Mode) || "admin"
  );
  useEffect(() => {
    localStorage.setItem("vckg.mode", mode);
  }, [mode]);
  return <Ctx.Provider value={{ mode, setMode }}>{children}</Ctx.Provider>;
}

export const useApp = () => useContext(Ctx);

/* ------------------------------------------------------------------ */
/* Central WebSocket-driven dashboard store.                          */
/*                                                                    */
/* One /ws/dashboard connection feeds health/disk/jobs to the whole   */
/* app. Pages READ from this store instead of polling REST endpoints. */
/* REST is only used for the initial snapshot fallback and explicit   */
/* user refresh actions.                                              */
/* ------------------------------------------------------------------ */

interface DashboardState {
  health: { ok: boolean } | null;
  disk: DiskInfo | null;
  jobs: Job[];
  connection: ConnStatus;
  lastUpdated: number | null;
  pollingFallback: boolean;
  refreshSnapshot: () => void;
  refreshDisk: () => void;
  reconnect: () => void;
}

const DashCtx = createContext<DashboardState | null>(null);

export function DashboardProvider({ children }: { children: React.ReactNode }) {
  const [health, setHealth] = useState<{ ok: boolean } | null>(null);
  const [disk, setDisk] = useState<DiskInfo | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [connection, setConnection] = useState<ConnStatus>("connecting");
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [pollingFallback, setPollingFallback] = useState(false);
  const sock = useRef<DashboardSocket | null>(null);

  const upsertJob = (job: Job) =>
    setJobs((prev) => {
      const idx = prev.findIndex((j) => j.job_id === job.job_id);
      if (idx === -1) return [job, ...prev];
      const next = prev.slice();
      next[idx] = { ...next[idx], ...job };
      return next;
    });

  useEffect(() => {
    const s = subscribeDashboard(
      (msg) => {
        setLastUpdated(Date.now());
        switch (msg.type) {
          case "dashboard_snapshot":
            setHealth(msg.health || { ok: true });
            setDisk(msg.disk || null);
            setJobs(msg.jobs || []);
            setPollingFallback(!!msg.polling_fallback);
            break;
          case "health_updated":
            setHealth(msg.health || null);
            break;
          case "disk_updated":
            setDisk(msg.disk || null);
            break;
          case "job_created":
            if (msg.job) upsertJob(msg.job);
            break;
          case "job_updated":
            if (msg.job) upsertJob(msg.job);
            break;
          default:
            break;
        }
      },
      (status) => setConnection(status),
    );
    sock.current = s;
    return () => s.close();
  }, []);

  // Allowed REST: initial snapshot only if the socket has not delivered one
  // yet (so a slow/unavailable WS still shows data once), and explicit refresh.
  const refreshSnapshot = () => {
    api.jobs().then(setJobs).catch(() => {});
    api.disk().then(setDisk).catch(() => {});
    api.health().then(() => setHealth({ ok: true })).catch(() => setHealth({ ok: false }));
    setLastUpdated(Date.now());
  };
  const refreshDisk = () => {
    // push=true also broadcasts to other connected dashboards.
    fetch("/api/dashboard/disk?push=true")
      .then((r) => r.json())
      .then(setDisk)
      .catch(() => {});
  };
  const reconnect = () => sock.current?.reconnect();

  useEffect(() => {
    // If the socket never connects, do ONE REST snapshot so the UI is not blank.
    const t = window.setTimeout(() => {
      if (lastUpdated == null) refreshSnapshot();
    }, 4000);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value: DashboardState = {
    health,
    disk,
    jobs,
    connection,
    lastUpdated,
    pollingFallback,
    refreshSnapshot,
    refreshDisk,
    reconnect,
  };
  return <DashCtx.Provider value={value}>{children}</DashCtx.Provider>;
}

export function useDashboard(): DashboardState {
  const ctx = useContext(DashCtx);
  if (!ctx) throw new Error("useDashboard must be used within DashboardProvider");
  return ctx;
}

/** Generic async-resource hook with loading/error/reload. */
export function useAsync<T>(fn: () => Promise<T>, deps: any[] = []): {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => active && setData(d))
      .catch((e) => active && setError(String(e.message || e)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

export function fmtBytes(n?: number): string {
  if (!n && n !== 0) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

export function fmtDuration(seconds?: number | null): string {
  if (seconds == null) return "—";
  const s = Math.round(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${r}s`;
  return `${r}s`;
}
