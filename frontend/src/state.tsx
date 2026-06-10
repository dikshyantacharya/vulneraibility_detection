import React, { createContext, useContext, useEffect, useState } from "react";
import type { Mode } from "./api/types";

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
