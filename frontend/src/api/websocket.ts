import type { DashboardEvent } from "./types";

function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}${path}`;
}

export interface WSHandle {
  close: () => void;
}

/** Subscribe to all dashboard events (global stream). */
export function subscribeEvents(onEvent: (e: DashboardEvent) => void): WSHandle {
  return subscribe(wsUrl("/ws/dashboard/events"), onEvent);
}

/** Subscribe to one job's stream (history is replayed on connect). */
export function subscribeJob(jobId: string, onEvent: (e: DashboardEvent) => void): WSHandle {
  return subscribe(wsUrl(`/ws/dashboard/jobs/${jobId}`), onEvent);
}

function subscribe(url: string, onEvent: (e: DashboardEvent) => void): WSHandle {
  let closed = false;
  let ws: WebSocket | null = null;
  let retry: number | undefined;

  const connect = () => {
    if (closed) return;
    ws = new WebSocket(url);
    ws.onmessage = (ev) => {
      try {
        onEvent(JSON.parse(ev.data) as DashboardEvent);
      } catch {
        /* ignore malformed */
      }
    };
    ws.onclose = () => {
      if (!closed) retry = window.setTimeout(connect, 2000);
    };
    ws.onerror = () => ws?.close();
  };
  connect();

  return {
    close: () => {
      closed = true;
      if (retry) window.clearTimeout(retry);
      ws?.close();
    },
  };
}
