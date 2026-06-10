import type { DashboardEvent } from "./types";

function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}${path}`;
}

export interface WSHandle {
  close: () => void;
}

export type ConnStatus = "connecting" | "connected" | "reconnecting" | "disconnected";

export interface DashboardSocket {
  close: () => void;
  reconnect: () => void;
  send: (data: string) => void;
}

/**
 * Primary control-plane socket (/ws/dashboard). Reconnects with exponential
 * backoff (never a fixed REST poll), sends a heartbeat ping, and reports
 * connection status transitions. The first connect emits "connecting"; once a
 * message arrives we are "connected"; drops move to "reconnecting" until the
 * backoff ceiling, then "disconnected".
 */
export function subscribeDashboard(
  onMessage: (msg: any) => void,
  onStatus: (s: ConnStatus) => void,
): DashboardSocket {
  let closed = false;
  let ws: WebSocket | null = null;
  let retry: number | undefined;
  let heartbeat: number | undefined;
  let attempt = 0;
  const MAX_BACKOFF = 30000;

  const clearTimers = () => {
    if (retry) window.clearTimeout(retry);
    if (heartbeat) window.clearInterval(heartbeat);
    retry = undefined;
    heartbeat = undefined;
  };

  const connect = () => {
    if (closed) return;
    onStatus(attempt === 0 ? "connecting" : "reconnecting");
    ws = new WebSocket(wsUrl("/ws/dashboard"));

    ws.onopen = () => {
      attempt = 0;
      onStatus("connected");
      heartbeat = window.setInterval(() => {
        try {
          ws?.readyState === WebSocket.OPEN && ws.send("ping");
        } catch {
          /* ignore */
        }
      }, 30000);
    };
    ws.onmessage = (ev) => {
      try {
        onMessage(JSON.parse(ev.data));
      } catch {
        /* ignore malformed */
      }
    };
    ws.onclose = () => {
      clearTimers();
      if (closed) return;
      attempt += 1;
      const delay = Math.min(MAX_BACKOFF, 1000 * 2 ** Math.min(attempt, 5));
      onStatus(delay >= MAX_BACKOFF ? "disconnected" : "reconnecting");
      retry = window.setTimeout(connect, delay);
    };
    ws.onerror = () => ws?.close();
  };
  connect();

  return {
    close: () => {
      closed = true;
      clearTimers();
      ws?.close();
    },
    reconnect: () => {
      attempt = 0;
      clearTimers();
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
      closed = false;
      connect();
    },
    send: (data: string) => {
      try {
        ws?.readyState === WebSocket.OPEN && ws.send(data);
      } catch {
        /* ignore */
      }
    },
  };
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
