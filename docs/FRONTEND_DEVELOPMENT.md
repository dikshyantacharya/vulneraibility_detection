# Frontend development

The dashboard frontend is a Vite + React + TypeScript SPA in `frontend/`. It has
intentionally minimal dependencies: `react`, `react-dom`, `react-router-dom`
(plus Vite/TS tooling). No CSS framework or graph library — the design system is
plain CSS (`src/styles/globals.css`, light theme) and the KG view is a
dependency-free SVG renderer.

## Layout

```
frontend/
  index.html
  vite.config.ts        # dev proxy: /api + /ws -> http://127.0.0.1:8080
  tsconfig.json
  src/
    main.tsx, App.tsx, state.tsx
    api/{client.ts, websocket.ts, types.ts}
    components/{Layout, Sidebar, TopBar, MetricCard, JobStatusBadge,
                DataTable, LogViewer, KGGraphView}.tsx
    pages/{Overview, Projects, Functions, Build, LiveDashboard,
           KGExplorer, AgentAudit, Validation, Evaluation, Packaging, Settings}Page.tsx
    styles/globals.css
```

## Commands

```powershell
cd frontend
npm install        # one-time
npm run dev        # Vite dev server on :5173, proxies API/WS to :8080
npm run build      # typecheck (tsc --noEmit) + production build -> dist/
npm run typecheck  # types only
```

## Dev workflow

1. Start the backend with reload: `student-system-creator dashboard-dev --port 8080`.
2. `npm run dev` and open <http://127.0.0.1:5173>.
3. API and WebSocket calls are proxied to the backend; override the target with
   `VITE_API_TARGET`.

## Conventions

- **API access**: only through `src/api/client.ts` (`api.*`). It always sends the
  `mode` query param where masking applies.
- **Mode**: read from `useApp()` (admin/student), persisted in `localStorage`.
- **Async data**: use `useAsync(fn, deps)` → `{data, error, loading, reload}`.
- **WebSocket**: `subscribeJob(jobId, cb)` / `subscribeEvents(cb)`; both auto-reconnect.
- **Tables**: reuse `DataTable` (search, sort, paginate, selection).

## Production serving

`npm run build` emits `frontend/dist`. The backend auto-detects it and serves the
SPA (with deep-link fallback to `index.html`) plus `/assets`. No separate web
server needed.
