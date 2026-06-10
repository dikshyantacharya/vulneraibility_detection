import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research, type KGDashboardInfo } from "../api/research";

type Tab = "codekg" | "queries" | "evidence" | "react" | "raw";

const TABS: { id: Tab; label: string }[] = [
  { id: "codekg", label: "Old CodeKG Dashboard" },
  { id: "queries", label: "Agent KG Queries" },
  { id: "evidence", label: "Evidence Items" },
  { id: "react", label: "React Graph (experimental)" },
  { id: "raw", label: "Raw Files" },
];

const field = (q: any, ...keys: string[]) => {
  for (const k of keys) if (q && q[k] != null) return q[k];
  return undefined;
};

export default function KGQueryFlowPage() {
  const { runId, sampleId } = useParams();
  const nav = useNavigate();
  const [tab, setTab] = useState<Tab>("codekg");
  const [queries, setQueries] = useState<any[]>([]);
  const [sel, setSel] = useState<number | "all">("all");
  const [kg, setKg] = useState<KGDashboardInfo | null>(null);
  const [kgErr, setKgErr] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    research.kgQueries(runId!, sampleId!).then(setQueries).catch(() => setQueries([]));
    setKg(null); setKgErr(null);
    research.kgDashboard(runId!, sampleId!).then(setKg).catch((e) => setKgErr(String(e.message || e)));
  }, [runId, sampleId]);

  const iframeUrl = kg?.iframe_url || null;
  const legacyUrl = research.dashboardUrl(runId!, sampleId!);
  const shownQueries = sel === "all" ? queries : queries.filter((_, i) => i + 1 === sel);

  const copyPath = () => {
    if (kg?.dashboard_index) {
      navigator.clipboard?.writeText(kg.dashboard_index);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }
  };

  return (
    <div>
      <h1 className="page-title">KG Query Flow</h1>
      <p className="page-sub">
        Sample <strong className="mono">{sampleId}</strong> — the original CodeKG explorer plus the agent's KG queries and evidence.
      </p>

      <div className="toolbar">
        <button className="btn" onClick={() => nav(`/research/trace/${runId}/${sampleId}`)}>← Agent Trace</button>
        <span style={{ flex: 1 }} />
      </div>

      <div className="tabs" style={{ display: "flex", gap: 6, margin: "12px 0", flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button key={t.id} className={`btn ${tab === t.id ? "primary" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}{t.id === "queries" && queries.length ? ` (${queries.length})` : ""}
          </button>
        ))}
      </div>

      {/* ---- Old CodeKG Dashboard (default) ---- */}
      {tab === "codekg" && (
        <div>
          <div className="toolbar" style={{ marginBottom: 10 }}>
            {iframeUrl ? (
              <>
                <a className="btn primary" href={iframeUrl} target="_blank" rel="noreferrer">Open CodeKG Dashboard</a>
                <a className="btn" href={iframeUrl} target="_blank" rel="noreferrer">Open in new tab</a>
                <button className="btn" onClick={() => setReloadKey((k) => k + 1)}>Reload dashboard</button>
                <button className="btn" onClick={copyPath}>{copied ? "Copied" : "Copy dashboard path"}</button>
              </>
            ) : <span className="muted">Locating CodeKG dashboard…</span>}
          </div>
          {iframeUrl && (
            <iframe key={reloadKey} title="CodeKG dashboard" src={iframeUrl}
              style={{ width: "100%", height: "calc(100vh - 220px)", minHeight: 640, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "#fff" }} />
          )}
          {!iframeUrl && (kg || kgErr) && (
            <div className="banner warn">
              <strong>No CodeKG dashboard found for this sample.</strong>
              {kgErr && <div className="mono" style={{ marginTop: 6 }}>{kgErr}</div>}
              {kg?.reason && <div style={{ marginTop: 6 }}>{kg.reason}</div>}
              {kg?.searched?.length ? <pre className="log-viewer" style={{ height: 180, marginTop: 8 }}>{kg.searched.join("\n")}</pre> : null}
            </div>
          )}
        </div>
      )}

      {/* ---- Agent KG Queries ---- */}
      {tab === "queries" && (
        <div>
          <div className="toolbar" style={{ marginBottom: 10 }}>
            <span className="muted">{queries.length} queries issued by the agent</span>
            <span style={{ flex: 1 }} />
            {queries.length > 0 && (
              <select value={String(sel)} onChange={(e) => setSel(e.target.value === "all" ? "all" : Number(e.target.value))}>
                <option value="all">all queries</option>
                {queries.map((_, i) => <option key={i} value={i + 1}>q{i + 1}</option>)}
              </select>
            )}
          </div>
          {queries.length === 0 && <div className="banner warn">No KG queries captured for this sample.</div>}
          {shownQueries.map((q, i) => {
            const idx = sel === "all" ? i : (sel as number) - 1;
            if (q && q._summary_only) {
              return (
                <div className="card" key={i} style={{ marginBottom: 10, borderLeft: "4px solid #b45309" }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <span className="badge amber">summary only</span>
                    <strong>agent.kg_tools</strong>
                    <span style={{ flex: 1 }} />
                    <span className="muted">{q.queries} queries · {q.returned_items} items · {q.evidence_items} evidence</span>
                  </div>
                  <div className="banner warn" style={{ marginTop: 8, fontSize: 12 }}>{q.reason}</div>
                </div>
              );
            }
            return (
              <div className="card" key={i} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
                  <span className="badge blue">q{idx + 1}</span>
                  <strong>{field(q, "query_type", "kind", "query_kind") || "query"}</strong>
                  {field(q, "round_index") != null && <span className="badge gray">round {field(q, "round_index")}</span>}
                  {field(q, "status") && <span className="badge gray">{field(q, "status")}</span>}
                  <span style={{ flex: 1 }} />
                  <span className="muted">
                    {field(q, "retrieved_node_count", "nodes") ?? (Array.isArray(field(q, "items")) ? field(q, "items").length : "?")} items
                    {field(q, "retrieved_edge_count", "edges") != null ? ` · ${field(q, "retrieved_edge_count", "edges")} edges` : ""}
                  </span>
                </div>
                {field(q, "reason") && <p style={{ marginTop: 0 }}>{field(q, "reason")}</p>}
                <div className="section-title" style={{ marginTop: 4 }}>Request</div>
                <pre className="log-viewer" style={{ height: 110 }}>
                  {JSON.stringify(field(q, "query", "query_object", "params", "tool_parameters") ?? q, null, 2)}
                </pre>
                {field(q, "wanted_evidence") && (
                  <div className="muted" style={{ fontSize: 12 }}>Wanted: {String(field(q, "wanted_evidence"))}</div>
                )}
                {Array.isArray(field(q, "items")) && field(q, "items").length > 0 && (
                  <>
                    <div className="section-title">Returned evidence ({field(q, "items").length})</div>
                    <pre className="log-viewer" style={{ height: 160 }}>{JSON.stringify(field(q, "items").slice(0, 8), null, 2)}</pre>
                  </>
                )}
                {iframeUrl && (
                  <a className="btn small" href={iframeUrl} target="_blank" rel="noreferrer" style={{ marginTop: 8, display: "inline-block" }}>
                    Highlight in CodeKG dashboard ↗
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ---- Evidence Items ---- */}
      {tab === "evidence" && (
        <div>
          {queries.length === 0 && <div className="banner warn">No structured evidence captured.</div>}
          {queries.map((q, i) => {
            const items = field(q, "items", "evidence_items");
            if (!Array.isArray(items) || items.length === 0) return null;
            return (
              <div className="card" key={i} style={{ marginBottom: 10 }}>
                <strong>q{i + 1} · {field(q, "query_type", "kind") || "query"}</strong>
                <pre className="log-viewer" style={{ height: 200, marginTop: 8 }}>{JSON.stringify(items, null, 2)}</pre>
              </div>
            );
          })}
        </div>
      )}

      {/* ---- React Graph (experimental) ---- */}
      {tab === "react" && (
        <div className="banner warn">
          The in-browser React graph is <strong>experimental</strong> and lower fidelity than the CodeKG dashboard.
          Open it from the <button className="btn" onClick={() => nav("/kg")}>KG Explorer</button> page.
        </div>
      )}

      {/* ---- Raw Files ---- */}
      {tab === "raw" && (
        <div className="card">
          <div className="section-title" style={{ marginTop: 0 }}>Raw artifacts</div>
          <ul>
            <li><a href={legacyUrl} target="_blank" rel="noreferrer">Per-sample audit page (legacy index.html)</a></li>
            {kg?.dashboard_index && <li className="mono">CodeKG dashboard: {kg.dashboard_index}</li>}
            {kg?.graph_dir && <li className="mono">Graph dir: {kg.graph_dir}</li>}
            {iframeUrl && <li><a href={iframeUrl.replace(/index\.html$/, "graph_data.json")} target="_blank" rel="noreferrer">graph_data.json</a></li>}
          </ul>
        </div>
      )}
    </div>
  );
}
