import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research, type KGDashboardInfo } from "../api/research";

type Tab = "codekg" | "evidence" | "react" | "raw";

const TABS: { id: Tab; label: string }[] = [
  { id: "codekg", label: "Old CodeKG Dashboard (recommended)" },
  { id: "evidence", label: "Query Evidence" },
  { id: "react", label: "React Graph (experimental)" },
  { id: "raw", label: "Raw Files" },
];

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
  }, [runId, sampleId]);

  useEffect(() => {
    setKg(null);
    setKgErr(null);
    research
      .kgDashboard(runId!, sampleId!)
      .then(setKg)
      .catch((e) => setKgErr(String(e.message || e)));
  }, [runId, sampleId]);

  const legacyUrl = research.dashboardUrl(runId!, sampleId!);
  const iframeUrl = kg?.iframe_url || null;
  const shown = sel === "all" ? queries : queries.filter((_, i) => i + 1 === sel);
  const field = (q: any, ...keys: string[]) => {
    for (const k of keys) if (q[k] != null) return q[k];
    return undefined;
  };

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
        Sample <strong className="mono">{sampleId}</strong> — the original high-quality CodeKG explorer is the
        default visualization. The React graph is experimental.
      </p>

      <div className="toolbar">
        <button className="btn" onClick={() => nav(`/research/trace/${runId}/${sampleId}`)}>← Agent Trace</button>
        <span style={{ flex: 1 }} />
      </div>

      <div className="tabs" style={{ display: "flex", gap: 6, margin: "12px 0", flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`btn ${tab === t.id ? "primary" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
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
            ) : (
              <span className="muted">Locating CodeKG dashboard…</span>
            )}
          </div>

          {iframeUrl && (
            <iframe
              key={reloadKey}
              title="CodeKG dashboard"
              src={iframeUrl}
              style={{ width: "100%", height: "calc(100vh - 220px)", minHeight: 640, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "#fff" }}
            />
          )}

          {!iframeUrl && (kg || kgErr) && (
            <div className="banner warn">
              <strong>No CodeKG dashboard found for this sample.</strong>
              {kgErr && <div className="mono" style={{ marginTop: 6 }}>{kgErr}</div>}
              {kg?.reason && <div style={{ marginTop: 6 }}>{kg.reason}</div>}
              {kg?.searched?.length ? (
                <>
                  <div className="section-title" style={{ marginTop: 10 }}>Searched paths</div>
                  <pre className="log-viewer" style={{ height: 180 }}>{kg.searched.join("\n")}</pre>
                </>
              ) : null}
              <p className="muted" style={{ marginTop: 8 }}>
                The dashboard is written during a run to <code>cache/kg/&lt;repo&gt;/&lt;commit&gt;/…/dashboard/index.html</code>.
                Rebuild the KG for this sample to generate it.
              </p>
            </div>
          )}

          {kg && kg.candidates.length > 1 && (
            <div className="card" style={{ marginTop: 10 }}>
              <div className="section-title" style={{ marginTop: 0 }}>Other dashboard candidates</div>
              {kg.candidates.map((c, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0" }}>
                  <a className="btn" href={c.iframe_url} target="_blank" rel="noreferrer">Open</a>
                  <span className="mono" style={{ fontSize: 12 }}>{c.dashboard_index}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ---- Query Evidence ---- */}
      {tab === "evidence" && (
        <div>
          <div className="toolbar">
            {queries.length > 0 && (
              <select value={String(sel)} onChange={(e) => setSel(e.target.value === "all" ? "all" : Number(e.target.value))}>
                <option value="all">All queries</option>
                {queries.map((q, i) => (
                  <option key={i} value={i + 1}>q{i + 1} {field(q, "kind", "query_kind") || ""}</option>
                ))}
              </select>
            )}
          </div>
          {queries.length === 0 && (
            <div className="banner warn">
              No structured KG queries captured for this sample. Use the Old CodeKG Dashboard tab for full
              query/search/highlight tooling.
            </div>
          )}
          {shown.map((q, i) => (
            <div className="card" key={i} style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                <span className="badge blue">q{(sel === "all" ? i : (sel as number) - 1) + 1}</span>
                <strong>{field(q, "kind", "query_kind") || "query"}</strong>
                <span style={{ flex: 1 }} />
                <span className="muted">
                  {field(q, "retrieved_node_count", "nodes") ?? "?"} nodes · {field(q, "retrieved_edge_count", "edges") ?? "?"} edges
                </span>
              </div>
              {field(q, "reason") && <p style={{ marginTop: 0 }}>{field(q, "reason")}</p>}
              {field(q, "params", "query_params") && (
                <pre className="log-viewer" style={{ height: 90 }}>{JSON.stringify(field(q, "params", "query_params"), null, 2)}</pre>
              )}
              {field(q, "evidence_summary") && (
                <>
                  <div className="section-title">Evidence summary</div>
                  <pre className="log-viewer" style={{ height: 120 }}>{field(q, "evidence_summary")}</pre>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ---- React Graph (experimental) ---- */}
      {tab === "react" && (
        <div className="banner warn">
          The in-browser React graph is <strong>experimental</strong> and lower fidelity than the CodeKG dashboard.
          Open it from the <button className="btn" onClick={() => nav("/kg")}>KG Explorer</button> page. For
          source-grounded analysis use the Old CodeKG Dashboard tab.
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
