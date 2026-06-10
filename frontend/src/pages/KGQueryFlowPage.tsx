import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research } from "../api/research";

export default function KGQueryFlowPage() {
  const { runId, sampleId } = useParams();
  const nav = useNavigate();
  const [queries, setQueries] = useState<any[]>([]);
  const [sel, setSel] = useState<number | "all">("all");
  const [embed, setEmbed] = useState(true);

  useEffect(() => {
    research.kgQueries(runId!, sampleId!).then(setQueries).catch(() => setQueries([]));
  }, [runId, sampleId]);

  const dashUrl = research.dashboardUrl(runId!, sampleId!);
  const shown = sel === "all" ? queries : queries.filter((_, i) => i + 1 === sel);

  const field = (q: any, ...keys: string[]) => {
    for (const k of keys) if (q[k] != null) return q[k];
    return undefined;
  };

  return (
    <div>
      <h1 className="page-title">KG Query Flow</h1>
      <p className="page-sub">
        Agentic KG queries for sample <strong className="mono">{sampleId}</strong>, plus the original CodeKG static
        dashboard embedded as the reference visualization.
      </p>

      <div className="toolbar">
        <button className="btn" onClick={() => nav(`/research/trace/${runId}/${sampleId}`)}>← Agent Trace</button>
        {queries.length > 0 && (
          <select value={String(sel)} onChange={(e) => setSel(e.target.value === "all" ? "all" : Number(e.target.value))}>
            <option value="all">All queries</option>
            {queries.map((q, i) => (
              <option key={i} value={i + 1}>q{i + 1} {field(q, "kind", "query_kind") || ""}</option>
            ))}
          </select>
        )}
        <span style={{ flex: 1 }} />
        <label className="inline-check" style={{ margin: 0 }}>
          <input type="checkbox" checked={embed} onChange={(e) => setEmbed(e.target.checked)} />
          Embed static dashboard
        </label>
        <a className="btn" href={dashUrl} target="_blank" rel="noreferrer">Open in new tab</a>
      </div>

      {queries.length === 0 && (
        <div className="banner warn">
          No structured KG queries captured for this sample (the run's <code>kg_queries</code> array is empty). The
          embedded static dashboard below still provides full query/search/highlight tooling.
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

      {embed && (
        <>
          <div className="section-title">CodeKG static dashboard (reference visualization)</div>
          <iframe
            title="CodeKG dashboard"
            src={dashUrl}
            style={{ width: "100%", height: 720, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "#fff" }}
          />
        </>
      )}
    </div>
  );
}
