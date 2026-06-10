import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApp } from "../state";
import type { GraphNode, KgGraph } from "../api/types";
import KGGraphView from "../components/KGGraphView";

export default function KGExplorerPage() {
  const { kgId } = useParams();
  const { mode } = useApp();
  const [kgList, setKgList] = useState<{ knowledge_graph_id: string; function_name?: string }[]>([]);
  const [current, setCurrent] = useState<string | undefined>(kgId);
  const [graph, setGraph] = useState<KgGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [nodeType, setNodeType] = useState<string>("");
  const [limit, setLimit] = useState(400);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    api.kgs(mode).then((r) => setKgList(r as any)).catch(() => {});
  }, [mode]);

  useEffect(() => {
    if (!current) return;
    setLoading(true);
    setErr(null);
    setSelected(null);
    api
      .kgGraph(current, { limit, node_type: nodeType || undefined })
      .then(setGraph)
      .catch((e) => setErr(String(e.message)))
      .finally(() => setLoading(false));
  }, [current, limit, nodeType]);

  const nodeTypes = useMemo(
    () => Object.entries(graph?.node_type_distribution || {}).sort((a, b) => b[1] - a[1]),
    [graph]
  );

  return (
    <div>
      <h1 className="page-title">KG Explorer</h1>
      <p className="page-sub">Interactive in-browser KG view (replaces the static index.html dump).</p>

      <div className="toolbar">
        <select value={current || ""} onChange={(e) => setCurrent(e.target.value)} style={{ maxWidth: 360 }}>
          <option value="">Select a knowledge graph…</option>
          {kgList.map((k) => (
            <option key={k.knowledge_graph_id} value={k.knowledge_graph_id}>
              {k.knowledge_graph_id.slice(0, 16)}… {k.function_name ? `(${k.function_name})` : ""}
            </option>
          ))}
        </select>
        <select value={nodeType} onChange={(e) => setNodeType(e.target.value)}>
          <option value="">All node types</option>
          {nodeTypes.map(([t, c]) => (
            <option key={t} value={t}>{t} ({c})</option>
          ))}
        </select>
        <label className="muted" style={{ display: "flex", gap: 6, alignItems: "center" }}>
          max nodes
          <input type="number" value={limit} min={50} max={3000} step={50} style={{ width: 90 }} onChange={(e) => setLimit(Number(e.target.value))} />
        </label>
        {current && (
          <a className="btn" href={`/api/dashboard/kgs/${current}/graph?limit=2000`} target="_blank" rel="noreferrer">
            Raw graph JSON
          </a>
        )}
      </div>

      {err && <div className="banner err">{err}</div>}
      {!current && <div className="empty">Pick a knowledge graph above to explore.</div>}

      {current && graph && (
        <div className="grid" style={{ gridTemplateColumns: "1fr 320px" }}>
          <div className="card" style={{ padding: 0 }}>
            {loading ? <div className="empty">Loading graph…</div> : (
              <KGGraphView
                nodes={graph.returned_nodes}
                edges={graph.returned_edges}
                onSelect={setSelected}
                selectedId={selected?.id}
              />
            )}
          </div>

          <div>
            <div className="card" style={{ marginBottom: 12 }}>
              <div className="metric"><div className="label">Graph</div></div>
              <dl className="kv">
                <dt>Nodes</dt><dd>{graph.node_count.toLocaleString()}{graph.truncated ? ` (showing ${graph.returned_nodes.length})` : ""}</dd>
                <dt>Edges</dt><dd>{graph.edge_count.toLocaleString()}</dd>
                <dt>Node types</dt><dd>{Object.keys(graph.node_type_distribution).length}</dd>
                <dt>Edge types</dt><dd>{Object.keys(graph.edge_type_distribution).length}</dd>
              </dl>
            </div>

            <div className="card">
              <h3 className="section-title" style={{ marginTop: 0 }}>Selected node</h3>
              {selected ? (
                <dl className="kv">
                  <dt>id</dt><dd className="mono">{selected.id}</dd>
                  <dt>type</dt><dd>{selected.type}</dd>
                  <dt>name</dt><dd>{selected.name || selected.label || "—"}</dd>
                  <dt>file</dt><dd className="mono">{selected.file || "—"}</dd>
                  <dt>lines</dt><dd>{selected.line_start ?? "?"}–{selected.line_end ?? "?"}</dd>
                  <dt>degree</dt><dd>{selected.degree ?? "—"}</dd>
                </dl>
              ) : (
                <p className="muted">Click a node to inspect it.</p>
              )}
              {selected?.code && (
                <pre className="log-viewer" style={{ height: 180, marginTop: 8 }}>{selected.code}</pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
