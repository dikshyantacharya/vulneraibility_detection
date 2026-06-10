import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { useApp, useAsync } from "../state";
import DataTable, { Column } from "../components/DataTable";
import type { FunctionRow } from "../api/types";

export default function FunctionsPage() {
  const { mode } = useApp();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const projectFilter = params.get("project");
  const { data, error, loading } = useAsync(() => api.functions(mode), [mode]);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const rows = useMemo(
    () => (projectFilter ? (data || []).filter((f) => f.project === projectFilter) : data || []),
    [data, projectFilter]
  );

  const toggle = (k: string) =>
    setSelected((s) => {
      const n = new Set(s);
      n.has(k) ? n.delete(k) : n.add(k);
      return n;
    });
  const toggleAll = (keys: string[]) =>
    setSelected((s) => {
      const all = keys.every((k) => s.has(k));
      const n = new Set(s);
      keys.forEach((k) => (all ? n.delete(k) : n.add(k)));
      return n;
    });

  const columns: Column<FunctionRow>[] = [
    { key: "sample_id", header: "Sample", mono: true, render: (f) => f.sample_id || "—" },
    { key: "project", header: "Project" },
    { key: "function_name", header: "Function", render: (f) => <strong>{f.function_name}</strong> },
    { key: "filepath", header: "File", mono: true, render: (f) => f.filepath || "—" },
    { key: "split", header: "Split", render: (f) => <span className="badge gray">{f.split}</span> },
    ...(mode === "admin"
      ? [
          {
            key: "label",
            header: "Label",
            value: (f: FunctionRow) => f.label ?? -1,
            render: (f: FunctionRow) =>
              f.label === 1 ? <span className="badge red">vuln</span>
              : f.label === 0 ? <span className="badge green">safe</span>
              : "—",
          },
        ]
      : []),
    {
      key: "knowledge_graph_id",
      header: "KG",
      mono: true,
      render: (f) => (
        <a onClick={(e) => { e.stopPropagation(); nav(`/kg/${f.knowledge_graph_id}`); }}>
          {f.knowledge_graph_id.slice(0, 14)}…
        </a>
      ),
    },
  ];

  const buildSelected = async () => {
    const ids = rows.filter((f) => selected.has(f.knowledge_graph_id)).map((f) => f.sample_id!).filter(Boolean);
    await api.createJob({ type: "build_challenge", mode: "selected_functions", sample_ids: ids });
    nav("/live");
  };

  return (
    <div>
      <h1 className="page-title">Functions</h1>
      <p className="page-sub">
        Candidate target functions{projectFilter ? ` in ${projectFilter}` : ""}. Select rows to build / audit.
      </p>
      {error && <div className="banner err">{error}</div>}
      <div className="btn-row" style={{ marginBottom: 12 }}>
        <button className="btn primary" disabled={selected.size === 0} onClick={buildSelected}>
          Build KG for selected ({selected.size})
        </button>
        <button className="btn" onClick={() => nav("/audit")}>Open Agent Audit</button>
        {projectFilter && <button className="btn" onClick={() => nav("/functions")}>Clear project filter</button>}
      </div>
      {loading ? (
        <div className="empty">Loading functions…</div>
      ) : (
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(f) => f.knowledge_graph_id}
          selectable={{
            selected,
            onToggle: toggle,
            onToggleAll: toggleAll,
            getKey: (f) => f.knowledge_graph_id,
          }}
          onRowClick={(f) => nav(`/kg/${f.knowledge_graph_id}`)}
          searchPlaceholder="Search functions / files / samples…"
        />
      )}
    </div>
  );
}
