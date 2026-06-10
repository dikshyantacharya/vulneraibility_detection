import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useApp, useAsync } from "../state";
import DataTable, { Column } from "../components/DataTable";
import type { Project } from "../api/types";

export default function ProjectsPage() {
  const { mode } = useApp();
  const nav = useNavigate();
  const { data, error, loading, reload } = useAsync(() => api.projects(mode), [mode]);
  const [selected, setSelected] = useState<Set<string>>(new Set());

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

  const columns: Column<Project>[] = [
    { key: "project", header: "Project", render: (p) => <strong>{p.project}</strong> },
    { key: "repo_key", header: "Repo key", mono: true, render: (p) => p.repo_key || "—" },
    { key: "function_count", header: "Functions", value: (p) => p.function_count },
    ...(mode === "admin"
      ? [
          { key: "vuln", header: "Vuln", value: (p: Project) => p.vuln ?? 0, render: (p: Project) => <span className="badge red">{p.vuln ?? 0}</span> },
          { key: "safe", header: "Safe", value: (p: Project) => p.safe ?? 0, render: (p: Project) => <span className="badge green">{p.safe ?? 0}</span> },
        ]
      : []),
    { key: "kg_built", header: "KGs built", value: (p) => p.kg_built },
    {
      key: "splits",
      header: "Splits",
      render: (p) => Object.entries(p.splits).map(([k, v]) => `${k}:${v}`).join("  "),
    },
  ];

  const buildSelected = async () => {
    const ids = data!.filter((p) => selected.has(p.project_id)).map((p) => p.project_id);
    await api.createJob({ type: "build_challenge", mode: "selected_projects", project_ids: ids });
    nav("/live");
  };

  return (
    <div>
      <h1 className="page-title">Projects</h1>
      <p className="page-sub">
        Discovered from the challenge registry, ordered smallest → biggest by candidate functions.
      </p>
      {error && <div className="banner err">{error}</div>}
      <div className="btn-row" style={{ marginBottom: 12 }}>
        <button className="btn primary" disabled={selected.size === 0} onClick={buildSelected}>
          Run selected projects ({selected.size})
        </button>
        <button className="btn" onClick={reload}>Refresh</button>
      </div>
      {loading ? (
        <div className="empty">Loading projects…</div>
      ) : (
        <DataTable
          rows={data || []}
          columns={columns}
          rowKey={(p) => p.project_id}
          selectable={{
            selected,
            onToggle: toggle,
            onToggleAll: toggleAll,
            getKey: (p) => p.project_id,
          }}
          onRowClick={(p) => nav(`/functions?project=${encodeURIComponent(p.project_id)}`)}
          searchPlaceholder="Search projects…"
        />
      )}
    </div>
  );
}
