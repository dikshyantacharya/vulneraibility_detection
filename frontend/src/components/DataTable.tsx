import { useMemo, useState } from "react";
import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  value?: (row: T) => string | number;
  mono?: boolean;
}

export type SelectionConfig<T = any> = {
  selected: Set<string>;
  onToggle: (key: string) => void;
  onToggleAll?: (keys: string[]) => void;
  getKey?: (row: T, index: number) => string;
};

interface Props<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  selectable?: boolean | SelectionConfig<T>;
  onRowClick?: (row: T) => void;
  pageSize?: number;
  searchPlaceholder?: string;
}

export default function DataTable<T>({
  rows,
  columns,
  rowKey,
  selectable,
  onRowClick,
  pageSize = 50,
  searchPlaceholder = "Search…",
}: Props<T>) {
  const [q, setQ] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [asc, setAsc] = useState(true);
  const [page, setPage] = useState(0);

  const isControlled = typeof selectable === "object" && selectable !== null;
  const selected = isControlled ? selectable.selected : new Set<string>();
  const onToggle = isControlled ? selectable.onToggle : undefined;
  const onToggleAll = isControlled ? selectable.onToggleAll : undefined;
  const getKey = isControlled && selectable.getKey ? selectable.getKey : rowKey;

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();
    let r = rows;
    if (needle) {
      r = rows.filter((row) =>
        columns.some((c) => {
          const v = c.value ? c.value(row) : (row as any)[c.key];
          return String(v ?? "").toLowerCase().includes(needle);
        })
      );
    }
    if (sortKey) {
      const col = columns.find((c) => c.key === sortKey);
      r = [...r].sort((a, b) => {
        const va = col?.value ? col.value(a) : (a as any)[sortKey];
        const vb = col?.value ? col.value(b) : (b as any)[sortKey];
        if (va == null) return 1;
        if (vb == null) return -1;
        if (va < vb) return asc ? -1 : 1;
        if (va > vb) return asc ? 1 : -1;
        return 0;
      });
    }
    return r;
  }, [rows, q, sortKey, asc, columns]);

  const pages = Math.ceil(filtered.length / pageSize) || 1;
  const view = filtered.slice(page * pageSize, page * pageSize + pageSize);
  const viewKeys = view.map((row, idx) => getKey(row, idx));
  const allSelected = isControlled && viewKeys.length > 0 && viewKeys.every((k) => selected.has(k));
  const someSelected = isControlled && viewKeys.some((k) => selected.has(k));

  return (
    <div>
      <div className="toolbar">
        <input
          type="text"
          placeholder={searchPlaceholder}
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(0);
          }}
        />
        <span className="muted">
          {filtered.length} row{filtered.length !== 1 ? "s" : ""}
          {isControlled ? ` · ${selected.size} selected` : ""}
        </span>
        <span style={{ flex: 1 }} />
        {pages > 1 && (
          <span className="btn-row">
            <button className="btn" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              ‹
            </button>
            <span className="muted" style={{ alignSelf: "center" }}>
              {page + 1}/{pages}
            </span>
            <button className="btn" disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}>
              ›
            </button>
          </span>
        )}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {isControlled && (
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    checked={!!allSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = someSelected && !allSelected;
                    }}
                    onChange={() => onToggleAll?.(viewKeys)}
                  />
                </th>
              )}
              {columns.map((c) => (
                <th
                  key={c.key}
                  onClick={() => {
                    if (sortKey === c.key) setAsc(!asc);
                    else {
                      setSortKey(c.key);
                      setAsc(true);
                    }
                  }}
                >
                  {c.header}
                  {sortKey === c.key ? (asc ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {view.map((row, idx) => {
              const k = getKey(row, idx);
              return (
                <tr
                  key={k}
                  className={isControlled && selected.has(k) ? "selected" : undefined}
                  onClick={() => onRowClick?.(row)}
                  style={onRowClick ? { cursor: "pointer" } : undefined}
                >
                  {isControlled && (
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(k)}
                        onChange={() => onToggle?.(k)}
                      />
                    </td>
                  )}
                  {columns.map((c) => (
                    <td key={c.key} className={c.mono ? "mono" : undefined}>
                      {c.render ? c.render(row) : String((row as any)[c.key] ?? "—")}
                    </td>
                  ))}
                </tr>
              );
            })}
            {view.length === 0 && (
              <tr>
                <td colSpan={columns.length + (isControlled ? 1 : 0)} className="empty">
                  No matching rows.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
