import { useMemo, useRef, useState } from "react";
import type { GraphEdge, GraphNode } from "../api/types";

const PALETTE = [
  "#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed",
  "#0891b2", "#db2777", "#65a30d", "#475569", "#ea580c",
];

function colorFor(type: string | undefined, types: string[]): string {
  const i = Math.max(0, types.indexOf(type || ""));
  return PALETTE[i % PALETTE.length];
}

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlight?: Set<string>;
  showOnlyHighlight?: boolean;
  onSelect?: (node: GraphNode) => void;
  selectedId?: string;
}

/** Dependency-free SVG graph: deterministic circular layout + pan/zoom. */
export default function KGGraphView({ nodes, edges, highlight, showOnlyHighlight, onSelect, selectedId }: Props) {
  const [view, setView] = useState({ x: -500, y: -400, w: 1000, h: 800 });
  const drag = useRef<{ x: number; y: number } | null>(null);

  const types = useMemo(() => Array.from(new Set(nodes.map((n) => n.type || ""))), [nodes]);

  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    const R = 360;
    nodes.forEach((n, i) => {
      const a = (i / Math.max(1, nodes.length)) * Math.PI * 2;
      // ring by degree band so high-degree nodes sit inner
      const band = 1 - Math.min(1, (n.degree || 0) / 40) * 0.45;
      pos.set(n.id, { x: Math.cos(a) * R * band, y: Math.sin(a) * R * band });
    });
    return pos;
  }, [nodes]);

  const visibleNodes = showOnlyHighlight && highlight ? nodes.filter((n) => highlight.has(n.id)) : nodes;
  const visibleIds = new Set(visibleNodes.map((n) => n.id));
  const visibleEdges = edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.1 : 0.9;
    setView((v) => ({
      ...v,
      x: v.x - (v.w * (factor - 1)) / 2,
      y: v.y - (v.h * (factor - 1)) / 2,
      w: v.w * factor,
      h: v.h * factor,
    }));
  };

  return (
    <svg
      className="graph-svg"
      viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
      onWheel={onWheel}
      onMouseDown={(e) => (drag.current = { x: e.clientX, y: e.clientY })}
      onMouseUp={() => (drag.current = null)}
      onMouseLeave={() => (drag.current = null)}
      onMouseMove={(e) => {
        if (!drag.current) return;
        const dx = ((e.clientX - drag.current.x) / 600) * view.w;
        const dy = ((e.clientY - drag.current.y) / 480) * view.h;
        drag.current = { x: e.clientX, y: e.clientY };
        setView((v) => ({ ...v, x: v.x - dx, y: v.y - dy }));
      }}
    >
      <g>
        {visibleEdges.map((e, i) => {
          const a = layout.get(e.source);
          const b = layout.get(e.target);
          if (!a || !b) return null;
          const hot = highlight && (highlight.has(e.source) || highlight.has(e.target));
          return (
            <line
              key={i}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={hot ? "#2563eb" : "#cbd5e1"}
              strokeOpacity={highlight && !hot ? 0.15 : 0.5}
              strokeWidth={hot ? 1.4 : 0.6}
            />
          );
        })}
        {visibleNodes.map((n) => {
          const p = layout.get(n.id);
          if (!p) return null;
          const isHi = !highlight || highlight.has(n.id);
          const r = 4 + Math.min(8, (n.degree || 0) / 6);
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} onClick={() => onSelect?.(n)} style={{ cursor: "pointer" }}>
              <circle
                r={n.id === selectedId ? r + 3 : r}
                fill={colorFor(n.type, types)}
                fillOpacity={isHi ? 1 : 0.18}
                stroke={n.id === selectedId ? "#111827" : "#fff"}
                strokeWidth={n.id === selectedId ? 2 : 0.8}
              />
              {(n.id === selectedId || (highlight?.has(n.id) && r > 7)) && (
                <text x={r + 2} y={3} fontSize={9} fill="#374151">{(n.name || n.label || "").slice(0, 18)}</text>
              )}
            </g>
          );
        })}
      </g>
    </svg>
  );
}
