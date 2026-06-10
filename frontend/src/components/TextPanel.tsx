import { useMemo, useState } from "react";

interface Props {
  text?: string | null;
  title?: string;
  /** pretty-print as JSON if the text parses */
  json?: boolean;
  height?: number;
}

/**
 * Large, readable monospace panel for LLM prompts/responses with copy, in-text
 * search/highlight, line-wrap toggle and a fullscreen modal view.
 */
export default function TextPanel({ text, title, json, height = 320 }: Props) {
  const [wrap, setWrap] = useState(true);
  const [full, setFull] = useState(false);
  const [q, setQ] = useState("");
  const [copied, setCopied] = useState(false);

  const display = useMemo(() => {
    const t = text ?? "";
    if (json && t.trim()) {
      try {
        return JSON.stringify(JSON.parse(t), null, 2);
      } catch {
        return t;
      }
    }
    return t;
  }, [text, json]);

  const matches = q ? (display.toLowerCase().match(new RegExp(q.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length : 0;

  const highlighted = useMemo(() => {
    if (!q) return display;
    try {
      const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
      return display.split(re).map((part, i) =>
        re.test(part) ? <mark key={i} style={{ background: "#fde68a" }}>{part}</mark> : <span key={i}>{part}</span>
      );
    } catch {
      return display;
    }
  }, [display, q]);

  const copy = () => {
    navigator.clipboard?.writeText(display);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const body = (h: number) => (
    <pre
      className="log-viewer"
      style={{
        height: h,
        whiteSpace: wrap ? "pre-wrap" : "pre",
        wordBreak: wrap ? "break-word" : "normal",
        overflow: "auto",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        fontSize: 12.5,
        lineHeight: 1.5,
        resize: "vertical",
      }}
    >
      {highlighted}
    </pre>
  );

  const controls = (
    <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
      {title && <strong>{title}</strong>}
      <span style={{ flex: 1 }} />
      <input
        placeholder="search…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        style={{ width: 140, fontSize: 12, padding: "2px 6px" }}
      />
      {q && <span className="muted" style={{ fontSize: 11 }}>{matches} hit{matches === 1 ? "" : "s"}</span>}
      <button className="btn small" onClick={() => setWrap((w) => !w)}>{wrap ? "No wrap" : "Wrap"}</button>
      <button className="btn small" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      <button className="btn small" onClick={() => setFull(true)}>Fullscreen</button>
    </div>
  );

  return (
    <div>
      {controls}
      {body(height)}
      {full && (
        <div
          onClick={() => setFull(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(15,23,42,.6)", zIndex: 1000, display: "flex", padding: 24 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: "var(--panel, #fff)", borderRadius: 12, padding: 16, margin: "auto", width: "min(1100px, 95vw)", maxHeight: "92vh", display: "flex", flexDirection: "column" }}
          >
            <div style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
              <strong>{title || "Text"}</strong>
              <span style={{ flex: 1 }} />
              <button className="btn" onClick={() => setFull(false)}>Close ✕</button>
            </div>
            {controls}
            {body(Math.round(window.innerHeight * 0.72))}
          </div>
        </div>
      )}
    </div>
  );
}
