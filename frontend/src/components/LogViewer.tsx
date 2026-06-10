import { useEffect, useRef } from "react";

export interface LogLine {
  text: string;
  level?: string;
}

export default function LogViewer({ lines, height }: { lines: LogLine[]; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines.length]);
  return (
    <div className="log-viewer" ref={ref} style={height ? { height } : undefined}>
      {lines.length === 0 && <span className="muted">No log output yet…</span>}
      {lines.map((l, i) => (
        <div key={i} className={l.level ? `lvl-${l.level}` : undefined}>
          {l.text}
        </div>
      ))}
    </div>
  );
}
