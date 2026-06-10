import type { ReactNode } from "react";

export default function MetricCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: "green" | "red" | "amber" | "blue";
}) {
  const color =
    accent === "green" ? "var(--green)"
    : accent === "red" ? "var(--red)"
    : accent === "amber" ? "var(--amber)"
    : accent === "blue" ? "var(--primary)"
    : "var(--text)";
  return (
    <div className="card metric">
      <div className="label">{label}</div>
      <div className="value" style={{ color }}>{value}</div>
      {sub != null && <div className="sub">{sub}</div>}
    </div>
  );
}
