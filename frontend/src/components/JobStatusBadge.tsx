import type { JobStatus } from "../api/types";

const MAP: Record<JobStatus, { cls: string; label: string }> = {
  queued: { cls: "gray", label: "Queued" },
  running: { cls: "blue", label: "Running" },
  completed: { cls: "green", label: "Completed" },
  failed: { cls: "red", label: "Failed" },
  cancelled: { cls: "amber", label: "Cancelled" },
};

export default function JobStatusBadge({ status }: { status: JobStatus }) {
  const m = MAP[status] || MAP.queued;
  return (
    <span className={`badge ${m.cls}`}>
      <span className="dot" />
      {m.label}
    </span>
  );
}
