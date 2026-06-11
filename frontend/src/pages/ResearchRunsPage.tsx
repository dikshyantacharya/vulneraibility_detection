import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { research, type ResearchRun, type ResearchSample, type RunMetrics, type RunSummary } from "../api/research";
import { useApp, useAsync } from "../state";

type FilterKey = "all" | "correct" | "incorrect" | "fp" | "fn" | "inconclusive" | "failed";

function providerModel(s?: RunSummary): string {
  if (!s) return "—";
  const p = s.llm?.provider_name || s.llm?.model_backend || "—";
  const m = s.llm?.model || "—";
  return `${p} · ${m}`;
}

function fmt(v: number | null | undefined, digits = 2): string {
  return v != null ? (v * 100).toFixed(digits) + "%" : "—";
}

function fmtN(v: number | null | undefined): string {
  return v != null ? String(v) : "—";
}

function CompactMetrics({ m, note }: { m: RunMetrics; note?: string | null }) {
  const acc = fmt(m.accuracy);
  const f1 = fmt(m.f1);
  const tp = fmtN(m.tp); const fp = fmtN(m.fp);
  const tn = fmtN(m.tn); const fn = fmtN(m.fn);
  const inc = m.inconclusive ?? 0;
  return (
    <span>
      <span className="badge gray">Acc {acc}</span>{" "}
      <span className="badge gray">F1 {f1}</span>{" "}
      <span className="muted">TP {tp} / FP {fp} / TN {tn} / FN {fn}</span>
      {inc > 0 && <span className="badge amber" style={{ marginLeft: 6 }}>Inconclusive {inc}</span>}
      {note && <span className="badge amber" style={{ marginLeft: 6 }}>{note}</span>}
    </span>
  );
}

function MetricsDrilldown({ m }: { m: RunMetrics }) {
  const cards: { label: string; value: string; cls?: string }[] = [
    { label: "Accuracy", value: fmt(m.accuracy) },
    { label: "Precision", value: fmt(m.precision) },
    { label: "Recall", value: fmt(m.recall) },
    { label: "F1", value: fmt(m.f1), cls: m.f1 != null && m.f1 >= 0.7 ? "green" : undefined },
    { label: "TP", value: fmtN(m.tp) },
    { label: "FP", value: fmtN(m.fp) },
    { label: "TN", value: fmtN(m.tn) },
    { label: "FN", value: fmtN(m.fn) },
    { label: "Inconclusive", value: fmtN(m.inconclusive) },
    { label: "Failed", value: fmtN(m.failed) },
  ];

  const vuln_safe = (m.tp ?? 0) + (m.fn ?? 0);
  const safe_total = (m.fp ?? 0) + (m.tn ?? 0);

  return (
    <div style={{ marginTop: 8, marginBottom: 8 }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 10 }}>
        {cards.map((c) => (
          <div key={c.label} style={{
            border: "1px solid var(--border)", borderRadius: 6, padding: "4px 10px",
            minWidth: 70, textAlign: "center",
          }}>
            <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase" }}>{c.label}</div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>{c.value}</div>
          </div>
        ))}
      </div>

      {(vuln_safe > 0 || safe_total > 0) && (
        <div style={{ overflowX: "auto", marginBottom: 8 }}>
          <table style={{ fontSize: 12, borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={thS}>True \\ Pred</th>
                <th style={thS}>Predicted Vuln</th>
                <th style={thS}>Predicted Safe</th>
                <th style={thS}>Inconclusive</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={tdS}><strong>True Vulnerable</strong></td>
                <td style={{ ...tdS, color: "var(--green)" }}>{fmtN(m.tp)} (TP)</td>
                <td style={{ ...tdS, color: "var(--red)" }}>{fmtN(m.fn)} (FN)</td>
                <td style={tdS}>—</td>
              </tr>
              <tr>
                <td style={tdS}><strong>True Safe</strong></td>
                <td style={{ ...tdS, color: "var(--red)" }}>{fmtN(m.fp)} (FP)</td>
                <td style={{ ...tdS, color: "var(--green)" }}>{fmtN(m.tn)} (TN)</td>
                <td style={tdS}>—</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {m.diagnostic && (
        <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
          Note: {m.diagnostic}
        </div>
      )}
    </div>
  );
}

const thS: React.CSSProperties = {
  border: "1px solid var(--border)", padding: "3px 8px", background: "var(--bg2)", textAlign: "center", fontSize: 11,
};
const tdS: React.CSSProperties = {
  border: "1px solid var(--border)", padding: "3px 8px", textAlign: "center", fontSize: 12,
};

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "correct", label: "Correct" },
  { key: "incorrect", label: "Incorrect" },
  { key: "fp", label: "FP" },
  { key: "fn", label: "FN" },
  { key: "inconclusive", label: "Inconclusive" },
  { key: "failed", label: "Failed" },
];

function filterSamples(samples: ResearchSample[], f: FilterKey): ResearchSample[] {
  if (f === "all") return samples;
  if (f === "correct") return samples.filter((s) => s.result === "correct");
  if (f === "incorrect") return samples.filter((s) => s.result === "incorrect");
  if (f === "fp") return samples.filter((s) => s.error_type === "fp");
  if (f === "fn") return samples.filter((s) => s.error_type === "fn");
  if (f === "inconclusive") return samples.filter((s) => s.result === "inconclusive");
  if (f === "failed") return samples.filter((s) => !s.prediction_available && s.result !== "inconclusive");
  return samples;
}

export default function ResearchRunsPage() {
  const nav = useNavigate();
  const { mode } = useApp();
  const runs = useAsync(() => research.runs(), []);
  const [open, setOpen] = useState<string | null>(null);
  const [samples, setSamples] = useState<ResearchSample[]>([]);
  const [summaries, setSummaries] = useState<Record<string, RunSummary>>({});
  const [filter, setFilter] = useState<FilterKey>("all");

  useEffect(() => {
    if (open) {
      research.samples(open, mode).then(setSamples).catch(() => setSamples([]));
      setFilter("all");
    }
  }, [open, mode]);

  // Enrich each run with the real provider/model/KG/metrics summary.
  useEffect(() => {
    (runs.data || []).forEach((r) => {
      if (!summaries[r.run_id]) {
        research.runSummary(r.run_id, mode).then((s) =>
          setSummaries((prev) => ({ ...prev, [r.run_id]: s }))
        ).catch(() => {});
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runs.data, mode]);

  return (
    <div>
      <h1 className="page-title">Research Audit — Runs</h1>
      <p className="page-sub">Past and in-progress agentic audit runs with real provider/model and metrics.</p>
      <button className="btn" onClick={() => { runs.reload(); setSummaries({}); }} style={{ marginBottom: 12 }}>Refresh</button>

      {(runs.data || []).length === 0 && <div className="empty">No runs yet. Start one from Run Audit.</div>}

      {(runs.data || []).map((r: ResearchRun) => {
        const s = summaries[r.run_id];
        const m = s?.metrics;
        const isOpen = open === r.run_id;
        const visible = filterSamples(samples, filter);

        return (
          <div className="card" key={r.run_id} style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <button className="btn" onClick={() => setOpen(isOpen ? null : r.run_id)}>
                {isOpen ? "▾" : "▸"}
              </button>
              <strong className="mono">{r.run_id}</strong>
              {s?.status && <span className={`badge ${s.status === "completed" ? "green" : s.status === "failed" ? "red" : s.status === "running" ? "blue" : "gray"}`}>{s.status}</span>}
              {r.is_job_run && <span className="badge blue">dashboard job</span>}
              <span style={{ flex: 1 }} />
              <span className="muted">{new Date(r.mtime * 1000).toLocaleString()}</span>
            </div>

            <dl className="kv" style={{ fontSize: 12, marginTop: 10 }}>
              <dt>LLM</dt><dd><strong>{providerModel(s)}</strong></dd>
              <dt>Server</dt><dd className="mono">{s?.llm?.base_url || "—"}</dd>
              <dt>KG</dt><dd>{s?.kg?.display_name || s?.kg?.preset || "—"} → <span className="mono">{s?.kg?.effective_backend || "—"}</span></dd>
              <dt>Config</dt><dd className="mono">{s?.config_name || "—"}</dd>
              <dt>Samples</dt>
              <dd>
                {s ? `${s.samples_completed}/${s.samples_requested} completed` : `${r.samples} samples`}
                {s?.samples_failed ? ` · ${s.samples_failed} failed` : ""}
                {s?.samples_pending ? ` · ${s.samples_pending} pending` : ""}
                {s?.selection?.exact_sample_ids_only ? " · exact mode" : ""}
              </dd>
              <dt>Tokens</dt><dd>{s?.usage?.total_tokens ?? "—"} {s?.usage?.cost_total_usd != null ? `· $${Number(s.usage.cost_total_usd).toFixed(4)}` : ""}</dd>
              <dt>Metrics</dt>
              <dd>
                {!s ? (
                  <span className="muted">—</span>
                ) : s.metrics_available && m ? (
                  <CompactMetrics m={m} note={s.metrics_note} />
                ) : (
                  <span className="muted">
                    {s.metrics_reason
                      ? `Metrics unavailable: ${(m as any)?.diagnostic || s.metrics_reason}`
                      : "—"}
                  </span>
                )}
              </dd>
            </dl>

            {isOpen && (
              <div style={{ marginTop: 12 }}>
                {/* Metrics drilldown */}
                {s?.metrics_available && m && (
                  <MetricsDrilldown m={m} />
                )}

                {/* Filter pills */}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                  {FILTERS.map(({ key, label }) => (
                    <button
                      key={key}
                      className={`btn${filter === key ? " btn-active" : ""}`}
                      style={{ fontSize: 12, padding: "2px 10px" }}
                      onClick={() => setFilter(key)}
                    >
                      {label}
                      {key !== "all" && (
                        <span style={{ marginLeft: 4, opacity: 0.7 }}>
                          ({filterSamples(isOpen ? samples : [], key).length})
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Sample</th>
                        <th>Function</th>
                        {mode === "admin" && <th>True Label</th>}
                        <th>Prediction</th>
                        <th>Confidence</th>
                        <th>Status</th>
                        {mode === "admin" && <th>Result</th>}
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {visible.map((sm) => (
                        <tr key={sm.sample_id} style={
                          sm.result === "incorrect" ? { background: "rgba(220,50,50,0.04)" }
                          : sm.result === "correct" ? { background: "rgba(50,180,50,0.04)" }
                          : undefined
                        }>
                          <td className="mono">{sm.sample_id}</td>
                          <td>{sm.function_name}</td>
                          {mode === "admin" && (
                            <td>
                              {sm.true_label === "vulnerable" ? <span className="badge red">vuln</span>
                               : sm.true_label === "safe" ? <span className="badge green">safe</span>
                               : <span className="muted">—</span>}
                            </td>
                          )}
                          <td>
                            {sm.prediction === "vulnerable" ? <span className="badge red">vulnerable</span>
                              : sm.prediction === "safe" ? <span className="badge green">safe</span>
                              : <span className="badge gray">—</span>}
                          </td>
                          <td>{sm.confidence != null ? `${(sm.confidence * 100).toFixed(0)}%` : "—"}</td>
                          <td className="muted">{sm.decision_status || "—"}</td>
                          {mode === "admin" && (
                            <td>
                              {sm.result === "correct" ? <span className="badge green">{sm.error_type?.toUpperCase() || "✓"}</span>
                               : sm.result === "incorrect" ? <span className="badge red">{sm.error_type?.toUpperCase() || "✗"}</span>
                               : sm.result === "inconclusive" ? <span className="badge amber">inconclusive</span>
                               : sm.result === "failed" ? <span className="badge red">failed</span>
                               : <span className="muted">—</span>}
                            </td>
                          )}
                          <td style={{ whiteSpace: "nowrap" }}>
                            <a onClick={() => nav(`/research/trace/${r.run_id}/${sm.sample_id}`)} style={{ marginRight: 8, cursor: "pointer" }}>Trace</a>
                            <a onClick={() => nav(`/research/kg/${r.run_id}/${sm.sample_id}`)} style={{ marginRight: 8, cursor: "pointer" }}>KG flow</a>
                            <a href={research.flowReportUrl(r.run_id, sm.sample_id)} target="_blank" rel="noreferrer" style={{ fontSize: 11 }}>Report</a>
                          </td>
                        </tr>
                      ))}
                      {visible.length === 0 && (
                        <tr>
                          <td colSpan={mode === "admin" ? 8 : 6} className="empty">
                            {samples.length === 0 ? "No samples in this run." : `No samples match filter "${filter}".`}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
