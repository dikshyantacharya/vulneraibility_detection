import { useEffect, useReducer, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research, type AgentFlow, type FlowStage, type IterationSummary, type ResearchRun, type ResearchSample } from "../api/research";
import { useAsync } from "../state";
import { subscribeDashboard } from "../api/websocket";

// ---------------------------------------------------------------------------
// Stage classification helpers
// ---------------------------------------------------------------------------

function parseIteration(stage: string | null | undefined): number {
  if (!stage) return 0;
  const m = stage.match(/_iter(\d+)$/);
  return m ? parseInt(m[1], 10) : 0;
}

function stagePhase(stage: string | null | undefined): "llm" | "retrieval" | "validation" | "unknown" {
  if (!stage) return "unknown";
  if (stage.includes("retrieval") || stage.startsWith("03_")) return "retrieval";
  if (stage.includes("repair") || stage.includes("validated")) return "validation";
  return "llm";
}

function statusColor(status?: FlowStage["status"] | string): string {
  if (status === "completed") return "green";
  if (status === "failed") return "red";
  if (status === "running") return "amber";
  if (status === "skipped") return "gray";
  return "gray";
}

// ---------------------------------------------------------------------------
// Live WS state reducer
// ---------------------------------------------------------------------------

type FlowAction =
  | { type: "SET_FLOW"; flow: AgentFlow }
  | { type: "STAGE_STARTED"; stage: string }
  | { type: "STAGE_COMPLETED"; stage: string; data?: any }
  | { type: "STAGE_FAILED"; stage: string; error?: string }
  | { type: "ITERATION_STARTED"; data: any }
  | { type: "ITERATION_COMPLETED"; data: any };

function flowReducer(state: AgentFlow | null, action: FlowAction): AgentFlow | null {
  if (action.type === "SET_FLOW") return action.flow;
  if (!state) return state;

  const withUpdatedStage = (stage: string, patch: Partial<FlowStage>): AgentFlow => {
    const existing = state.stages.find((s) => s.stage === stage);
    if (existing) {
      return { ...state, stages: state.stages.map((s) => s.stage === stage ? { ...s, ...patch } : s) };
    }
    return { ...state, stages: [...state.stages, { stage, iteration: parseIteration(stage), ...patch }] };
  };

  switch (action.type) {
    case "STAGE_STARTED":
      return withUpdatedStage(action.stage, { status: "running" });
    case "STAGE_COMPLETED":
      return withUpdatedStage(action.stage, {
        status: "completed",
        elapsed_seconds: action.data?.elapsed_seconds,
        finish_reason: action.data?.finish_reason,
        was_truncated: action.data?.was_truncated,
        usage: action.data?.usage,
      });
    case "STAGE_FAILED":
      return withUpdatedStage(action.stage, { status: "failed", error: action.error });
    case "ITERATION_COMPLETED": {
      const row: IterationSummary = {
        iteration: action.data?.iteration,
        phase: action.data?.phase,
        new_evidence_count: action.data?.new_evidence_count,
        stop_reason: action.data?.stop_reason,
      };
      const already = state.iterations.some(
        (it) => it.iteration === row.iteration && it.phase === row.phase
      );
      return already ? state : { ...state, iterations: [...state.iterations, row] };
    }
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function IterationBadge({ iteration }: { iteration: number }) {
  if (!iteration) return null;
  return <span className="badge gray" style={{ fontSize: 10 }}>iter {iteration}</span>;
}

function PhaseBadge({ stage }: { stage?: string | null }) {
  const ph = stagePhase(stage);
  if (ph === "retrieval") return <span className="badge gray" style={{ fontSize: 10 }}>retrieval</span>;
  if (ph === "validation") return <span className="badge gray" style={{ fontSize: 10 }}>validation</span>;
  return null;
}

function ParseStatusBadge({ s }: { s: FlowStage }) {
  const ps = s.parse_status;
  // Synthesize from parse_status or fall back to parsed_answer presence.
  if (ps === "valid" || (!ps && s.parsed_answer != null)) {
    return <span className="badge green" style={{ fontSize: 10 }}>JSON valid</span>;
  }
  if (ps === "invalid") {
    return <span className="badge red" style={{ fontSize: 10 }} title={s.parse_error ?? s.validation_error ?? undefined}>JSON invalid</span>;
  }
  if (ps === "repaired" || ps === "repair_failed") {
    return <span className="badge amber" style={{ fontSize: 10 }}>{ps === "repaired" ? "repaired" : "repair failed"}</span>;
  }
  if (ps === "text_only") {
    return <span className="badge gray" style={{ fontSize: 10 }}>text response</span>;
  }
  if (ps === "failed") {
    return <span className="badge red" style={{ fontSize: 10 }}>parse failed</span>;
  }
  // Unknown — don't show a misleading badge; absence of badge means "no parse data".
  return null;
}

function FlowStageCard({ s, selected, onClick }: { s: FlowStage; selected: boolean; onClick: () => void }) {
  const iter = parseIteration(s.stage);
  const color = statusColor(s.status);
  const usage = s.usage as any;
  const totalTok = usage?.total_tokens ?? usage?.total ?? null;
  const tokStr = totalTok != null ? `${totalTok} tok` : null;

  return (
    <div
      className="card"
      style={{
        marginBottom: 6,
        cursor: "pointer",
        borderLeft: `3px solid var(--${color === "green" ? "green" : color === "red" ? "red" : color === "amber" ? "amber" : "border"})`,
        background: selected ? "var(--surface2, #f0f4ff)" : undefined,
      }}
      onClick={onClick}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <strong style={{ fontFamily: "monospace", fontSize: 13 }}>{s.stage || "—"}</strong>
        <span className={`badge ${color}`}>{s.status || "pending"}</span>
        <IterationBadge iteration={iter} />
        <PhaseBadge stage={s.stage} />
        <ParseStatusBadge s={s} />
        {s.was_truncated && <span className="badge red" title="response was cut off">truncated</span>}
        {s.finish_reason && s.finish_reason !== "stop" && !s.was_truncated && (
          <span className="badge amber">{s.finish_reason}</span>
        )}
        {(s.system_prompt || s.user_prompt || s.response) && (
          <span className="badge gray" style={{ fontSize: 10 }}>has content</span>
        )}
        <span style={{ flex: 1 }} />
        <span className="muted" style={{ fontSize: 11 }}>
          {s.prompt_chars != null ? `${s.prompt_chars}p` : ""}
          {s.elapsed_seconds != null ? ` · ${Number(s.elapsed_seconds).toFixed(1)}s` : ""}
          {tokStr ? ` · ${tokStr}` : ""}
          {s.requested_max_tokens != null ? ` · max=${s.requested_max_tokens}` : ""}
        </span>
      </div>
    </div>
  );
}

function ContentBlock({ label, text }: { label: string; text: string | null | undefined }) {
  if (!text) return null;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4, color: "var(--muted, #64748b)" }}>{label}</div>
      <pre style={{
        background: "var(--surface2, #f8fafc)",
        border: "1px solid var(--border, #e2e8f0)",
        borderRadius: 4,
        padding: "8px 10px",
        fontSize: 11,
        fontFamily: "monospace",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        maxHeight: 320,
        overflowY: "auto",
        margin: 0,
      }}>{text}</pre>
    </div>
  );
}

function StageDetailPanel({ s }: { s: FlowStage }) {
  type TabKey = "user" | "system" | "messages" | "response" | "answer" | "parsed" | "error";
  const [tab, setTab] = useState<TabKey>("user");
  const hasSystem = !!s.system_prompt;
  const hasUser = !!s.user_prompt;
  const hasMessages = !!(s.messages && s.messages.length > 0);
  const hasResponse = !!s.response;
  const hasAnswer = !!s.answer_text;
  const hasParsed = s.parsed_answer != null;
  const hasError = !!(s.error || s.parse_error || s.validation_error);

  const noContent = !hasSystem && !hasUser && !hasMessages && !hasResponse && !hasAnswer && !hasParsed && !hasError;

  const tabs: { key: TabKey; label: string; available: boolean }[] = [
    { key: "user", label: "User Prompt", available: hasUser },
    { key: "system", label: "System Prompt", available: hasSystem },
    { key: "messages", label: "Messages", available: hasMessages },
    { key: "response", label: "Response", available: hasResponse },
    { key: "answer", label: "Answer Text", available: hasAnswer },
    { key: "parsed", label: "Parsed JSON", available: hasParsed },
    { key: "error", label: "Error / Diagnostics", available: hasError },
  ];

  const parsedText = hasParsed ? JSON.stringify(s.parsed_answer, null, 2) : null;
  const errorText = [
    s.error ? `Runtime error:\n${s.error}` : null,
    s.parse_error ? `Parse error:\n${s.parse_error}` : null,
    s.validation_error ? `Validation error:\n${s.validation_error}` : null,
    s.repair_status ? `Repair status: ${s.repair_status}` : null,
  ].filter(Boolean).join("\n\n") || null;

  return (
    <div className="card" style={{ marginTop: 8, marginBottom: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 13 }}>
        {s.stage} — detail
        {s.status && (
          <span className={`badge ${statusColor(s.status)}`} style={{ marginLeft: 8 }}>{s.status}</span>
        )}
        {s.parse_status && (
          <span className="muted" style={{ fontSize: 11, marginLeft: 8 }}>parse: {s.parse_status}</span>
        )}
      </div>

      {noContent ? (
        <div className="muted" style={{ fontSize: 12 }}>
          {s.status === "running"
            ? "Stage is running — content will appear after completion. Refresh to reload."
            : s.status === "completed"
              ? "Stage completed but no content stored — this may be a legacy artifact without enriched model_calls.jsonl."
              : "No prompt/response content available for this stage."}
        </div>
      ) : (
        <>
          <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
            {tabs.filter(t => t.available).map(t => (
              <button
                key={t.key}
                className={`btn${tab === t.key ? "" : " btn-secondary"}`}
                style={{ fontSize: 11, padding: "2px 10px" }}
                onClick={() => setTab(t.key)}
              >
                {t.label}
              </button>
            ))}
          </div>

          {tab === "system" && <ContentBlock label="System Prompt" text={s.system_prompt} />}
          {tab === "user" && <ContentBlock label="User Prompt" text={s.user_prompt} />}
          {tab === "messages" && (
            <div>
              {(s.messages || []).map((m, i) => (
                <div key={i} style={{ marginBottom: 8 }}>
                  <span className="badge gray" style={{ fontSize: 10, marginBottom: 4 }}>{m.role}</span>
                  <pre style={{
                    background: "var(--surface2, #f8fafc)",
                    border: "1px solid var(--border, #e2e8f0)",
                    borderRadius: 4, padding: "6px 8px", fontSize: 11,
                    fontFamily: "monospace", whiteSpace: "pre-wrap", wordBreak: "break-word",
                    maxHeight: 240, overflowY: "auto", margin: 0,
                  }}>{m.content}</pre>
                </div>
              ))}
            </div>
          )}
          {tab === "response" && <ContentBlock label="Raw Response" text={s.response} />}
          {tab === "answer" && <ContentBlock label="Extracted <answer> text" text={s.answer_text} />}
          {tab === "parsed" && <ContentBlock label="Parsed JSON" text={parsedText} />}
          {tab === "error" && <ContentBlock label="Error / Diagnostics" text={errorText} />}
        </>
      )}
    </div>
  );
}

function IterationRow({ it }: { it: IterationSummary }) {
  return (
    <div style={{ padding: "4px 8px", background: "var(--surface2, #f8fafc)",
                  borderRadius: 4, marginBottom: 4, fontSize: 12, display: "flex", gap: 8, alignItems: "center" }}>
      <span className="badge gray">phase: {it.phase ?? "?"}</span>
      <span className="badge gray">iter {it.iteration}</span>
      {it.new_evidence_count != null && (
        <span>{it.new_evidence_count > 0
          ? <span className="badge green">+{it.new_evidence_count} evidence</span>
          : <span className="badge amber">no new evidence</span>}
        </span>
      )}
      {it.stop_reason && <span className="muted">stop: {it.stop_reason}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Landing page (no runId/sampleId)
// ---------------------------------------------------------------------------

function PredBadge({ p }: { p?: string | null }) {
  if (p === "vulnerable") return <span className="badge red">vulnerable</span>;
  if (p === "safe") return <span className="badge green">safe</span>;
  return <span className="badge gray">{p || "—"}</span>;
}

function DecisionStatusBadge({ ds }: { ds?: string | null }) {
  if (!ds) return null;
  if (ds === "confirmed_vulnerable") return <span className="badge red" style={{ fontSize: 10 }}>confirmed</span>;
  if (ds === "confirmed_non_vulnerable") return <span className="badge green" style={{ fontSize: 10 }}>confirmed</span>;
  if (ds === "forced_binary_vulnerable" || ds === "forced_binary_non_vulnerable")
    return <span className="badge amber" style={{ fontSize: 10 }}>forced binary</span>;
  if (ds.includes("failed")) return <span className="badge red" style={{ fontSize: 10 }}>failed parse</span>;
  return <span className="badge gray" style={{ fontSize: 10 }}>{ds}</span>;
}

function AgentFlowLanding() {
  const nav = useNavigate();
  const runs = useAsync<ResearchRun[]>(() => research.runs(), []);
  const sorted = (runs.data || []).slice().sort((a, b) => b.mtime - a.mtime);
  const latestRun = sorted[0] ?? null;
  const latestSamples = useAsync<ResearchSample[]>(
    () => latestRun ? research.samples(latestRun.run_id) : Promise.resolve([]),
    [latestRun?.run_id],
  );

  return (
    <div>
      <h1 className="page-title">Agentic Flow</h1>
      <p className="page-sub">
        Select an audit run/sample to inspect the full agentic decision flow — stages, prompts,
        responses, KG evidence, loop iterations, and final decision.
      </p>

      <div className="btn-row" style={{ marginBottom: 16 }}>
        <button className="btn btn-primary" onClick={() => nav("/research")}>Run new audit</button>
        <button className="btn" onClick={() => nav("/research/runs")}>View audit runs</button>
      </div>

      {runs.loading && <div className="empty">Loading recent runs…</div>}

      {runs.error && (
        <div className="card" style={{ borderLeft: "4px solid var(--red, #dc2626)" }}>
          <div className="muted">Could not load audit runs: {runs.error}</div>
          <div className="btn-row" style={{ marginTop: 8 }}>
            <button className="btn" onClick={runs.reload}>Retry</button>
            <button className="btn" onClick={() => nav("/research")}>Run Audit</button>
          </div>
        </div>
      )}

      {!runs.loading && !runs.error && sorted.length === 0 && (
        <div className="card" style={{ textAlign: "center", padding: 32 }}>
          <div style={{ fontSize: 15, marginBottom: 8 }}>No agentic audit runs found.</div>
          <div className="muted" style={{ marginBottom: 16 }}>
            Start one from Run Audit to see agentic flow timelines here.
          </div>
          <button className="btn btn-primary" onClick={() => nav("/research")}>Run Audit</button>
        </div>
      )}

      {sorted.length > 0 && (
        <>
          {/* Latest run — show samples inline */}
          <div className="section-title">
            Latest run: <span className="mono" style={{ fontSize: 12 }}>{latestRun!.run_id}</span>
            <span className="muted" style={{ fontSize: 11, marginLeft: 8 }}>
              {new Date(latestRun!.mtime * 1000).toLocaleString()}
            </span>
          </div>

          {latestSamples.loading && <div className="empty">Loading samples…</div>}

          {!latestSamples.loading && (latestSamples.data || []).length === 0 && (
            <div className="banner warn">No samples found in this run.</div>
          )}

          {(latestSamples.data || []).length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, marginBottom: 16 }}>
              <thead>
                <tr style={{ borderBottom: "2px solid var(--border, #e2e8f0)", textAlign: "left" }}>
                  <th style={{ padding: "4px 8px" }}>Function</th>
                  <th style={{ padding: "4px 8px" }}>Prediction</th>
                  <th style={{ padding: "4px 8px" }}>Status</th>
                  <th style={{ padding: "4px 8px" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(latestSamples.data || []).map((s) => (
                  <tr key={s.sample_id} style={{ borderBottom: "1px solid var(--border, #e2e8f0)" }}>
                    <td style={{ padding: "4px 8px", fontFamily: "monospace" }}>
                      {s.function_name || s.sample_id}
                    </td>
                    <td style={{ padding: "4px 8px" }}>
                      <PredBadge p={s.prediction} />
                      {s.confidence != null && (
                        <span className="muted" style={{ marginLeft: 4 }}>
                          {(s.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                    </td>
                    <td style={{ padding: "4px 8px", color: "var(--muted, #64748b)" }}>
                      <DecisionStatusBadge ds={s.decision_status} />
                      {!s.decision_status && "—"}
                    </td>
                    <td style={{ padding: "4px 8px" }}>
                      <div style={{ display: "flex", gap: 4 }}>
                        <button
                          className="btn"
                          style={{ fontSize: 11, padding: "2px 8px" }}
                          onClick={() => nav(`/research/flow/${encodeURIComponent(latestRun!.run_id)}/${encodeURIComponent(s.sample_id)}`)}
                        >
                          Open flow
                        </button>
                        <a
                          className="btn"
                          style={{ fontSize: 11, padding: "2px 8px" }}
                          href={research.flowReportUrl(latestRun!.run_id, s.sample_id)}
                          download
                          title="Download full-flow text report"
                        >
                          Report
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Older runs — compact list */}
          {sorted.length > 1 && (
            <>
              <div className="section-title">Older runs</div>
              {sorted.slice(1, 8).map((r) => (
                <div key={r.run_id} className="card" style={{ marginBottom: 6, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <span className="mono" style={{ fontSize: 12, flex: 1 }}>{r.run_id}</span>
                  <span className="muted" style={{ fontSize: 11 }}>
                    {new Date(r.mtime * 1000).toLocaleString()} · {r.samples} sample{r.samples !== 1 ? "s" : ""}
                  </span>
                  <button
                    className="btn"
                    style={{ fontSize: 11, padding: "2px 8px" }}
                    onClick={() => nav(`/research/runs`)}
                  >
                    Browse samples
                  </button>
                </div>
              ))}
            </>
          )}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detail view (runId + sampleId present) — extracted so hooks are unconditional
// ---------------------------------------------------------------------------

function AgentFlowDetail({ runId, sampleId }: { runId: string; sampleId: string }) {
  const nav = useNavigate();
  const fetched = useAsync<AgentFlow>(() => research.flow(runId, sampleId), [runId, sampleId]);
  const [flow, dispatch] = useReducer(flowReducer, null);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const reloadRef = useRef(fetched.reload);
  reloadRef.current = fetched.reload;

  useEffect(() => {
    if (fetched.data) dispatch({ type: "SET_FLOW", flow: fetched.data });
  }, [fetched.data]);

  useEffect(() => {
    const handle = subscribeDashboard((msg: any) => {
      const d = msg?.event?.data || msg?.data || {};
      const sid = d?.sample_id || d?.sid;
      if (sid && String(sid) !== String(sampleId)) return;

      const etype: string = msg?.event?.type || msg?.type || "";
      const stage: string = d?.stage || d?.api_stage || d?.agent_stage || "";

      if (etype === "model_call.start" && stage) {
        dispatch({ type: "STAGE_STARTED", stage });
      } else if (etype === "model_call.done" && stage) {
        dispatch({ type: "STAGE_COMPLETED", stage, data: d });
        reloadRef.current();
      } else if (etype === "model_call.error" && stage) {
        dispatch({ type: "STAGE_FAILED", stage, error: d?.error });
        reloadRef.current();
      } else if (etype === "evidence_iteration_completed") {
        dispatch({ type: "ITERATION_COMPLETED", data: d });
      }
    }, () => {});
    return () => handle.close();
  }, [sampleId]);

  const f = flow ?? fetched.data;
  const stages = f?.stages ?? [];
  const iterations = f?.iterations ?? [];
  const selectedS = stages.find(s => s.stage === selectedStage) ?? null;

  return (
    <div>
      <h1 className="page-title">Agentic Flow</h1>
      <p className="page-sub">
        Sample <strong className="mono">{sampleId}</strong> · run <span className="mono">{runId}</span>
      </p>

      <div className="btn-row" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => nav(`/research/trace/${runId}/${sampleId}`)}>Agent Trace</button>
        <button className="btn" onClick={() => nav(`/research/kg/${runId}/${sampleId}`)}>KG Query Flow</button>
        <button className="btn" onClick={() => { fetched.reload(); dispatch({ type: "SET_FLOW", flow: { stages: [], iterations: [] } }); }}>Refresh</button>
        <a
          className="btn btn-primary"
          href={research.flowReportUrl(runId, sampleId)}
          download
          title="Download full-flow text report (prompts, responses, parsed JSON, KG queries, final decision)"
        >
          Download full flow report
        </a>
        <button className="btn" onClick={() => nav("/research/flow")}>← Agentic Flow</button>
        <button className="btn" onClick={() => nav("/research/runs")}>← Runs</button>
      </div>

      {fetched.loading && <div className="empty">Loading flow data…</div>}
      {fetched.error && <div className="banner error">Error loading flow: {fetched.error}</div>}

      {f && (
        <>
          {/* Loop metadata */}
          <div className="card" style={{ marginBottom: 12 }}>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 13, alignItems: "center" }}>
              <span>
                <span className="muted">Loop:</span>{" "}
                {f.iterative_loop_enabled
                  ? <span className="badge green">enabled</span>
                  : <span className="badge gray">disabled (linear)</span>}
              </span>
              {f.iterations_completed != null && (
                <span>
                  <span className="muted">Iterations:</span>{" "}
                  {f.iterations_completed > 0
                    ? <span className="badge green">{f.iterations_completed}</span>
                    : <span className="badge amber">0</span>}
                </span>
              )}
              {f.loop_stop_reason && (
                <span>
                  <span className="muted">Stop reason:</span>{" "}
                  <code style={{ fontSize: 11 }}>{f.loop_stop_reason}</code>
                </span>
              )}
              {f.iterative_loop_enabled && f.iterations_completed === 0 && !f.loop_stop_reason && (
                <span className="badge amber" title="Loop enabled but no iteration summary recorded">0 iterations — no stop reason recorded</span>
              )}
              {f.total_evidence_items != null && (
                <span>
                  <span className="muted">Evidence:</span>{" "}
                  {f.initial_evidence_items ?? "?"} initial → {f.total_evidence_items} total
                </span>
              )}
              {f.fallback && (
                <span className="badge amber" title="Pre-iterative run; rendered from agent_trace/model_calls">legacy artifact</span>
              )}
            </div>
          </div>

          {iterations.length > 0 && (
            <>
              <div className="section-title">Evidence iterations ({iterations.length})</div>
              {iterations.map((it, i) => <IterationRow key={i} it={it} />)}
            </>
          )}

          <div className="section-title" style={{ marginTop: 12 }}>
            Stage timeline ({stages.length})
            {stages.length > 0 && (
              <span className="muted" style={{ fontSize: 11, marginLeft: 8 }}>click a stage to view prompts / response</span>
            )}
          </div>

          {stages.length === 0 && !fetched.loading && (
            <div className="banner warn">
              No stage data found yet.{" "}
              {f.fallback
                ? "Old run: iterative flow artifacts not available; showing trace fallback."
                : "The run may still be in progress. Live WS updates will appear as stages complete. Use Refresh to reload."}
            </div>
          )}

          {stages.map((s, i) => (
            <div key={`${s.stage}-${i}`}>
              <FlowStageCard
                s={s}
                selected={selectedStage === s.stage}
                onClick={() => setSelectedStage(prev => prev === s.stage ? null : s.stage ?? null)}
              />
              {selectedStage === s.stage && selectedS && (
                <StageDetailPanel s={selectedS} />
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page — dispatches to landing or detail based on URL params
// ---------------------------------------------------------------------------

export default function AgentFlowPage() {
  const { runId, sampleId } = useParams();
  if (runId && sampleId) return <AgentFlowDetail runId={runId} sampleId={sampleId} />;
  return <AgentFlowLanding />;
}
