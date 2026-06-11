import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research, type NormalizedSample, type Stage } from "../api/research";
import { useApp, useAsync } from "../state";
import TextPanel from "../components/TextPanel";

type StageTab = "system" | "user" | "messages" | "response" | "parsed" | "error";
type Filter = "all" | "failed" | "repair" | "planning" | "final";

function messagesText(s: Stage): string {
  if (s.messages && s.messages.length) {
    return s.messages.map((m) => `### ${m.role.toUpperCase()}\n${m.content}`).join("\n\n");
  }
  const parts: string[] = [];
  if (s.system_prompt) parts.push(`### SYSTEM\n${s.system_prompt}`);
  if (s.user_prompt || s.prompt) parts.push(`### USER\n${s.user_prompt || s.prompt}`);
  return parts.join("\n\n");
}

function VerdictBadge({ label }: { label?: string | null }) {
  if (label === "vulnerable") return <span className="badge red">vulnerable</span>;
  if (label === "safe") return <span className="badge green">safe / non-vulnerable</span>;
  return <span className="badge gray">—</span>;
}

function tokensLabel(t?: Stage["tokens"]): string {
  if (!t) return "tokens: unavailable";
  const n = t.total ?? t.completion ?? t.prompt;
  return n != null ? `${n} tok` : "tokens: unavailable";
}

function jsonStatusBadge(s: Stage) {
  if (s.status === "failed") return null;
  if (s.is_repair) {
    return s.json_valid === false
      ? <span className="badge red">repair: still invalid</span>
      : <span className="badge amber">repair stage</span>;
  }
  if (!s.json_expected) return <span className="badge gray">text response</span>;
  if (s.json_valid === false)
    return s.repaired_next
      ? <span className="badge amber">JSON invalid → repaired</span>
      : <span className="badge red">JSON invalid</span>;
  if (s.json_valid === true) return <span className="badge green">JSON valid</span>;
  return <span className="badge gray">JSON: unknown</span>;
}

function StageCard({ s }: { s: Stage }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<StageTab>("user");
  const [compare, setCompare] = useState(false);
  const statusColor = s.status === "failed" ? "red" : s.status === "repaired" ? "amber" : s.status === "completed" ? "green" : "gray";
  const legacy = s.legacy_prompt_only;
  const userLabel = legacy ? "Legacy Prompt" : "User Prompt";

  return (
    <div className="card" style={{ marginBottom: 8 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer", flexWrap: "wrap" }} onClick={() => setOpen(!open)}>
        <span className="btn small">{open ? "▾" : "▸"}</span>
        <strong>{s.index}. {s.stage}</strong>
        <span className={`badge ${statusColor}`}>{s.status || "?"}</span>
        {jsonStatusBadge(s)}
        {s.was_truncated && <span className="badge red" title="finish_reason=length — response was cut off">truncated</span>}
        {s.finish_reason && s.finish_reason !== "stop" && !s.was_truncated && (
          <span className="badge amber" title={`finish_reason: ${s.finish_reason}`}>{s.finish_reason}</span>
        )}
        {s.source === "log" && <span className="badge gray" title="recovered from run log">log</span>}
        <span style={{ flex: 1 }} />
        <span className="muted" style={{ fontSize: 12 }}>
          {s.prompt_chars ?? "?"}p / {s.response_chars ?? "?"}r chars · {tokensLabel(s.tokens)}
          {s.elapsed_seconds != null ? ` · ${Number(s.elapsed_seconds).toFixed(1)}s` : ""}
        </span>
      </div>

      {open && (
        <div style={{ marginTop: 10 }}>
          {s.source === "log" && (
            <div className="banner warn" style={{ fontSize: 12 }}>
              Recovered from run log — prompt/response text was not persisted for this stage (run failed). Metadata only.
            </div>
          )}
          <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
            {([
              ["system", legacy ? "System Prompt (none)" : "System Prompt"],
              ["user", userLabel],
              ["messages", "Full Messages"],
              ["response", "Response"],
              ["parsed", "Parsed JSON"],
              ["error", "Error"],
            ] as [StageTab, string][]).map(([t, lbl]) => (
              <button key={t} className={`btn small ${tab === t ? "primary" : ""}`} onClick={() => setTab(t)}>{lbl}</button>
            ))}
            <span style={{ flex: 1 }} />
            {((s.user_prompt || s.prompt) || s.response) && (
              <button className={`btn small ${compare ? "primary" : ""}`} onClick={() => setCompare((c) => !c)}>Compare prompt/response</button>
            )}
          </div>

          {compare ? (
            <div className="grid cols-2">
              <TextPanel title={userLabel} text={s.user_prompt || s.prompt} height={360} />
              <TextPanel title="Response" text={s.response} height={360} />
            </div>
          ) : (
            <>
              {tab === "system" && (
                s.system_prompt
                  ? <TextPanel title="System Prompt" text={s.system_prompt} height={300} />
                  : <div className="muted">{legacy ? "No system prompt recorded (legacy artifact)." : "No system prompt for this stage."}</div>
              )}
              {tab === "user" && ((s.user_prompt || s.prompt) ? <TextPanel title={userLabel} text={s.user_prompt || s.prompt} height={400} /> : <div className="muted">User prompt text not available.</div>)}
              {tab === "messages" && (
                messagesText(s)
                  ? <TextPanel title="Full chat messages" text={messagesText(s)} height={420} />
                  : <div className="muted">No messages recorded for this stage.</div>
              )}
              {tab === "response" && (s.response ? <TextPanel title="Response" text={s.response} json height={400} /> : <div className="muted">Response text not available.</div>)}
              {tab === "parsed" && (
                s.parsed_json != null
                  ? <TextPanel title="Parsed JSON" text={JSON.stringify(s.parsed_json, null, 2)} height={320} />
                  : <div className="banner warn">No parsed JSON{s.json_valid === false ? " (invalid — see Error tab for raw response)" : s.json_expected ? "" : " (free-text stage)"}.</div>
              )}
              {tab === "error" && (
                s.error
                  ? <TextPanel title="Stage error / provider response" text={s.error} height={260} />
                  : s.status === "failed"
                    ? <div className="banner warn">Stage failed but no error body was captured in the log.</div>
                    : <div className="muted">No error for this stage.</div>
              )}
            </>
          )}
          {s.request_payload_keys && (
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>request payload keys: {s.request_payload_keys.join(", ")}</div>
          )}
          {(s.requested_max_tokens != null || s.finish_reason) && (
            <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
              {s.requested_max_tokens != null && <>max_tokens: req={s.requested_max_tokens} / eff={s.effective_max_tokens ?? s.requested_max_tokens}</>}
              {s.finish_reason && <> · finish_reason: <strong>{s.finish_reason}</strong></>}
              {s.was_truncated && <> · <span style={{ color: "var(--red, #b91c1c)" }}>response truncated</span></>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AgentTracePage() {
  const { runId, sampleId } = useParams();
  const nav = useNavigate();
  const { mode } = useApp();
  const norm = useAsync<NormalizedSample>(() => research.sampleNormalized(runId!, sampleId!, mode), [runId, sampleId, mode]);
  const [filter, setFilter] = useState<Filter>("all");
  const [reloadKey, setReloadKey] = useState(0);
  const [copied, setCopied] = useState(false);
  const [showSource, setShowSource] = useState(false);

  const n = norm.data;
  const stages = (n?.stages || []).filter((s) => {
    if (filter === "all") return true;
    if (filter === "failed") return s.status === "failed" || s.json_valid === false;
    if (filter === "repair") return !!s.is_repair;
    if (filter === "planning") return !!s.is_planning;
    if (filter === "final") return !!s.is_final;
    return true;
  });

  const failed = n?.failed;
  const predAvail = n?.prediction_available;

  return (
    <div>
      <h1 className="page-title">Agent Trace</h1>
      <p className="page-sub">Sample <strong className="mono">{sampleId}</strong> · run <span className="mono">{runId}</span></p>

      <div className="btn-row" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => nav(`/research/kg/${runId}/${sampleId}`)}>KG Query Flow</button>
        <a
          className="btn"
          href={research.flowReportUrl(runId!, sampleId!)}
          download={`flow_report_${runId}_${sampleId}.txt`}
        >Download full flow report</a>
        <button className="btn" onClick={() => nav("/research/runs")}>← Runs</button>
      </div>

      {/* Verdict */}
      {n && (
        <div className="card" style={{ marginBottom: 16, borderLeft: `4px solid ${n.correct === true ? "#047857" : n.correct === false ? "#b91c1c" : failed ? "#b45309" : "#64748b"}` }}>
          <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
            <div><div className="muted" style={{ fontSize: 11 }}>True label</div>{mode === "admin" ? <VerdictBadge label={n.true_label} /> : <span className="badge gray">hidden</span>}</div>
            <div className="muted">→</div>
            <div>
              <div className="muted" style={{ fontSize: 11 }}>Prediction</div>
              {predAvail ? <VerdictBadge label={n.prediction} /> : <span className="badge gray">not available</span>}
            </div>
            <div>
              <div className="muted" style={{ fontSize: 11 }}>Result</div>
              {!predAvail
                ? <span className="badge amber">{failed ? "failed before final prediction" : "no prediction"}</span>
                : n.correct === true ? <span className="badge green">correct</span>
                : n.correct === false ? <span className="badge red">incorrect</span>
                : <span className="badge gray">{mode === "admin" ? "unknown" : "no label (student mode)"}</span>}
            </div>
            <div>
              <div className="muted" style={{ fontSize: 11 }}>Confidence</div>
              <strong>{n.confidence_available && n.confidence != null ? `${(n.confidence * 100).toFixed(0)}%` : "not available"}</strong>
            </div>
            <span style={{ flex: 1 }} />
            <div className="muted" style={{ fontSize: 12 }}>{n.project}/{n.function}</div>
          </div>
          <dl className="kv" style={{ fontSize: 12, marginTop: 10 }}>
            <dt>LLM</dt><dd><strong>{n.llm?.provider_name || n.llm?.model_backend || "—"}</strong> · {n.llm?.model || "—"}</dd>
            <dt>Decision status</dt><dd>{failed && !predAvail ? `failed at ${n.failed_stage || "unknown stage"}` : (n.decision_status || "—")}</dd>
            <dt>Resolved commit</dt><dd className="mono">{n.resolved_commit || "—"}</dd>
            <dt>Commit message</dt>
            <dd style={{ fontStyle: n.commit_message ? "normal" : "italic", color: n.commit_message ? "inherit" : "var(--muted, #64748b)" }}>
              {n.commit_message || "Commit message unavailable"}
            </dd>
          </dl>
          {n.verdict_text && (
            <>
              <div className="section-title">Final reasoning</div>
              <pre className="log-viewer" style={{ height: 130, whiteSpace: "pre-wrap" }}>{n.verdict_text}</pre>
            </>
          )}
          {n.target_function_source && (
            <div style={{ marginTop: 10 }}>
              <button
                className="btn btn-secondary"
                style={{ fontSize: 12, padding: "2px 10px" }}
                onClick={() => setShowSource((v) => !v)}
              >
                {showSource ? "Hide target function source" : "Show target function source"}
              </button>
              {showSource && (
                <div style={{ marginTop: 8 }}>
                  <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
                    {n.filepath || "?"} :: <strong>{n.function || "?"}</strong>
                  </div>
                  <pre style={{
                    background: "var(--surface2, #f8fafc)",
                    border: "1px solid var(--border, #e2e8f0)",
                    borderRadius: 4,
                    padding: "8px 10px",
                    fontSize: 11,
                    fontFamily: "monospace",
                    whiteSpace: "pre",
                    overflowX: "auto",
                    maxHeight: 400,
                    overflowY: "auto",
                    margin: 0,
                  }}>{n.target_function_source}</pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Failure panel */}
      {n && failed && (
        <div className="card" style={{ marginBottom: 16, borderLeft: "4px solid #b45309" }}>
          <h3 className="section-title" style={{ marginTop: 0 }}>Run failed — what we recovered</h3>
          <dl className="kv" style={{ fontSize: 12 }}>
            <dt>Failed stage</dt><dd className="mono">{n.failed_stage || "—"}</dd>
            <dt>Last completed stage</dt><dd className="mono">{n.last_completed_stage || "—"}</dd>
            <dt>Error</dt><dd>{n.error_message || n.error_type || "no error body captured"}</dd>
            {n.provider_error && <><dt>Provider error</dt><dd className="mono" style={{ fontSize: 11 }}>{n.provider_error.slice(0, 400)}</dd></>}
            <dt>KG loaded</dt><dd>{n.kg_loaded ? "yes" : "no"}</dd>
            <dt>Initial retrieval</dt><dd>{n.initial_retrieval ? "yes" : "no"}</dd>
            <dt>KG queries issued</dt><dd>{n.kg_queries_count ?? 0}</dd>
          </dl>
        </div>
      )}

      {/* Stage timeline */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div className="section-title" style={{ flex: 1 }}>
          LLM stage timeline ({n?.stages?.length ?? 0}{failed ? ", partial / failed" : ""})
        </div>
        <select value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
          <option value="all">All stages</option>
          <option value="failed">Only failed stages</option>
          <option value="repair">Only repair stages</option>
          <option value="planning">Only KG planning</option>
          <option value="final">Only final verdict</option>
        </select>
      </div>
      {norm.loading && <div className="empty">Loading trace…</div>}
      {n && (n.stages?.length ?? 0) === 0 && (
        <div className="banner warn">No stage events found in artifacts or run logs for this sample.</div>
      )}
      {stages.map((s) => <StageCard key={s.index} s={s} />)}

      {/* Embedded CodeKG dashboard */}
      <div className="section-title">CodeKG Dashboard for this sample</div>
      {n?.kg?.dashboard_url ? (
        <>
          <div className="toolbar" style={{ marginBottom: 8 }}>
            <a className="btn primary" href={n.kg.dashboard_url} target="_blank" rel="noreferrer">Open in new tab</a>
            <button className="btn" onClick={() => setReloadKey((k) => k + 1)}>Reload</button>
            <button className="btn" onClick={() => { navigator.clipboard?.writeText(n.kg.graph_dir || ""); setCopied(true); setTimeout(() => setCopied(false), 1200); }}>
              {copied ? "Copied" : "Copy dashboard path"}
            </button>
          </div>
          <dl className="kv" style={{ fontSize: 12 }}>
            <dt>KG preset</dt><dd>{n.kg.display_name || n.kg.preset || "—"} → <span className="mono">{n.kg.effective_backend || "—"}</span></dd>
            <dt>graph_dir</dt><dd className="mono" style={{ fontSize: 11 }}>{n.kg.graph_dir || "—"}</dd>
            <dt>Nodes / Edges</dt><dd>{n.kg.nodes ?? "—"} / {n.kg.edges ?? "—"}</dd>
            <dt>Target function found</dt><dd>{n.kg.target_found ? "yes" : "—"}</dd>
            <dt>KG queries</dt><dd>{n.kg_queries_count ?? 0}</dd>
          </dl>
          <iframe key={reloadKey} title="CodeKG dashboard" src={n.kg.dashboard_url}
            style={{ width: "100%", height: 640, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "#fff" }} />
        </>
      ) : (
        <div className="banner warn">No CodeKG dashboard found for this sample. Open the KG Query Flow page for discovery details.</div>
      )}
    </div>
  );
}
