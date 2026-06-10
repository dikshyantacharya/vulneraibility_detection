import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { research } from "../api/research";
import { useAsync } from "../state";

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function Expandable({ title, badges, body }: { title: string; badges?: React.ReactNode; body: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer" }} onClick={() => setOpen(!open)}>
        <span className="btn">{open ? "▾" : "▸"}</span>
        <strong>{title}</strong>
        {badges}
      </div>
      {open && <div style={{ marginTop: 12 }}>{body}</div>}
    </div>
  );
}

export default function AgentTracePage() {
  const { runId, sampleId } = useParams();
  const nav = useNavigate();
  const trace = useAsync(() => research.trace(runId!, sampleId!), [runId, sampleId]);
  const [calls, setCalls] = useState<any[]>([]);
  const report = useAsync(() => research.report(runId!, sampleId!), [runId, sampleId]);

  useEffect(() => {
    research.llmCalls(runId!, sampleId!).then(setCalls).catch(() => setCalls([]));
  }, [runId, sampleId]);

  const t = trace.data || {};
  const fp = report.data?.final_prediction || {};

  // Build the canonical stage timeline. Prefer explicit model_calls; otherwise
  // fall back to whatever the trace + final prediction expose.
  const stages: { stage: string; prompt?: string; response?: string; meta?: any }[] = [];
  if (calls.length) {
    calls.forEach((c) =>
      stages.push({
        stage: c.stage || c.name || "llm_call",
        prompt: c.prompt || c.prompt_text || c.messages && JSON.stringify(c.messages, null, 2),
        response: c.response || c.completion || c.raw_response,
        meta: { tokens: c.completion_tokens || c.tokens, model: c.model || fp.model_backend, elapsed: c.elapsed_seconds },
      })
    );
  }

  return (
    <div>
      <h1 className="page-title">Agent Trace</h1>
      <p className="page-sub">
        Full agentic stage timeline for sample <strong className="mono">{sampleId}</strong> in run{" "}
        <span className="mono">{runId}</span>.
      </p>
      <div className="btn-row" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => nav(`/research/kg/${runId}/${sampleId}`)}>KG Query Flow</button>
        <a className="btn" href={research.dashboardUrl(runId!, sampleId!)} target="_blank" rel="noreferrer">Open static dashboard</a>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <dl className="kv">
          <dt>Verdict</dt>
          <dd>
            {fp.is_vulnerable === true ? <span className="badge red">vulnerable</span>
              : fp.is_vulnerable === false ? <span className="badge green">safe</span>
              : <span className="badge gray">unknown</span>}
            {fp.confidence != null ? `  ·  ${(fp.confidence * 100).toFixed(0)}% confidence` : ""}
          </dd>
          <dt>Decision status</dt><dd>{fp.decision_status || "—"}</dd>
          <dt>Model backend</dt><dd>{fp.model_backend || "—"}</dd>
          <dt>Resolved commit</dt><dd className="mono">{t.resolved_commit_id || fp.resolved_commit_id || "—"}</dd>
          <dt>Evidence (init/accum)</dt><dd>{t.initial_evidence_count ?? "—"} / {t.accumulated_evidence_count ?? "—"}</dd>
        </dl>
        {fp.reasoning_summary && (
          <>
            <div className="section-title">Final reasoning</div>
            <pre className="log-viewer" style={{ height: 160 }}>{fp.reasoning_summary}</pre>
          </>
        )}
      </div>

      <div className="section-title">LLM stages</div>
      {stages.length === 0 && (
        <div className="banner warn">
          This run did not capture per-stage prompt/response artifacts (model_calls is empty). The final adjudication
          response is shown below; richer stage capture appears for runs where the pipeline writes model_calls.
        </div>
      )}
      {stages.map((s, i) => (
        <Expandable
          key={i}
          title={`${i + 1}. ${s.stage}`}
          badges={
            <>
              {s.meta?.model && <span className="badge gray">{s.meta.model}</span>}
              {s.meta?.tokens != null && <span className="badge blue">{s.meta.tokens} tok</span>}
              {s.meta?.elapsed != null && <span className="muted">{Number(s.meta.elapsed).toFixed(1)}s</span>}
            </>
          }
          body={
            <div className="grid cols-2">
              <div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <strong>Prompt</strong>{s.prompt && <CopyBtn text={s.prompt} />}
                </div>
                <pre className="log-viewer" style={{ height: 280 }}>{s.prompt || "—"}</pre>
              </div>
              <div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <strong>Response</strong>{s.response && <CopyBtn text={s.response} />}
                </div>
                <pre className="log-viewer" style={{ height: 280 }}>{s.response || "—"}</pre>
              </div>
            </div>
          }
        />
      ))}

      {stages.length === 0 && fp.raw_response && (
        <Expandable
          title="Final adjudication (raw response)"
          badges={<span className="badge gray">{fp.model_backend}</span>}
          body={
            <>
              <CopyBtn text={fp.raw_response} />
              <pre className="log-viewer" style={{ height: 360, marginTop: 8 }}>{fp.raw_response}</pre>
            </>
          }
        />
      )}
    </div>
  );
}
