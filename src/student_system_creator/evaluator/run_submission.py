from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

from student_system_creator.progress import fmt_duration, progress_eta


def _short(text: object, limit: int = 80) -> str:
    s = str(text or "")
    return s if len(s) <= limit else s[: limit - 1] + "…"


class KGClient:
    def __init__(self, api_base: str, api_key: str | None = None, timeout: int = 30, *, verbose: bool = True):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verbose = verbose

    def health(self) -> dict[str, Any]:
        r = requests.get(f"{self.api_base}/health", timeout=min(self.timeout, 10))
        r.raise_for_status()
        return r.json()

    def query(self, kg_id: str, query: dict[str, Any], *, sample_id: str | None = None, round_id: int | None = None, query_index: int | None = None) -> dict[str, Any]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        kind = query.get("kind")
        target = query.get("target_function")
        t0 = time.time()
        if self.verbose:
            print(
                f"eval.query.start | sample={sample_id} | round={round_id} | q={query_index} | kg={_short(kg_id, 64)} | kind={kind} | target={target} | max_nodes={query.get('max_nodes')}",
                flush=True,
            )
        try:
            r = requests.post(f"{self.api_base}/api/v1/kgs/{kg_id}/query", json=query, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except requests.Timeout as exc:
            elapsed = time.time() - t0
            raise TimeoutError(f"KG API query timed out after {elapsed:.1f}s | kg={kg_id} | kind={kind} | target={target}") from exc
        except requests.HTTPError as exc:
            body = getattr(exc.response, "text", "")[:500] if getattr(exc, "response", None) is not None else ""
            raise RuntimeError(f"KG API HTTP error | kg={kg_id} | kind={kind} | status={getattr(exc.response, 'status_code', '?')} | body={body}") from exc
        elapsed = time.time() - t0
        if self.verbose:
            timing = data.get("timing") or {}
            print(
                f"eval.query.done | sample={sample_id} | round={round_id} | q={query_index} | kind={kind} | nodes={data.get('retrieved_node_count')} | edges={data.get('retrieved_edge_count')} | engine_cache_hit={timing.get('engine_cache_hit')} | time={elapsed:.2f}s",
                flush=True,
            )
        return data


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(rows[0].keys()) if rows else ["sample_id", "prediction"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)



def _truthy_env(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        val = os.getenv(name)
        if val is not None and str(val).strip():
            return str(val).strip()
    return default


def _default_student_llm_api_base() -> str:
    return _first_env(
        "STUDENT_LLM_API_BASE",
        "ACADEMIC_CLOUD_API_BASE",
        "ACADEMIC_CLOUD_BASE_URL",
        "SAIA_API_BASE",
        "LLM_API_BASE",
        default="https://chat-ai.academiccloud.de/v1",
    )


def _default_student_llm_model() -> str:
    return _first_env(
        "STUDENT_LLM_MODEL",
        "ACADEMIC_CLOUD_MODEL",
        "SAIA_MODEL",
        "LLM_MODEL",
        default="mistral-large-3-675b-instruct-2512",
    )


def _default_student_llm_api_key_env() -> str:
    explicit = _first_env("STUDENT_LLM_API_KEY_ENV", default="")
    if explicit:
        return explicit
    for candidate in ("STUDENT_LLM_API_KEY", "ACADEMIC_CLOUD_API_KEY", "SAIA_API_KEY", "LLM_API_KEY", "OPENAI_API_KEY"):
        if os.getenv(candidate):
            return candidate
    return "STUDENT_LLM_API_KEY"


def _student_llm_defaults() -> dict[str, Any]:
    key_env = _default_student_llm_api_key_env()
    enabled = _truthy_env("STUDENT_AGENT_LLM", False) or _truthy_env("STUDENT_LLM_ENABLED", False)
    return {
        "llm_enabled": enabled,
        "llm_api_base": _default_student_llm_api_base(),
        "llm_model": _default_student_llm_model(),
        "llm_api_key_env": key_env,
        "llm_api_key_present": bool(os.getenv(key_env)),
    }



def _json_compact(obj: object, limit: int = 12000) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        text = str(obj)
    if len(text) <= limit:
        return text
    half = max(1000, limit // 2)
    return text[:half] + "\n...<truncated>...\n" + text[-half:]


def _safe_filename(text: object, fallback: str = "sample") -> str:
    raw = str(text or fallback)
    out = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in raw)
    return out[:120] or fallback


def write_sample_trace_artifacts(out_dir: Path, trace: dict[str, Any]) -> None:
    """Write per-sample student-agent artifacts for frontend audit/download.

    This is intentionally evaluator-side, so any submitted solution that returns
    extra metadata (agentic_trace, final_adjudication, stage, decision_status)
    can be inspected without changing the solution contract.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    sid = _safe_filename(trace.get("sample_id"), "sample")
    prefix = out_dir / f"sample_{sid}"
    (prefix.with_suffix(".trace.json")).write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  STUDENT AGENTIC TRACE REPORT")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"sample_id: {trace.get('sample_id')}")
    lines.append(f"function: {trace.get('function_name') or trace.get('target_function') or '—'}")
    lines.append(f"kg_id: {trace.get('kg_id') or '—'}")
    ans = trace.get("answer") or {}
    lines.append(f"prediction: {ans.get('prediction')}")
    lines.append(f"confidence: {ans.get('confidence')}")
    if ans.get("decision_status"):
        lines.append(f"decision_status: {ans.get('decision_status')}")
    lines.append(f"stop_reason: {trace.get('stop_reason')}")
    lines.append(f"query_count: {trace.get('query_count')}")
    lines.append(f"elapsed_seconds: {trace.get('elapsed_seconds')}")
    if trace.get("error"):
        lines.append(f"error: {trace.get('error')}")
    if ans.get("llm_config"):
        lines.append(f"llm_enabled: {ans.get('llm_config', {}).get('enabled')}")
        lines.append(f"llm_model: {ans.get('llm_config', {}).get('model') or '—'}")
        lines.append(f"llm_api_base: {ans.get('llm_config', {}).get('api_base') or '—'}")
        lines.append(f"llm_api_key_env: {ans.get('llm_config', {}).get('api_key_env') or '—'}")
        lines.append(f"llm_call_count: {ans.get('llm_call_count', 0)}")
    lines.append("")
    lines.append("FINAL ANSWER")
    lines.append("-" * 72)
    lines.append(_json_compact(ans, 16000))
    lines.append("")
    lines.append("AGENTIC STAGE TIMELINE")
    lines.append("-" * 72)
    agentic_trace = trace.get("agentic_trace") or []
    if agentic_trace:
        for i, st in enumerate(agentic_trace, 1):
            if isinstance(st, dict):
                lines.append(f"{i:02d}. {st.get('stage') or st.get('name') or 'stage'}")
            else:
                lines.append(f"{i:02d}. {str(st)[:200]}")
    else:
        lines.append("No internal agentic_trace metadata was returned by solution.py.")
    lines.append("")
    lines.append("QUERY HISTORY")
    lines.append("-" * 72)
    for i, q in enumerate(trace.get("query_history") or [], 1):
        lines.append(f"q{i}: round={q.get('round')} reason={q.get('reason')}")
        lines.append(_json_compact(q.get("query"), 4000))
    lines.append("")
    lines.append("ACTION HISTORY")
    lines.append("-" * 72)
    for i, a in enumerate(trace.get("action_history") or [], 1):
        lines.append(f"action {i}: stage={a.get('stage')} action={a.get('action')} round={a.get('round')}")
        lines.append(f"reason: {a.get('reason')}")
        if a.get("queries"):
            lines.append(_json_compact(a.get("queries"), 6000))
    lines.append("")
    if trace.get("final_adjudication"):
        lines.append("FINAL ADJUDICATION")
        lines.append("-" * 72)
        lines.append(_json_compact(trace.get("final_adjudication"), 20000))
    (prefix.with_suffix(".report.txt")).write_text("\n".join(lines), encoding="utf-8")


def load_solution(path: str | Path):
    spec = importlib.util.spec_from_file_location("student_solution", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not import solution: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["student_solution"] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "build_agent"):
        raise RuntimeError("solution.py must define build_agent(config)")
    return module.build_agent


def validate_query(query: dict[str, Any], limits: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(query, dict):
        raise ValueError("query must be a dict")
    allowed = set(limits["allowed_query_kinds"])
    kind = str(query.get("kind") or "")
    if kind not in allowed:
        raise ValueError(f"unsupported query kind: {kind}")
    out = dict(query)
    out["max_nodes"] = min(int(out.get("max_nodes") or limits["max_nodes_per_query"]), int(limits["max_nodes_per_query"]))
    return out


def validate_final(action: dict[str, Any]) -> dict[str, Any]:
    pred = 1 if int(action.get("prediction", 0)) == 1 else 0
    try:
        conf = float(action.get("confidence", 0.0))
    except Exception:
        conf = 0.0
    out = {
        "prediction": pred,
        "confidence": max(0.0, min(1.0, conf)),
        "reason": str(action.get("reason") or "")[:4000],
    }
    # Preserve rich student-agent metadata for audit pages and report downloads.
    for key in (
        "decision_status", "stage", "agentic_trace", "final_adjudication",
        "source_facts", "hypotheses", "verifications", "counter_evidence_review",
        "llm_config", "llm_call_count",
    ):
        if key in action:
            out[key] = action.get(key)
    return out


def run_agent_for_sample(
    agent: Any,
    sample: dict[str, Any],
    client: KGClient,
    limits: dict[str, Any],
    *,
    sample_index: int | None = None,
    total_samples: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    start = time.time()
    evidence: list[dict[str, Any]] = []
    query_history: list[dict[str, Any]] = []
    action_history: list[dict[str, Any]] = []
    latest_agentic_trace: list[Any] = []
    latest_final_adjudication: dict[str, Any] | None = None
    used = 0
    sample_id = str(sample.get("sample_id"))
    fn = sample.get("function_name") or sample.get("target_function") or ""
    kg_id = sample.get("knowledge_graph_id") or sample.get("kg_id")
    print(
        f"eval.sample.start | {sample_index or '?'} / {total_samples or '?'} | sample={sample_id} | fn={fn} | kg={_short(kg_id, 72)}",
        flush=True,
    )
    final_answer: dict[str, Any] | None = None
    stop_reason = "budget_exhausted"

    for round_id in range(1, int(limits["max_rounds"]) + 1):
        elapsed = time.time() - start
        if elapsed > int(limits["timeout_per_sample_seconds"]):
            stop_reason = "sample_timeout"
            break
        budget = {
            "round": round_id,
            "max_rounds": limits["max_rounds"],
            "used_queries": used,
            "remaining_queries": int(limits["max_queries_per_sample"]) - used,
            "max_queries_per_round": limits["max_queries_per_round"],
            "max_nodes_per_query": limits["max_nodes_per_query"],
            "allowed_query_kinds": list(limits["allowed_query_kinds"]),
        }
        print(
            f"eval.round.start | sample={sample_id} | round={round_id}/{limits['max_rounds']} | used_queries={used}/{limits['max_queries_per_sample']} | elapsed={fmt_duration(elapsed)}",
            flush=True,
        )
        action = agent.step(sample, {"round": round_id - 1, "evidence": evidence, "query_history": query_history}, budget)
        if not isinstance(action, dict):
            raise RuntimeError("agent.step returned non-dict")
        stage = str(action.get("stage") or "student_step")
        if isinstance(action.get("agentic_trace"), list):
            latest_agentic_trace = action.get("agentic_trace") or []
        if isinstance(action.get("final_adjudication"), dict):
            latest_final_adjudication = action.get("final_adjudication")
        action_history.append({
            "round": round_id,
            "action": action.get("action"),
            "stage": stage,
            "reason": action.get("reason"),
            "queries": action.get("queries"),
            "agentic_trace_len": len(latest_agentic_trace),
        })
        print(
            f"eval.agent.stage | sample={sample_id} | round={round_id} | stage={stage} | action={action.get('action')} | trace_len={len(latest_agentic_trace)} | reason={_short(action.get('reason'), 140)}",
            flush=True,
        )
        if action.get("action") == "final":
            final_answer = validate_final(action)
            stop_reason = "agent_final"
            break
        if action.get("action") != "query":
            raise RuntimeError("agent must return action=query or action=final")
        queries = list(action.get("queries") or [])[: int(limits["max_queries_per_round"])]
        print(
            f"eval.round.action | sample={sample_id} | round={round_id} | stage={stage} | action=query | requested={len(action.get('queries') or [])} | executing={len(queries)} | reason={_short(action.get('reason'), 140)}",
            flush=True,
        )
        if not queries:
            stop_reason = "agent_no_queries"
            break
        for qi, raw in enumerate(queries, 1):
            if used >= int(limits["max_queries_per_sample"]):
                stop_reason = "query_budget_exhausted"
                break
            if time.time() - start > int(limits["timeout_per_sample_seconds"]):
                stop_reason = "sample_timeout"
                break
            query = validate_query(raw, limits)
            result = client.query(str(kg_id), query, sample_id=sample_id, round_id=round_id, query_index=qi)
            evidence.append({"query": query, "reason": action.get("reason", ""), "result": result})
            query_history.append({"round": round_id, "query": query, "reason": action.get("reason", "")})
            used += 1
        if used >= int(limits["max_queries_per_sample"]):
            stop_reason = "query_budget_exhausted"
            break

    if final_answer is None:
        forced = agent.step(sample, {"evidence": evidence, "query_history": query_history}, {"force_final": True, "remaining_queries": 0, **limits})
        if isinstance(forced, dict):
            if isinstance(forced.get("agentic_trace"), list):
                latest_agentic_trace = forced.get("agentic_trace") or latest_agentic_trace
            if isinstance(forced.get("final_adjudication"), dict):
                latest_final_adjudication = forced.get("final_adjudication")
            action_history.append({
                "round": "forced",
                "action": forced.get("action"),
                "stage": forced.get("stage") or "forced_final",
                "reason": forced.get("reason"),
                "queries": forced.get("queries"),
                "agentic_trace_len": len(latest_agentic_trace),
            })
        if isinstance(forced, dict) and forced.get("action") == "final":
            final_answer = validate_final(forced)
            stop_reason = f"forced_final_after_{stop_reason}"
        else:
            final_answer = {"prediction": 0, "confidence": 0.0, "reason": f"No final answer within budget ({stop_reason})"}

    trace = {
        "sample_id": sample_id,
        "function_name": fn,
        "kg_id": kg_id,
        "answer": final_answer,
        "query_count": used,
        "rounds_observed": len({q["round"] for q in query_history}),
        "elapsed_seconds": round(time.time() - start, 3),
        "stop_reason": stop_reason,
        "query_history": query_history,
        "action_history": action_history,
        "agentic_trace": latest_agentic_trace or final_answer.get("agentic_trace") or [],
        "final_adjudication": latest_final_adjudication or final_answer.get("final_adjudication"),
    }
    print(
        f"eval.sample.done | sample={sample_id} | prediction={final_answer['prediction']} | confidence={final_answer.get('confidence')} | queries={used} | stop={stop_reason} | time={fmt_duration(time.time() - start)}",
        flush=True,
    )
    return final_answer, trace


def score_predictions(labels_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not labels_path.exists():
        return {"score_available": False}
    labels = {r["sample_id"]: int(r["vulnerability"]) for r in read_csv(labels_path)}
    preds = {str(r["sample_id"]): int(r["prediction"]) for r in rows}
    ids = [sid for sid in labels if sid in preds]
    tp = sum(labels[s] == 1 and preds[s] == 1 for s in ids)
    tn = sum(labels[s] == 0 and preds[s] == 0 for s in ids)
    fp = sum(labels[s] == 0 and preds[s] == 1 for s in ids)
    fn = sum(labels[s] == 1 and preds[s] == 0 for s in ids)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"score_available": True, "n": len(ids), "accuracy": (tp + tn) / len(ids) if ids else 0.0, "precision": precision, "recall": recall, "f1": f1, "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a student solution.py against the KG challenge API.")
    parser.add_argument("--solution", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--train", default=None)
    parser.add_argument("--train-limit", type=int, default=None, help="Load only the first N train rows for agent.fit/config")
    parser.add_argument("--labels", default=None)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="dev-key-KG")
    parser.add_argument("--out", default="outputs/student_eval")
    parser.add_argument("--limit", type=int, default=None, help="Evaluate only the first N rows")
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--max-queries-per-round", type=int, default=2)
    parser.add_argument("--max-queries-per-sample", type=int, default=8)
    parser.add_argument("--max-nodes-per-query", type=int, default=500)
    parser.add_argument("--timeout-per-sample-seconds", type=int, default=120)
    parser.add_argument("--query-timeout-seconds", type=int, default=30, help="HTTP timeout for each KG query")
    parser.add_argument("--quiet", action="store_true", help="Reduce evaluator progress logs")
    parser.add_argument("--llm-api-base", default=_default_student_llm_api_base(), help="Optional OpenAI-compatible LLM API base for solution.py config")
    parser.add_argument("--llm-model", default=_default_student_llm_model(), help="Optional model name passed to solution.py config")
    parser.add_argument("--llm-api-key-env", default=_default_student_llm_api_key_env(), help="Environment variable containing student LLM API key")
    parser.add_argument("--llm-enabled", action="store_true", default=_student_llm_defaults()["llm_enabled"], help="Pass llm_enabled=True to solution.py config; defaults from STUDENT_AGENT_LLM/STUDENT_LLM_ENABLED env")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    train_rows = read_csv(args.train) if args.train and Path(args.train).exists() else []
    if args.train_limit is not None:
        train_rows = train_rows[: int(args.train_limit)]
    test_rows = read_csv(args.input)
    if args.limit is not None:
        test_rows = test_rows[: int(args.limit)]
    limits = {
        "max_rounds": args.max_rounds,
        "max_queries_per_round": args.max_queries_per_round,
        "max_queries_per_sample": args.max_queries_per_sample,
        "max_nodes_per_query": args.max_nodes_per_query,
        "timeout_per_sample_seconds": args.timeout_per_sample_seconds,
        "allowed_query_kinds": ["security_context", "evidence_slice", "function_context", "call_neighborhood", "variable_flow", "semantic_facts", "file_context", "shortest_path"],
    }
    agent_config = {
        "train_rows": train_rows,
        "train_limit": args.train_limit,
        "train_rows_loaded": len(train_rows),
        "limits": limits,
        "kg_api_base": args.api_base,
        "kg_api_key": args.api_key,
        "llm_enabled": bool(args.llm_enabled),
        "llm_api_base": args.llm_api_base,
        "llm_model": args.llm_model,
        "llm_api_key_env": args.llm_api_key_env,
        "allowed_query_kinds": list(limits["allowed_query_kinds"]),
    }
    llm_key_present = bool(os.getenv(str(args.llm_api_key_env)))
    safe_llm_config = {
        "llm_enabled": bool(args.llm_enabled),
        "llm_api_base": args.llm_api_base,
        "llm_model": args.llm_model,
        "llm_api_key_env": args.llm_api_key_env,
        "llm_api_key_present": llm_key_present,
    }
    (out / "student_llm_config.json").write_text(json.dumps(safe_llm_config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        "eval.llm.config | enabled={enabled} | base={base} | model={model} | key_env={key_env} | key_present={present}".format(
            enabled=safe_llm_config["llm_enabled"],
            base=safe_llm_config["llm_api_base"] or "—",
            model=safe_llm_config["llm_model"] or "—",
            key_env=safe_llm_config["llm_api_key_env"] or "—",
            present=safe_llm_config["llm_api_key_present"],
        ),
        flush=True,
    )
    agent = load_solution(args.solution)(agent_config)
    if hasattr(agent, "fit"):
        agent.fit(train_rows)
    client = KGClient(args.api_base, args.api_key, timeout=args.query_timeout_seconds, verbose=not args.quiet)
    try:
        health = client.health()
        print(f"eval.api.health | ok={health.get('ok')} | graphs={health.get('graphs')} | api={args.api_base}", flush=True)
    except Exception as exc:
        print(f"eval.api.health_failed | api={args.api_base} | error={exc}", flush=True)
    pred_rows: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []
    start = time.time()
    try:
        for idx, row in enumerate(test_rows, 1):
            try:
                ans, trace = run_agent_for_sample(agent, row, client, limits, sample_index=idx, total_samples=len(test_rows))
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                ans = {"prediction": 0, "confidence": 0.0, "reason": f"error: {exc}"}
                trace = {"sample_id": row.get("sample_id"), "answer": ans, "error": str(exc)}
                print(f"eval.sample.error | {idx}/{len(test_rows)} | sample={row.get('sample_id')} | error={exc}", flush=True)
            pred_rows.append({"sample_id": row["sample_id"], "prediction": int(ans["prediction"]), "confidence": ans.get("confidence", 0.0), "reason": ans.get("reason", "")})
            traces.append(trace)
            write_csv(out / "predictions.csv", pred_rows)
            (out / "traces.json").write_text(json.dumps(traces, ensure_ascii=False, indent=2), encoding="utf-8")
            write_sample_trace_artifacts(out, trace)
            elapsed, rate, eta = progress_eta(start, idx, len(test_rows))
            print(
                f"eval.progress | processed={idx}/{len(test_rows)} | elapsed={fmt_duration(elapsed)} | rate={rate*60:.2f} samples/min | eta={eta} | partial_predictions={out / 'predictions.csv'}",
                flush=True,
            )
    except KeyboardInterrupt:
        print(f"eval.interrupted | processed={len(pred_rows)}/{len(test_rows)} | partial_out={out}", flush=True)
        if pred_rows:
            metrics = score_predictions(Path(args.labels), pred_rows) if args.labels else {"score_available": False}
            (out / "score.partial.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
        raise
    metrics = score_predictions(Path(args.labels), pred_rows) if args.labels else {"score_available": False}
    (out / "score.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print("eval.done | out=%s | elapsed=%s" % (out, fmt_duration(time.time() - start)), flush=True)
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
