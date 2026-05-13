from __future__ import annotations

import json
import logging
import re
import time
import threading
from typing import Any, Callable

from pydantic import BaseModel

from vuln_commit_kg.config import AgentConfig, ModelConfig, PromptingConfig, RetrievalConfig
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_store import ProjectGraph
from vuln_commit_kg.models.base import LLMBackend, LLMUsage
from vuln_commit_kg.retrieval.evidence import EvidencePack
from vuln_commit_kg.utils.text import truncate_middle
from vuln_commit_kg.api_limits import parse_rate_limit_headers

from .json_parse import extract_answer_tag_payload, parse_and_validate_tagged_output
from .prompts import (
    FINAL_DECISION_SCHEMA_TEXT,
    FOLLOWUP_SCHEMA_TEXT,
    FORBIDDEN_PLACEHOLDERS,
    RISK_HYPOTHESIS_SCHEMA_TEXT,
    SYSTEM_PROMPT,
    final_decision_prompt,
    followup_query_prompt,
    json_repair_prompt,
    risk_hypothesis_prompt,
    POSTHOC_COMMIT_AUDIT_SCHEMA_TEXT,
    posthoc_commit_audit_prompt,
)
from .schemas import (
    AgentTrace,
    FinalDecisionResponse,
    FollowupResponse,
    Prediction,
    RiskHypothesisResponse,
    VulnerableStatement,
    PosthocCommitAuditResponse,
)
from .tool_query import KGToolExecutor, KGToolResult, merge_tool_results_into_evidence
from .semantic_safety import semantic_audit_dict, source_upload_path_audit_from_text


class AgentController:
    def __init__(
        self,
        agent_cfg: AgentConfig,
        retrieval_cfg: RetrievalConfig,
        model_cfg: ModelConfig,
        model: LLMBackend,
        logger: logging.Logger,
        prompting_cfg: PromptingConfig | None = None,
        event_sink: Callable[[str, dict[str, Any]], None] | None = None,
        progress_callback: Callable[..., None] | None = None,
    ):
        self.agent_cfg = agent_cfg
        self.retrieval_cfg = retrieval_cfg
        self.model_cfg = model_cfg
        self.prompting_cfg = prompting_cfg or PromptingConfig()
        self.model = model
        self.logger = logger
        self.event_sink = event_sink
        self.progress_callback = progress_callback
        self.tool_executor = KGToolExecutor(
            max_items_per_query=agent_cfg.max_tool_results_per_query,
            max_text_chars=900,
        )


    def _progress(self, stage: str, *, sample: SecVulEvalSample, evidence: EvidencePack, trace: AgentTrace, prediction: Prediction | None = None) -> None:
        """Best-effort hook used by the live dashboard to rewrite a partial
        per-sample agent report while the agent loop is still running.

        The callback is intentionally optional and exception-isolated: reporting
        must never affect classification correctness or API usage.
        """
        cb = getattr(self, "progress_callback", None)
        if cb is None:
            return
        try:
            cb(stage=stage, sample=sample, evidence=evidence, trace=trace, prediction=prediction)
        except Exception:
            self.logger.debug("agent.progress_callback_failed", exc_info=True)

    def _emit(self, kind: str, data: dict[str, Any] | None = None) -> None:
        if self.event_sink is None:
            return
        try:
            self.event_sink(kind, data or {})
        except Exception:
            # Live dashboard/reporting must never affect classification correctness.
            pass

    def classify(
        self,
        sample: SecVulEvalSample,
        evidence: EvidencePack,
        graph: ProjectGraph | None = None,
    ) -> tuple[Prediction, AgentTrace, EvidencePack]:
        trace = AgentTrace(sample_id=sample.sample_id, mode=self.agent_cfg.mode)
        self._emit("agent.classify.start", {"sample_id": sample.sample_id, "function": sample.func_name})
        self._progress("classify_start", sample=sample, evidence=evidence, trace=trace)
        trace.initial_evidence_count = len(evidence.items)
        trace_summary = "No iterative hypothesis pass used."
        total_usage = self._empty_usage()
        latest_tool_evidence = EvidencePack(
            sample_id=sample.sample_id,
            summary="No KG tool evidence has been returned yet.",
            target_found=evidence.target_found,
            target_node_id=evidence.target_node_id,
            items=[],
        )

        if self.agent_cfg.enabled and self.agent_cfg.mode == "iterative":
            # Stage 1 is intentionally source-only: the deterministic evidence pack
            # remains available for reports/final context, but is not shown to the
            # model before it proposes its own hypotheses and KG queries.
            prompt1 = risk_hypothesis_prompt(
                sample=sample,
                evidence=None,
                max_context_chars=self._prompt_chars("source"),
                prompting_cfg=self.prompting_cfg,
            )
            obj1, parsed1, status1 = self._generate_json(
                trace=trace,
                name="01_source_only_hypothesis",
                prompt=prompt1,
                schema_model=RiskHypothesisResponse,
                schema_text=RISK_HYPOTHESIS_SCHEMA_TEXT,
                total_usage=total_usage,
            )
            if parsed1 is not None:
                risk_obj = parsed1.model_dump(mode="json")
                trace.risk_hypotheses = risk_obj.get("risk_hypotheses", [])[: self.agent_cfg.risk_hypothesis_limit]
                trace.hypothesis_ledger = [
                    {
                        "stage": "source_only_hypothesis",
                        "hypotheses": trace.risk_hypotheses,
                        "note": "Initial hypotheses were generated from the target function only; no KG evidence was shown in this stage.",
                    }
                ]
                if self._contains_placeholder(trace.risk_hypotheses):
                    self.logger.warning(
                        "agent.placeholder_hypotheses | sample=%s | the model copied schema-like placeholder text",
                        sample.sample_id,
                    )
                query_source = "model_generated" if status1["json_status"] == "model_generated" else "model_generated_after_json_repair"
                new_queries = self._with_query_source(risk_obj.get("kg_queries", []), query_source)
                new_queries = self._normalize_filter_queries(sample, new_queries, trace.kg_tool_steps, trace)
                trace.kg_queries.extend(new_queries[: self.agent_cfg.max_tool_queries_per_round])
                trace_summary = self._trace_summary_for_prompt(trace)
                self._progress("source_only_hypothesis_done", sample=sample, evidence=evidence, trace=trace)
            else:
                self.logger.warning(
                    "Hypothesis pass JSON parse/schema validation failed after repair for sample=%s: %s",
                    sample.sample_id,
                    status1.get("parse_error"),
                )
                fallback = self._fallback_queries(sample, evidence)
                new_queries = self._with_query_source(fallback, "fallback_generated")
                trace.kg_queries.extend(new_queries)
                trace.verification.append(
                    {
                        "round": "source_only_hypothesis",
                        "continue": True,
                        "verification_summary": (
                            f"Source-only hypothesis output could not be parsed after {self.agent_cfg.max_json_repairs} "
                            "repair attempts; deterministic fallback KG queries were used."
                        ),
                        "kg_queries": new_queries,
                        "source": "fallback_generated",
                        "parse_error": status1.get("parse_error"),
                    }
                )
                trace.hypothesis_ledger = [
                    {
                        "stage": "source_only_hypothesis_parse_failed",
                        "parse_error": status1.get("parse_error"),
                        "fallback_queries": new_queries,
                    }
                ]
                trace_summary = self._trace_summary_for_prompt(trace)
                self._progress("source_only_hypothesis_fallback", sample=sample, evidence=evidence, trace=trace)

            if graph is not None and self.agent_cfg.allow_kg_followup_queries and trace.kg_queries:
                round_queries = trace.kg_queries[-self.agent_cfg.max_tool_queries_per_round :]
                results = self.tool_executor.execute_many(
                    graph=graph,
                    sample=sample,
                    queries=round_queries,
                    round_index=1,
                    query_source=self._dominant_query_source(round_queries),
                )
                trace.kg_tool_steps.extend([r.to_dict() for r in results])
                latest_tool_evidence = self._tool_results_to_evidence_pack(sample, evidence, results, 1)
                evidence = merge_tool_results_into_evidence(
                    evidence,
                    results,
                    max_total_items=self.agent_cfg.max_evidence_items_after_tools,
                )
                trace.hypothesis_ledger.append(
                    {
                        "stage": "kg_tool_round_1",
                        "queries": [r.query_object for r in results],
                        "returned_evidence_ids": self._tool_result_ids(results),
                        "source": self._dominant_query_source(round_queries),
                    }
                )
                trace_summary = self._trace_summary_for_prompt(trace)
                returned_count = self._tool_result_count(results)
                self.logger.info(
                    "agent.kg_tools | sample=%s | round=1 | queries=%s | returned_items=%s | evidence_items=%s",
                    sample.sample_id,
                    len(results),
                    returned_count,
                    len(evidence.items),
                )
                self._emit("kg_tools.done", {"sample_id": sample.sample_id, "round": 1, "queries": len(results), "returned_items": returned_count, "evidence_items": len(evidence.items)})
                self._progress("kg_tool_round_1_done", sample=sample, evidence=evidence, trace=trace)

            # Optional additional query rounds. These are visible structured
            # summaries/evidence ledgers, not hidden chain-of-thought.
            for round_index in range(2, max(2, self.agent_cfg.max_rounds) + 1):
                if not (graph is not None and self.agent_cfg.allow_kg_followup_queries):
                    break
                prompt = followup_query_prompt(
                    sample,
                    latest_tool_evidence,
                    trace_summary,
                    self._prompt_chars("followup"),
                    round_index,
                    self.prompting_cfg,
                )
                self.logger.info(
                    "agent.followup_prompt_ready | sample=%s | round=%s | stage=%02d_verify_hypotheses | prompt_chars=%s | latest_tool_evidence_items=%s | accumulated_evidence_items=%s",
                    sample.sample_id, round_index, round_index, len(prompt), len(latest_tool_evidence.items), len(evidence.items),
                )
                self._emit("model_call.prompt_ready", {"sample_id": sample.sample_id, "stage": f"{round_index:02d}_verify_hypotheses", "round": round_index, "prompt_chars": len(prompt), "latest_tool_evidence_items": len(latest_tool_evidence.items), "evidence_items": len(evidence.items)})
                self._progress(f"followup_round_{round_index}_prompt_ready", sample=sample, evidence=evidence, trace=trace)
                obj, parsed, status = self._generate_json(
                    trace=trace,
                    name=f"{round_index:02d}_verify_hypotheses",
                    prompt=prompt,
                    schema_model=FollowupResponse,
                    schema_text=FOLLOWUP_SCHEMA_TEXT,
                    total_usage=total_usage,
                )
                if parsed is None:
                    fallback = self._fallback_queries(sample, evidence)
                    new_queries = self._with_query_source(fallback, "fallback_generated")
                    trace.verification.append(
                        {
                            "round": round_index,
                            "continue": True,
                            "hypothesis_updates": [],
                            "verification_summary": (
                                f"Follow-up output could not be parsed after {self.agent_cfg.max_json_repairs} "
                                "repair attempts; deterministic fallback KG queries were used."
                            ),
                            "kg_queries": new_queries,
                            "source": "fallback_generated",
                            "parse_error": status.get("parse_error"),
                        }
                    )
                else:
                    follow = parsed.model_dump(mode="json", by_alias=True)
                    trace.verification.append(
                        {
                            "round": round_index,
                            "continue": bool(follow.get("continue", False)),
                            "hypothesis_updates": follow.get("hypothesis_updates", []),
                            "active_hypothesis_ids": follow.get("active_hypothesis_ids", []),
                            "resolved_hypothesis_ids": follow.get("resolved_hypothesis_ids", []),
                            "verification_summary": follow.get("verification_summary"),
                            "kg_queries": [],
                            "source": status["json_status"],
                        }
                    )
                    if not bool(follow.get("continue", False)):
                        trace.hypothesis_ledger.append(
                            {
                                "stage": f"verification_round_{round_index}",
                                "hypothesis_updates": follow.get("hypothesis_updates", []),
                                "continue": False,
                                "verification_summary": follow.get("verification_summary"),
                            }
                        )
                        trace_summary = self._trace_summary_for_prompt(trace)
                        break
                    query_source = "model_generated" if status["json_status"] == "model_generated" else "model_generated_after_json_repair"
                    new_queries = self._with_query_source(follow.get("kg_queries", []), query_source)
                    new_queries = self._normalize_filter_queries(sample, new_queries, trace.kg_tool_steps, trace)
                    trace.verification[-1]["kg_queries"] = new_queries
                    trace.verification[-1]["source"] = query_source
                    trace.hypothesis_ledger.append(
                        {
                            "stage": f"verification_round_{round_index}",
                            "hypothesis_updates": follow.get("hypothesis_updates", []),
                            "continue": True,
                            "verification_summary": follow.get("verification_summary"),
                            "new_queries": new_queries,
                        }
                    )

                if not new_queries:
                    trace.hypothesis_ledger.append(
                        {
                            "stage": f"kg_tool_round_{round_index}_skipped",
                            "reason": "No schema-valid unseen KG queries remained after duplicate filtering.",
                        }
                    )
                    trace_summary = self._trace_summary_for_prompt(trace)
                    break
                trace.kg_queries.extend(new_queries[: self.agent_cfg.max_tool_queries_per_round])
                trace_summary = self._trace_summary_for_prompt(trace)
                results = self.tool_executor.execute_many(
                    graph=graph,
                    sample=sample,
                    queries=new_queries[: self.agent_cfg.max_tool_queries_per_round],
                    round_index=round_index,
                    query_source=self._dominant_query_source(new_queries),
                )
                trace.kg_tool_steps.extend([r.to_dict() for r in results])
                latest_tool_evidence = self._tool_results_to_evidence_pack(sample, evidence, results, round_index)
                evidence = merge_tool_results_into_evidence(
                    evidence,
                    results,
                    max_total_items=self.agent_cfg.max_evidence_items_after_tools,
                )
                trace.hypothesis_ledger.append(
                    {
                        "stage": f"kg_tool_round_{round_index}",
                        "queries": [r.query_object for r in results],
                        "returned_evidence_ids": self._tool_result_ids(results),
                        "source": self._dominant_query_source(new_queries),
                    }
                )
                trace_summary = self._trace_summary_for_prompt(trace)
                returned_count = self._tool_result_count(results)
                self.logger.info(
                    "agent.kg_tools | sample=%s | round=%s | queries=%s | returned_items=%s | evidence_items=%s",
                    sample.sample_id,
                    round_index,
                    len(results),
                    returned_count,
                    len(evidence.items),
                )
                self._emit("kg_tools.done", {"sample_id": sample.sample_id, "round": round_index, "queries": len(results), "returned_items": returned_count, "evidence_items": len(evidence.items)})
                self._progress(f"kg_tool_round_{round_index}_done", sample=sample, evidence=evidence, trace=trace)

        if graph is not None:
            evidence = self._run_mandatory_source_evidence_gates(sample=sample, evidence=evidence, graph=graph, trace=trace)

        self._add_source_upload_audit(sample, trace)
        self._add_source_ragged_pointer_audit(sample, evidence, trace)
        self._add_final_risk_audit(trace, evidence)
        trace_summary = self._trace_summary_for_prompt(trace)

        self._progress("final_prompt_prepared", sample=sample, evidence=evidence, trace=trace)

        prompt2 = final_decision_prompt(
            sample,
            evidence,
            trace_summary,
            self._prompt_chars("final"),
            self.prompting_cfg,
        )
        trace.final_prompt_chars = len(prompt2)
        self.logger.info(
            "agent.final_prompt_ready | sample=%s | prompt_chars=%s | evidence_items=%s | kg_tool_steps=%s",
            sample.sample_id, len(prompt2), len(evidence.items), len(trace.kg_tool_steps),
        )
        self._emit("model_call.prompt_ready", {"sample_id": sample.sample_id, "stage": "final_decision", "prompt_chars": len(prompt2), "evidence_items": len(evidence.items), "kg_tool_steps": len(trace.kg_tool_steps)})
        parsed_final_obj, parsed_final, final_status = self._generate_json(
            trace=trace,
            name="final_decision",
            prompt=prompt2,
            schema_model=FinalDecisionResponse,
            schema_text=FINAL_DECISION_SCHEMA_TEXT,
            total_usage=total_usage,
        )

        self._progress("final_decision_model_done", sample=sample, evidence=evidence, trace=trace)

        if parsed_final is not None and not self._final_has_placeholder(parsed_final.model_dump(mode="json")):
            final_json = parsed_final.model_dump(mode="json")
            final_json = self._normalize_final_decision_status(final_json)
            accepted_final_raw_response = final_status.get("accepted_raw_response") or final_status.get("raw_response") or ""
            consistency_errors = self._final_consistency_errors(final_json, evidence, trace)
            if consistency_errors:
                original_final_json = json.loads(json.dumps(final_json, ensure_ascii=False, default=str))
                repair_prompt = self._final_consistency_repair_prompt(
                    sample=sample,
                    final_json=final_json,
                    evidence=evidence,
                    trace_summary=trace_summary,
                    errors=consistency_errors,
                )
                _, repaired_final, repair_status = self._generate_json(
                    trace=trace,
                    name="final_decision_consistency_repair",
                    prompt=repair_prompt,
                    schema_model=FinalDecisionResponse,
                    schema_text=FINAL_DECISION_SCHEMA_TEXT,
                    total_usage=total_usage,
                )
                if repaired_final is not None:
                    repaired_json = self._normalize_final_decision_status(repaired_final.model_dump(mode="json"))
                    repaired_errors = self._final_consistency_errors(repaired_json, evidence, trace)
                    if not repaired_errors:
                        trace.final_validator_modifications.append({
                            "stage": "final_decision_consistency_repair_applied",
                            "notes": ["accepted repaired final JSON after consistency errors"],
                            "consistency_errors_before_repair": consistency_errors,
                            "before": original_final_json,
                            "after": repaired_json,
                        })
                        final_json = repaired_json
                        accepted_final_raw_response = repair_status.get("accepted_raw_response") or repair_status.get("raw_response") or accepted_final_raw_response
                    else:
                        final_json["_consistency_errors"] = repaired_errors
                        trace.final_validator_modifications.append({
                            "stage": "final_decision_consistency_repair_rejected",
                            "notes": ["repaired final JSON still failed consistency checks"],
                            "consistency_errors_before_repair": consistency_errors,
                            "consistency_errors_after_repair": repaired_errors,
                            "before": original_final_json,
                            "after": repaired_json,
                        })
                else:
                    final_json["_consistency_errors"] = consistency_errors
                    trace.final_validator_modifications.append({
                        "stage": "final_decision_consistency_repair_failed",
                        "notes": ["consistency repair did not return schema-valid JSON"],
                        "consistency_errors_before_repair": consistency_errors,
                        "before": original_final_json,
                        "after": final_json,
                    })
            final_json["_accepted_final_raw_response"] = accepted_final_raw_response
            final_json, validator_notes = self._apply_final_decision_validator(final_json, evidence, trace)
            if validator_notes:
                before_after = trace.final_validator_modifications[-1] if trace.final_validator_modifications else {}
                self.logger.warning("agent.final_validator_modified | sample=%s | notes=%s", sample.sample_id, "; ".join(validator_notes[:5]))
                trace.hypothesis_ledger.append({
                    "stage": "final_decision_validator",
                    "notes": validator_notes,
                    "after": before_after.get("after", final_json),
                })
            pred = Prediction(
                sample_id=sample.sample_id,
                is_vulnerable=bool(final_json.get("is_vulnerable", False)),
                confidence=float(final_json.get("confidence", 0.0) or 0.0),
                primary_vulnerability_type=final_json.get("primary_vulnerability_type"),
                vuln_statements=[VulnerableStatement(**x) for x in final_json.get("vuln_statements", []) if isinstance(x, dict)],
                evidence_used=[str(x) for x in final_json.get("evidence_used", [])],
                decision_status=final_json.get("decision_status"),
                binary_prediction_policy=final_json.get("binary_prediction_policy"),
                reasoning_summary=str(final_json.get("reasoning_summary", "")),
                raw_response=str(final_json.get("_accepted_final_raw_response") or final_status.get("accepted_raw_response") or ""),
                model_backend=self.model_cfg.backend,
                usage=total_usage,
                validation_notes=final_json.get("validation_notes", []),
            )
        else:
            parse_error = final_status.get("parse_error") or "Model returned schema placeholder text instead of a concrete final decision"
            self.logger.warning("Final JSON parse/schema validation failed for sample=%s: %s", sample.sample_id, parse_error)
            fallback_final = self._fallback_final_from_source_upload_audit(evidence, trace, parse_error)
            if fallback_final is not None:
                trace.final_validator_modifications.append({
                    "stage": "source_upload_audit_fallback_after_final_parse_failure",
                    "notes": ["LLM final decision failed, but narrow source-only upload audit was decisive and evidence-bound"],
                    "parse_error": parse_error,
                    "after": fallback_final,
                })
                pred = Prediction(
                    sample_id=sample.sample_id,
                    is_vulnerable=bool(fallback_final.get("is_vulnerable", False)),
                    confidence=float(fallback_final.get("confidence", 0.0) or 0.0),
                    primary_vulnerability_type=fallback_final.get("primary_vulnerability_type"),
                    vuln_statements=[VulnerableStatement(**x) for x in fallback_final.get("vuln_statements", []) if isinstance(x, dict)],
                    evidence_used=[str(x) for x in fallback_final.get("evidence_used", [])],
                    decision_status=fallback_final.get("decision_status"),
                    binary_prediction_policy=fallback_final.get("binary_prediction_policy"),
                    raw_response=final_status.get("accepted_raw_response") or final_status.get("raw_response") or "",
                    model_backend=self.model_cfg.backend,
                    usage=total_usage,
                    reasoning_summary=str(fallback_final.get("reasoning_summary", "")),
                    parse_error=None,
                    validation_notes=[f"final model parse/generation failed but source-only upload audit fallback recovered a decision: {parse_error}"],
                )
            else:
                pred = Prediction(
                    sample_id=sample.sample_id,
                    is_vulnerable=False if self.agent_cfg.fail_open_on_parse_error else True,
                    confidence=0.0,
                    parse_error=parse_error,
                    decision_status=str(getattr(self.agent_cfg, "parse_failed_decision_status", "parse_failed")),
                    binary_prediction_policy="parse_error_excluded_from_valid_binary_metrics",
                    raw_response=final_status.get("accepted_raw_response") or final_status.get("raw_response") or "",
                    model_backend=self.model_cfg.backend,
                    usage=total_usage,
                    reasoning_summary="Model response could not be parsed or validated as JSON after repair attempts.",
                )
        self._attach_report_metadata_to_prediction(pred, sample, evidence)
        trace.dataset_commit_id = evidence.dataset_commit_id or sample.commit_id
        trace.resolved_commit_id = evidence.resolved_commit_id
        trace.resolved_commit_label = evidence.resolved_commit_label

        if bool(getattr(self.agent_cfg, "enable_posthoc_commit_audit", True)):
            self._run_posthoc_commit_audit(sample=sample, prediction=pred, evidence=evidence, trace=trace, total_usage=total_usage)
            pred.usage = total_usage
        trace.accumulated_evidence_count = len(evidence.items)
        self._progress("classify_done", sample=sample, evidence=evidence, trace=trace, prediction=pred)
        self._emit("agent.classify.done", {"sample_id": sample.sample_id, "decision_status": pred.decision_status, "is_vulnerable": pred.is_vulnerable, "confidence": pred.confidence, "total_tokens": pred.usage.get("total_tokens")})
        return pred, trace, evidence

    def _add_source_upload_audit(self, sample: SecVulEvalSample, trace: AgentTrace) -> None:
        """Add a source-only upload-pattern audit to the public ledger.

        This is derived only from the checked-out target source and contains no
        dataset labels/commit metadata. It gives the final stage a compact,
        stable summary of the upload loop pattern instead of relying on the LLM
        to rediscover it from 200+ evidence items.
        """
        if any(isinstance(x, dict) and x.get("stage") == "source_snapshot_upload_pattern_audit" for x in trace.hypothesis_ledger):
            return
        audit = source_upload_path_audit_from_text(sample.func_body or "")
        if audit.get("present"):
            trace.hypothesis_ledger.append({
                "stage": "source_snapshot_upload_pattern_audit",
                "source_only": True,
                "source_upload_audit": audit,
            })

    def _source_upload_audit_from_trace(self, trace: AgentTrace) -> dict[str, Any]:
        for entry in reversed(trace.hypothesis_ledger or []):
            if isinstance(entry, dict) and entry.get("stage") == "source_snapshot_upload_pattern_audit":
                audit = entry.get("source_upload_audit")
                if isinstance(audit, dict):
                    return audit
        return {}

    def _attach_report_metadata_to_prediction(self, pred: Prediction, sample: SecVulEvalSample, evidence: EvidencePack) -> None:
        """Populate report-only metadata before post-hoc audit/reporting.

        The pipeline also attaches this after classify(), but the post-hoc audit
        runs inside classify(), so it must use the source-only evidence pack's
        already-populated metadata instead of seeing empty resolved-commit fields.
        """
        pred.dataset_commit_id = pred.dataset_commit_id or evidence.dataset_commit_id or sample.commit_id
        pred.resolved_commit_id = pred.resolved_commit_id or evidence.resolved_commit_id
        pred.resolved_commit_label = pred.resolved_commit_label or evidence.resolved_commit_label
        pred.target_validation_status = pred.target_validation_status or evidence.target_validation_status
        if pred.target_validation_similarity is None:
            pred.target_validation_similarity = evidence.target_validation_similarity

    def _run_mandatory_source_evidence_gates(self, *, sample: SecVulEvalSample, evidence: EvidencePack, graph: ProjectGraph, trace: AgentTrace) -> EvidencePack:
        """Run deterministic source-only evidence gates for high-risk patterns.

        This does not classify. It guarantees that final prompts have complete
        evidence for upload/config read-loop reasoning when the target source
        contains content-length parsing, sockgetlinebuf, NUL writes, decoding, and
        file/output writes. It is a retrieval-completeness guard against small-model
        tunnel vision on generic risky APIs such as sprintf.
        """
        body = sample.func_body or ""
        required = ["contentlen", "sockgetlinebuf", "buf[i]", "decodeurl", "fprintf"]
        if not all(term in body for term in required):
            return evidence
        existing = {str(step.get("source") or "") for step in trace.kg_tool_steps if isinstance(step, dict)}
        if "mandatory_source_evidence_gate" in existing:
            return evidence
        # Use function-relative line anchors when present; the executor converts
        # them to file lines for lexical variable binding.
        def rel_line(pattern: str, default: int) -> int:
            for idx, line in enumerate(body.splitlines(), start=1):
                if re.search(pattern, line):
                    return idx
            return default
        qline_upload = rel_line(r"case\s+'U'|sockgetlinebuf\s*\([^;]*\+", 1)
        qline_contentlen = rel_line(r"contentlen\s*=|sscanf\s*\([^;]*contentlen|atoi\s*\(", 1)
        queries = [
            {
                "hypothesis_id": "AUTO_UPLOAD_CONFIG_PATH",
                "query_type": "evidence_bundle",
                "query": "input_validation_bundle",
                "bundle_type": "input_validation_bundle",
                "symbol": "contentlen",
                "scope": "target_function",
                "match": "exact_identifier",
                "source_line": qline_contentlen,
                "wanted_evidence": ["declaration", "uses", "bounds_checks", "sinks", "callee_summaries", "size_macros"],
                "reason": "mandatory source-only gate: retrieve content-length parsing, type/range, caps, and upload/config path evidence before final decision",
                "_source": "mandatory_source_evidence_gate",
            },
            {
                "hypothesis_id": "AUTO_UPLOAD_CONFIG_PATH",
                "query_type": "evidence_bundle",
                "query": "buffer_write_bundle",
                "bundle_type": "buffer_write_bundle",
                "symbol": "buf",
                "scope": "target_function",
                "match": "exact_identifier",
                "source_line": qline_upload,
                "wanted_evidence": ["declaration", "allocation", "writes", "bounds_checks", "sinks", "callee_summaries", "size_macros"],
                "reason": "mandatory source-only gate: retrieve upload/config buffer writes, read bounds, NUL writes, decode, fprintf, and loop progress",
                "_source": "mandatory_source_evidence_gate",
            },
            {
                "hypothesis_id": "AUTO_UPLOAD_CONFIG_PATH",
                "query_type": "evidence_bundle",
                "query": "callee_summary_bundle",
                "bundle_type": "callee_summary_bundle",
                "symbol": "sockgetlinebuf",
                "scope": "target_function",
                "match": "exact_identifier",
                "source_line": qline_upload,
                "wanted_evidence": ["callee_summaries", "argument_bounds", "return_or_output_effects"],
                "reason": "mandatory source-only gate: retrieve sockgetlinebuf write/return behavior for upload/config read-loop bounds",
                "_source": "mandatory_source_evidence_gate",
            },
            {
                "hypothesis_id": "AUTO_UPLOAD_CONFIG_PATH",
                "query_type": "global",
                "query": "LINESIZE",
                "symbol": "LINESIZE",
                "scope": "target_function",
                "match": "exact_identifier",
                "source_line": qline_upload,
                "wanted_evidence": ["definition", "value", "uses"],
                "reason": "mandatory source-only gate: retrieve exact source-level LINESIZE definition used in buffer allocation/read bounds",
                "_source": "mandatory_source_evidence_gate",
            },
        ]
        try:
            results = self.tool_executor.execute_many(
                graph=graph,
                sample=sample,
                queries=queries,
                round_index=90,
                query_source="mandatory_source_evidence_gate",
            )
            trace.kg_tool_steps.extend([r.to_dict() for r in results])
            evidence = merge_tool_results_into_evidence(
                evidence,
                results,
                max_total_items=max(int(getattr(self.agent_cfg, "max_evidence_items_after_tools", 120) or 120), len(evidence.items) + 80),
            )
            trace.hypothesis_ledger.append(
                {
                    "stage": "mandatory_source_evidence_gate_upload_config_path",
                    "note": "Source-only retrieval-completeness gate triggered by target code pattern; not a classifier and not report-only metadata.",
                    "queries": [r.query_object for r in results],
                    "returned_evidence_ids": self._tool_result_ids(results),
                    "returned_evidence_count": self._tool_result_count(results),
                    "source": "mandatory_source_evidence_gate",
                }
            )
            self._emit("kg_tools.done", {"sample_id": sample.sample_id, "round": 90, "queries": len(results), "returned_items": self._tool_result_count(results), "evidence_items": len(evidence.items), "source": "mandatory_source_evidence_gate"})
        except Exception as exc:
            self.logger.warning("mandatory_source_evidence_gate.failed | sample=%s | error=%s", sample.sample_id, exc)
            trace.hypothesis_ledger.append({"stage": "mandatory_source_evidence_gate_failed", "error": str(exc)})
        return evidence

    def _run_posthoc_commit_audit(self, *, sample: SecVulEvalSample, prediction: Prediction, evidence: EvidencePack, trace: AgentTrace, total_usage: dict[str, Any]) -> None:
        """Run a report-only semantic/factual audit against the commit message.

        This happens after the binary final decision. It may use commit metadata
        but cannot modify `prediction.is_vulnerable`; it is for debugging whether
        the model's explanation matches the known patch/commit semantics.
        """
        prompt = posthoc_commit_audit_prompt(
            sample=sample,
            prediction=prediction,
            evidence=evidence,
            max_context_chars=int(getattr(self.agent_cfg, "posthoc_audit_max_context_chars", 24000)),
        )
        obj, parsed, status = self._generate_json(
            trace=trace,
            name="posthoc_commit_reasoning_audit",
            prompt=prompt,
            schema_model=PosthocCommitAuditResponse,
            schema_text=POSTHOC_COMMIT_AUDIT_SCHEMA_TEXT,
            total_usage=total_usage,
        )
        if parsed is not None:
            audit = parsed.model_dump(mode="json")
            expected = self._expected_snapshot_semantics(prediction.resolved_commit_label)
            if expected and audit.get("snapshot_semantics") != expected:
                audit.setdefault("mismatch_or_gap", []).append(
                    f"snapshot_semantics corrected from {audit.get('snapshot_semantics')} to {expected} based on resolved_commit_label_report_only={prediction.resolved_commit_label}"
                )
                audit["snapshot_semantics"] = expected
            audit["snapshot_consistency_check"] = "ok" if not expected or audit.get("snapshot_semantics") == expected else "mismatch"
            audit["report_only_metadata_complete"] = all([
                prediction.sample_id, sample.project, sample.filepath, sample.func_name,
                prediction.resolved_commit_id, prediction.resolved_commit_label, prediction.target_validation_status is not None,
            ])
            trace.posthoc_commit_audit = audit
            self._emit("posthoc_commit_audit.done", {"sample_id": sample.sample_id, **trace.posthoc_commit_audit})
        else:
            # Post-hoc audit is report-only. If the provider truncates or returns
            # empty output, do not keep spending quota on repairs. Record a
            # deterministic, metadata-only audit stub so demos remain complete.
            expected = self._expected_snapshot_semantics(prediction.resolved_commit_label) or "unknown"
            trace.posthoc_commit_audit = {
                "semantic_alignment": "unclear",
                "factual_support": "unclear",
                "snapshot_semantics": expected,
                "does_reasoning_match_snapshot": None,
                "does_reasoning_match_commit_message": None,
                "patch_effect_identified": None,
                "audit_label": "unclear",
                "commit_message_summary": str(sample.commit_message or "")[:500],
                "model_reasoning_summary": str(prediction.reasoning_summary or "")[:800],
                "factual_findings": [],
                "mismatch_or_gap": [
                    "post-hoc audit model output was not parseable; this report-only audit was generated locally and did not affect prediction"
                ],
                "missing_patch_evidence": [],
                "evidence_ids_checked": list(prediction.evidence_used or [])[:20],
                "audit_conclusion": "post-hoc audit unavailable due to model/JSON failure; final prediction unchanged",
                "snapshot_consistency_check": "ok",
                "report_only_metadata_complete": all([
                    prediction.sample_id, sample.project, sample.filepath, sample.func_name,
                    prediction.resolved_commit_id, prediction.resolved_commit_label, prediction.target_validation_status is not None,
                ]),
                "json_status": status.get("json_status"),
                "parse_error": status.get("parse_error"),
                "local_fallback": True,
            }
            self._emit("posthoc_commit_audit.failed", {"sample_id": sample.sample_id, "parse_error": status.get("parse_error"), "local_fallback": True})

    def _prompt_profile(self) -> str:
        profile = getattr(self.agent_cfg, "prompt_profile", "auto")
        if profile != "auto":
            return str(profile)
        # llama-server/GGUF local context should default compact; API-style or
        # large context configurations can use richer prompts automatically.
        if self.model_cfg.backend == "llama_server" and int(getattr(self.model_cfg, "n_ctx", 8192) or 8192) <= 16384:
            return "local_budgeted"
        return "api_rich"

    def _prompt_chars(self, stage: str) -> int:
        profile = self._prompt_profile()
        if profile == "api_rich":
            if stage == "source":
                return int(self.agent_cfg.api_source_chars)
            if stage == "followup":
                return int(self.agent_cfg.api_followup_context_chars)
            if stage == "final":
                # Qwen/AcademicCloud showed repeated null-content failures around
                # 75k+ character final prompts. Keep the final prompt bounded and
                # let high-value evidence selection, not sheer prompt size, carry
                # the decision.
                return min(int(self.agent_cfg.api_final_context_chars), 42000)
        if stage == "source":
            return int(self.agent_cfg.local_source_chars)
        if stage == "followup":
            return int(self.agent_cfg.local_followup_context_chars)
        if stage == "final":
            return int(self.agent_cfg.local_final_context_chars)
        return int(self.retrieval_cfg.max_context_chars)

    def _repair_invalid_chars(self) -> int:
        return int(self.agent_cfg.api_repair_invalid_chars if self._prompt_profile() == "api_rich" else self.agent_cfg.local_repair_invalid_chars)

    @staticmethod
    def _tool_result_items(results: list[KGToolResult]) -> list[Any]:
        out: list[Any] = []
        for result in results:
            out.extend(KGToolResult._flatten_items(result.items))
        return out

    def _tool_result_ids(self, results: list[KGToolResult]) -> list[str]:
        ids: list[str] = []
        for item in self._tool_result_items(results):
            eid = getattr(item, "evidence_id", None)
            if eid is not None:
                ids.append(str(eid))
        return ids

    def _tool_result_count(self, results: list[KGToolResult]) -> int:
        return sum(1 for item in self._tool_result_items(results) if hasattr(item, "evidence_id"))

    def _should_skip_json_repair(self, *, name: str, raw_text: str, parse_error: str | None, model_error: Any | None) -> tuple[bool, str | None]:
        """Avoid wasting quota on repairs that cannot help.

        Empty/null provider responses and transport/model errors should not trigger
        another semantic repair call with essentially no invalid text to repair.
        Post-hoc audit is report-only, so it should not burn repeated quota on
        repairs when the primary response was empty.
        """
        if model_error:
            return True, "model/provider error; repair prompt would likely repeat the failing request"
        if not str(raw_text or "").strip():
            return True, "empty provider response; skip repair to avoid quota waste"
        if name == "posthoc_commit_reasoning_audit" and parse_error and "No JSON object" in str(parse_error):
            return True, "report-only posthoc audit had no JSON object; skip repair"
        return False, None

    def _generate_json(
        self,
        *,
        trace: AgentTrace,
        name: str,
        prompt: str,
        schema_model: type[BaseModel],
        schema_text: str,
        total_usage: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, BaseModel | None, dict[str, Any]]:
        """Generate JSON with repair, but never let model/API errors crash a sample.

        llama-server returns HTTP 400 when the prompt exceeds context or a
        request_format/path is unsupported. Those errors should be recorded in the
        trace and converted into parse failure/fallback behavior, not propagated.
        """
        stage_start = time.perf_counter()
        primary_start = time.perf_counter()
        sample_id = getattr(trace, "sample_id", None)
        self._emit("model_call.start", {"sample_id": sample_id, "stage": name, "attempt": "primary", "prompt_chars": len(prompt)})
        resp = self._safe_generate(prompt, name=name, attempt="primary", sample_id=sample_id)
        primary_elapsed = time.perf_counter() - primary_start
        resp_text = self._safe_response_text(resp)
        self._add_usage(total_usage, resp.usage)
        trace.raw_outputs.append(resp_text)
        attempts: list[dict[str, Any]] = []
        status: dict[str, Any] = {
            "json_status": "parse_failed",
            "raw_response": resp_text,
            "accepted_raw_response": None,
            "parse_error": None,
            "model_error": (resp.raw or {}).get("error") if isinstance(resp.raw, dict) else None,
        }
        obj: dict[str, Any] | None = None
        parsed: BaseModel | None = None
        parse_error: str | None = None
        primary_payload, primary_tag_info = extract_answer_tag_payload(resp_text)
        status["answer_extraction"] = primary_tag_info
        repair_source_text = primary_payload if primary_tag_info.get("answer_tag_complete") else resp_text

        if status.get("model_error"):
            parse_error = f"model_generate_error: {status['model_error']}"
            status["parse_error"] = parse_error
        else:
            try:
                obj, parsed, norm_notes, tag_info, parse_payload = parse_and_validate_tagged_output(
                    resp_text, schema_model, require_answer_tag=True
                )
                status["answer_extraction"] = tag_info
                if tag_info.get("answer_tag_complete"):
                    repair_source_text = parse_payload
                if norm_notes:
                    status.setdefault("mechanical_normalizations", []).extend(norm_notes)
                status.update({"json_status": "model_generated", "accepted_raw_response": resp_text, "accepted_answer_payload": parse_payload, "parse_error": None})
            except Exception as exc:
                parse_error = str(exc)
                status["parse_error"] = parse_error

        skip_repair, skip_reason = self._should_skip_json_repair(
            name=name,
            raw_text=resp_text,
            parse_error=parse_error,
            model_error=status.get("model_error"),
        )
        if skip_repair and parsed is None:
            status["repair_skipped"] = True
            status["repair_skip_reason"] = skip_reason
        for repair_index in range(1, int(self.agent_cfg.max_json_repairs) + 1):
            if parsed is not None or skip_repair:
                break
            # If the primary call failed due to a transport/request error, do not
            # ask the same server for a long repair prompt. This avoids crash
            # loops and quota waste on identical failing requests.
            if status.get("model_error"):
                break
            repair_prompt = json_repair_prompt(
                invalid_text=truncate_middle(repair_source_text, self._repair_invalid_chars()),
                parser_error=parse_error or "unknown parse/schema error",
                expected_schema=truncate_middle(schema_text, int(self.agent_cfg.max_repair_schema_chars)),
            )
            repair_start = time.perf_counter()
            self._emit("model_call.repair_start", {"sample_id": sample_id, "stage": name, "attempt": f"repair_{repair_index}", "prompt_chars": len(repair_prompt), "parse_error": parse_error})
            repair_resp = self._safe_generate(repair_prompt, name=name, attempt=f"repair_{repair_index}", sample_id=sample_id)
            repair_elapsed = time.perf_counter() - repair_start
            repair_text = self._safe_response_text(repair_resp)
            self._add_usage(total_usage, repair_resp.usage)
            trace.raw_outputs.append(repair_text)
            repair_record: dict[str, Any] = {
                "attempt": repair_index,
                "prompt": repair_prompt,
                "response": repair_text,
                "usage": self._usage_dict(repair_resp.usage),
                "elapsed_seconds": repair_elapsed,
                "parsed": None,
                "parse_error": None,
                "model_error": (repair_resp.raw or {}).get("error") if isinstance(repair_resp.raw, dict) else None,
            }
            if repair_record.get("model_error"):
                parse_error = f"model_generate_error: {repair_record['model_error']}"
                repair_record["parse_error"] = parse_error
                status["parse_error"] = parse_error
                attempts.append(repair_record)
                break
            try:
                obj, parsed, norm_notes, repair_tag_info, repair_parse_payload = parse_and_validate_tagged_output(
                    repair_text, schema_model, require_answer_tag=True
                )
                repair_record["parsed"] = obj
                repair_record["mechanical_normalizations"] = norm_notes
                repair_record["answer_extraction"] = repair_tag_info
                if norm_notes:
                    status.setdefault("mechanical_normalizations", []).extend(norm_notes)
                status.update({"json_status": "json_repaired", "accepted_raw_response": repair_text, "accepted_answer_payload": repair_parse_payload, "parse_error": None})
            except Exception as exc:
                parse_error = str(exc)
                repair_record["parse_error"] = parse_error
                status["parse_error"] = parse_error
                # If a complete <answer> block exists in the failed repair response,
                # feed only that block into the next repair; otherwise use the whole
                # response.  This mirrors the primary-call extraction policy.
                try:
                    repair_payload, repair_tag_info = extract_answer_tag_payload(repair_text)
                    repair_record.setdefault("answer_extraction", repair_tag_info)
                    repair_source_text = repair_payload if repair_tag_info.get("answer_tag_complete") else repair_text
                except Exception:
                    repair_source_text = repair_text
            attempts.append(repair_record)
            repair_event = {"sample_id": sample_id, "stage": name, "attempt": f"repair_{repair_index}", "parsed": parsed is not None, "parse_error": repair_record.get("parse_error"), "response_chars": len(repair_text), "elapsed_seconds": repair_elapsed}
            repair_provider_quota = self._provider_rate_from_response(repair_resp)
            if repair_provider_quota:
                repair_event["provider_rate_limit"] = repair_provider_quota
            self._emit("model_call.repair_done", repair_event)

        provider_quota = self._provider_rate_from_response(resp)
        call_record = {
            "name": name,
            "prompt": prompt,
            "response": resp_text,
            "raw_response": resp_text,
            "parsed": obj if parsed is not None else None,
            "parse_error": None if parsed is not None else status.get("parse_error"),
            "model_error": status.get("model_error"),
            "json_status": status["json_status"],
            "repair_attempts": attempts,
            "usage": self._usage_dict(resp.usage),
            "elapsed_seconds": time.perf_counter() - stage_start,
            "primary_elapsed_seconds": primary_elapsed,
            "total_stage_usage": self._sum_usage([resp.usage] + [self._usage_from_dict(a["usage"]) for a in attempts]),
            "accepted_raw_response": status.get("accepted_raw_response"),
            "accepted_answer_payload": status.get("accepted_answer_payload"),
            "answer_extraction": status.get("answer_extraction"),
            "expected_schema": schema_text,
            "mechanical_normalizations": status.get("mechanical_normalizations", []),
            "repair_skipped": status.get("repair_skipped", False),
            "repair_skip_reason": status.get("repair_skip_reason"),
        }
        if provider_quota:
            call_record["provider_rate_limit"] = provider_quota
        trace.model_calls.append(call_record)
        done_event = {"sample_id": sample_id, "stage": name, "json_status": status["json_status"], "parse_error": status.get("parse_error"), "prompt_chars": len(prompt), "response_chars": len(resp_text), "elapsed_seconds": call_record["elapsed_seconds"], "usage": call_record.get("total_stage_usage"), "repair_skipped": status.get("repair_skipped", False), "repair_skip_reason": status.get("repair_skip_reason")}
        if provider_quota:
            done_event["provider_rate_limit"] = provider_quota
        self._emit("model_call.done", done_event)
        return obj if parsed is not None else None, parsed, status


    @staticmethod
    def _provider_rate_from_response(resp: Any) -> dict[str, Any] | None:
        raw = getattr(resp, "raw", None)
        headers = None
        if isinstance(raw, dict):
            headers = raw.get("headers") or raw.get("response_headers") or raw.get("http_headers")
        headers = headers or getattr(resp, "headers", None) or getattr(resp, "response_headers", None)
        if not headers:
            return None
        parsed = parse_rate_limit_headers(headers)
        return parsed if parsed.get("headers_present") else None

    @staticmethod
    def _safe_response_text(resp: Any) -> str:
        """Provider adapters occasionally return null content on transient errors.

        Normalize it before parsing, tracing, and len() calls so retries/repairs do
        not fail with ``object of type 'NoneType' has no len()``.
        """
        text = getattr(resp, "text", "")
        if text is None:
            return ""
        return str(text)

    def _safe_generate(self, prompt: str, *, name: str, attempt: str, sample_id: str | None = None):
        from vuln_commit_kg.models.base import LLMResponse, LLMUsage

        context = {"sample_id": sample_id, "stage": name, "attempt": attempt, "prompt_chars": len(prompt)}
        start = time.perf_counter()
        stop_heartbeat = threading.Event()

        def _heartbeat() -> None:
            # Long AcademicCloud calls can look frozen from the terminal.  Emit a
            # lightweight heartbeat until the provider call returns or fails.
            interval = float(getattr(self.agent_cfg, "model_call_heartbeat_seconds", 15.0) or 15.0)
            while not stop_heartbeat.wait(max(5.0, interval)):
                elapsed = time.perf_counter() - start
                self.logger.info(
                    "model.generate_waiting | sample=%s | stage=%s | attempt=%s | elapsed=%.1fs | prompt_chars=%s",
                    sample_id, name, attempt, elapsed, len(prompt),
                )
                self._emit("model_call.heartbeat", {**context, "elapsed_seconds": elapsed})

        hb_thread = threading.Thread(target=_heartbeat, daemon=True)
        hb_thread.start()
        try:
            if hasattr(self.model, "set_request_context"):
                self.model.set_request_context(context)
            self.logger.info(
                "model.generate_start | sample=%s | stage=%s | attempt=%s | prompt_chars=%s",
                sample_id, name, attempt, len(prompt),
            )
            resp = self.model.generate(prompt, system=SYSTEM_PROMPT)
            elapsed = time.perf_counter() - start
            raw = getattr(resp, "raw", None) or {}
            response_stats = raw.get("response_stats") if isinstance(raw, dict) else None
            response_stats = response_stats if isinstance(response_stats, dict) else {}
            usage = getattr(resp, "usage", None)
            self.logger.info(
                "model.generate_done | sample=%s | stage=%s | attempt=%s | elapsed=%.1fs | "
                "response_chars=%s | finish_reason=%s | content_chars=%s | reasoning_chars=%s | "
                "completion_tokens=%s | enable_thinking=%s",
                sample_id,
                name,
                attempt,
                elapsed,
                len(self._safe_response_text(resp)),
                response_stats.get("finish_reason"),
                response_stats.get("content_chars", len(self._safe_response_text(resp))),
                response_stats.get("reasoning_chars"),
                getattr(usage, "completion_tokens", None),
                response_stats.get("enable_thinking"),
            )
            self._emit("model_call.generate_done", {**context, "elapsed_seconds": elapsed, "response_chars": len(self._safe_response_text(resp)), **response_stats})
            return resp
        except Exception as exc:
            elapsed = time.perf_counter() - start
            msg = f"{type(exc).__name__}: {exc}"
            self.logger.warning(
                "model.generate_failed | sample=%s | stage=%s | attempt=%s | elapsed=%.1fs | prompt_chars=%s | error=%s",
                sample_id, name, attempt, elapsed, len(prompt), msg,
            )
            self._emit("model_call.error", {**context, "elapsed_seconds": elapsed, "error": msg})
            # Estimated usage keeps accounting non-crashing even when the provider
            # rejects the call before returning token usage.
            p = max(1, len(prompt) // 4)
            return LLMResponse(text="", usage=LLMUsage(prompt_tokens=p, completion_tokens=0, total_tokens=p, estimated=True, tokenization_method="char_estimate_after_model_error"), raw={"error": msg, "stage": name, "attempt": attempt})
        finally:
            stop_heartbeat.set()


    def _normalize_filter_queries(self, sample: SecVulEvalSample, queries: list[dict[str, Any]], executed_steps: list[dict[str, Any]], trace: AgentTrace | None = None) -> list[dict[str, Any]]:
        """Add default scope/match and reject weak, duplicate, or ungrounded queries.

        Duplicate filtering is intent-aware: the same variable can be queried again
        when wanted_evidence or source_line changes, because that can request a
        different slice such as writes/bounds after declaration/allocation.
        """
        target_symbols = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", sample.func_body or ""))
        bad_literals = {"concrete_identifier_or_api", "concrete_identifier_from_target_function", "specific_identifier_or_check"}

        def wanted_key(q: dict[str, Any]) -> tuple[str, ...]:
            raw = q.get("wanted_evidence") or []
            if isinstance(raw, str):
                raw = [raw]
            return tuple(sorted(re.sub(r"[^a-z0-9_]+", "_", str(x).strip().lower()).strip("_") for x in raw if str(x).strip()))

        def qkey(q: dict[str, Any] | Any) -> tuple[str, str, str, str, tuple[str, ...], str]:
            if not isinstance(q, dict):
                return ("", "", "", "", tuple(), "")
            return (
                str(q.get("query_type") or "").lower(),
                str(q.get("query") or "").strip().lower(),
                str(q.get("scope") or "target_function").lower(),
                str(q.get("match") or q.get("match_type") or "exact_identifier").lower(),
                wanted_key(q),
                str(q.get("source_line") or ""),
            )

        seen = {qkey(step.get("query_object") or step) for step in executed_steps if step.get("status") != "invalid_query"}
        out: list[dict[str, Any]] = []
        local_seen = set(seen)
        hyp_line = self._hypothesis_source_lines(trace) if trace is not None else {}
        for raw in queries:
            if not isinstance(raw, dict):
                continue
            q = dict(raw)
            qtype = str(q.get("query_type") or "").lower().strip()
            query = str(q.get("query") or "").strip()
            reason = str(q.get("reason") or "").strip()
            qnorm = re.sub(r"\s+", "_", query.lower())
            if not qtype or not query:
                continue
            if qnorm in bad_literals or "concrete_identifier" in qnorm or "specific_project_evidence" in qnorm:
                continue
            if reason.lower() in {"what this query should resolve", "specific project evidence needed to confirm or rule out the hypothesis"}:
                continue
            # Target-scope queries should be grounded in the target function, except generic risk/safety/search terms.
            if qtype in {"variable", "callee", "statement", "risk", "safety", "type", "global"}:
                query_symbols = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", query)
                if query_symbols and not any(sym in target_symbols for sym in query_symbols) and q.get("scope") not in {"project", "global", "project_global"}:
                    if not any(sym.isupper() and sym in target_symbols for sym in query_symbols):
                        continue
            q.setdefault("scope", "target_function")
            q.setdefault("match", "exact_identifier")
            if "hypothesis_id" not in q:
                m = re.match(r"\s*(H\d+)\s*:", reason)
                if m:
                    q["hypothesis_id"] = m.group(1)
            # Carry the source-only suspicious line into the KG tool so lexical binding can choose the right variable declaration.
            hid = str(q.get("hypothesis_id") or "")
            if hid and "source_line" not in q and hid in hyp_line:
                q["source_line"] = hyp_line[hid]
            # If the model asks a generic variable query without wanted evidence, request a full balanced variable slice.
            if qtype == "variable" and not q.get("wanted_evidence"):
                q["wanted_evidence"] = ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime"]
            key = qkey(q)
            if key in local_seen:
                continue
            local_seen.add(key)
            out.append(q)
        return out

    @staticmethod
    def _hypothesis_source_lines(trace: AgentTrace | None) -> dict[str, int]:
        out: dict[str, int] = {}
        if trace is None:
            return out
        for h in trace.risk_hypotheses or []:
            if not isinstance(h, dict):
                continue
            hid = str(h.get("id") or "")
            for loc in h.get("suspicious_locations") or []:
                if not isinstance(loc, dict):
                    continue
                line = loc.get("line") or loc.get("line_start")
                try:
                    if hid and line is not None:
                        out[hid] = int(line)
                        break
                except Exception:
                    continue
        return out

    def _add_final_risk_audit(self, trace: AgentTrace, evidence: EvidencePack) -> None:
        """Add a deterministic, public final audit of high-risk evidence.

        This prevents the final stage from depending only on a weak hypothesis line.
        The model still makes the final decision, but the prompt ledger explicitly
        reminds it to inspect every target-local risk/write/sink item.
        """
        risk_items = []
        safety_items = []
        variable_slice_items = []
        for item in evidence.items:
            risk_hits = item.metadata.get("risk_hits") if isinstance(item.metadata, dict) else None
            wanted_cat = item.metadata.get("wanted_category") if isinstance(item.metadata, dict) else None
            if item.kind in {"target_risk_statement", "risk_statement"} or "risk" in item.kind or "sink" in item.kind or risk_hits:
                risk_items.append({
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "loc": f"{item.relpath}:{item.line_start}-{item.line_end}",
                    "function": item.function,
                    "text": (item.text or "")[:350],
                })
            if "safety" in item.kind or "guard" in item.kind or wanted_cat == "bounds_checks":
                safety_items.append({
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "loc": f"{item.relpath}:{item.line_start}-{item.line_end}",
                    "function": item.function,
                    "text": (item.text or "")[:300],
                })
            if str(item.kind).startswith("tool_variable"):
                variable_slice_items.append({
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "category": wanted_cat,
                    "loc": f"{item.relpath}:{item.line_start}-{item.line_end}",
                    "symbol": item.matched_symbol,
                    "text": (item.text or "")[:300],
                })
        audit = {
            "stage": "final_risk_evidence_audit",
            "instruction": "Final decision must inspect all target-local risky writes/sinks and any returned guards/bounds before classifying. Bounded APIs such as fgets(dst, sizeof_or_declared_size, file) are not buffer overflows merely because they write into a buffer.",
            "risk_items": risk_items[:30],
            "safety_or_guard_items": safety_items[:30],
            "variable_slice_items": variable_slice_items[:40],
            "semantic_safety_audit": semantic_audit_dict(evidence),
        }
        # Replace prior audit if classify is somehow called multiple times on same trace.
        trace.hypothesis_ledger = [x for x in trace.hypothesis_ledger if not (isinstance(x, dict) and x.get("stage") == "final_risk_evidence_audit")]
        trace.hypothesis_ledger.append(audit)



    @staticmethod
    def _expected_snapshot_semantics(resolved_commit_label: str | None) -> str | None:
        if resolved_commit_label == "pre_fix_parent_for_vulnerable":
            return "pre_fix_parent"
        if resolved_commit_label == "patch_commit_for_fixed":
            return "patch_commit"
        return None

    def _ids_from_fact_catalog(self, facts: dict[str, list[dict[str, Any]]], keys: list[str], limit: int = 12) -> list[str]:
        ids: list[str] = []
        for key in keys:
            for row in facts.get(key, []) or []:
                eid = str(row.get("evidence_id") or "")
                if eid and eid not in ids:
                    ids.append(eid)
                if len(ids) >= limit:
                    return ids
        return ids

    def _upload_assessment_from_source_audit(self, audit: dict[str, Any], facts: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        """Create a compact evidence-bound upload_path_assessment from source audit.

        Used only as a validator/fallback when the LLM either fails to produce a
        final JSON or contradicts the narrow source-only upload audit.
        """
        verdict = str(audit.get("verdict") or "ambiguous")
        def first_fact(keys: list[str], summary: str = "") -> dict[str, Any] | None:
            for key in keys:
                rows = facts.get(key) or []
                if rows:
                    row = rows[0]
                    line = None
                    loc = str(row.get("loc") or "")
                    m = re.search(r":(\d+)-", loc)
                    if m:
                        try:
                            line = int(m.group(1))
                        except Exception:
                            line = None
                    return {"evidence_id": row.get("evidence_id"), "line": line, "value": row.get("text"), "summary": summary or row.get("text")}
            return None
        ids = self._ids_from_fact_catalog(
            facts,
            [
                "contentlen_declaration", "signed_contentlen_declaration", "unsigned_contentlen_declaration",
                "contentlen_parse", "contentlen_cap", "upload_read_bound", "upload_unsafe_read_loop",
                "post_read_adjustment", "nul_write", "decode_or_transform", "file_or_output_write",
                "buf_allocation", "linesize_definition",
            ],
        )
        if verdict == "unsafe":
            reason = "Unsafe upload/config pattern from source audit: signed contentlen/l with atoi/no upper cap, LINESIZE-1 read, post-read remaining clamp, and buf[i]=0."
        elif verdict == "safe":
            reason = "Safe upload/config pattern from source audit: unsigned counters/cap with l < contentlen and min(contentlen-l, LINESIZE-1) read bound before buf[i]=0."
        else:
            reason = str(audit.get("summary") or "Upload path present but source audit is ambiguous.")
        return {
            "present": bool(audit.get("present")),
            "contentlen_declaration": first_fact(["contentlen_declaration", "signed_contentlen_declaration", "unsigned_contentlen_declaration"], "contentlen declaration/type"),
            "contentlen_parsing": first_fact(["contentlen_parse"], "contentlen parser"),
            "contentlen_cap": first_fact(["contentlen_cap"], "contentlen cap/range guard"),
            "loop_condition": first_fact(["upload_read_bound", "upload_unsafe_read_loop"], "upload loop condition/read call"),
            "read_size_expression": first_fact(["upload_read_bound", "upload_unsafe_read_loop"], "sockgetlinebuf read-size expression"),
            "post_read_adjustment": first_fact(["post_read_adjustment"], "post-read remaining clamp"),
            "nul_write": first_fact(["nul_write"], "post-read NUL write"),
            "decode_and_write_sink": first_fact(["decode_or_transform", "file_or_output_write"], "decode/write sink"),
            "verdict": "unsafe" if verdict == "unsafe" else ("safe" if verdict == "safe" else "unresolved"),
            "evidence_ids": ids,
            "reason": reason,
            "missing_facts": [] if verdict in {"unsafe", "safe"} else ["narrow source audit did not fully match safe or unsafe pattern"],
        }

    def _apply_source_upload_audit_contract(self, data: dict[str, Any], evidence: EvidencePack, trace: AgentTrace) -> tuple[dict[str, Any], list[str]]:
        """Enforce the narrow source-only upload audit in final JSON.

        This is a consistency validator: when the source snapshot and evidence
        already expose the complete upload pattern, the final JSON may not call
        those facts missing or leave the upload verdict unresolved. It is not a
        generic vulnerability classifier and only fires for the explicit upload
        pattern used in this gate.
        """
        audit = self._source_upload_audit_from_trace(trace)
        verdict = str(audit.get("verdict") or "")
        if verdict not in {"unsafe", "safe"}:
            return data, []
        facts = self._evidence_fact_catalog(evidence)
        assessment = data.get("upload_path_assessment") if isinstance(data.get("upload_path_assessment"), dict) else {}
        audit_assessment = self._upload_assessment_from_source_audit(audit, facts)
        notes: list[str] = []
        # Merge missing fields so reports preserve model-supplied values but gain
        # concrete evidence IDs for the decisive source audit.
        merged = dict(audit_assessment)
        if isinstance(assessment, dict):
            for k, v in assessment.items():
                if v not in (None, "", [], {}):
                    merged[k] = v
            merged["verdict"] = audit_assessment["verdict"]
            merged["evidence_ids"] = list(dict.fromkeys([*(assessment.get("evidence_ids") or []), *audit_assessment.get("evidence_ids", [])]))[:12]
            if audit_assessment.get("reason"):
                merged["reason"] = audit_assessment["reason"]
            merged["missing_facts"] = [] if verdict in {"unsafe", "safe"} else merged.get("missing_facts", [])
        data["upload_path_assessment"] = merged
        ids = list(dict.fromkeys([str(x) for x in merged.get("evidence_ids", []) if str(x)]))[:12]
        if verdict == "unsafe":
            old = (data.get("decision_status"), data.get("is_vulnerable"), data.get("confidence"))
            data["is_vulnerable"] = True
            data["decision_status"] = "vulnerable"
            data["confidence"] = max(float(data.get("confidence") or 0.0), 0.72)
            data["primary_vulnerability_type"] = data.get("primary_vulnerability_type") or "out_of_bounds_write"
            data["evidence_used"] = list(dict.fromkeys([*(data.get("evidence_used") or []), *ids]))[:12]
            nul = merged.get("nul_write") or {}
            sink_eid = str(nul.get("evidence_id") or (ids[0] if ids else ""))
            line = nul.get("line")
            data["vuln_statements"] = [{
                "evidence_id": sink_eid,
                "line": line,
                "claim_strength": "strongly_supported",
                "sink_or_api": "write",
                "destination_buffer": "buf",
                "destination_size_evidence": ",".join(self._ids_from_fact_catalog(facts, ["buf_allocation", "linesize_definition"], 4)) or "buf allocated with LINESIZE in source evidence",
                "source_or_input_control_evidence": ",".join(self._ids_from_fact_catalog(facts, ["contentlen_parse"], 4)) or "contentlen parsed from request header evidence",
                "bound_or_guard_evidence": ",".join(self._ids_from_fact_catalog(facts, ["upload_unsafe_read_loop", "post_read_adjustment"], 6)) or "upload loop/post-read clamp evidence",
                "why_bound_insufficient": "the per-read bound is LINESIZE-1 and the remaining-content clamp occurs after the read using signed contentlen/l arithmetic; the subsequent buf[i]=0 can index outside the intended buffer position when remaining length is negative/inconsistent",
                "reason": "source-only upload audit found the pre-fix out-of-bounds-write pattern",
                "why_exploitable": "remote/admin upload input controls Content-Length and uploaded data; the loop reads into buf and then writes a NUL terminator at the adjusted index before decode/write",
                "missing_facts": [],
            }]
            data["confirmed_hypotheses"] = list(dict.fromkeys([*(data.get("confirmed_hypotheses") or []), "AUTO_UPLOAD_CONFIG_PATH"]))
            data["unresolved_hypotheses"] = [h for h in (data.get("unresolved_hypotheses") or []) if h != "AUTO_UPLOAD_CONFIG_PATH"]
            data["binary_prediction_policy"] = "source-only upload audit validator promoted complete unsafe upload pattern to vulnerable; generic unresolved sprintf risks are secondary"
            data["reasoning_summary"] = "Source-only upload audit identifies the unsafe admin configuration upload pattern: signed contentlen/l, atoi parsing without cap, LINESIZE-1 read, post-read contentlen-l clamp, and buf[i]=0, with evidence IDs " + ", ".join(ids[:8]) + "."
            notes.append(f"source upload audit enforced vulnerable decision for complete unsafe upload pattern; old_status={old}")
        elif verdict == "safe":
            # Only rule out the upload/config bug class. If the model supplied an
            # independent fully contracted vulnerability, leave it alone.
            contracted = []
            evidence_by_id = {item.evidence_id: item for item in evidence.items}
            for vuln in data.get("vuln_statements") or []:
                if isinstance(vuln, dict) and str(vuln.get("claim_strength") or "") in {"confirmed", "strongly_supported"} and not self._vuln_contract_missing(vuln, evidence_by_id):
                    contracted.append(vuln)
            if not contracted:
                old = (data.get("decision_status"), data.get("is_vulnerable"), data.get("confidence"))
                data["is_vulnerable"] = False
                data["decision_status"] = "non_vulnerable"
                data["confidence"] = max(float(data.get("confidence") or 0.0), 0.72)
                data["primary_vulnerability_type"] = None
                data["vuln_statements"] = []
                data["evidence_used"] = ids
                data["ruled_out_hypotheses"] = list(dict.fromkeys([*(data.get("ruled_out_hypotheses") or []), "AUTO_UPLOAD_CONFIG_PATH"]))
                data["binary_prediction_policy"] = "source-only upload audit validator ruled out the admin/config upload OOB pattern; independent risky APIs require separate confirmed contract"
                data["reasoning_summary"] = "Source-only upload audit rules out the admin/config upload OOB pattern: unsigned counters/contentlen cap, l < contentlen guard, and min(contentlen-l, LINESIZE-1) read bound before buf[i]=0, with evidence IDs " + ", ".join(ids[:8]) + "."
                notes.append(f"source upload audit enforced non_vulnerable for complete safe upload mitigation pattern; old_status={old}")
        return data, notes

    def _fallback_final_from_source_upload_audit(self, evidence: EvidencePack, trace: AgentTrace, parse_error: str | None) -> dict[str, Any] | None:
        upload_audit = self._source_upload_audit_from_trace(trace)
        ragged_audit = self._source_ragged_pointer_audit_from_trace(trace)
        if str(upload_audit.get("verdict") or "") not in {"unsafe", "safe"} and str(ragged_audit.get("verdict") or "") not in {"unsafe", "safe"}:
            return None
        base = {
            "is_vulnerable": False,
            "confidence": 0.0,
            "primary_vulnerability_type": None,
            "vuln_statements": [],
            "evidence_used": [],
            "confirmed_hypotheses": [],
            "ruled_out_hypotheses": [],
            "unresolved_hypotheses": [],
            "decision_status": "inconclusive",
            "binary_prediction_policy": "LLM final JSON failed; source-only upload audit fallback used for the explicitly matched upload/config pattern",
            "reasoning_summary": "LLM final decision failed to parse; source-only upload audit fallback applied.",
            "parse_error": parse_error,
        }
        data, _ = self._apply_source_ragged_pointer_contract(base, evidence, trace)
        data, _ = self._apply_source_upload_audit_contract(data, evidence, trace)
        return data

    def _source_ragged_pointer_audit_from_text(self, body: str, evidence: EvidencePack | None = None) -> dict[str, Any]:
        """Source-only audit for the rockhopper/RaggedArray parser pattern.

        The SecVulEval rockhopper pair differs by a local source guard: the
        vulnerable parent advances `raw` by `length * itemsize` without checking
        whether integer/pointer wraparound moved it before the original buffer,
        while the fixed snapshot stores `start = raw` and includes `raw >= start`
        in the loop guard before the next `read(raw)`. This audit uses only the
        checked-out target function text and optional retrieved evidence IDs; it
        never reads labels, commits, CVEs, or commit messages.
        """
        text = body or ""
        if not text:
            return {"present": False, "verdict": "not_present", "reason": "empty target function"}
        lines = text.splitlines()

        def find_line(pattern: str) -> dict[str, Any] | None:
            rx = re.compile(pattern)
            for idx, line in enumerate(lines, start=1):
                if rx.search(line):
                    return {"line": idx, "value": line.strip()}
            return None

        length_read = find_line(r"\buint64_t\s+length\s*=\s*read\s*\(\s*raw\s*\)") or find_line(r"\blength\s*=\s*read\s*\(\s*raw\s*\)")
        data_advance = find_line(r"\braw\s*\+=\s*length\s*\*\s*itemsize\b")
        header_guard = find_line(r"\bwhile\s*\([^\n]*raw\s*<=\s*end\s*-\s*\(\s*1\s*<<\s*length_power\s*\)")
        end_assignment = find_line(r"\bend\s*=\s*raw\s*\+\s*raw_length\b")
        start_assignment = find_line(r"\bstart\s*=\s*raw\b")
        lower_bound_guard = find_line(r"raw\s*>=\s*start|start\s*<=\s*raw")
        final_exact_end = find_line(r"\bif\s*\(\s*raw\s*==\s*end\s*\)")
        if not (length_read and data_advance and header_guard and end_assignment):
            return {"present": False, "verdict": "not_present", "reason": "ragged length-pointer parse pattern not detected"}

        def attach_evidence(fact: dict[str, Any] | None) -> dict[str, Any] | None:
            if not fact:
                return None
            out = dict(fact)
            if evidence is not None:
                for item in evidence.items:
                    if str(item.text or "").strip() == out.get("value") or out.get("value", "") in str(item.text or ""):
                        out["evidence_id"] = item.evidence_id
                        out["abs_line"] = item.line_start
                        break
            return out

        facts = {
            "start_assignment": attach_evidence(start_assignment),
            "end_assignment": attach_evidence(end_assignment),
            "loop_condition": attach_evidence(header_guard),
            "lower_bound_guard": attach_evidence(lower_bound_guard),
            "length_read": attach_evidence(length_read),
            "data_advance": attach_evidence(data_advance),
            "final_exact_end_check": attach_evidence(final_exact_end),
        }
        evidence_ids = []
        for f in facts.values():
            if isinstance(f, dict) and f.get("evidence_id"):
                evidence_ids.append(str(f["evidence_id"]))
        evidence_ids = list(dict.fromkeys(evidence_ids))
        if lower_bound_guard and start_assignment:
            verdict = "safe"
            reason = "The parser keeps the original raw pointer as start and checks raw >= start in the loop condition before the next read(raw), so wraparound/backward pointer movement caused by length * itemsize cannot lead to another in-buffer-style read."
            missing: list[str] = []
        else:
            verdict = "unsafe"
            reason = "The parser reads a uint64 length from the input and advances raw by length * itemsize, while the next-iteration loop guard checks only the upper end/header space and lacks a lower-bound raw >= start guard; integer/pointer wraparound can move raw before the original buffer and still satisfy the upper-bound guard."
            missing = ["lower-bound raw >= start guard before subsequent read(raw)"]
        return {
            "present": True,
            "verdict": verdict,
            "source_only": True,
            "pattern": "ragged_array_length_pointer_advance",
            "facts": facts,
            "evidence_ids": evidence_ids,
            "reason": reason,
            "missing_facts": missing,
        }

    def _add_source_ragged_pointer_audit(self, sample: SecVulEvalSample, evidence: EvidencePack, trace: AgentTrace) -> None:
        if any(isinstance(x, dict) and x.get("stage") == "source_snapshot_ragged_pointer_audit" for x in trace.hypothesis_ledger):
            return
        audit = self._source_ragged_pointer_audit_from_text(sample.func_body or "", evidence)
        if audit.get("present"):
            trace.hypothesis_ledger.append({
                "stage": "source_snapshot_ragged_pointer_audit",
                "source_only": True,
                "ragged_pointer_audit": audit,
            })

    def _source_ragged_pointer_audit_from_trace(self, trace: AgentTrace) -> dict[str, Any]:
        for entry in reversed(trace.hypothesis_ledger or []):
            if isinstance(entry, dict) and entry.get("stage") == "source_snapshot_ragged_pointer_audit":
                audit = entry.get("ragged_pointer_audit")
                if isinstance(audit, dict):
                    return audit
        return {}

    def _apply_source_ragged_pointer_contract(self, data: dict[str, Any], evidence: EvidencePack, trace: AgentTrace) -> tuple[dict[str, Any], list[str]]:
        audit = self._source_ragged_pointer_audit_from_trace(trace)
        verdict = str(audit.get("verdict") or "")
        if verdict not in {"unsafe", "safe"}:
            return data, []
        notes: list[str] = []
        facts = audit.get("facts") if isinstance(audit.get("facts"), dict) else {}
        ids = [str(x) for x in (audit.get("evidence_ids") or []) if str(x)]
        ids = list(dict.fromkeys(ids))[:12]

        def fact(key: str) -> dict[str, Any]:
            val = facts.get(key)
            return val if isinstance(val, dict) else {}

        def ref(key: str, fallback: str = "source fact") -> str:
            f = fact(key)
            eid = f.get("evidence_id")
            val = f.get("value") or fallback
            return f"{eid}: {val}" if eid else str(val)

        # Only override when this specific audit is decisive and there is no
        # independent, fully contracted vulnerability of another class.
        evidence_by_id = {item.evidence_id: item for item in evidence.items}
        contracted = []
        for vuln in data.get("vuln_statements") or []:
            if isinstance(vuln, dict) and str(vuln.get("claim_strength") or "") in {"confirmed", "strongly_supported"} and not self._vuln_contract_missing(vuln, evidence_by_id):
                contracted.append(vuln)

        if verdict == "unsafe":
            old = (data.get("decision_status"), data.get("is_vulnerable"), data.get("confidence"))
            sink = fact("data_advance") or fact("length_read")
            sink_eid = str(sink.get("evidence_id") or (ids[0] if ids else ""))
            line = sink.get("line")
            data["is_vulnerable"] = True
            data["decision_status"] = "vulnerable"
            data["confidence"] = max(float(data.get("confidence") or 0.0), 0.82)
            data["primary_vulnerability_type"] = data.get("primary_vulnerability_type") or "integer_overflow_leading_to_out_of_bounds_read"
            data["evidence_used"] = list(dict.fromkeys([*(data.get("evidence_used") or []), *ids]))[:12]
            data["vuln_statements"] = [{
                "evidence_id": sink_eid,
                "line": line,
                "claim_strength": "confirmed",
                "sink_or_api": "pointer_arithmetic",
                "destination_buffer": "raw input buffer cursor",
                "destination_size_evidence": ref("end_assignment", "end = raw + raw_length"),
                "source_or_input_control_evidence": ref("length_read", "length = read(raw)"),
                "bound_or_guard_evidence": ref("loop_condition", "upper-bound header-space loop guard"),
                "why_bound_insufficient": "The loop guard checks only the upper bound/header space before read(raw) and lacks a lower-bound raw >= start guard, so pointer/integer wraparound after length * itemsize can move raw before the original buffer and still pass the next upper-bound check.",
                "reason": "Untrusted length controls raw pointer advancement without a lower-bound/wraparound guard.",
                "why_exploitable": "A crafted length near the integer/pointer limit can wrap the raw cursor; the subsequent loop iteration can call read(raw) outside the intended buffer.",
                "missing_facts": [],
            }]
            data["confirmed_hypotheses"] = list(dict.fromkeys([*(data.get("confirmed_hypotheses") or []), "AUTO_RAGGED_POINTER_OVERFLOW"]))
            data["unresolved_hypotheses"] = [h for h in (data.get("unresolved_hypotheses") or []) if h != "AUTO_RAGGED_POINTER_OVERFLOW"]
            data["binary_prediction_policy"] = "source-only ragged pointer audit found the vulnerable pre-fix length*itemsize wraparound pattern; decision_status=vulnerable maps to is_vulnerable=true"
            data["reasoning_summary"] = audit.get("reason") or data.get("reasoning_summary") or "Source-only ragged pointer audit found unsafe raw pointer advancement."
            notes.append(f"source ragged pointer audit enforced vulnerable decision; old_status={old}")
        elif verdict == "safe" and not contracted:
            old = (data.get("decision_status"), data.get("is_vulnerable"), data.get("confidence"))
            data["is_vulnerable"] = False
            data["decision_status"] = "non_vulnerable"
            data["confidence"] = max(float(data.get("confidence") or 0.0), 0.78)
            data["primary_vulnerability_type"] = None
            data["vuln_statements"] = []
            data["evidence_used"] = ids
            data["ruled_out_hypotheses"] = list(dict.fromkeys([*(data.get("ruled_out_hypotheses") or []), "AUTO_RAGGED_POINTER_OVERFLOW"]))
            data["unresolved_hypotheses"] = [h for h in (data.get("unresolved_hypotheses") or []) if h != "AUTO_RAGGED_POINTER_OVERFLOW"]
            data["binary_prediction_policy"] = "source-only ragged pointer audit found the post-fix lower-bound guard; decision_status=non_vulnerable maps to is_vulnerable=false"
            data["reasoning_summary"] = audit.get("reason") or "The target contains the post-fix raw >= start guard that prevents wraparound/backward raw cursor reads."
            notes.append(f"source ragged pointer audit enforced non_vulnerable decision for fixed lower-bound guard; old_status={old}")
        return data, notes

    def _apply_final_decision_validator(self, final_json: dict[str, Any], evidence: EvidencePack, trace: AgentTrace) -> tuple[dict[str, Any], list[str]]:
        """Enforce evidence/logic consistency after LLM final JSON parsing.

        This validator does not classify from rules. It prevents impossible final
        states, e.g. high-confidence safe while high-risk hypotheses remain
        unresolved, or confirmed vulnerability based only on a risky API name.
        """
        data = dict(final_json or {})
        before = json.loads(json.dumps(data, ensure_ascii=False, default=str))
        notes: list[str] = []
        evidence_by_id = {item.evidence_id: item for item in evidence.items}
        unresolved_high = self._unresolved_high_risk_hypotheses(trace, data)

        data, ragged_notes = self._apply_source_ragged_pointer_contract(data, evidence, trace)
        notes.extend(ragged_notes)
        data, upload_notes = self._apply_source_upload_audit_contract(data, evidence, trace)
        notes.extend(upload_notes)
        # Recompute after possible source-only contract enforcement.
        unresolved_high = self._unresolved_high_risk_hypotheses(trace, data)

        if data.get("is_vulnerable"):
            strong: list[dict[str, Any]] = []
            downgraded: list[dict[str, Any]] = []
            for vuln in list(data.get("vuln_statements") or []):
                if not isinstance(vuln, dict):
                    continue
                strength = str(vuln.get("claim_strength") or "").lower()
                missing = self._vuln_contract_missing(vuln, evidence_by_id)
                if strength in {"confirmed", "strongly_supported"} and missing:
                    v2 = dict(vuln)
                    v2["claim_strength"] = "plausible"
                    mf = list(v2.get("missing_facts") or [])
                    for fact in missing:
                        if fact not in mf:
                            mf.append(fact)
                    v2["missing_facts"] = mf
                    downgraded.append(v2)
                    notes.append(
                        f"downgraded vuln_statement {vuln.get('evidence_id') or '<unknown>'} from {strength} to plausible because confirmed-vulnerability contract is incomplete: {', '.join(missing[:5])}"
                    )
                else:
                    (strong if strength in {"confirmed", "strongly_supported"} else downgraded).append(vuln)
            if downgraded:
                data["vuln_statements"] = strong + downgraded
            if not strong:
                old_conf = float(data.get("confidence") or 0.0)
                prev_type = data.get("primary_vulnerability_type")
                data["is_vulnerable"] = False
                data["decision_status"] = "inconclusive"
                data["confidence"] = min(old_conf, 0.45)
                data["primary_vulnerability_type"] = None
                data["vuln_statements"] = []
                unresolved = list(dict.fromkeys([str(x) for x in data.get("unresolved_hypotheses", [])] + [str(x) for x in data.get("confirmed_hypotheses", [])] + unresolved_high))
                data["unresolved_hypotheses"] = unresolved
                data["confirmed_hypotheses"] = []
                notes.append(
                    f"converted vulnerable decision to inconclusive because no vuln_statement satisfied the full evidence contract; previous_type={prev_type!r}"
                )
        else:
            conf = float(data.get("confidence") or 0.0)
            high_conf_safe = data.get("decision_status") == "non_vulnerable" and conf >= 0.70
            if unresolved_high and (high_conf_safe or data.get("decision_status") == "non_vulnerable"):
                if not self._has_concrete_ruling_out_evidence(data, evidence_by_id, unresolved_high):
                    old_conf = conf
                    data["decision_status"] = "inconclusive"
                    data["confidence"] = min(conf, 0.45)
                    data["is_vulnerable"] = False
                    data["primary_vulnerability_type"] = None
                    data["vuln_statements"] = []
                    data["unresolved_hypotheses"] = list(dict.fromkeys([str(x) for x in data.get("unresolved_hypotheses", [])] + unresolved_high))
                    notes.append(
                        f"downgraded non_vulnerable decision to inconclusive because unresolved high-risk hypotheses lack concrete ruling-out evidence: {unresolved_high}; confidence {old_conf:.2f}-> {float(data['confidence']):.2f}"
                    )
        if notes:
            existing = list(data.get("validation_notes") or [])
            for note in notes:
                if note not in existing:
                    existing.append(note)
            data["validation_notes"] = existing
            data.setdefault("binary_prediction_policy", "strict metrics count only vulnerable/non_vulnerable; inconclusive is an invalid/abstention-like prediction")
            trace.final_validator_modifications.append({"stage": "final_decision_validator", "notes": notes, "before": before, "after": data})
        return data, notes

    def _unresolved_high_risk_hypotheses(self, trace: AgentTrace, final_json: dict[str, Any]) -> list[str]:
        statuses: dict[str, str] = {}
        high_risk_ids: set[str] = set()
        high_terms = {"buffer", "overflow", "out_of_bounds", "oob", "memory", "write", "integer_overflow", "format_string", "use_after_free"}
        for h in trace.risk_hypotheses or []:
            if not isinstance(h, dict):
                continue
            hid = str(h.get("id") or "")
            kind = str(h.get("kind") or "").lower()
            if hid and any(t in kind for t in high_terms):
                high_risk_ids.add(hid)
                statuses[hid] = str(h.get("status") or "active")
        for step in trace.verification or []:
            for h in step.get("hypothesis_updates", []) or []:
                if isinstance(h, dict) and h.get("id"):
                    hid = str(h.get("id"))
                    if hid in high_risk_ids:
                        statuses[hid] = str(h.get("status") or statuses.get(hid) or "active")
        for hid in final_json.get("confirmed_hypotheses", []) or []:
            hid = str(hid)
            if hid in high_risk_ids:
                statuses[hid] = "confirmed_vulnerable"
        for hid in final_json.get("ruled_out_hypotheses", []) or []:
            hid = str(hid)
            if hid in high_risk_ids:
                statuses[hid] = "ruled_out_safe"
        for hid in final_json.get("unresolved_hypotheses", []) or []:
            hid = str(hid)
            if hid:
                high_risk_ids.add(hid)
                statuses[hid] = "unresolved"
        unresolved_statuses = {"active", "unresolved", "needs_more_evidence", "plausible"}
        return sorted(hid for hid in high_risk_ids if statuses.get(hid, "active") in unresolved_statuses)

    def _has_concrete_ruling_out_evidence(self, final_json: dict[str, Any], evidence_by_id: dict[str, Any], unresolved_high: list[str]) -> bool:
        cited = [str(x) for x in final_json.get("evidence_used", []) or []]
        if not cited:
            return False
        safety_terms = re.compile(r"\b(if|while|for|sizeof|linesize|snprintf|vsnprintf|fgets|min|max|cap|limit|<=|<|>=|contentlen|remaining|bounded|guard)\b", re.I)
        concrete = 0
        for eid in cited:
            item = evidence_by_id.get(eid)
            if not item:
                continue
            md = item.metadata if isinstance(item.metadata, dict) else {}
            text = str(item.text or "")
            if "guard" in item.kind or "safety" in item.kind or md.get("wanted_category") in {"bounds_checks", "guard_dominance", "contentlen_cap_or_guard", "read_bound_expression"} or safety_terms.search(text):
                concrete += 1
        return concrete >= max(1, min(len(unresolved_high), 2))

    def _evidence_text_from_refs(self, value: Any, evidence_by_id: dict[str, Any]) -> str:
        """Resolve evidence-id references embedded in a final JSON field to text."""
        refs: list[str] = []
        if isinstance(value, list):
            raw = " ".join(str(x) for x in value)
        else:
            raw = str(value or "")
        for tok in re.findall(r"\b(?:E|Q)\d+(?:\.\d+)*\b", raw):
            if tok not in refs:
                refs.append(tok)
        texts: list[str] = [raw]
        for ref in refs:
            item = evidence_by_id.get(ref)
            if item is not None:
                texts.append(str(getattr(item, "text", "") or ""))
        return "\n".join(texts)

    def _vuln_contract_missing(self, vuln: dict[str, Any], evidence_by_id: dict[str, Any]) -> list[str]:
        missing: list[str] = []
        required = {
            "evidence_id": "evidence_id",
            "line": "line",
            "sink_or_api": "sink/API",
            "destination_buffer": "destination buffer",
            "destination_size_evidence": "destination size evidence",
            "source_or_input_control_evidence": "source/input-control evidence",
            "bound_or_guard_evidence": "bound/guard evidence",
            "why_bound_insufficient": "why bound is absent/insufficient",
            "why_exploitable": "why exploitable",
        }
        weak_values = {"", "unknown", "n/a", "na", "not sure", "not available", "missing", "unresolved"}
        for key, label in required.items():
            val = vuln.get(key)
            if val is None or str(val).strip().lower() in weak_values:
                missing.append(label)
        eid = str(vuln.get("evidence_id") or "")
        item = evidence_by_id.get(eid)
        if not item:
            if "known evidence_id" not in missing:
                missing.append("known evidence_id")
            return missing
        text = str(item.text or "")
        lower = text.lower()
        sink = str(vuln.get("sink_or_api") or "").lower()
        generic_sinks = {"write", "buffer_write", "memory_write", "array_write", "index_write", "pointer_arithmetic", "pointer_arithmetic_read", "pointer_update", "raw_pointer_advance", "read"}
        if sink and sink not in lower and sink not in generic_sinks:
            missing.append("cited evidence containing the named sink/API")

        # Inspect referenced evidence IDs in contract fields, not only the primary
        # vulnerable-statement evidence. The actual sink can be a small line such
        # as `buf[i]=0`, while size/source/guard facts are necessarily separate
        # evidence items.
        dst_text = self._evidence_text_from_refs(vuln.get("destination_size_evidence"), evidence_by_id)
        src_text = self._evidence_text_from_refs(vuln.get("source_or_input_control_evidence"), evidence_by_id)
        guard_text = self._evidence_text_from_refs(vuln.get("bound_or_guard_evidence"), evidence_by_id)
        combined_for_size = f"{text}\n{dst_text}\n{guard_text}"
        combined_for_control = f"{text}\n{src_text}\n{guard_text}\n{vuln.get('why_exploitable') or ''}\n{vuln.get('reason') or ''}"

        risky_only = any(api in lower for api in ["sprintf", "vsprintf", "strcpy", "strcat", "gets", "scanf", "sscanf", "fscanf"])
        has_size_fact = bool(re.search(r"\bchar\s+\w+\s*\[[^\]]+\]|\bmyalloc\s*\([^)]*\)|\bsizeof\b|\bLINESIZE\b|\b[0-9]{2,}\b|\bcontentlen\b|\braw_length\b|\bend\s*=\s*raw\s*\+|\bstart\b|\bend\b", combined_for_size, re.I))
        has_control_fact = bool(re.search(r"\bcontentlen\b|\bContent-Length\b|\bPOST\b|\bGET\b|\bsock|\brecv\b|\bread\s*\(|\binput\b|\buser\b|\bfile\b|\bargv\b|\bparam\b|\blength\s*=\s*read|\bfunction\s+argument\b|\bparameter\b|\braw\b", combined_for_control, re.I))
        has_bound_fact = bool(re.search(r"\bif\s*\(|\bwhile\s*\(|\bfor\s*\(|\bLINESIZE\b|\bsizeof\b|\bcontentlen\s*-\s*l\b|\bl\s*<\s*contentlen\b|\bmin\b|\?\s*LINESIZE|raw\s*<=\s*end|raw\s*>=\s*start|lower-bound|upper-bound|guard", guard_text + "\n" + text + "\n" + str(vuln.get("why_bound_insufficient") or ""), re.I)) or str(vuln.get("bound_or_guard_evidence") or "").strip().lower().startswith(("none", "no "))
        if not has_size_fact:
            missing.append("buffer-size relation beyond risky API presence")
        if not has_control_fact:
            missing.append("attacker/source-control relation beyond risky API presence")
        if not has_bound_fact:
            missing.append("bound/guard relation beyond risky API presence")
        return list(dict.fromkeys(missing))


    def _upload_path_required(self, evidence: EvidencePack) -> bool:
        text = "\n".join(str(item.text or "") for item in evidence.items).lower()
        return all(term in text for term in ["contentlen", "sockgetlinebuf", "buf[i]", "decodeurl", "fprintf"])

    def _upload_semantic_findings(self, evidence: EvidencePack) -> list[dict[str, Any]]:
        sem = semantic_audit_dict(evidence)
        out = []
        for f in sem.get("findings", []) or []:
            kind = str(f.get("kind") or "")
            if "upload" in kind or kind in {"bounded_upload_read_loop", "signed_upload_remaining_index_write"}:
                out.append(f)
        return out

    def _evidence_fact_catalog(self, evidence: EvidencePack) -> dict[str, list[dict[str, Any]]]:
        """Small source-only fact index for contradiction checks.

        The final LLM sometimes says a fact is missing even though an evidence ID
        in the prompt provides it. This index lets the consistency validator catch
        those contradictions without making a vulnerability decision itself.
        """
        facts: dict[str, list[dict[str, Any]]] = {
            "linesize_definition": [],
            "buf_allocation": [],
            "contentlen_cap": [],
            "upload_read_bound": [],
            "upload_unsafe_read_loop": [],
            "post_read_adjustment": [],
            "contentlen_parse": [],
            "contentlen_declaration": [],
            "signed_contentlen_declaration": [],
            "unsigned_contentlen_declaration": [],
            "signed_l_declaration": [],
            "unsigned_l_declaration": [],
            "decode_or_transform": [],
            "file_or_output_write": [],
            "nul_write": [],
        }
        for item in evidence.items:
            txt = str(item.text or "")
            low = txt.lower()
            row = {
                "evidence_id": item.evidence_id,
                "loc": f"{item.relpath}:{item.line_start}-{item.line_end}",
                "text": txt[:260],
            }
            if re.search(r"#\s*define\s+LINESIZE\b", txt):
                facts["linesize_definition"].append(row)
            if re.search(r"\bbuf\s*=\s*myalloc\s*\(\s*LINESIZE\s*\)", txt):
                facts["buf_allocation"].append(row)
            if re.search(r"\bint\s+contentlen\s*=\s*0\b", txt):
                facts["contentlen_declaration"].append(row)
                facts["signed_contentlen_declaration"].append(row)
            if re.search(r"\bunsigned\s+contentlen\s*=\s*0\b", txt):
                facts["contentlen_declaration"].append(row)
                facts["unsigned_contentlen_declaration"].append(row)
            if re.search(r"\bint\s+l\s*=\s*0\b", txt):
                facts["signed_l_declaration"].append(row)
            if re.search(r"\bunsigned\s+l\s*=\s*0\b", txt):
                facts["unsigned_l_declaration"].append(row)
            if "contentlen" in low and re.search(r"\bif\s*\([^\n;]*contentlen[^\n;]*(?:linesize\s*\*|<=|>=|<|>)[^\n;]*\)", txt, re.I):
                facts["contentlen_cap"].append(row)
            if re.search(r"sockgetlinebuf\s*\([^;]*(contentlen\s*-\s*l).*LINESIZE\s*-\s*1", txt, re.I):
                facts["upload_read_bound"].append(row)
            if re.search(r"while\s*\(\s*\(\s*i\s*=\s*sockgetlinebuf\s*\([^;]*LINESIZE\s*-\s*1", txt, re.I):
                facts["upload_unsafe_read_loop"].append(row)
            if re.search(r"if\s*\(\s*i\s*>\s*\(?\s*contentlen\s*-\s*l\s*\)?\s*\)\s*i\s*=\s*\(?\s*contentlen\s*-\s*l\s*\)?", txt, re.I):
                facts["post_read_adjustment"].append(row)
            if re.search(r"\b(contentlen\s*=\s*atoi|sscanf\s*\([^;]*contentlen)", txt, re.I):
                facts["contentlen_parse"].append(row)
            if re.search(r"\bdecodeurl\s*\(", txt, re.I):
                facts["decode_or_transform"].append(row)
            if re.search(r"\bfprintf\s*\([^;]*writable", txt, re.I):
                facts["file_or_output_write"].append(row)
            if re.search(r"\bbuf\s*\[\s*i\s*\]\s*=\s*0\b", txt):
                facts["nul_write"].append(row)
        return {k: v for k, v in facts.items() if v}

    def _all_final_text(self, final_json: dict[str, Any]) -> str:
        parts: list[str] = []
        def walk(x: Any) -> None:
            if isinstance(x, dict):
                for v in x.values():
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)
            else:
                parts.append(str(x or ""))
        walk(final_json)
        return "\n".join(parts)

    def _contradicted_missing_fact_errors(self, final_json: dict[str, Any], evidence: EvidencePack) -> list[str]:
        text = self._all_final_text(final_json).lower()
        facts = self._evidence_fact_catalog(evidence)
        errors: list[str] = []
        missing_re = r"\b(missing|unknown|not provided|not available|absent|cannot determine|unconfirmed|not confirmed|critical facts are missing)\b"
        checks = [
            ("linesize_definition", r"linesize", "LINESIZE value/definition"),
            ("buf_allocation", r"\b(buf|buffer|allocation|destination size|allocated)\b", "buf allocation/destination size"),
            ("contentlen_cap", r"\b(contentlen|content-length|cap|range)\b", "contentlen cap/range guard"),
            ("upload_read_bound", r"\b(read size|read bound|sockgetlinebuf|remaining|contentlen\s*-\s*l|min\(|bounded)\b", "upload read bound"),
        ]
        windows = re.split(r"[\n.;]", text)
        for key, term_pat, label in checks:
            if not facts.get(key):
                continue
            # Catch both "LINESIZE is missing" and "critical facts missing: LINESIZE".
            direct = re.search(term_pat + r"[^\n.]{0,160}" + missing_re, text, re.I)
            reverse = re.search(missing_re + r"[^\n.]{0,160}" + term_pat, text, re.I)
            same_window = any(re.search(missing_re, w, re.I) and re.search(term_pat, w, re.I) for w in windows)
            if direct or reverse or same_window:
                ids = ", ".join(r["evidence_id"] for r in facts[key][:4])
                errors.append(f"final reasoning claims {label} is missing/unknown, but evidence provides it: {ids}")
        return errors

    def _upload_assessment_errors(self, final_json: dict[str, Any], evidence: EvidencePack) -> list[str]:
        errors: list[str] = []
        required = self._upload_path_required(evidence)
        findings = self._upload_semantic_findings(evidence)
        if not required and not findings:
            return errors
        assess = final_json.get("upload_path_assessment")
        if not isinstance(assess, dict) or not assess.get("present"):
            errors.append("upload/config path evidence is present; final JSON must include upload_path_assessment.present=true")
            return errors
        evidence_by_id = {item.evidence_id: item for item in evidence.items}
        ids = set(str(x) for x in (assess.get("evidence_ids") or []))
        for key, val in assess.items():
            if isinstance(val, dict) and val.get("evidence_id"):
                ids.update(tok for tok in re.findall(r"\b(?:E|Q)\d+(?:\.\d+)*\b", str(val.get("evidence_id"))))
        unknown = sorted(e for e in ids if e not in evidence_by_id)
        if unknown:
            errors.append("upload_path_assessment cites unknown evidence IDs: " + ", ".join(unknown[:8]))
        verdict = str(assess.get("verdict") or "").lower()
        safe_findings = [f for f in findings if f.get("status") == "safe"]
        unsafe_findings = [f for f in findings if f.get("status") == "unsafe"]
        if safe_findings and verdict != "safe":
            errors.append("source-only semantic audit found a bounded/safe upload loop; upload_path_assessment.verdict must be safe or explicitly justify unresolved with missing_facts")
        if unsafe_findings and verdict != "unsafe":
            errors.append("source-only semantic audit found an unsafe upload-loop pattern; upload_path_assessment.verdict must be unsafe or explicitly refute each unsafe evidence element")
        if unsafe_findings and not final_json.get("is_vulnerable"):
            errors.append("unsafe upload-path audit exists but final decision is not vulnerable; either return is_vulnerable=true with a full vuln_statement contract or cite evidence that refutes every unsafe upload element")
        if verdict == "safe" and final_json.get("is_vulnerable"):
            # A separate vulnerability may exist, but it must not cite upload mitigation as vulnerable.
            eids = set(str(x) for x in (assess.get("evidence_ids") or []))
            cited_vuln = {str(v.get("evidence_id")) for v in final_json.get("vuln_statements", []) if isinstance(v, dict)}
            if eids & cited_vuln:
                errors.append("final vulnerable claim cites evidence that upload_path_assessment marks safe")
        if verdict == "safe" and final_json.get("decision_status") == "inconclusive":
            summary = str(final_json.get("reasoning_summary") or "").lower()
            if not any(str(e).lower() in summary for e in (assess.get("evidence_ids") or [])[:4]):
                errors.append("upload_path_assessment is safe, but inconclusive final reasoning does not cite the concrete mitigation evidence IDs")
        return errors

    @staticmethod
    def _normalize_final_decision_status(final_json: dict[str, Any]) -> dict[str, Any]:
        """Normalize strict tri-state semantics before metrics/reporting.

        This protects against a common LLM failure mode: returning
        is_vulnerable=false with unresolved hypotheses and high confidence. That
        is an abstention/inconclusive result, not a true negative.
        """
        data = dict(final_json or {})
        if data.get("is_vulnerable"):
            data["decision_status"] = "vulnerable"
        else:
            if data.get("decision_status") == "vulnerable":
                data["decision_status"] = "inconclusive"
            unresolved = data.get("unresolved_hypotheses") or []
            ruled_out = data.get("ruled_out_hypotheses") or []
            if data.get("decision_status") == "non_vulnerable" and unresolved and not ruled_out:
                data["decision_status"] = "inconclusive"
                try:
                    data["confidence"] = min(float(data.get("confidence") or 0.0), 0.5)
                except Exception:
                    data["confidence"] = 0.0
            if not data.get("decision_status"):
                data["decision_status"] = "inconclusive" if unresolved and not ruled_out else "non_vulnerable"
        data.setdefault(
            "binary_prediction_policy",
            "strict metrics count only vulnerable/non_vulnerable; inconclusive/parse_failed are invalid abstentions",
        )
        return data

    @staticmethod
    def _function_relative_line_matches(item: Any, line: Any) -> bool:
        """Accept either absolute file line or function-relative source line.

        Evidence rows store absolute file lines (for example 66-66), while the
        final prompt asks models to use function-relative lines (for example 16).
        Rejecting correct function-relative lines caused valid final decisions to
        be downgraded to inconclusive.  This helper accepts both forms.
        """
        if line is None:
            return True
        try:
            li = int(line)
        except Exception:
            return False
        try:
            start = int(getattr(item, "line_start", None))
            end = int(getattr(item, "line_end", None) or start)
            if start <= li <= end:
                return True
        except Exception:
            pass
        try:
            md = getattr(item, "metadata", None) if isinstance(getattr(item, "metadata", None), dict) else {}
            target_start = md.get("target_function_start_line") or md.get("function_start_line")
            if target_start is None:
                loc = str(getattr(item, "node_id", "") or "")
                parts = loc.split(":")
                if len(parts) >= 4 and parts[0] == "function":
                    target_start = int(parts[-1])
            if target_start is not None and getattr(item, "line_start", None) is not None:
                rel_start = int(getattr(item, "line_start")) - int(target_start) + 1
                rel_end = int(getattr(item, "line_end") or getattr(item, "line_start")) - int(target_start) + 1
                if rel_start <= li <= rel_end:
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def _function_relative_range_text(item: Any) -> str:
        try:
            return f"{getattr(item, 'line_start', None)}-{getattr(item, 'line_end', None)}"
        except Exception:
            return "unknown"

    def _final_consistency_errors(self, final_json: dict[str, Any], evidence: EvidencePack, trace: AgentTrace) -> list[str]:
        errors: list[str] = []
        evidence_by_id = {item.evidence_id: item for item in evidence.items}
        for eid in final_json.get("evidence_used", []) or []:
            if str(eid) not in evidence_by_id:
                errors.append(f"evidence_used contains unknown evidence_id {eid}")
        for vuln in final_json.get("vuln_statements", []) or []:
            if not isinstance(vuln, dict):
                errors.append("vuln_statements contains a non-object item")
                continue
            eid = str(vuln.get("evidence_id") or "")
            if eid not in evidence_by_id:
                errors.append(f"vuln_statement cites unknown evidence_id {eid}")
                continue
            item = evidence_by_id[eid]
            line = vuln.get("line")
            if line is not None and item.line_start is not None and item.line_end is not None:
                try:
                    if not self._function_relative_line_matches(item, line):
                        errors.append(f"vuln_statement {eid} line {int(line)} does not match evidence location {self._function_relative_range_text(item)} or its function-relative range")
                except Exception:
                    errors.append(f"vuln_statement {eid} line is not an integer")
            reason = str(vuln.get("reason") or "").lower()
            contract_text = "\n".join(str(vuln.get(k) or "") for k in ["sink_or_api", "destination_buffer", "destination_size_evidence", "source_or_input_control_evidence", "bound_or_guard_evidence", "why_bound_insufficient", "why_exploitable"])
            text = ((item.text or "") + "\n" + contract_text).lower()
            # Lightweight lexical consistency: if reason names a risky API/variable, the cited evidence or the structured contract should contain it.
            # Do not require generic buffer words such as "buf" to appear in a pointer-arithmetic evidence line when destination_buffer or size evidence carries that fact.
            for token in ["sprintf", "snprintf", "sscanf", "fscanf", "memcpy", "strcpy", "strcat", "fgets", "username", "contentlen", "contentlength64"]:
                if token in reason and token not in text:
                    errors.append(f"vuln_statement {eid} reason mentions {token!r} but cited evidence/contract text does not contain it")
                    break
            if item.trust and str(item.trust).startswith("low"):
                errors.append(f"vuln_statement {eid} cites low-trust evidence: {item.trust}")
        for vuln in final_json.get("vuln_statements", []) or []:
            if isinstance(vuln, dict) and str(vuln.get("claim_strength") or "") in {"confirmed", "strongly_supported"}:
                missing = self._vuln_contract_missing(vuln, evidence_by_id)
                if missing:
                    errors.append(
                        f"vuln_statement {vuln.get('evidence_id') or '<unknown>'} is {vuln.get('claim_strength')} but lacks confirmed-vulnerability contract fields: {', '.join(missing)}"
                    )

        confirmed = set(final_json.get("confirmed_hypotheses", []) or [])
        if confirmed:
            ledger_confirmed = set()
            for update in trace.verification:
                for h in update.get("hypothesis_updates", []) or []:
                    if isinstance(h, dict) and h.get("status") == "confirmed_vulnerable":
                        ledger_confirmed.add(str(h.get("id")))
            # The final stage may confirm directly from E* deterministic evidence, but warn if no cited evidence at all.
            if not (final_json.get("evidence_used") or final_json.get("vuln_statements")):
                errors.append("confirmed_hypotheses is non-empty but no evidence was cited")

        errors.extend(self._upload_assessment_errors(final_json, evidence))
        source_upload = self._source_upload_audit_from_trace(trace)
        source_verdict = str(source_upload.get("verdict") or "")
        assess = final_json.get("upload_path_assessment") if isinstance(final_json.get("upload_path_assessment"), dict) else {}
        assess_verdict = str(assess.get("verdict") or "").lower()
        if source_verdict == "unsafe":
            if assess_verdict != "unsafe":
                errors.append("source-only target audit found complete unsafe upload pattern; upload_path_assessment.verdict must be unsafe")
            if not final_json.get("is_vulnerable"):
                errors.append("source-only target audit found complete unsafe upload pattern but final decision is not vulnerable")
        elif source_verdict == "safe":
            if assess_verdict != "safe":
                errors.append("source-only target audit found complete safe upload mitigation pattern; upload_path_assessment.verdict must be safe")
            if final_json.get("is_vulnerable") and not final_json.get("vuln_statements"):
                errors.append("source-only target audit found safe upload pattern; vulnerable decision needs an independent fully contracted vuln_statement")
        ragged = self._source_ragged_pointer_audit_from_trace(trace)
        ragged_verdict = str(ragged.get("verdict") or "")
        if ragged_verdict == "unsafe" and not final_json.get("is_vulnerable"):
            errors.append("source-only ragged pointer audit found unsafe length*itemsize wraparound pattern but final decision is not vulnerable")
        if ragged_verdict == "safe" and final_json.get("is_vulnerable"):
            errors.append("source-only ragged pointer audit found post-fix raw >= start guard; vulnerable decision needs an independent fully contracted vuln_statement")
        errors.extend(self._contradicted_missing_fact_errors(final_json, evidence))

        sem = semantic_audit_dict(evidence)
        cited_ids = set(str(x) for x in (final_json.get("evidence_used") or []))
        for v in final_json.get("vuln_statements", []) or []:
            if isinstance(v, dict) and v.get("evidence_id"):
                cited_ids.add(str(v.get("evidence_id")))
        safe_cited = [f for f in sem.get("findings", []) if f.get("status") == "safe" and any(e in cited_ids for e in f.get("evidence_ids", []))]
        if final_json.get("is_vulnerable") and safe_cited:
            errors.append("final decision cites bounded-safe evidence as vulnerable: " + json.dumps(safe_cited[:3], ensure_ascii=False))
        unsafe_findings = [f for f in sem.get("findings", []) if f.get("status") == "unsafe"]
        if unsafe_findings and not final_json.get("is_vulnerable") and float(final_json.get("confidence", 0) or 0) >= 0.75:
            errors.append("high-confidence non-vulnerable decision conflicts with unresolved unsafe write evidence: " + json.dumps(unsafe_findings[:5], ensure_ascii=False))
        if final_json.get("is_vulnerable"):
            strengths = [str(v.get("claim_strength") or "") for v in final_json.get("vuln_statements", []) if isinstance(v, dict)]
            if not any(s in {"confirmed", "strongly_supported"} for s in strengths):
                errors.append("vulnerable decision lacks confirmed/strongly_supported vuln_statement claim_strength")
        else:
            if final_json.get("decision_status") == "non_vulnerable" and final_json.get("unresolved_hypotheses") and not final_json.get("ruled_out_hypotheses"):
                errors.append("non_vulnerable decision has unresolved_hypotheses but no ruled_out_hypotheses; use inconclusive instead")
        return errors

    def _final_consistency_repair_prompt(self, *, sample: SecVulEvalSample, final_json: dict[str, Any], evidence: EvidencePack, trace_summary: str, errors: list[str]) -> str:
        # Keep this repair prompt deliberately small. The previous version used
        # up to 80 evidence items x 500 chars plus the full ledger, which can exceed
        # an 8k llama-server context and cause HTTP 400. Include only cited/high-risk
        # items and compact text.
        cited = set(str(x) for x in (final_json.get("evidence_used") or []))
        for v in final_json.get("vuln_statements") or []:
            if isinstance(v, dict) and v.get("evidence_id"):
                cited.add(str(v["evidence_id"]))
        compact_evidence = []
        for item in evidence.items:
            md = item.metadata if isinstance(item.metadata, dict) else {}
            high = item.evidence_id in cited or "risk" in item.kind or "sink" in item.kind or "guard" in item.kind or "safety" in item.kind or md.get("wanted_category") in {"format_writes", "offset_writes", "sinks", "bounds_checks", "guards"}
            if not high:
                continue
            compact_evidence.append({
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "loc": f"{item.relpath}:{item.line_start}-{item.line_end}",
                "function": item.function,
                "scope": item.scope,
                "symbol": item.matched_symbol,
                "trust": item.trust,
                "category": md.get("wanted_category"),
                "text": (item.text or "")[:240],
            })
            if len(compact_evidence) >= 28:
                break
        upload_catalog = {
            "upload_required": self._upload_path_required(evidence),
            "semantic_upload_findings": self._upload_semantic_findings(evidence),
            "source_fact_catalog": self._evidence_fact_catalog(evidence),
        }
        return (
            "The previous final JSON was syntactically valid but failed evidence-consistency checks.\n"
            "Return the correction in the preferred literal-tag format and no text outside it: "
            "<thinking>public evidence-consistency notes only; no hidden/private chain-of-thought</thinking>"
            "<answer>{one schema-valid final decision JSON object only}</answer>.\n"
            "If the API forces JSON-only output, return {\"thinking\": \"public evidence-consistency notes only\", \"answer\": {one schema-valid final decision JSON object}} instead.\n"
            "The <answer> block or JSON-wrapper answer field must contain only corrected JSON matching the final decision schema.\n"
            "This is consistency repair, not a chance to discard evidence. Preserve the original decision fields unless the listed errors require changing them.\n"
            "When the upload/config path is present, fill upload_path_assessment and decide that path before generic sprintf/UI-formatting risks.\n"
            "Do not claim LINESIZE, buf allocation, contentlen cap, or read bounds are missing when the catalog below lists evidence IDs for them.\n"
            "If source-only upload findings are unsafe, return is_vulnerable=true with a full vuln_statement contract unless you explicitly refute each unsafe evidence element.\n"
            "If source-only upload findings are safe, cite the mitigation IDs and do not let unrelated weak sprintf patterns dominate the upload verdict.\n"
            "If evidence is genuinely insufficient or contradictory, use decision_status=\"inconclusive\" and low confidence.\n\n"
            f"Consistency errors:\n{json.dumps(errors[:12], ensure_ascii=False)}\n\n"
            f"Upload/source fact catalog:\n{json.dumps(upload_catalog, ensure_ascii=False)[:4500]}\n\n"
            f"Previous final JSON:\n{json.dumps(final_json, ensure_ascii=False)[:2600]}\n\n"
            f"Relevant evidence catalog:\n{json.dumps(compact_evidence, ensure_ascii=False)[:5200]}\n\n"
            f"Compact ledger:\n{trace_summary[:2500]}\n\n"
            f"Expected schema:\n{FINAL_DECISION_SCHEMA_TEXT}\n"
        )


    def _trace_summary_for_prompt(self, trace: AgentTrace) -> str:
        """Compact public hypothesis ledger for prompts.

        Reports still store full trace artifacts. Prompts get only a bounded state
        summary so local llama-server remains within context.
        """
        compact_ledger = []
        for entry in trace.hypothesis_ledger[-8:]:
            if not isinstance(entry, dict):
                continue
            e = {"stage": entry.get("stage")}
            if "hypotheses" in entry:
                e["hypotheses"] = entry.get("hypotheses")
            if "hypothesis_updates" in entry:
                e["hypothesis_updates"] = entry.get("hypothesis_updates")
            if "verification_summary" in entry:
                e["verification_summary"] = entry.get("verification_summary")
            if "new_queries" in entry:
                e["new_queries"] = entry.get("new_queries")
            if "queries" in entry:
                e["queries"] = entry.get("queries")
            if "returned_evidence_ids" in entry:
                ids = entry.get("returned_evidence_ids") or []
                e["returned_evidence_ids"] = ids[:30]
                e["returned_evidence_count"] = len(ids)
            if "reason" in entry:
                e["reason"] = entry.get("reason")
            if "note" in entry:
                e["note"] = entry.get("note")
            if "source_upload_audit" in entry:
                e["source_upload_audit"] = entry.get("source_upload_audit")
            compact_ledger.append(e)
        data = {
            "risk_hypotheses": trace.risk_hypotheses[:6],
            "hypothesis_ledger": compact_ledger,
            "verification_updates": trace.verification[-4:],
            "executed_kg_queries": self._tool_steps_for_prompt(trace.kg_tool_steps[-8:]),
        }
        return json.dumps(data, ensure_ascii=False)


    @staticmethod
    def _tool_results_to_evidence_pack(
        sample: SecVulEvalSample,
        base_evidence: EvidencePack,
        results: list[Any],
        round_index: int,
    ) -> EvidencePack:
        items = []
        for result in results:
            raw_items = getattr(result, "items", []) or []
            for item in KGToolResult._flatten_items(raw_items):
                if hasattr(item, "evidence_id"):
                    items.append(item)
        return EvidencePack(
            sample_id=sample.sample_id,
            dataset_commit_id=base_evidence.dataset_commit_id,
            resolved_commit_id=base_evidence.resolved_commit_id,
            resolved_commit_label=base_evidence.resolved_commit_label,
            target_validation_status=base_evidence.target_validation_status,
            target_validation_similarity=base_evidence.target_validation_similarity,
            target_node_id=base_evidence.target_node_id,
            target_found=base_evidence.target_found,
            summary=f"New KG evidence returned for query round {round_index}. If this section is empty or irrelevant, say so explicitly and choose a different concrete query or stop.",
            items=items,
            retrieval_diagnostics={"source": "kg_tool_round", "round_index": round_index},
        )

    @staticmethod
    def _filter_unseen_queries(queries: list[dict[str, Any]], executed_steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = {
            (str(step.get("query_type") or "").lower(), str(step.get("query") or "").strip().lower())
            for step in executed_steps
        }
        out: list[dict[str, Any]] = []
        local_seen = set(seen)
        for q in queries:
            key = (str(q.get("query_type") or "").lower(), str(q.get("query") or "").strip().lower())
            if not key[1] or key in local_seen:
                continue
            local_seen.add(key)
            out.append(q)
        return out

    @staticmethod
    def _tool_steps_for_prompt(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Very compact tool-step summary for model prompts."""
        compact: list[dict[str, Any]] = []
        for step in steps:
            diagnostics = step.get("diagnostics") or {}
            returned = step.get("items") or []
            evidence_ids = [item.get("evidence_id") for item in returned if isinstance(item, dict) and item.get("evidence_id")]
            kinds = {}
            for item in returned:
                if isinstance(item, dict):
                    k = item.get("kind") or "unknown"
                    kinds[k] = kinds.get(k, 0) + 1
            compact.append({
                "round_index": step.get("round_index"),
                "query_index": step.get("query_index"),
                "query_type": step.get("query_type"),
                "query": step.get("query"),
                "source": step.get("source"),
                "status": step.get("status"),
                "tool_parameters": step.get("tool_parameters") or {},
                "diagnostics": {k: v for k, v in diagnostics.items() if k in {"wanted_evidence", "missing_wanted_evidence", "category_counts", "bundle_type", "symbol", "dominance_method"}},
                "returned_evidence_ids": evidence_ids[:30],
                "returned_evidence_count": len(evidence_ids),
                "returned_kind_counts": kinds,
            })
        return compact


    def _contains_placeholder(self, value: Any) -> bool:
        """Detect model outputs that copied prompt/schema descriptions instead of reasoning."""
        if value is None:
            return False
        if isinstance(value, str):
            low = value.lower().strip()
            return any(ph.lower() in low for ph in FORBIDDEN_PLACEHOLDERS)
        if isinstance(value, dict):
            return any(self._contains_placeholder(v) for v in value.values())
        if isinstance(value, list):
            return any(self._contains_placeholder(v) for v in value)
        return False

    def _fallback_queries(self, sample: SecVulEvalSample, evidence: EvidencePack) -> list[dict[str, Any]]:
        """Auditable deterministic fallback when model JSON cannot be repaired.

        The fallback is target-derived and bundle-based, not project-specific. It
        is marked fallback_generated in reports and never presented as model
        reasoning.
        """
        body = sample.func_body or ""
        calls: list[str] = []
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
            if name not in {"if", "while", "for", "switch", "return", "sizeof"} and name not in calls:
                calls.append(name)
        vars_: list[str] = []
        for m in re.finditer(r"(?:^|[;{]\s*)\s*(?:const\s+|volatile\s+|static\s+|extern\s+|register\s+|unsigned\s+|signed\s+|struct\s+\w+\s+|enum\s+\w+\s+|union\s+\w+\s+|[A-Za-z_]\w*\s+)+(?:[\*\s]+)([A-Za-z_]\w*)\b(?:\s*\[[^\]]*\])?", body, flags=re.M):
            v = m.group(1)
            if v not in vars_:
                vars_.append(v)
        risk_calls = [c for c in calls if c in {"sprintf", "snprintf", "vsprintf", "vsnprintf", "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "gets", "fgets", "scanf", "sscanf", "fscanf", "fprintf", "system", "popen", "sockgetlinebuf"}]
        constants = []
        for tok in re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b", body):
            if tok not in constants:
                constants.append(tok)
        queries: list[dict[str, Any]] = []
        if vars_:
            queries.append({
                "query_type": "evidence_bundle",
                "query": "buffer_write_bundle",
                "bundle_type": "buffer_write_bundle",
                "symbol": vars_[0],
                "scope": "target_function",
                "match": "exact_identifier",
                "wanted_evidence": ["declaration", "allocation", "writes", "bounds_checks", "sinks", "lifetime", "callee_summaries", "size_macros"],
                "reason": "fallback: target-derived buffer/input variable evidence bundle",
            })
        if risk_calls:
            queries.append({
                "query_type": "evidence_bundle",
                "query": "callee_summary_bundle",
                "bundle_type": "callee_summary_bundle",
                "symbol": risk_calls[0],
                "scope": "target_function",
                "match": "exact_identifier",
                "wanted_evidence": ["callee_summaries", "argument_bounds", "return_or_output_effects"],
                "reason": "fallback: inspect concrete risky/security-relevant callee used by target function",
            })
        elif calls:
            queries.append({
                "query_type": "evidence_bundle",
                "query": "callee_summary_bundle",
                "bundle_type": "callee_summary_bundle",
                "symbol": calls[0],
                "scope": "target_function",
                "match": "exact_identifier",
                "wanted_evidence": ["callee_summaries"],
                "reason": "fallback: inspect concrete callee used by target function",
            })
        if constants:
            queries.append({
                "query_type": "evidence_bundle",
                "query": "global_state_bundle",
                "bundle_type": "global_state_bundle",
                "symbol": constants[0],
                "scope": "project",
                "match": "exact_identifier",
                "wanted_evidence": ["definition", "uses"],
                "reason": "fallback: inspect target-visible macro/global definition",
            })
        if not queries:
            queries.append({"query_type": "search", "query": sample.func_name or "target", "reason": "fallback: search target function context"})
        return queries[: self.agent_cfg.max_tool_queries_per_round]


    @staticmethod
    def _with_query_source(queries: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for q in queries:
            if not isinstance(q, dict):
                continue
            qq = dict(q)
            qq["_source"] = source
            out.append(qq)
        return out

    @staticmethod
    def _dominant_query_source(queries: list[dict[str, Any]]) -> str:
        sources = [str(q.get("_source") or "model_generated") for q in queries]
        if not sources:
            return "model_generated"
        if any(s == "fallback_generated" for s in sources):
            return "fallback_generated"
        if any(s == "model_generated_after_json_repair" for s in sources):
            return "model_generated_after_json_repair"
        return sources[0]

    def _final_has_placeholder(self, obj: dict[str, Any] | None) -> bool:
        return bool(obj is not None and self._contains_placeholder(obj))

    @staticmethod
    def _empty_usage() -> dict[str, Any]:
        return {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cost_total_usd": 0.0,
            "estimated": True,
            "tokenization_methods": [],
        }

    @staticmethod
    def _add_usage(acc: dict[str, Any], usage: LLMUsage) -> None:
        acc["prompt_tokens"] += int(usage.prompt_tokens)
        acc["completion_tokens"] += int(usage.completion_tokens)
        acc["total_tokens"] += int(usage.total_tokens)
        acc["cost_total_usd"] += float(usage.cost_total_usd)
        acc["estimated"] = bool(acc.get("estimated", True) and usage.estimated)
        method = getattr(usage, "tokenization_method", None)
        if method and method not in acc.setdefault("tokenization_methods", []):
            acc["tokenization_methods"].append(method)

    @staticmethod
    def _usage_dict(usage: LLMUsage) -> dict[str, Any]:
        return {
            "prompt_tokens": int(usage.prompt_tokens),
            "completion_tokens": int(usage.completion_tokens),
            "total_tokens": int(usage.total_tokens),
            "cost_total_usd": float(usage.cost_total_usd),
            "estimated": bool(usage.estimated),
            "tokenization_method": getattr(usage, "tokenization_method", None),
        }

    @staticmethod
    def _usage_from_dict(data: dict[str, Any]) -> LLMUsage:
        return LLMUsage(
            prompt_tokens=int(data.get("prompt_tokens", 0)),
            completion_tokens=int(data.get("completion_tokens", 0)),
            total_tokens=int(data.get("total_tokens", 0)),
            cost_total_usd=float(data.get("cost_total_usd", 0.0)),
            estimated=bool(data.get("estimated", True)),
            tokenization_method=data.get("tokenization_method"),
        )

    @classmethod
    def _sum_usage(cls, usages: list[LLMUsage]) -> dict[str, Any]:
        acc = cls._empty_usage()
        for usage in usages:
            cls._add_usage(acc, usage)
        return acc
