from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel
from .parser import parse_model_object
from .prompts import (counter_evidence_prompt, counter_gap_analysis_prompt,
                      evidence_gap_analysis_prompt, final_decision_prompt,
                      hypothesis_verification_prompt, kg_query_planning_prompt,
                      source_only_hypothesis_prompt, consistency_repair_prompt)
from .schemas import (CounterEvidenceReview, EvidenceGapPlan, FinalDecision,
                      FinalPrediction, HypothesisStatus, KGQuery, KGQueryPlan,
                      VulnerabilityHypothesis)
from .validator import validate_final_decision


def _make_emergency_fallback_decision(error_msg: str) -> FinalDecision:
    """Return a minimal FinalDecision that marks the sample as failed_parse.

    Used when Stage 06 JSON cannot be parsed or validated. Excluded from binary
    metrics by _is_valid_binary_prediction() via decision_status='failed_parse'.
    """
    return FinalDecision(
        prediction=FinalPrediction.fixed_or_non_vulnerable,
        confidence=0.0,
        local_risk_present=False,
        confirmed_security_vulnerability=False,
        explanation="Stage 06 final adjudication could not be parsed or validated.",
        limitations=[],
        forced_prediction="fixed/non-vulnerable",
        forced_prediction_bool=False,
        decision_status="failed_parse",
        evidence_strength="insufficient_static_evidence",
        evidence_exhausted=True,
        why_forced_binary=f"Emergency fallback: parse/validate failed. {error_msg}",
    )


_RESOLVED_STATUSES = {
    HypothesisStatus.confirmed_vulnerability.value,
    HypothesisStatus.refuted_by_guard.value,
    HypothesisStatus.refuted_by_caller_constraint.value,
    HypothesisStatus.refuted_by_patch_or_changed_logic.value,
    HypothesisStatus.irrelevant_to_target_function.value,
}


def _norm_query(text: str) -> str:
    """Normalize a query text for deduplication (case-insensitive, whitespace-collapsed)."""
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _all_hypotheses_resolved(verifications: Dict[str, Any]) -> bool:
    items = verifications.get("verifications") or []
    if not items:
        return False
    return all(v.get("status") in _RESOLVED_STATUSES for v in items)


def _gap_plan_has_queryable_high_value_gaps(gap_plan: EvidenceGapPlan) -> bool:
    """Return True when the LLM says stop but its own structured gaps are queryable.

    This protects the controller from a common contradiction: the model sets
    needs_more_evidence=false while still listing high/medium-priority queryable
    gaps and concrete follow-up queries. In that situation the controller should
    continue bounded retrieval instead of silently ending the proof loop.
    """
    priorities = {"high", "medium"}
    return any(
        bool(getattr(g, "queryable", False))
        and str(getattr(g, "priority", "medium") or "medium").lower() in priorities
        for g in (gap_plan.gaps or [])
    )


def _effective_follow_up_queries(gap_plan: EvidenceGapPlan) -> List[KGQuery]:
    """Return follow-up queries only when the plan contains actionable gaps.

    The CodeKG executor is deterministic and bounded; executing a small number of
    non-duplicate queries is safer than stopping with unresolved proof elements.
    """
    if not gap_plan.follow_up_queries:
        return []
    if gap_plan.needs_more_evidence or _gap_plan_has_queryable_high_value_gaps(gap_plan):
        return list(gap_plan.follow_up_queries)
    return []


def _plan_effective_needs_more_evidence(gap_plan: EvidenceGapPlan) -> bool:
    return bool(gap_plan.needs_more_evidence or _effective_follow_up_queries(gap_plan))


@dataclass
class AgenticProofConfig:
    max_hypotheses: int = 12
    max_queries_per_hypothesis: int = 6
    evidence_limit_per_query: int = 8
    # Per-stage token budgets
    max_tokens_source_only_hypothesis: int = 16384
    max_tokens_kg_query_planning: int = 8192
    max_tokens_hypothesis_verification: int = 16384
    max_tokens_counter_evidence_review: int = 16384
    max_tokens_final_decision: int = 8192
    max_tokens_schema_repair: int = 8192
    max_tokens_evidence_gap_analysis: int = 8192
    # Iterative evidence loop controls
    iterative_evidence_loop: bool = False
    max_evidence_iterations: int = 3
    max_queries_per_iteration: int = 5
    stop_when_no_new_evidence: bool = True
    stop_when_no_new_queries: bool = True
    stop_when_all_hypotheses_resolved: bool = True
    enable_counter_evidence_loop: bool = False
    max_counter_iterations: int = 2
    # Other
    temperature: float = 0.0
    provider_extra_body: Dict[str, Any] = field(
        default_factory=lambda: {"chat_template_kwargs": {"enable_thinking": False}}
    )
    enable_pair_aware_dev_mode: bool = False


@dataclass
class AgentEvent:
    sample_id: Any
    stage: str
    event: str
    elapsed_seconds: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LegacyPrediction:
    prediction_bool: Optional[bool]
    prediction_label: str
    confidence: float
    final_json: Dict[str, Any]
    events: List[Dict[str, Any]]
    usage: Dict[str, Any]


@dataclass
class AgenticProofResult:
    decision: FinalDecision
    hypotheses: Dict[str, Any]
    query_plan: KGQueryPlan
    retrieved_evidence: List[Dict[str, Any]]
    verifications: Dict[str, Any]
    counter_review: CounterEvidenceReview
    events: List[AgentEvent]
    usage: Dict[str, Any]
    # Iterative loop metadata
    loop_stop_reason: Optional[str] = None
    iterations_completed: int = 0

    def to_legacy_prediction(self) -> LegacyPrediction:
        return LegacyPrediction(
            self.decision.prediction_bool,
            self.decision.prediction.value,
            self.decision.confidence,
            self.decision.model_dump(mode="json"),
            [e.__dict__ for e in self.events],
            self.usage,
        )


def _message_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        if isinstance(response.get("content"), str):
            return response["content"]
        choices = response.get("choices")
        if choices:
            msg = choices[0].get("message", {})
            if msg.get("content"):
                return msg["content"]
            if msg.get("reasoning"):
                return str(msg["reasoning"])
        if "text" in response:
            return str(response["text"])
    content = getattr(response, "content", None)
    if content:
        return content
    return str(response)


def _usage(response: Any) -> Dict[str, Any]:
    return response.get("usage", {}) if isinstance(response, dict) else (getattr(response, "usage", {}) or {})


def _merge_usage(total: Dict[str, Any], usage: Dict[str, Any]) -> None:
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        v = usage.get(k)
        if isinstance(v, (int, float)):
            total[k] = total.get(k, 0) + v


def _call_llm(
    *,
    llm_generate: Callable[..., Any],
    messages: List[Dict[str, Any]],
    sample_id: Any,
    stage: str,
    max_tokens: int,
    config: AgenticProofConfig,
    events: List[AgentEvent],
) -> tuple[str, Dict[str, Any]]:
    start = time.monotonic()
    # Prompt builders should produce OpenAI-style messages with string content.
    # A malformed prompt string can accidentally evaluate to a boolean in Python
    # (for example, an unescaped `"in"` inside a concatenated string expression).
    # Normalize here so optional loop stages cannot crash before the failure is
    # recorded, while preserving a warning event for diagnosis.
    normalized_messages: List[Dict[str, Any]] = []
    coerced_fields: List[Dict[str, Any]] = []
    for idx, msg in enumerate(messages or []):
        content = msg.get("content", "")
        if content is None:
            content_text = ""
            coerced_fields.append({"index": idx, "from_type": "NoneType"})
        elif isinstance(content, str):
            content_text = content
        else:
            content_text = str(content)
            coerced_fields.append({"index": idx, "from_type": type(content).__name__})
        copied = dict(msg)
        copied["content"] = content_text
        normalized_messages.append(copied)

    prompt_chars = sum(len(m.get("content", "")) for m in normalized_messages)
    if coerced_fields:
        events.append(AgentEvent(sample_id, stage, "prompt_content_coerced",
                                  details={"coerced_fields": coerced_fields}))
    events.append(AgentEvent(sample_id, stage, "start",
                              details={"prompt_chars": prompt_chars, "max_tokens": max_tokens}))
    try:
        response = llm_generate(
            normalized_messages,
            stage=stage,
            max_tokens=max_tokens,
            temperature=config.temperature,
            extra_body=config.provider_extra_body,
        )
    except Exception as exc:
        elapsed = time.monotonic() - start
        events.append(AgentEvent(sample_id, stage, "error", elapsed_seconds=elapsed,
                                  details={"prompt_chars": prompt_chars,
                                           "error": f"{type(exc).__name__}: {exc}"}))
        raise
    elapsed = time.monotonic() - start
    text = _message_text(response)
    usage = _usage(response)
    events.append(AgentEvent(sample_id, stage, "done", elapsed_seconds=elapsed,
                              details={"response_chars": len(text or ""), "usage": usage,
                                       "enable_thinking": config.provider_extra_body.get(
                                           "chat_template_kwargs", {}).get("enable_thinking")}))
    return text, usage


_BINARY_DECISION_STATUSES = frozenset({
    "confirmed_vulnerable", "confirmed_non_vulnerable",
    "forced_binary_vulnerable", "forced_binary_non_vulnerable",
})


def _decision_has_valid_binary(decision: "FinalDecision") -> bool:
    """Return True when the validator has already produced a definitive binary decision.

    When True, Stage 07 consistency repair is unnecessary — the forced binary choice
    (forced_prediction_bool) is already set deterministically.
    """
    return (
        decision.forced_prediction_bool is not None
        and decision.decision_status in _BINARY_DECISION_STATUSES
    )


def _repair_llm(
    llm_generate: Callable[..., Any],
    config: AgenticProofConfig,
    sample_id: Any,
    events: List[AgentEvent],
    stage: str,
) -> Callable[[List[Dict[str, str]]], str]:
    def repair(messages: List[Dict[str, str]]) -> str:
        text, _ = _call_llm(
            llm_generate=llm_generate,
            messages=messages,
            sample_id=sample_id,
            stage=f"{stage}_json_repair",
            max_tokens=config.max_tokens_schema_repair,
            config=config,
            events=events,
        )
        return text
    return repair


class _HypothesisEnvelope(BaseModel):
    hypotheses: List[VulnerabilityHypothesis]
    source_observations: list[str] = []
    non_vulnerability_possibilities: list[str] = []


class _VerificationEnvelope(BaseModel):
    verifications: list


def run_agentic_proof_pipeline(
    *,
    sample: Dict[str, Any],
    target_source: str,
    initial_evidence: List[Dict[str, Any]],
    llm_generate: Callable[..., Any],
    kg_search: Callable[..., List[Dict[str, Any]]],
    config: Optional[AgenticProofConfig] = None,
    on_iteration_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> AgenticProofResult:
    """Run the agentic proof pipeline with optional iterative evidence loop.

    on_iteration_event: optional callback(event_type, data) called at iteration
    start/end so callers (pipeline.py) can emit live WS events and write artifacts.
    """
    config = config or AgenticProofConfig()
    sample_id = sample.get("id") or sample.get("sample_id") or "unknown"
    events: List[AgentEvent] = []
    usage_total: Dict[str, Any] = {}

    # ── Stage 01: source-only hypothesis generation ──────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=source_only_hypothesis_prompt(sample, target_source),
        sample_id=sample_id,
        stage="01_source_only_hypothesis",
        max_tokens=config.max_tokens_source_only_hypothesis,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    hypothesis_obj, _ = parse_model_object(
        text, _HypothesisEnvelope,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "01_source_only_hypothesis"),
    )
    hypotheses = hypothesis_obj.model_dump(mode="json")
    hypotheses["hypotheses"] = hypotheses.get("hypotheses", [])[:config.max_hypotheses]

    # ── Stage 02: KG query planning ──────────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=kg_query_planning_prompt(sample, hypotheses["hypotheses"], initial_evidence),
        sample_id=sample_id,
        stage="02_kg_query_planning",
        max_tokens=config.max_tokens_kg_query_planning,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    query_plan, _ = parse_model_object(
        text, KGQueryPlan,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "02_kg_query_planning"),
    )
    query_dicts = [q.model_dump(mode="json") for q in query_plan.queries]

    # ── Stage 03: Initial KG retrieval ───────────────────────────────────────
    events.append(AgentEvent(sample_id, "03_initial_retrieval", "start",
                              details={"queries": len(query_dicts)}))
    retrieved = kg_search(query_dicts, sample=sample, limit=config.evidence_limit_per_query)
    events.append(AgentEvent(sample_id, "03_initial_retrieval", "done",
                              details={"items": len(retrieved)}))

    accumulated_evidence = list(initial_evidence) + list(retrieved)
    # Track which query IDs and normalized query texts have been executed to
    # prevent re-running duplicates (by id OR by identical text with a new id).
    executed_query_ids: set[str] = {q.get("query_id", "") for q in query_dicts}
    executed_query_texts: set[str] = {_norm_query(q.get("query_text", "")) for q in query_dicts}

    # ── Stages 04 + iterative evidence loop ──────────────────────────────────
    verifications: Dict[str, Any] = {}
    loop_stop_reason: Optional[str] = None
    iterations_completed: int = 0

    for iteration in range(config.max_evidence_iterations + 1):
        stage_suffix = "" if iteration == 0 else f"_iter{iteration}"
        verif_stage = f"04_hypothesis_verification{stage_suffix}"

        text, usage = _call_llm(
            llm_generate=llm_generate,
            messages=hypothesis_verification_prompt(
                sample, hypotheses["hypotheses"], accumulated_evidence
            ),
            sample_id=sample_id,
            stage=verif_stage,
            max_tokens=config.max_tokens_hypothesis_verification,
            config=config,
            events=events,
        )
        _merge_usage(usage_total, usage)
        verifications_obj, _ = parse_model_object(
            text, _VerificationEnvelope,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, verif_stage),
        )
        verifications = verifications_obj.model_dump(mode="json")

        # ── Stopping checks ──────────────────────────────────────────────────
        if not config.iterative_evidence_loop:
            loop_stop_reason = "loop_disabled"
            break

        if iteration >= config.max_evidence_iterations:
            loop_stop_reason = "max_iterations_reached"
            break

        if (config.stop_when_all_hypotheses_resolved
                and _all_hypotheses_resolved(verifications)):
            loop_stop_reason = "all_hypotheses_resolved"
            break

        # ── Stage 04_evidence_gap_iter{N}: gap analysis ───────────────────
        gap_stage = f"04_evidence_gap_iter{iteration + 1}"

        if on_iteration_event:
            on_iteration_event("evidence_iteration_started", {
                "sample_id": sample_id, "phase": "verification",
                "iteration": iteration + 1, "accumulated_evidence_count": len(accumulated_evidence),
            })

        # Gap analysis is an optional loop stage: a ReadTimeout here should
        # stop the evidence loop gracefully rather than failing the whole sample.
        try:
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=evidence_gap_analysis_prompt(
                    sample,
                    verifications.get("verifications") or [],
                    accumulated_evidence,
                    list(executed_query_ids),
                    iteration=iteration + 1,
                ),
                sample_id=sample_id,
                stage=gap_stage,
                max_tokens=config.max_tokens_evidence_gap_analysis,
                config=config,
                events=events,
            )
        except Exception as _gap_exc:
            if "Timeout" not in type(_gap_exc).__name__:
                raise
            loop_stop_reason = "llm_timeout_gap_analysis"
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "llm_timeout_gap_analysis",
                })
            break
        _merge_usage(usage_total, usage)
        gap_plan, _ = parse_model_object(
            text, EvidenceGapPlan,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, gap_stage),
        )

        # ── Stopping checks on gap plan ───────────────────────────────────
        # Do not blindly trust needs_more_evidence=false when the same response
        # contains queryable gaps and concrete follow-up queries. That exact
        # contradiction was responsible for premature loop termination on
        # pointer-overflow cases where caller/input-source evidence was still
        # missing.
        effective_gap_queries = _effective_follow_up_queries(gap_plan)
        if not _plan_effective_needs_more_evidence(gap_plan):
            _stop = (gap_plan.stop_reason_if_no_queries
                     or gap_plan.stop_reason
                     or "no_more_evidence_needed")
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": _stop,
                })
            loop_stop_reason = _stop
            break

        if not effective_gap_queries and config.stop_when_no_new_queries:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "no_new_queries_proposed",
                })
            loop_stop_reason = "no_new_queries_proposed"
            break

        # Deduplicate by query_id AND by normalized query_text (LLM may reuse
        # identical text with a fresh id to bypass id-only dedup).
        new_queries = [
            q for q in effective_gap_queries[:config.max_queries_per_iteration]
            if q.query_id not in executed_query_ids
            and _norm_query(q.query_text) not in executed_query_texts
        ]
        if not new_queries and config.stop_when_no_new_queries:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "all_queries_duplicate",
                })
            loop_stop_reason = "all_queries_duplicate"
            break

        # ── Follow-up KG retrieval ────────────────────────────────────────
        retrieval_stage = f"03_followup_retrieval_iter{iteration + 1}"
        followup_dicts = [q.model_dump(mode="json") for q in new_queries]
        events.append(AgentEvent(sample_id, retrieval_stage, "start",
                                  details={"queries": len(followup_dicts)}))
        new_evidence = kg_search(followup_dicts, sample=sample, limit=config.evidence_limit_per_query)
        events.append(AgentEvent(sample_id, retrieval_stage, "done",
                                  details={"items": len(new_evidence)}))

        if not new_evidence and config.stop_when_no_new_evidence:
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "verification",
                    "iteration": iteration + 1, "new_evidence_count": 0,
                    "stop_reason": "no_new_evidence_returned",
                })
            loop_stop_reason = "no_new_evidence_returned"
            break

        accumulated_evidence.extend(new_evidence)
        executed_query_ids.update(q.query_id for q in new_queries)
        executed_query_texts.update(_norm_query(q.query_text) for q in new_queries)
        iterations_completed = iteration + 1

        if on_iteration_event:
            on_iteration_event("evidence_iteration_completed", {
                "sample_id": sample_id, "phase": "verification",
                "iteration": iteration + 1, "new_evidence_count": len(new_evidence),
                "stop_reason": None,
            })

    # ── Stage 05: Counter-evidence review ────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=counter_evidence_prompt(
            sample, verifications.get("verifications") or [], accumulated_evidence
        ),
        sample_id=sample_id,
        stage="05_counter_evidence_review",
        max_tokens=config.max_tokens_counter_evidence_review,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    counter_review, _ = parse_model_object(
        text, CounterEvidenceReview,
        llm_repair=_repair_llm(llm_generate, config, sample_id, events, "05_counter_evidence_review"),
    )

    # ── Optional counter-evidence iterative loop ──────────────────────────────
    if config.enable_counter_evidence_loop:
        counter_executed_ids = set(executed_query_ids)
        counter_executed_texts = set(executed_query_texts)
        for c_iter in range(1, config.max_counter_iterations + 1):
            if on_iteration_event:
                on_iteration_event("evidence_iteration_started", {
                    "sample_id": sample_id, "phase": "counter",
                    "iteration": c_iter, "accumulated_evidence_count": len(accumulated_evidence),
                })
            c_gap_stage = f"05_counter_gap_iter{c_iter}"
            # Counter-gap analysis is also optional; timeout stops the loop.
            try:
                text, usage = _call_llm(
                    llm_generate=llm_generate,
                    messages=counter_gap_analysis_prompt(
                        sample,
                        counter_review.model_dump(mode="json").get("findings") or [],
                        accumulated_evidence,
                        list(counter_executed_ids),
                        iteration=c_iter,
                    ),
                    sample_id=sample_id,
                    stage=c_gap_stage,
                    max_tokens=config.max_tokens_evidence_gap_analysis,
                    config=config,
                    events=events,
                )
            except Exception as _cgap_exc:
                if "Timeout" not in type(_cgap_exc).__name__:
                    raise
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "llm_timeout_counter_gap_analysis",
                    })
                break
            _merge_usage(usage_total, usage)
            c_gap, _ = parse_model_object(
                text, EvidenceGapPlan,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, c_gap_stage),
            )
            c_effective_queries = _effective_follow_up_queries(c_gap)
            if not _plan_effective_needs_more_evidence(c_gap) or not c_effective_queries:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "no_more_counter_queries",
                    })
                break
            c_new_queries = [
                q for q in c_effective_queries[:config.max_queries_per_iteration]
                if q.query_id not in counter_executed_ids
                and _norm_query(q.query_text) not in counter_executed_texts
            ]
            if not c_new_queries:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "all_counter_queries_duplicate",
                    })
                break
            c_ret_stage = f"03_counter_retrieval_iter{c_iter}"
            c_followup_dicts = [q.model_dump(mode="json") for q in c_new_queries]
            events.append(AgentEvent(sample_id, c_ret_stage, "start",
                                      details={"queries": len(c_followup_dicts)}))
            c_new_evidence = kg_search(c_followup_dicts, sample=sample, limit=config.evidence_limit_per_query)
            events.append(AgentEvent(sample_id, c_ret_stage, "done",
                                      details={"items": len(c_new_evidence)}))
            if not c_new_evidence:
                if on_iteration_event:
                    on_iteration_event("evidence_iteration_completed", {
                        "sample_id": sample_id, "phase": "counter",
                        "iteration": c_iter, "new_evidence_count": 0,
                        "stop_reason": "no_new_counter_evidence",
                    })
                break
            accumulated_evidence.extend(c_new_evidence)
            counter_executed_ids.update(q.query_id for q in c_new_queries)
            counter_executed_texts.update(_norm_query(q.query_text) for q in c_new_queries)
            # Re-run counter review with expanded evidence
            c_rev_stage = f"05_counter_evidence_review_iter{c_iter}"
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=counter_evidence_prompt(
                    sample, verifications.get("verifications") or [], accumulated_evidence
                ),
                sample_id=sample_id,
                stage=c_rev_stage,
                max_tokens=config.max_tokens_counter_evidence_review,
                config=config,
                events=events,
            )
            _merge_usage(usage_total, usage)
            counter_review, _ = parse_model_object(
                text, CounterEvidenceReview,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, c_rev_stage),
            )
            if on_iteration_event:
                on_iteration_event("evidence_iteration_completed", {
                    "sample_id": sample_id, "phase": "counter",
                    "iteration": c_iter, "new_evidence_count": len(c_new_evidence),
                    "stop_reason": None,
                })

    # ── Stage 06: Final adjudication ─────────────────────────────────────────
    text, usage = _call_llm(
        llm_generate=llm_generate,
        messages=final_decision_prompt(
            sample,
            verifications.get("verifications") or [],
            counter_review.model_dump(mode="json"),
            accumulated_evidence,
        ),
        sample_id=sample_id,
        stage="06_final_adjudication",
        max_tokens=config.max_tokens_final_decision,
        config=config,
        events=events,
    )
    _merge_usage(usage_total, usage)
    # Wrap parse + validate in a single handler so a schema validation failure or a
    # failed JSON repair does not crash the whole sample.  A failed Stage 06 produces
    # an emergency fallback decision with decision_status='failed_parse' so the
    # sample is excluded from binary metrics rather than raising an unhandled exception.
    notes: List[str] = []
    modified = False
    try:
        decision, _ = parse_model_object(
            text, FinalDecision,
            llm_repair=_repair_llm(llm_generate, config, sample_id, events, "06_final_adjudication"),
        )
        decision, notes, modified = validate_final_decision(
            decision, evidence_items=accumulated_evidence, counter_review=counter_review
        )
        events.append(AgentEvent(sample_id, "06_final_adjudication", "validated", details={
            "validator_notes": list(notes), "modified": bool(modified),
            "prediction": decision.prediction.value, "confidence": decision.confidence,
            "final_decision_source": decision.final_decision_source,
            "normalization_warnings": list(decision.normalization_warnings or []),
        }))
    except Exception as _stage06_exc:
        _err_msg = f"{type(_stage06_exc).__name__}: {_stage06_exc}"
        decision = _make_emergency_fallback_decision(_err_msg)
        notes = [f"stage06_failed: {_err_msg}"]
        events.append(AgentEvent(sample_id, "06_final_adjudication", "parse_failed", details={
            "error_type": type(_stage06_exc).__name__,
            "error_message": str(_stage06_exc),
            "recovery": "emergency_fallback",
            "decision_status": "failed_parse",
        }))

    # ── Stage 07: Schema consistency repair (conditional) ────────────────────
    # Skip repair when the validator has already produced a definitive forced binary
    # decision — repair cannot improve on a deterministically-set forced_prediction_bool.
    if modified and not _decision_has_valid_binary(decision):
        _fallback_decision = decision  # save stage-06 validated decision before attempting repair
        try:
            text, usage = _call_llm(
                llm_generate=llm_generate,
                messages=consistency_repair_prompt(decision.model_dump(mode="json"), notes),
                sample_id=sample_id,
                stage="07_schema_consistency_repair",
                max_tokens=config.max_tokens_schema_repair,
                config=config,
                events=events,
            )
            _merge_usage(usage_total, usage)
            repaired_decision, _ = parse_model_object(
                text, FinalDecision,
                llm_repair=_repair_llm(llm_generate, config, sample_id, events, "07_schema_consistency_repair"),
            )
            decision, notes2, modified2 = validate_final_decision(
                repaired_decision, evidence_items=accumulated_evidence, counter_review=counter_review
            )
            notes.extend(notes2)
            events.append(AgentEvent(sample_id, "07_schema_consistency_repair", "validated", details={
                "validator_notes": list(notes2), "modified": bool(modified2),
                "prediction": decision.prediction.value, "confidence": decision.confidence,
            }))
        except Exception as _repair_exc:
            # Fall back to the validated stage-06 decision rather than crashing the sample.
            decision = _fallback_decision
            events.append(AgentEvent(sample_id, "07_schema_consistency_repair", "fallback", details={
                "error": str(_repair_exc),
                "fallback_reason": "repair_stage_failed_using_stage06_validated_decision",
                "prediction": decision.prediction.value,
                "confidence": decision.confidence,
            }))

    events.append(AgentEvent(sample_id, "agentic_proof", "done", details={
        "prediction": decision.prediction.value, "forced_prediction": decision.forced_prediction,
        "forced_prediction_bool": decision.forced_prediction_bool,
        "decision_status": decision.decision_status, "confidence": decision.confidence,
        "validator_notes": notes, "loop_stop_reason": loop_stop_reason,
        "iterations_completed": iterations_completed,
    }))

    return AgenticProofResult(
        decision=decision,
        hypotheses=hypotheses,
        query_plan=query_plan,
        retrieved_evidence=retrieved,
        verifications=verifications,
        counter_review=counter_review,
        events=events,
        usage=usage_total,
        loop_stop_reason=loop_stop_reason,
        iterations_completed=iterations_completed,
    )
