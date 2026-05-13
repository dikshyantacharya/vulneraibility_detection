from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel
from .parser import parse_model_object
from .prompts import counter_evidence_prompt, final_decision_prompt, hypothesis_verification_prompt, kg_query_planning_prompt, source_only_hypothesis_prompt, consistency_repair_prompt
from .schemas import CounterEvidenceReview, FinalDecision, KGQueryPlan
from .validator import validate_final_decision

@dataclass
class AgenticProofConfig:
    max_hypotheses: int = 12
    max_queries_per_hypothesis: int = 6
    evidence_limit_per_query: int = 8
    max_tokens_source_only_hypothesis: int = 4096
    max_tokens_kg_query_planning: int = 2048
    max_tokens_hypothesis_verification: int = 4096
    max_tokens_counter_evidence_review: int = 4096
    max_tokens_final_decision: int = 4096
    max_tokens_schema_repair: int = 2048
    temperature: float = 0.0
    provider_extra_body: Dict[str, Any] = field(default_factory=lambda: {"chat_template_kwargs": {"enable_thinking": False}})
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
    def to_legacy_prediction(self) -> LegacyPrediction:
        return LegacyPrediction(self.decision.prediction_bool, self.decision.prediction.value, self.decision.confidence, self.decision.model_dump(mode="json"), [e.__dict__ for e in self.events], self.usage)

def _message_text(response: Any) -> str:
    if isinstance(response, str): return response
    if isinstance(response, dict):
        if isinstance(response.get("content"), str): return response["content"]
        choices = response.get("choices")
        if choices:
            msg = choices[0].get("message", {})
            if msg.get("content"): return msg["content"]
            if msg.get("reasoning"): return str(msg["reasoning"])
        if "text" in response: return str(response["text"])
    content = getattr(response, "content", None)
    if content: return content
    return str(response)

def _usage(response: Any) -> Dict[str, Any]:
    return response.get("usage", {}) if isinstance(response, dict) else (getattr(response, "usage", {}) or {})

def _merge_usage(total: Dict[str, Any], usage: Dict[str, Any]) -> None:
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        v = usage.get(k)
        if isinstance(v, (int, float)): total[k] = total.get(k, 0) + v

def _call_llm(*, llm_generate: Callable[..., Any], messages: List[Dict[str, str]], sample_id: Any, stage: str, max_tokens: int, config: AgenticProofConfig, events: List[AgentEvent]) -> tuple[str, Dict[str, Any]]:
    start = time.monotonic(); prompt_chars = sum(len(m.get("content", "")) for m in messages)
    events.append(AgentEvent(sample_id, stage, "start", details={"prompt_chars": prompt_chars, "max_tokens": max_tokens}))
    try:
        response = llm_generate(messages, stage=stage, max_tokens=max_tokens, temperature=config.temperature, extra_body=config.provider_extra_body)
    except Exception as exc:
        elapsed = time.monotonic() - start
        events.append(AgentEvent(sample_id, stage, "error", elapsed_seconds=elapsed, details={"prompt_chars": prompt_chars, "error": f"{type(exc).__name__}: {exc}"}))
        raise
    elapsed = time.monotonic() - start
    text = _message_text(response); usage = _usage(response)
    events.append(AgentEvent(sample_id, stage, "done", elapsed_seconds=elapsed, details={"response_chars": len(text or ""), "usage": usage, "enable_thinking": config.provider_extra_body.get("chat_template_kwargs", {}).get("enable_thinking")}))
    return text, usage

def _repair_llm(llm_generate: Callable[..., Any], config: AgenticProofConfig, sample_id: Any, events: List[AgentEvent], stage: str):
    def repair(messages: List[Dict[str, str]]) -> str:
        text, _ = _call_llm(llm_generate=llm_generate, messages=messages, sample_id=sample_id, stage=f"{stage}_json_repair", max_tokens=config.max_tokens_schema_repair, config=config, events=events)
        return text
    return repair

class _HypothesisEnvelope(BaseModel):
    hypotheses: list
    source_observations: list[str] = []
    non_vulnerability_possibilities: list[str] = []

class _VerificationEnvelope(BaseModel):
    verifications: list

def run_agentic_proof_pipeline(*, sample: Dict[str, Any], target_source: str, initial_evidence: List[Dict[str, Any]], llm_generate: Callable[..., Any], kg_search: Callable[..., List[Dict[str, Any]]], config: Optional[AgenticProofConfig] = None) -> AgenticProofResult:
    config = config or AgenticProofConfig(); sample_id = sample.get("id", "unknown"); events: List[AgentEvent] = []; usage_total: Dict[str, Any] = {}
    text, usage = _call_llm(llm_generate=llm_generate, messages=source_only_hypothesis_prompt(sample, target_source), sample_id=sample_id, stage="01_source_only_hypothesis", max_tokens=config.max_tokens_source_only_hypothesis, config=config, events=events); _merge_usage(usage_total, usage)
    hypothesis_obj, _ = parse_model_object(text, _HypothesisEnvelope, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "01_source_only_hypothesis"))
    hypotheses = hypothesis_obj.model_dump(mode="json"); hypotheses["hypotheses"] = hypotheses.get("hypotheses", [])[:config.max_hypotheses]
    text, usage = _call_llm(llm_generate=llm_generate, messages=kg_query_planning_prompt(sample, hypotheses["hypotheses"], initial_evidence), sample_id=sample_id, stage="02_kg_query_planning", max_tokens=config.max_tokens_kg_query_planning, config=config, events=events); _merge_usage(usage_total, usage)
    query_plan, _ = parse_model_object(text, KGQueryPlan, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "02_kg_query_planning"))
    query_dicts = [q.model_dump(mode="json") for q in query_plan.queries]
    events.append(AgentEvent(sample_id, "03_evidence_retrieval", "start", details={"queries": len(query_dicts)}))
    retrieved = kg_search(query_dicts, sample=sample, limit=config.evidence_limit_per_query)
    events.append(AgentEvent(sample_id, "03_evidence_retrieval", "done", details={"items": len(retrieved)}))
    accumulated_evidence = list(initial_evidence) + list(retrieved)
    text, usage = _call_llm(llm_generate=llm_generate, messages=hypothesis_verification_prompt(sample, hypotheses["hypotheses"], accumulated_evidence), sample_id=sample_id, stage="04_hypothesis_verification", max_tokens=config.max_tokens_hypothesis_verification, config=config, events=events); _merge_usage(usage_total, usage)
    verifications_obj, _ = parse_model_object(text, _VerificationEnvelope, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "04_hypothesis_verification"))
    verifications = verifications_obj.model_dump(mode="json")
    text, usage = _call_llm(llm_generate=llm_generate, messages=counter_evidence_prompt(sample, verifications["verifications"], accumulated_evidence), sample_id=sample_id, stage="05_counter_evidence_review", max_tokens=config.max_tokens_counter_evidence_review, config=config, events=events); _merge_usage(usage_total, usage)
    counter_review, _ = parse_model_object(text, CounterEvidenceReview, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "05_counter_evidence_review"))
    text, usage = _call_llm(llm_generate=llm_generate, messages=final_decision_prompt(sample, verifications["verifications"], counter_review.model_dump(mode="json"), accumulated_evidence), sample_id=sample_id, stage="06_final_adjudication", max_tokens=config.max_tokens_final_decision, config=config, events=events); _merge_usage(usage_total, usage)
    decision, _ = parse_model_object(text, FinalDecision, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "06_final_adjudication"))
    decision, notes, modified = validate_final_decision(decision, evidence_items=accumulated_evidence, counter_review=counter_review)
    events.append(AgentEvent(sample_id, "06_final_adjudication", "validated", details={"validator_notes": list(notes), "modified": bool(modified), "prediction": decision.prediction.value, "confidence": decision.confidence}))
    if modified:
        text, usage = _call_llm(llm_generate=llm_generate, messages=consistency_repair_prompt(decision.model_dump(mode="json"), notes), sample_id=sample_id, stage="07_schema_consistency_repair", max_tokens=config.max_tokens_schema_repair, config=config, events=events); _merge_usage(usage_total, usage)
        repaired_decision, _ = parse_model_object(text, FinalDecision, llm_repair=_repair_llm(llm_generate, config, sample_id, events, "07_schema_consistency_repair"))
        decision, notes2, modified2 = validate_final_decision(repaired_decision, evidence_items=accumulated_evidence, counter_review=counter_review); notes.extend(notes2)
        events.append(AgentEvent(sample_id, "07_schema_consistency_repair", "validated", details={"validator_notes": list(notes2), "modified": bool(modified2), "prediction": decision.prediction.value, "confidence": decision.confidence}))
    events.append(AgentEvent(sample_id, "agentic_proof", "done", details={"prediction": decision.prediction.value, "confidence": decision.confidence, "validator_notes": notes}))
    return AgenticProofResult(decision, hypotheses, query_plan, retrieved, verifications, counter_review, events, usage_total)
