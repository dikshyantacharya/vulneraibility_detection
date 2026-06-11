from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, model_validator

class HypothesisStatus(str, Enum):
    confirmed_vulnerability = "confirmed_vulnerability"
    plausible_but_unproven = "plausible_but_unproven"
    refuted_by_guard = "refuted_by_guard"
    refuted_by_caller_constraint = "refuted_by_caller_constraint"
    refuted_by_patch_or_changed_logic = "refuted_by_patch_or_changed_logic"
    irrelevant_to_target_function = "irrelevant_to_target_function"
    insufficient_evidence = "insufficient_evidence"

class FinalPrediction(str, Enum):
    vulnerable = "vulnerable"
    fixed_or_non_vulnerable = "fixed/non-vulnerable"
    inconclusive = "inconclusive"

class EvidenceItem(BaseModel):
    id: str
    kind: str
    file: Optional[str] = None
    function: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    text: str
    relation: Optional[str] = None
    score: Optional[float] = None

class MinimumVulnerabilityProof(BaseModel):
    input_control: str = ""
    dangerous_operation: str = ""
    missing_or_failed_guard: str = ""
    unsafe_use: str = ""
    security_impact: str = ""
    cited_evidence_ids: List[str] = Field(default_factory=list)
    def complete(self) -> bool:
        fields = [self.input_control, self.dangerous_operation, self.missing_or_failed_guard, self.unsafe_use, self.security_impact]
        return all((x or "").strip() for x in fields) and bool(self.cited_evidence_ids)

class VulnerabilityHypothesis(BaseModel):
    hypothesis_id: str
    title: str
    vulnerability_class: Optional[str] = None
    affected_code_region: Optional[str] = None
    attacker_model: Optional[str] = None
    risk_summary: str
    required_proof_questions: List[str] = Field(default_factory=list)

class KGQuery(BaseModel):
    query_id: str
    hypothesis_id: Optional[str] = None
    purpose: str
    # Use CodeKG function-call syntax here, for example:
    # security_context(target_function="foo", depth=3, call_depth=2)
    # evidence_slice(target_function="foo", target_statement="len * size", relation_depth=4)
    query_text: str
    variables: List[str] = Field(default_factory=list)
    expected_evidence: str
    limit: int = 8

class KGQueryPlan(BaseModel):
    queries: List[KGQuery] = Field(default_factory=list)

class HypothesisVerification(BaseModel):
    hypothesis_id: str
    status: HypothesisStatus
    local_risk_present: bool = False
    confirmed_security_vulnerability: bool = False
    proof: MinimumVulnerabilityProof = Field(default_factory=MinimumVulnerabilityProof)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    counter_evidence_ids: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    explanation: str

class CounterEvidenceFinding(BaseModel):
    hypothesis_id: str
    strongest_counterargument: str
    counter_evidence_ids: List[str] = Field(default_factory=list)
    refutes_or_weakens: str
    recommended_status: HypothesisStatus

class CounterEvidenceReview(BaseModel):
    findings: List[CounterEvidenceFinding] = Field(default_factory=list)
    overall_notes: str = ""

class FinalDecision(BaseModel):
    prediction: FinalPrediction
    prediction_bool: Optional[bool] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    local_risk_present: bool = False
    confirmed_security_vulnerability: bool = False
    final_hypothesis_statuses: List[HypothesisVerification] = Field(default_factory=list)
    minimum_vulnerability_proof: Optional[MinimumVulnerabilityProof] = None
    decisive_evidence_ids: List[str] = Field(default_factory=list)
    decisive_counter_evidence_ids: List[str] = Field(default_factory=list)
    explanation: str
    limitations: List[str] = Field(default_factory=list)
    # Forced binary fields — always set by the validator so benchmark scoring
    # always has a definitive True/False even when the evidence status is inconclusive.
    forced_prediction: Optional[str] = None           # "vulnerable" | "fixed/non-vulnerable"
    forced_prediction_bool: Optional[bool] = None     # always True/False once validator runs
    decision_status: Optional[str] = None             # confirmed_vulnerable | confirmed_non_vulnerable | forced_binary_vulnerable | forced_binary_non_vulnerable
    evidence_strength: Optional[str] = None           # confirmed | likely | weak | insufficient_static_evidence
    residual_uncertainty: List[str] = Field(default_factory=list)
    why_forced_binary: Optional[str] = None
    evidence_exhausted: bool = False
    loop_stop_reason: Optional[str] = None
    final_decision_source: Optional[str] = None
    normalization_warnings: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_null_proofs(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        statuses = data.get("final_hypothesis_statuses")
        if not isinstance(statuses, list):
            return data
        null_ids: List[str] = []
        new_statuses = []
        for h in statuses:
            if isinstance(h, dict) and h.get("proof") is None:
                h = {**h, "proof": {}}
                null_ids.append(h.get("hypothesis_id") or "unknown")
            new_statuses.append(h)
        if null_ids:
            existing = list(data.get("normalization_warnings") or [])
            existing.append(f"normalized_null_proof_fields: {null_ids}")
            data = {
                **data,
                "final_hypothesis_statuses": new_statuses,
                "normalization_warnings": existing,
                "final_decision_source": data.get("final_decision_source") or "stage06_normalized",
            }
        return data

    def normalize_prediction_bool(self) -> "FinalDecision":
        if self.forced_prediction_bool is not None:
            self.prediction_bool = self.forced_prediction_bool
        elif self.prediction == FinalPrediction.vulnerable:
            self.prediction_bool = True
        elif self.prediction == FinalPrediction.fixed_or_non_vulnerable:
            self.prediction_bool = False
        else:
            self.prediction_bool = None
        return self


class GapItem(BaseModel):
    """One identified proof-element gap from the LLM gap-analysis stage."""
    gap_id: str
    hypothesis_id: str
    proof_element: str  # input_control | dangerous_operation | missing_or_failed_guard | unsafe_use | security_impact | counter_evidence
    missing_evidence: str
    queryable: bool = True
    why_queryable_or_not: str = ""
    priority: str = "medium"  # high | medium | low
    recommended_query_focus: str = ""


class EvidenceGapPlan(BaseModel):
    """Output of the evidence-gap-analysis LLM stage.

    The LLM proposes follow-up KG queries to fill missing proof elements identified
    during hypothesis verification. Used only when iterative_evidence_loop=True.

    Backward-compatible: old artifacts without 'gaps'/'reason' still parse because
    all new fields have defaults. The legacy 'gap_summary' field is kept optional.
    """
    needs_more_evidence: bool
    reason: str = ""                          # preferred; maps to gap_summary for the LLM
    gap_summary: str = ""                     # legacy alias; kept so old model outputs still parse
    gaps: List[GapItem] = Field(default_factory=list)
    follow_up_queries: List[KGQuery] = Field(default_factory=list)
    # Machine-readable stop reason when needs_more_evidence=False or no queries proposed.
    # Allows the backend to record why no loop happened without free-text parsing.
    stop_reason_if_no_queries: Optional[str] = None
    stop_reason: Optional[str] = None        # legacy alias
