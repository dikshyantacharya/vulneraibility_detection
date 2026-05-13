from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


AllowedKGQueryType = Literal[
    # Integrated CodeKG Explorer deterministic query kinds.
    "security_context",
    "evidence_slice",
    "function_context",
    "call_neighborhood",
    "variable_flow",
    "semantic_facts",
    "file_context",
    "shortest_path",
    "risk_slice",
    "callers",
    "callees",
    # Legacy query types retained only for backward-compatible fallback outputs;
    # integrated runs normalize them to CodeKG retrieval before execution.
    "evidence_bundle",
    "guard_dominance",
    "callee",
    "caller",
    "safety",
    "risk",
    "statement",
    "variable",
    "type",
    "global",
    "search",
]

HypothesisStatus = Literal[
    "active",
    "confirmed_vulnerable",
    "ruled_out_safe",
    "unresolved",
    "needs_more_evidence",
]


class KGQuery(BaseModel):
    query_type: AllowedKGQueryType | None = None
    # New prompts use query_type as the normalized CodeKG kind. A model may also
    # provide a separate kind field or a function-call-style query string; the
    # runtime parser accepts both and validates the final CodeKG query.
    kind: str | None = None
    query: str | None = None
    reason: str
    hypothesis_id: str | None = None
    # CodeKG structured query fields. These are preserved through pydantic
    # validation so the executor can safely validate/clip and run them.
    target_function: str | None = None
    target_statement: str | None = None
    target: str | None = None
    file: str | None = None
    source_node: str | None = None
    target_node: str | None = None
    direction: str | None = None
    depth: int | None = None
    relation_depth: int | None = None
    call_depth: int | None = None
    data_depth: int | None = None
    control_depth: int | None = None
    joern_limit: int | None = None
    joern_edge_limit: int | None = None
    max_nodes: int | None = None
    include_callers: bool | None = None
    include_headers: bool | None = None
    include_globals: bool | None = None
    include_joern: bool | None = None
    include_defs: bool | None = None
    include_uses: bool | None = None
    include_guards: bool | None = None
    include_callees: bool | None = None
    risk_terms: list[str] = Field(default_factory=list)

    scope: str | dict | None = "target_function"
    match: str | None = "exact_identifier"
    wanted_evidence: list[str] = Field(default_factory=list)
    # LLM-guided evidence-bundle fields. Extra-free schema keeps the model contract
    # structured while letting the orchestrator expand bundles deterministically.
    bundle_type: str | None = None
    symbol: str | None = None
    suspect_symbols: list[str] = Field(default_factory=list)
    suspect_callees: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)
    sink_lines: list[int] = Field(default_factory=list)
    # Optional function-relative source line from the source-only hypothesis.
    # The KG tool converts this to real file lines using the located target function.
    source_line: int | None = None
    source_line_end: int | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_kind_aliases(cls, data):
        if isinstance(data, dict):
            data = dict(data)
            if not data.get("query_type") and data.get("kind"):
                data["query_type"] = data.get("kind")
            if not data.get("kind") and data.get("query_type"):
                data["kind"] = data.get("query_type")
            if not data.get("query") and data.get("query_type"):
                data["query"] = str(data.get("query_type"))
        return data

    @field_validator("query", "reason")
    @classmethod
    def non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = str(value).strip()
        if not value:
            return value
        if value.lower().startswith(("select ", "insert ", "update ", "delete ", "with ")):
            raise ValueError("SQL-like KG query strings are not allowed; use structured CodeKG query objects")
        low = value.lower().strip()
        if low in {"concrete_identifier_or_api", "concrete_identifier_from_target_function", "specific project evidence needed to confirm or rule out the hypothesis"} or "concrete_identifier" in low:
            raise ValueError("placeholder query/reason copied from schema is not allowed")
        return value


class SuspiciousLocation(BaseModel):
    """Model-visible source-only suspicion from the target function.

    The first agent stage intentionally has no KG evidence IDs. It can cite source
    line numbers and a short code reference, but later stages should switch to
    evidence IDs returned by the KG/retriever.
    """

    line: int | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_reference: str | None = None
    reason: str | None = None
    evidence_id: str | None = None  # backwards-compatible if older prompts cite evidence early


class RiskHypothesis(BaseModel):
    id: str
    kind: str
    suspicious_locations: list[SuspiciousLocation] = Field(default_factory=list)
    suspicious_evidence_ids: list[str] = Field(default_factory=list)
    needed_context: list[str] = Field(default_factory=list)
    required_context: list[str] = Field(default_factory=list)
    suspect_symbols: list[str] = Field(default_factory=list)
    suspect_callees: list[str] = Field(default_factory=list)
    needed_evidence_bundles: list[dict] = Field(default_factory=list)
    status: str = "active"

    @field_validator("id", "kind")
    @classmethod
    def non_empty_text(cls, value: str) -> str:
        value = str(value).strip()
        if not value:
            raise ValueError("must be a non-empty string")
        return value

    @model_validator(mode="after")
    def normalize_context(self) -> "RiskHypothesis":
        if self.required_context and not self.needed_context:
            self.needed_context = list(self.required_context)
        if self.needed_context and not self.required_context:
            self.required_context = list(self.needed_context)
        return self


class RiskHypothesisResponse(BaseModel):
    # Deliberately no max_length: the prompt asks the model to enumerate every
    # concrete, non-duplicative hypothesis it finds in the target code. Runtime
    # config still limits how many KG queries are executed per round.
    risk_hypotheses: list[RiskHypothesis] = Field(default_factory=list)
    kg_queries: list[KGQuery] = Field(default_factory=list)


class HypothesisUpdate(BaseModel):
    id: str
    status: HypothesisStatus
    evidence_used: list[str] = Field(default_factory=list)
    public_reason: str = ""
    remaining_context_needed: list[str] = Field(default_factory=list)

    @field_validator("id", "public_reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return str(value).strip()


class FollowupResponse(BaseModel):
    continue_: bool = Field(alias="continue")
    hypothesis_updates: list[HypothesisUpdate] = Field(default_factory=list)
    active_hypothesis_ids: list[str] = Field(default_factory=list)
    resolved_hypothesis_ids: list[str] = Field(default_factory=list)
    # No schema-level max_length; duplicate filtering and execution budgets are
    # handled by the orchestrator/config instead of silently constraining analysis.
    kg_queries: list[KGQuery] = Field(default_factory=list)
    verification_summary: str = ""

    @model_validator(mode="after")
    def queries_match_continue(self) -> "FollowupResponse":
        if not self.continue_ and self.kg_queries:
            raise ValueError("kg_queries must be [] when continue is false")
        return self


class VulnerableStatement(BaseModel):
    evidence_id: str | None = None
    line: int | None = None
    reason: str | None = None
    # Strength separates proven evidence from generic risky-pattern hits.
    # Final vulnerable decisions should cite at least one confirmed or strongly supported item.
    claim_strength: Literal["confirmed", "strongly_supported", "plausible", "weak_pattern_only"] = "strongly_supported"
    # Confirmed-vulnerability evidence contract. These are optional at parse time so
    # older model outputs can still be repaired/validated, but the final-decision
    # validator downgrades confirmed/strong claims when these facts are absent.
    sink_or_api: str | None = None
    destination_buffer: str | None = None
    destination_size_evidence: str | None = None
    source_or_input_control_evidence: str | None = None
    bound_or_guard_evidence: str | None = None
    why_bound_insufficient: str | None = None
    why_exploitable: str | None = None
    missing_facts: list[str] = Field(default_factory=list)
    # Backwards-compatible read path for older outputs/artifacts. New prompts require
    # evidence_id and must not require raw C statement strings inside JSON.
    statement: str | None = None


class UploadPathFact(BaseModel):
    evidence_id: str | None = None
    line: int | None = None
    value: str | None = None
    summary: str | None = None


class UploadPathAssessment(BaseModel):
    """Required final-stage binding for admin/config upload paths.

    This structure is model-visible and source-only. It does not encode dataset
    labels or patch metadata; it forces the final answer to bind content-length,
    read bounds, post-read writes, decode/write sinks, and evidence IDs before
    making a decision.
    """

    present: bool = False
    contentlen_declaration: UploadPathFact | None = None
    contentlen_parsing: UploadPathFact | None = None
    contentlen_cap: UploadPathFact | None = None
    loop_condition: UploadPathFact | None = None
    read_size_expression: UploadPathFact | None = None
    post_read_adjustment: UploadPathFact | None = None
    nul_write: UploadPathFact | None = None
    decode_and_write_sink: UploadPathFact | None = None
    verdict: Literal["unsafe", "safe", "unresolved"] = "unresolved"
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    missing_facts: list[str] = Field(default_factory=list)


class FinalDecisionResponse(BaseModel):
    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    primary_vulnerability_type: str | None = None
    vuln_statements: list[VulnerableStatement] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)
    confirmed_hypotheses: list[str] = Field(default_factory=list)
    ruled_out_hypotheses: list[str] = Field(default_factory=list)
    unresolved_hypotheses: list[str] = Field(default_factory=list)
    # Mandatory when source evidence contains an upload/config handling path.
    # Validators enforce this after parsing to keep older/non-upload outputs usable.
    upload_path_assessment: UploadPathAssessment | None = None
    # Explicit tri-state analysis status. The benchmark still reads is_vulnerable,
    # but reports can distinguish true negatives from inconclusive/abstention-like cases.
    decision_status: Literal["vulnerable", "non_vulnerable", "inconclusive"] | None = None
    binary_prediction_policy: str | None = None
    reasoning_summary: str = ""

    @model_validator(mode="after")
    def validate_decision_consistency(self) -> "FinalDecisionResponse":
        if self.is_vulnerable:
            self.decision_status = "vulnerable"
            missing_ids = [v for v in self.vuln_statements if not v.evidence_id]
            if missing_ids:
                raise ValueError("each vulnerable statement must use evidence_id instead of raw statement text")
            strong = [v for v in self.vuln_statements if v.claim_strength in {"confirmed", "strongly_supported"}]
            if not strong:
                raise ValueError("vulnerable decisions require at least one confirmed or strongly_supported vuln_statement")
        else:
            if self.vuln_statements:
                raise ValueError("vuln_statements must be [] when is_vulnerable is false")
            if self.primary_vulnerability_type is not None:
                raise ValueError("primary_vulnerability_type must be null when is_vulnerable is false")
            if self.decision_status == "vulnerable":
                raise ValueError("decision_status cannot be vulnerable when is_vulnerable is false")
            if self.decision_status is None:
                self.decision_status = "non_vulnerable"
            # Important: missing proof of vulnerability is not proof of safety.
            # If unresolved hypotheses remain and no concrete ruled-out hypotheses were reported, mark as inconclusive.
            if self.decision_status == "non_vulnerable" and self.unresolved_hypotheses and not self.ruled_out_hypotheses:
                self.decision_status = "inconclusive"
                self.confidence = min(float(self.confidence or 0.0), 0.5)
        if self.binary_prediction_policy is None:
            self.binary_prediction_policy = (
                "strict metrics count only decision_status in {vulnerable, non_vulnerable}; "
                "inconclusive/parse_failed are invalid/abstain, not true negatives"
            )
        return self


class PosthocCommitAuditResponse(BaseModel):
    """Report-only audit comparing model reasoning with commit-message semantics.

    This is intentionally separate from FinalDecisionResponse because it may see
    report-only commit metadata after the prediction has already been made. It is
    not model-visible before the final classification and must not change metrics.
    """

    semantic_alignment: Literal["aligned", "partially_aligned", "not_aligned", "unclear"] = "unclear"
    factual_support: Literal["supported", "partially_supported", "unsupported", "unclear"] = "unclear"
    snapshot_semantics: Literal["pre_fix_parent", "patch_commit", "dataset_commit", "unknown"] = "unknown"
    does_reasoning_match_snapshot: bool | None = None
    does_reasoning_match_commit_message: bool | None = None
    patch_effect_identified: bool | None = None
    audit_label: Literal["good", "partially_good", "misleading", "unsupported", "unclear"] = "unclear"
    commit_message_summary: str = ""
    model_reasoning_summary: str = ""
    factual_findings: list[str] = Field(default_factory=list)
    mismatch_or_gap: list[str] = Field(default_factory=list)
    missing_patch_evidence: list[str] = Field(default_factory=list)
    evidence_ids_checked: list[str] = Field(default_factory=list)
    audit_conclusion: str = ""



class Prediction(BaseModel):
    sample_id: str
    dataset_commit_id: str | None = None
    resolved_commit_id: str | None = None
    resolved_commit_label: str | None = None
    target_validation_status: str | None = None
    target_validation_similarity: float | None = None
    target_validation_artifact_dir: str | None = None
    is_vulnerable: bool
    confidence: float = 0.0
    primary_vulnerability_type: str | None = None
    vuln_statements: list[VulnerableStatement] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)
    decision_status: str | None = None
    binary_prediction_policy: str | None = None
    reasoning_summary: str = ""
    parse_error: str | None = None
    raw_response: str | None = None
    model_backend: str | None = None
    usage: dict = Field(default_factory=dict)
    validation_notes: list[str] = Field(default_factory=list)


class AgentTrace(BaseModel):
    sample_id: str
    dataset_commit_id: str | None = None
    resolved_commit_id: str | None = None
    resolved_commit_label: str | None = None
    target_validation_artifact_dir: str | None = None
    mode: str
    risk_hypotheses: list[dict] = Field(default_factory=list)
    kg_queries: list[dict] = Field(default_factory=list)
    kg_tool_steps: list[dict] = Field(default_factory=list)
    verification: list[dict] = Field(default_factory=list)
    hypothesis_ledger: list[dict] = Field(default_factory=list)
    final_prompt_chars: int = 0
    raw_outputs: list[str] = Field(default_factory=list)
    model_calls: list[dict] = Field(default_factory=list)
    prompt_files: list[str] = Field(default_factory=list)
    report_path: str | None = None
    initial_evidence_count: int = 0
    accumulated_evidence_count: int = 0
    posthoc_commit_audit: dict = Field(default_factory=dict)
    final_validator_modifications: list[dict] = Field(default_factory=list)
