from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .schemas import CounterEvidenceReview, EvidenceGapPlan, FinalDecision, KGQueryPlan, HypothesisVerification, VulnerabilityHypothesis, ProofObligationVerificationEnvelope
from .code_evidence import build_code_evidence_bundle, build_code_evidence_capsules, build_obligation_code_capsules, compact_code_evidence_index

COMMON_TAG_CONTRACT = """Return exactly:
<analysis>
3-5 bullets: evidence categories used, most important missing proof elements. No private chain-of-thought.
</analysis>
<answer>
A valid JSON object matching the requested schema.
</answer>
The <answer> tag must contain JSON only. Do not place markdown/code fences inside <answer>."""

def schema_block(model_cls: Any) -> str:
    return json.dumps(model_cls.model_json_schema(), indent=2)


def _binary_final_decision_schema() -> str:
    """Compact schema for final_decision_prompt and consistency_repair_prompt.

    Uses the full FinalDecision JSON schema but replaces the FinalPrediction enum
    with a binary-only version (no 'inconclusive') so the LLM cannot pick it.
    """
    schema = FinalDecision.model_json_schema()
    defs = schema.get("$defs", {})
    if "FinalPrediction" in defs:
        defs["FinalPrediction"]["enum"] = ["vulnerable", "fixed/non-vulnerable"]
    return json.dumps(schema, indent=2)


# Compact binary-only output contract for consistency_repair_prompt.
# Much smaller than the full Pydantic schema (~14KB) so it fits in repair token budgets.


_FINAL_DECISION_COMPACT_CONTRACT = json.dumps({
    "prediction": "vulnerable | fixed/non-vulnerable",
    "prediction_bool": True,
    "confidence": "number 0.0..1.0",
    "local_risk_present": True,
    "confirmed_security_vulnerability": False,
    "final_hypothesis_statuses": [
        {
            "hypothesis_id": "HYP-01",
            "status": "confirmed_vulnerability | plausible_but_unproven | refuted_by_guard | refuted_by_caller_constraint | refuted_by_patch_or_changed_logic | irrelevant_to_target_function | insufficient_evidence",
            "local_risk_present": True,
            "confirmed_security_vulnerability": False,
            "proof": {
                "input_control": "short string; empty if unproven",
                "dangerous_operation": "short string",
                "missing_or_failed_guard": "short string",
                "unsafe_use": "short string",
                "security_impact": "short string",
                "cited_evidence_ids": []
            },
            "supporting_evidence_ids": [],
            "counter_evidence_ids": [],
            "missing_evidence": [],
            "explanation": "one concise sentence"
        }
    ],
    "minimum_vulnerability_proof": "object with same proof fields, or null",
    "decisive_evidence_ids": [],
    "decisive_counter_evidence_ids": [],
    "explanation": "2-4 concise sentences; must match prediction",
    "limitations": [],
    "forced_prediction": "same as prediction",
    "forced_prediction_bool": True,
    "decision_status": "confirmed_vulnerable | confirmed_non_vulnerable | forced_binary_vulnerable | forced_binary_non_vulnerable",
    "evidence_strength": "confirmed | likely | weak | insufficient_static_evidence",
    "residual_uncertainty": [],
    "why_forced_binary": "string or null",
    "evidence_exhausted": True
}, indent=2)


def _short_evidence_digest(evidence: List[Dict[str, Any]], max_items: int = 90, max_text: int = 360) -> List[Dict[str, Any]]:
    """Compact evidence for final adjudication.

    Stage 06 should decide, not re-read the entire graph dump.  Long evidence
    blocks cause verbose/truncated answers, so pass only the id, kind, relation,
    metadata, and short text needed for citation.
    """
    out: List[Dict[str, Any]] = []
    priority_kinds = {"target_statement", "deterministic_source_fact", "callee_function", "codekg_semanticfact"}
    ordered = sorted(
        list(evidence or []),
        key=lambda e: (0 if (e.get("kind") in priority_kinds or str(e.get("id", "")).startswith("AUTO-SF")) else 1, str(e.get("id") or e.get("evidence_id") or "")),
    )
    for e in ordered[:max_items]:
        text = str(e.get("text") or "")
        if len(text) > max_text:
            text = text[:max_text] + " ..."
        item = {
            "id": e.get("id") or e.get("evidence_id"),
            "kind": e.get("kind"),
            "relation": e.get("relation"),
            "text": text,
        }
        if e.get("metadata"):
            item["metadata"] = e.get("metadata")
        if e.get("file"):
            item["file"] = e.get("file")
        if e.get("line_start") is not None:
            item["line_start"] = e.get("line_start")
        out.append(item)
    return out

_BINARY_REPAIR_CONTRACT = json.dumps({
    "prediction": "vulnerable | fixed/non-vulnerable  (ONLY these two — no inconclusive)",
    "confidence": 0.0,
    "local_risk_present": True,
    "confirmed_security_vulnerability": False,
    "final_hypothesis_statuses": "(keep existing array unchanged)",
    "minimum_vulnerability_proof": "(keep or set to null)",
    "decisive_evidence_ids": [],
    "decisive_counter_evidence_ids": [],
    "explanation": "string",
    "limitations": [],
    "forced_prediction": "vulnerable | fixed/non-vulnerable",
    "forced_prediction_bool": True,
    "decision_status": "confirmed_vulnerable | confirmed_non_vulnerable | forced_binary_vulnerable | forced_binary_non_vulnerable",
    "evidence_strength": "confirmed | likely | weak | insufficient_static_evidence",
    "why_forced_binary": "string or null",
    "evidence_exhausted": False,
}, indent=2)

def compact_json(data: Any, max_chars: int = 24000) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    return text if len(text) <= max_chars else text[:max_chars] + "\n...<truncated>..."


# Explicit, auditable per-stage context policy. Each stage declares what may be
# placed in the model-visible prompt. No dataset/project metadata appears in any
# stage. This is the single source of truth the prompt builders follow.
STAGE_CONTEXT_POLICY: Dict[str, Dict[str, List[str]]] = {
    "01_source_only_hypothesis": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name", "target_function_source"],
        "forbidden": ["sample_id", "project", "project_url", "filepath", "label", "commit",
                      "resolved_commit", "initial_evidence", "kg_evidence", "callee_evidence", "caller_evidence"],
    },
    "02_kg_query_planning": {
        "allowed": ["system_prompt", "output_format", "codekg_query_contract", "query_schema",
                    "target_function_name", "optional_target_file", "hypotheses"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit",
                      "initial_evidence", "retrieved_evidence", "callee_snippets"],
    },
    "04_hypothesis_verification": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name", "hypotheses",
                    "code_evidence_bundle", "source_code_sections", "retrieval_index"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit"],
    },
    "05_counter_evidence_review": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "current_verifications", "code_evidence_bundle"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit"],
    },
    "06_final_adjudication": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "verifications", "counter_review", "code_evidence_bundle"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit"],
    },
    "04_evidence_gap": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "verification_statuses", "missing_evidence_fields", "executed_query_ids",
                    "evidence_id_index", "iteration"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit",
                      "evidence_full_text"],
    },
    "05_counter_gap": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "counter_review_findings", "missing_counter_evidence", "executed_query_ids",
                    "evidence_id_index", "iteration"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit",
                      "evidence_full_text"],
    },
}


def _target_function_name(sample: Dict[str, Any]) -> str:
    return str(sample.get("function") or sample.get("func_name") or sample.get("target_function") or "").strip()


def _target_file(sample: Dict[str, Any]) -> str:
    return str(sample.get("filepath") or sample.get("file") or "").strip()


def source_only_hypothesis_prompt(sample: Dict[str, Any], target_source: str) -> List[Dict[str, str]]:
    # Stage 01 is SOURCE-ONLY: no sample/project metadata, no evidence. Only the
    # output contract, schema, target function name, and target source.
    schema = {
        "hypotheses": [VulnerabilityHypothesis.model_json_schema()],
        "source_observations": ["string"],
        "non_vulnerability_possibilities": ["string"],
    }
    fn = _target_function_name(sample)
    return [
        {"role": "system", "content": (
            "You are a source-only C/C++ security hypothesis generator. "
            "Generate candidate vulnerability hypotheses from the target function source only; do not confirm them. "
            "For each hypothesis, identify a concrete risky operation, the value or object that must be attacker-controlled or malformed, "
            "the exact guard/invariant that would be required, and the proof question that later CodeKG queries should test. "
            "Cover vulnerability families broadly rather than relying on project-specific rules: memory safety, integer/bounds, parser/state-machine, "
            "allocation/lifetime, path/file handling, command/API misuse, protocol/access-control, concurrency/lifecycle, and crypto/algorithmic misuse. "
            "Use language-specific semantics when forming hypotheses: distinguish selectors from values they select, bounded formatting from path construction, "
            "arbitrary-precision/library arithmetic from machine-integer arithmetic, and local robustness issues from externally reachable security impact. "
            "Prefer hypotheses that are source-grounded, target-relevant, falsifiable by deterministic code evidence, and not merely generic style concerns. "
            "Do not split the same root cause into many duplicate hypotheses; combine duplicate manifestations under one concise hypothesis."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"TARGET FUNCTION SOURCE:\n```c\n{target_source}\n```\n\n"
            "Generate all distinct, source-grounded vulnerability hypotheses that are plausible for this function; do not force an artificial fixed count.\n"
            "Use generic IDs: HYP-01, HYP-02, ...\n"
            "Prefer hypotheses that are testable by deterministic code evidence.\n"
            "Separate local source observations from non-vulnerability possibilities.\n"
            "Do not classify the function as vulnerable or non-vulnerable."
        )},
    ]


def kg_query_planning_prompt(
    sample: Dict[str, Any],
    hypotheses: List[Dict[str, Any]],
    initial_evidence: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, str]]:
    # Stage 02 plans deterministic CodeKG retrieval from hypotheses only.  It is
    # intentionally general: no function-family examples and no project metadata.
    codekg_contract = (
        "Use only the deterministic CodeKG query interface. "
        "Put one complete function-call-style query in each query_text field.\n"
        "Allowed query_text forms:\n"
        '- security_context(target_function="<function>", depth=3, call_depth=2, data_depth=4, '
        "include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=520)\n"
        '- evidence_slice(target_function="<function>", target_statement="<suspicious expression>", '
        "relation_depth=4, data_depth=4, control_depth=3, call_depth=2, include_defs=true, "
        "include_uses=true, include_guards=true, include_callees=true, include_headers=true, "
        "include_globals=true, include_joern=true, max_nodes=450)\n"
        '- variable_flow(target_function="<function>", symbol="<variable>", data_depth=4)\n'
        '- call_neighborhood(target_function="<function>", direction="in", call_depth=2)\n'
        '- call_neighborhood(target_function="<function>", direction="out", call_depth=2)\n'
        '- call_neighborhood(target_function="<function>", direction="both", call_depth=2)\n'
        '- semantic_facts(target_function="<function>")\n'
        '- function_context(target_function="<function>", depth=2)\n'
        '- file_context(file="<relative/source/file.c>")\n'
        '- shortest_path(source_node="<node-id>", target_node="<node-id>")\n\n'
        "Choose queries that retrieve source code needed for a human security review: "
        "the target operation, definitions/types/constants/macros used by it, callees that compute or validate values, "
        "callers that supply arguments or establish preconditions, and variable/data-flow for values central to the hypothesis. "
        "Prefer a small non-duplicated set. Use evidence_slice for exact risky expressions or guards, "
        "variable_flow for provenance of critical values, call_neighborhood(direction=\"in\") for caller preconditions, "
        "call_neighborhood(direction=\"out\") or function_context for callee behavior, and file_context for nearby definitions when required. "
        "Do not ask free-form questions. Do not classify vulnerability status."
    )
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    file_block = f"OPTIONAL TARGET FILE:\n{target_file}\n\n" if target_file else ""
    one = len(hypotheses or []) == 1
    return [
        {"role": "system", "content": (
            "Plan source-grounded CodeKG retrieval queries. "
            "The goal is to fetch the smallest useful set of code evidence needed to prove or falsify the supplied hypothesis or hypotheses. "
            "Be vulnerability-family agnostic: reason from the hypothesis proof obligations, not from hardcoded bug examples. "
            "A good plan retrieves code that explains where relevant values come from, how they are transformed, which guards dominate the risky operation, "
            "which callers/callees impose constraints, and which definitions/types/constants affect the semantics. "
            "Avoid redundant queries and avoid broad graph dumps when a focused slice, caller, callee, variable-flow, or definition query is enough."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"CODEKG QUERY CONTRACT:\n{codekg_contract}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(KGQueryPlan)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"{file_block}"
            f"{'CURRENT HYPOTHESIS' if one else 'HYPOTHESES'}:\n{compact_json(hypotheses, 12000)}\n\n"
            "Generate deterministic CodeKG queries whose returned source code can test or falsify the hypothesis.\n"
            "Do not use prior retrieved evidence. Do not invent evidence. Do not classify vulnerability status."
        )},
    ]


def _verification_system_prompt() -> str:
    return (
        "Verify the supplied hypothesis using only the tiny source-code evidence capsules. "
        "Answer the narrow proof question implied by the hypothesis; do not perform broad speculation. "
        "A confirmed vulnerability requires a cited, source-grounded chain connecting: "
        "a controllable or malformed value/object, the dangerous operation, the absent/failed dominating guard or invariant, "
        "a reachable unsafe use or accept path, and a concrete security impact. "
        "Refute only with positive code evidence that protects the same value/object and dominates the same dangerous operation, "
        "or with caller/callee code that makes the dangerous state unreachable. "
        "Do not treat absence of retrieved evidence as safety and do not treat generic semantic labels as proof. "
        "Use the vulnerability-family proof obligations generically: memory/integer issues need operand, type/size, guard, and use evidence; "
        "parser/state issues need input field, state/pointer/index update, remaining-bound guard, and accept/reject path evidence; "
        "path/file/API issues need construction, validation, and sink evidence; protocol/access-control issues need trust boundary, required check, and accept/use path evidence; "
        "lifecycle/concurrency issues need ownership/order/release evidence; crypto/algorithmic issues need attacker capability, deterministic weakness, missing diversification/validation, and consequence. "
        "For scaled pointer/index traversal, do not require every scale operand to be attacker-controlled; instead check whether the parsed or malformed value is bounded against remaining space and the scale before the state advance."
    )


def hypothesis_verification_prompt(
    sample: Dict[str, Any],
    hypotheses: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    target_source: str = "",
) -> List[Dict[str, str]]:
    # Backward-compatible multi-hypothesis prompt.  The new research flow calls
    # single_hypothesis_verification_prompt, but tests/older callers may use this.
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    schema = {"verifications": [HypothesisVerification.model_json_schema()]}
    code_bundle = build_code_evidence_capsules(
        evidence,
        target_function=fn,
        target_source=target_source,
        target_file=target_file,
        hypothesis=hypotheses,
        max_capsules=12,
        max_code_chars=1400,
        max_index_items=32,
    )
    return [
        {"role": "system", "content": _verification_system_prompt()},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"HYPOTHESES:\n{compact_json(hypotheses, 12000)}\n\n"
            f"SOURCE CODE EVIDENCE BUNDLE (TINY CAPSULES):\n{compact_json(code_bundle, 18000)}"
        )},
    ]


def single_hypothesis_verification_prompt(
    sample: Dict[str, Any],
    hypothesis: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    target_source: str = "",
    retrieval_status: Dict[str, Any] | None = None,
    terminal_closure: bool = False,
) -> List[Dict[str, str]]:
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    schema = {"verifications": [HypothesisVerification.model_json_schema()]}
    code_bundle = build_code_evidence_capsules(
        evidence,
        target_function=fn,
        target_source=target_source,
        target_file=target_file,
        hypothesis=hypothesis,
        max_capsules=10,
        max_code_chars=1400,
        max_index_items=28,
    )
    status_block = ""
    if retrieval_status:
        status_block = (
            "\n\nRETRIEVAL STATUS FOR THIS HYPOTHESIS:\n"
            f"{compact_json(retrieval_status, 8000)}"
        )
    if terminal_closure:
        instruction = (
            "Return exactly one terminal verification object for the current hypothesis. "
            "This is the closure pass for this hypothesis after the bounded KG retrieval loop. "
            "If the available source code now proves a reachable dangerous operation on controllable or malformed data with no relevant dominating guard, use confirmed_vulnerability. "
            "If positive code evidence refutes it, use the appropriate refuted_* status. "
            "If the proof still lacks caller/input/source evidence, guard dominance, impact, or reachable unsafe use after all useful static queries were attempted, do not ask for duplicate evidence; use plausible_but_unproven or insufficient_evidence and explicitly say static evidence was exhausted for this hypothesis."
        )
    else:
        instruction = (
            "Return exactly one verification object for the current hypothesis. "
            "If more code is needed to refute or confirm it, keep the status plausible_but_unproven or insufficient_evidence and list precise missing_evidence items."
        )
    return [
        {"role": "system", "content": _verification_system_prompt()},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"CURRENT HYPOTHESIS ONLY:\n{compact_json(hypothesis, 9000)}\n\n"
            f"SOURCE CODE EVIDENCE BUNDLE (TINY CAPSULES):\n{compact_json(code_bundle, 18000)}"
            f"{status_block}\n\n"
            f"{instruction}"
        )},
    ]


def counter_evidence_prompt(
    sample: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    target_source: str = "",
) -> List[Dict[str, str]]:
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    code_bundle = build_code_evidence_capsules(
        evidence,
        target_function=fn,
        target_source=target_source,
        target_file=target_file,
        hypothesis=verifications,
        max_capsules=12,
        max_code_chars=1300,
        max_index_items=32,
    )
    return [
        {"role": "system", "content": (
            "You are the defense reviewer. Try to falsify each non-refuted hypothesis using only concrete source code. "
            "Positive counter-evidence must protect the same value/object and dominate the same dangerous operation, or must show a caller/callee invariant that makes the dangerous state unreachable. "
            "Be proof-tier aware: confirmed_source_level_vulnerability means the local source-code vulnerability mechanism is proven; missing stricter caller/I/O exploitability evidence is a limitation, not a refutation. "
            "Recommend downgrading a confirmed proof tier only when you can cite concrete counter-evidence that contradicts one of its required obligations. "
            "Missing proof weakens confirmation but is not itself safety. Do not use graph scores, summaries, or unstated assumptions. "
            "If counter-evidence only weakens the proof, say weakens rather than refutes."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(CounterEvidenceReview)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"CURRENT VERIFICATIONS:\n{compact_json(verifications, 16000)}\n\n"
            f"SOURCE CODE EVIDENCE BUNDLE (TINY CAPSULES):\n{compact_json(code_bundle, 18000)}"
        )},
    ]


def final_decision_prompt(
    sample: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    counter_review: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    target_source: str = "",
) -> List[Dict[str, str]]:
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    code_bundle = build_code_evidence_capsules(
        evidence,
        target_function=fn,
        target_source=target_source,
        target_file=target_file,
        hypothesis=verifications,
        max_capsules=10,
        max_code_chars=1100,
        max_index_items=30,
    )
    return [
        {"role": "system", "content": (
            "Final adjudicator. Output compact valid JSON only inside <answer>. "
            "You MUST choose exactly one binary prediction: vulnerable or fixed/non-vulnerable. "
            "Use only the structured verifications, counter-review findings, and source-code evidence capsules. "
            "Choose vulnerable when at least one hypothesis has a complete cited proof after proof-gate validation: input/control source, dangerous operation, missing/failed dominating guard, reachable unsafe use, and security impact. "
            "Also choose vulnerable when a verification carries proof_tier=confirmed_source_level_vulnerability or proof_tier=confirmed_reachable_vulnerability; preserve that tier in decision_status/evidence_strength instead of downgrading to forced binary. "
            "Choose fixed/non-vulnerable when hypotheses are refuted by positive code evidence or remain unproven after the bounded per-hypothesis retrieval loop; local risk without complete proof is not confirmed vulnerability. "
            "Never treat missing attacker-control evidence alone as safety evidence, and never use dataset labels, commit messages, graph scores, or raw metadata. "
            "For each final_hypothesis_statuses entry, always output a proof object; never output proof:null. Cite evidence IDs only."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"COMPACT ANSWER CONTRACT (must validate against FinalDecision):\n{_FINAL_DECISION_COMPACT_CONTRACT}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"VERIFICATIONS:\n{compact_json(verifications, 16000)}\n\n"
            f"COUNTER REVIEW:\n{compact_json(counter_review, 9000)}\n\n"
            f"SOURCE CODE EVIDENCE BUNDLE (TINY CAPSULES):\n{compact_json(code_bundle, 16000)}"
        )},
    ]


_CODEKG_QUERY_FORMS = (
    "Allowed query_text forms:\n"
    '- security_context(target_function="<fn>", depth=3, call_depth=2)\n'
    '- evidence_slice(target_function="<fn>", target_statement="<expr>", relation_depth=4)\n'
    '- variable_flow(target_function="<fn>", symbol="<var>", data_depth=4)\n'
    '- call_neighborhood(target_function="<fn>", direction="in", call_depth=2)\n'
    '- call_neighborhood(target_function="<fn>", direction="out", call_depth=2)\n'
    '- call_neighborhood(target_function="<fn>", direction="both", call_depth=2)\n'
    '- semantic_facts(target_function="<fn>")\n'
    '- function_context(target_function="<fn>", depth=2)\n'
    '- file_context(file="<relative/path.c>")\n'
)


def evidence_gap_analysis_prompt(
    sample: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    executed_query_ids: List[str],
    iteration: int = 1,
) -> List[Dict[str, str]]:
    # Stage 04_evidence_gap_iter{N}: no sample/project metadata. Receives only
    # the target function name, current verification statuses (with missing_evidence
    # fields), an evidence ID index (not full text to save tokens), the list of
    # already-executed query IDs to avoid duplicates, and the iteration number.
    fn = _target_function_name(sample)

    # Compact verification summary: id, status, missing_evidence only
    verif_summary = [
        {
            "hypothesis_id": v.get("hypothesis_id"),
            "status": v.get("status"),
            "missing_evidence": v.get("missing_evidence") or [],
        }
        for v in (verifications or [])
    ]

    # Evidence index: id + type + role only — no full text to stay within token budget.
    evidence_index = compact_code_evidence_index(evidence, target_function=fn)

    return [
        {"role": "system", "content": (
            "You are an evidence-gap analyst for a security audit. "
            "Decide whether more KG evidence is necessary based on the current verification gaps. "
            "Set needs_more_evidence=false only when: evidence is sufficient for classification, "
            "all remaining gaps are unqueryable from static CodeKG, all useful queries already executed, "
            "or remaining uncertainty is unavoidable. "
            "If any high/medium priority gap is queryable and you propose a follow_up_query, "
            "needs_more_evidence MUST be true. "
            "Set needs_more_evidence=true when missing proof elements are: "
            "necessary for classification, likely present in static CodeKG, and not already retrieved. "
            "For each gap, set queryable=true only if a deterministic CodeKG query can realistically return "
            "that evidence. Set queryable=false for runtime behavior, external invariants, or gaps that "
            "static analysis cannot resolve. "
            "When needs_more_evidence=false, set stop_reason_if_no_queries to one of: "
            "no_more_evidence_needed | no_queryable_gaps | duplicate_queries_only | "
            "all_hypotheses_resolved | no_new_evidence | insufficient_static_evidence. "
            "Generate only deterministic CodeKG queries using the allowed forms. "
            "For variable_flow, the symbol must be a real identifier from the target code/evidence index, not an English proof-element word such as Bit, Bounds, Caller, or Unresolved. "
            "Do not duplicate already-executed queries (by text or id). "
            "Do not classify vulnerability status. Do not invent evidence."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(EvidenceGapPlan)}\n\n"
            f"{_CODEKG_QUERY_FORMS}\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"ITERATION: {iteration}\n\n"
            f"CURRENT VERIFICATION STATUSES:\n{compact_json(verif_summary, 8000)}\n\n"
            f"ALREADY EXECUTED QUERY IDs (do not duplicate by id or text): {json.dumps(executed_query_ids)}\n\n"
            f"EVIDENCE ID INDEX (already retrieved):\n{compact_json(evidence_index, 4000)}\n\n"
            "For each gap: classify proof_element, set queryable=true/false with reasoning, "
            "assign priority (high/medium/low). "
            "Propose follow_up_queries only for queryable=true gaps with non-duplicate query texts. "
            "If follow_up_queries is non-empty, set needs_more_evidence=true. "
            "Prioritize caller/input-source queries for missing attacker control, exact guard queries "
            "for missing overflow/bounds checks, and family-specific queries for protocol validation, access-control, parser-state, allocation, crypto/algorithmic, and path/file vulnerabilities. "
            "Never propose variable_flow over abstract English words; use only identifiers already visible in EVIDENCE ID INDEX or the current verification fields. Set needs_more_evidence=false with stop_reason_if_no_queries "
            "only if no useful queries exist."
        )},
    ]


def counter_gap_analysis_prompt(
    sample: Dict[str, Any],
    counter_findings: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    executed_query_ids: List[str],
    iteration: int = 1,
) -> List[Dict[str, str]]:
    # Stage 05_counter_gap_iter{N}: no sample/project metadata. Receives only
    # the target function name, counter-review findings, evidence ID index, and
    # already-executed query IDs.
    fn = _target_function_name(sample)
    findings_summary = [
        {
            "hypothesis_id": f.get("hypothesis_id"),
            "refutes_or_weakens": f.get("refutes_or_weakens"),
            "strongest_counterargument": f.get("strongest_counterargument"),
        }
        for f in (counter_findings or [])
    ]
    evidence_index = compact_code_evidence_index(evidence, target_function=fn)
    return [
        {"role": "system", "content": (
            "You are a security defense analyst. Generate follow-up CodeKG queries to find "
            "concrete counter-evidence: guards, early returns, range checks, caller constraints, "
            "safe invariants, bounded allocation, or patched logic. "
            "Only search for counter-evidence that directly applies to the exact dangerous operation/value or makes that dangerous state unreachable. "
            "A guard on a related value is not enough unless the code shows it dominates and constrains the same operand/object. "
            "If you propose follow_up_queries, needs_more_evidence must be true. "
            "Do not classify vulnerability status. Avoid duplicating already-executed queries."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(EvidenceGapPlan)}\n\n"
            f"{_CODEKG_QUERY_FORMS}\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"ITERATION: {iteration}\n\n"
            f"COUNTER REVIEW FINDINGS:\n{compact_json(findings_summary, 8000)}\n\n"
            f"ALREADY EXECUTED QUERY IDs (do not duplicate): {json.dumps(executed_query_ids)}\n\n"
            f"EVIDENCE ID INDEX:\n{compact_json(evidence_index, 4000)}\n\n"
            "Propose follow-up queries that may find positive counter-evidence of safety. "
            "Use call_neighborhood(direction=\"in\") for caller preconditions and evidence_slice for exact guards. "
            "Return needs_more_evidence=false only if no non-duplicate useful queries are needed."
        )},
    ]


def consistency_repair_prompt(decision: Dict[str, Any], validation_notes: List[str]) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": (
            "Repair final-decision consistency only. You may downgrade unsupported vulnerability claims. "
            "You must not upgrade to vulnerable. Do not add new evidence. "
            "You MUST produce a binary prediction: vulnerable or fixed/non-vulnerable. "
            "Inconclusive is NOT allowed. If validator notes say proof is incomplete, choose "
            "fixed/non-vulnerable when existing counter-evidence indicates safety; otherwise choose "
            "vulnerable with lower confidence to reflect the unresolved uncertainty."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"REQUIRED OUTPUT CONTRACT (binary only — no inconclusive):\n{_BINARY_REPAIR_CONTRACT}\n\n"
            f"VALIDATION NOTES:\n{json.dumps(validation_notes, indent=2)}\n\n"
            f"CURRENT DECISION:\n{compact_json(decision, 12000)}"
        )},
    ]


def proof_obligation_verification_prompt(
    sample: Dict[str, Any],
    hypothesis: Dict[str, Any],
    obligation: Any,
    evidence: List[Dict[str, Any]],
    target_source: str = "",
) -> List[Dict[str, str]]:
    """Micro-verification prompt: one proof obligation, a few capsules.

    The LLM is not asked to classify the whole hypothesis here.  It only marks
    whether this one proof obligation is proven, refuted, partially proven, or
    unanswered from the provided code capsules.
    """
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    schema = ProofObligationVerificationEnvelope.model_json_schema()
    code_bundle = build_obligation_code_capsules(
        evidence,
        target_function=fn,
        target_source=target_source,
        target_file=target_file,
        hypothesis=hypothesis,
        obligation=obligation,
        max_capsules=4,
        max_code_chars=1100,
        max_index_items=18,
    )
    obligation_payload = obligation.model_dump(mode="json") if hasattr(obligation, "model_dump") else obligation
    return [
        {"role": "system", "content": (
            "You are a micro proof-obligation verifier for C/C++ security auditing. "
            "Answer exactly one narrow proof question using only the provided source-code capsules. "
            "Do not decide the entire vulnerability hypothesis. Do not speculate from missing evidence. "
            "Return proven only when the code directly establishes this exact obligation. Return refuted only when positive source code contradicts this exact obligation. "
            "For negative safety obligations such as missing_remaining_bound_guard, proven means the required guard is absent; refuted means a concrete dominating guard exists. "
            "For scaled_state_advance, answer only whether the data-dependent scaled advance exists; do not demand bounds, alignment, or safety evidence. "
            "For unsafe_continuation_or_accept_path, a next loop iteration or parser-state reuse counts as later use; do not require a separate post-loop dereference. "
            "Return partially_proven when the capsule supports the obligation but one sub-element remains missing. Return not_answered when the capsules do not answer it. "
            "Fill supports_hypothesis/refutes_hypothesis if present in the schema. Cite only capsule_id values from the source-code bundle. Never use graph scores, semantic labels, or unstated assumptions as proof."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"CURRENT HYPOTHESIS:\n{compact_json(hypothesis, 6000)}\n\n"
            f"CURRENT PROOF OBLIGATION ONLY:\n{compact_json(obligation_payload, 5000)}\n\n"
            f"SOURCE CODE CAPSULES FOR THIS OBLIGATION:\n{compact_json(code_bundle, 10000)}\n\n"
            "Return exactly one object in verifications for the current obligation. "
            "Use result = proven | refuted | partially_proven | not_answered. "
            "Interpret polarity exactly: if obligation.polarity is supports_hypothesis, a proven result supports the vulnerability; if it is refutes_hypothesis, a proven result is counter-evidence. "
            "For missing_* obligations, missing safety checks are vulnerability support, not refutation. "
            "If result is not proven, list the precise missing_evidence needed for this obligation only."
        )},
    ]
