from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .schemas import CounterEvidenceReview, EvidenceGapPlan, FinalDecision, KGQueryPlan, HypothesisVerification, VulnerabilityHypothesis

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
                    "kg_query_results", "initial_retrieval_evidence", "source_snippets"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit"],
    },
    "05_counter_evidence_review": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "current_verifications", "evidence"],
        "forbidden": ["sample_id", "project", "project_url", "label", "commit", "resolved_commit"],
    },
    "06_final_adjudication": {
        "allowed": ["system_prompt", "output_format", "schema", "target_function_name",
                    "verifications", "counter_review", "evidence_index"],
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
            "You are a source-only security hypothesis generator. "
            "Generate candidate vulnerability hypotheses from the target function source. "
            "Do not confirm vulnerabilities. Each hypothesis must identify a concrete risky operation, "
            "a plausible attacker/input-control question, a missing-guard question, and a proof question "
            "that later KG queries can test. Pay special attention to parsed length/count fields read "
            "from raw buffers, integer/pointer wraparound, and missing checks before pointer advancement. "
            "Do not collapse distinct values: a selector such as length_power is not the same as the "
            "runtime length value read from input."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"TARGET FUNCTION SOURCE:\n```c\n{target_source}\n```\n\n"
            "Generate 3 to 6 plausible vulnerability hypotheses from the target function source.\n"
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
    # Stage 02 plans deterministic CodeKG queries from the hypotheses only. It
    # intentionally does NOT receive retrieved/initial evidence or dataset
    # metadata (see STAGE_CONTEXT_POLICY). `initial_evidence` is accepted for
    # backward-compatible call sites but deliberately ignored.
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
        "Prefer security_context for first-pass investigation. "
        "Prefer evidence_slice when a suspicious expression is known. "
        "Use variable_flow for suspicious symbols, call_neighborhood(direction=\"in\") for caller/input-source assumptions, "
        "and semantic_facts for deterministic risk/guard evidence. "
        "Do not ask for arbitrary free-form graph access. "
        "Do not classify from the query name. "
        "Final reasoning must use returned source-grounded evidence, not invented code."
    )
    fn = _target_function_name(sample)
    target_file = _target_file(sample)
    file_block = f"OPTIONAL TARGET FILE:\n{target_file}\n\n" if target_file else ""
    return [
        {"role": "system", "content": (
            "Plan source-grounded CodeKG retrieval queries to prove and disprove each hypothesis. "
            "Generate a compact, non-redundant plan: prefer 5 to 8 total queries. "
            "Always include at least one caller/input-source query when attacker control is a required "
            "proof element, because vulnerable data often enters before the target function. "
            "Prefer one security_context first, then evidence_slice for the most decisive suspicious "
            "expressions, variable_flow for variables central to input control or bounds, "
            "call_neighborhood(direction=\"in\") for caller constraints, and semantic_facts at most once. "
            "Do not classify vulnerability status at this stage. "
            "For buffer parsers, prefer queries that test the chain raw/user buffer -> parsed length/count -> size arithmetic -> pointer/index advance."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"CODEKG QUERY CONTRACT:\n{codekg_contract}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(KGQueryPlan)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"{file_block}"
            f"HYPOTHESES:\n{compact_json(hypotheses, 12000)}\n\n"
            "Generate a minimal deterministic KG query plan that can test or falsify the hypotheses.\n"
            "Do not use prior retrieved evidence.\n"
            "Do not invent evidence.\n"
            "Do not classify vulnerability status at this stage."
        )},
    ]


def hypothesis_verification_prompt(
    sample: Dict[str, Any],
    hypotheses: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    # Stage 04: no SAMPLE block, no dataset/project metadata. Target function name
    # is extracted from the sample dict for orientation only.
    fn = _target_function_name(sample)
    schema = {"verifications": [HypothesisVerification.model_json_schema()]}
    return [
        {"role": "system", "content": (
            "Verify each hypothesis using only the provided evidence. "
            "A confirmed vulnerability requires a complete cited chain: "
            "input/control source → dangerous operation → missing or failed guard → "
            "unsafe use/reachability → security impact. "
            "If any element is missing, use plausible_but_unproven or insufficient_evidence. "
            "Distinguish local risky code from exploitability. "
            "Do not treat semantic-fact labels alone as proof of exploitability. "
            "Do not treat absence of evidence as evidence of safety. "
            "Do not infer attacker control unless caller/input evidence supports it. "
            "For parser code, distinguish the encoded-width selector (for example length_power) from "
            "the parsed runtime value (for example length = read(raw)); a guard on the selector does "
            "not by itself bound the parsed value. If caller/input-source evidence is missing, keep the "
            "hypothesis unresolved and make the missing caller/input evidence explicit. "
            "Treat deterministic_source_fact items as source-grounded evidence. A pointer-wraparound "
            "lower-bound guard (for example start = raw and raw >= start after raw advances) plus an "
            "exact-end error return can be positive safety evidence for wraparound-to-lower-address parser traversal risks."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"HYPOTHESES:\n{compact_json(hypotheses, 12000)}\n\n"
            f"ACCUMULATED EVIDENCE:\n{compact_json(evidence, 22000)}"
        )},
    ]


def counter_evidence_prompt(
    sample: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    # Stage 05: no SAMPLE block, no dataset/project metadata.
    fn = _target_function_name(sample)
    return [
        {"role": "system", "content": (
            "You are the defense reviewer. Try to falsify each non-refuted hypothesis using "
            "concrete evidence: guards, early returns, range checks, caller constraints, trusted "
            "data origins, safe APIs, bounded allocation/length invariants, patched logic, or "
            "unreachable paths. Missing proof is not itself a guard. "
            "If counter-evidence only weakens the proof, say 'weakens' rather than 'refutes'. "
            "Important: 'No evidence of attacker control' weakens confirmation but is not positive "
            "counter-evidence of safety. 'Caller validates parameter X before this function' can be "
            "counter-evidence. 'Guard checks X <= bound before dangerous operation' can be "
            "counter-evidence. 'Semantic fact says nearby_guard_not_seen' is not counter-evidence. "
            "A guard refutes a hypothesis only if it directly bounds the exact dangerous value or "
            "dominates the exact dangerous operation. A guard on a related selector (for example "
            "length_power) does NOT refute overflow of a parsed value (for example length = read(raw)). "
            "Do not claim a reader-selection guard bounds the attacker-controlled value returned by the reader. "
            "A saved-base lower-bound guard on the advanced pointer (for example start = raw and raw >= start) "
            "combined with an exact-end error return may directly refute pointer-wraparound traversal hypotheses, "
            "but only for that pointer-wraparound class of risk."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(CounterEvidenceReview)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"CURRENT VERIFICATIONS:\n{compact_json(verifications, 16000)}\n\n"
            f"EVIDENCE:\n{compact_json(evidence, 22000)}"
        )},
    ]


def final_decision_prompt(
    sample: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    counter_review: Dict[str, Any],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    # Stage 06: no SAMPLE block, no dataset/project metadata.
    fn = _target_function_name(sample)
    return [
        {"role": "system", "content": (
            "Final adjudicator. Output compact valid JSON only inside <answer>. "
            "You MUST choose exactly one binary prediction: vulnerable or fixed/non-vulnerable. "
            "Inconclusive is not allowed in the final answer. "
            "Decide vulnerable only when a complete cited chain exists or when bounded retrieval leaves an unguarded local risk not covered by deterministic safety evidence. "
            "Decide fixed/non-vulnerable when positive counter-evidence covers the remaining risk, including deterministic source facts. "
            "For pointer-overflow parser hypotheses, a deterministic source fact showing a saved-base lower-bound guard on the advanced pointer plus an exact-end error return is exact counter-evidence for wraparound-to-lower-address traversal. "
            "Never treat missing attacker-control evidence alone as safety evidence. "
            "Do not output markdown/code fences. Do not exceed 1800 words. "
            "For each final_hypothesis_statuses entry, always output a proof object; never output proof:null. "
            "Keep every string concise and cite evidence IDs only, not long copied snippets."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"COMPACT ANSWER CONTRACT (must validate against FinalDecision):\n{_FINAL_DECISION_COMPACT_CONTRACT}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"VERIFICATIONS:\n{compact_json(verifications, 12000)}\n\n"
            f"COUNTER REVIEW:\n{compact_json(counter_review, 9000)}\n\n"
            f"EVIDENCE DIGEST:\n{compact_json(_short_evidence_digest(evidence), 12000)}"
        )},
    ]


_CODEKG_QUERY_FORMS = (
    "Allowed query_text forms:\n"
    '- security_context(target_function="<fn>", depth=3, call_depth=2)\n'
    '- evidence_slice(target_function="<fn>", target_statement="<expr>", relation_depth=4)\n'
    '- variable_flow(target_function="<fn>", symbol="<var>", data_depth=4)\n'
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

    # Evidence index: id + kind only — no full text to stay within token budget
    evidence_index = [
        {"id": e.get("id") or e.get("evidence_id"), "kind": e.get("kind")}
        for e in (evidence or [])
    ]

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
            "Prioritize caller/input-source queries for missing attacker control and exact guard queries "
            "for missing overflow/bounds checks. Set needs_more_evidence=false with stop_reason_if_no_queries "
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
    evidence_index = [
        {"id": e.get("id") or e.get("evidence_id"), "kind": e.get("kind")}
        for e in (evidence or [])
    ]
    return [
        {"role": "system", "content": (
            "You are a security defense analyst. Generate follow-up CodeKG queries to find "
            "concrete counter-evidence: guards, early returns, range checks, caller constraints, "
            "safe invariants, bounded allocation, or patched logic. "
            "Only search for counter-evidence that directly applies to the exact dangerous operation/value. "
            "For example, a bound on length_power does not bound length = read(raw). "
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
