from __future__ import annotations
import json
from typing import Any, Dict, List
from .schemas import CounterEvidenceReview, FinalDecision, KGQueryPlan, HypothesisVerification, VulnerabilityHypothesis

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
            "that later KG queries can test."
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
        '- call_neighborhood(target_function="<function>", direction="both", call_depth=2)\n'
        '- semantic_facts(target_function="<function>")\n'
        '- function_context(target_function="<function>", depth=2)\n'
        '- file_context(file="<relative/source/file.c>")\n'
        '- shortest_path(source_node="<node-id>", target_node="<node-id>")\n\n'
        "Prefer security_context for first-pass investigation. "
        "Prefer evidence_slice when a suspicious expression is known. "
        "Use variable_flow for suspicious symbols, call_neighborhood for caller/callee assumptions, "
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
            "Generate a compact, non-redundant plan: prefer 4 to 7 total queries. "
            "Prefer one security_context first, then evidence_slice for the most decisive suspicious "
            "expressions, variable_flow only for variables central to input control or bounds, and "
            "semantic_facts at most once. Do not classify vulnerability status at this stage."
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
            "Do not infer attacker control unless caller/input evidence supports it."
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
            "counter-evidence. 'Semantic fact says nearby_guard_not_seen' is not counter-evidence."
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
            "Final adjudicator. Decide vulnerable only if at least one hypothesis remains "
            "confirmed_vulnerability after counter-evidence and has a complete cited minimum proof. "
            "Decide fixed/non-vulnerable only when there is positive counter-evidence of safety: "
            "a guard, caller constraint, patched logic, safe invariant, or unreachable dangerous path. "
            "If local risk exists but the proof is incomplete and there is no positive safety evidence, "
            "prefer inconclusive. Keep local suspiciousness separate from confirmed vulnerability. "
            "Lack of proof should produce inconclusive unless positive counter-evidence supports safety."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(FinalDecision)}\n\n"
            f"TARGET FUNCTION:\n{fn}\n\n"
            f"VERIFICATIONS:\n{compact_json(verifications, 18000)}\n\n"
            f"COUNTER REVIEW:\n{compact_json(counter_review, 14000)}\n\n"
            f"EVIDENCE:\n{compact_json(evidence, 18000)}"
        )},
    ]


def consistency_repair_prompt(decision: Dict[str, Any], validation_notes: List[str]) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": (
            "Repair final-decision consistency only. You may downgrade unsupported vulnerability claims. "
            "You must not upgrade to vulnerable. Do not add new evidence. "
            "If validator notes say proof is incomplete, choose fixed/non-vulnerable when the existing "
            "decision/counter-evidence indicates safety; otherwise choose inconclusive."
        )},
        {"role": "user", "content": (
            f"{COMMON_TAG_CONTRACT}\n\n"
            f"ANSWER JSON SCHEMA:\n{schema_block(FinalDecision)}\n\n"
            f"VALIDATION NOTES:\n{json.dumps(validation_notes, indent=2)}\n\n"
            f"CURRENT DECISION:\n{compact_json(decision, 22000)}"
        )},
    ]
