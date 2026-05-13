from __future__ import annotations
import json
from typing import Any, Dict, List
from .schemas import CounterEvidenceReview, FinalDecision, KGQueryPlan, HypothesisVerification, VulnerabilityHypothesis

COMMON_TAG_CONTRACT = """Return exactly:
<analysis>
A concise public evidence audit. State what evidence was checked, what remains missing, and why the JSON answer follows. Do not include hidden/private chain-of-thought.
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

def source_only_hypothesis_prompt(sample: Dict[str, Any], target_source: str) -> List[Dict[str, str]]:
    schema = {"hypotheses": [VulnerabilityHypothesis.model_json_schema()], "source_observations": ["string"], "non_vulnerability_possibilities": ["string"]}
    return [
        {"role":"system", "content":"You are a security-analysis agent. Generate possible vulnerability hypotheses from target source only. Do not claim confirmation. Do not use report-only metadata for prediction. Hypotheses are candidates, not findings."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nSCHEMA:\n{json.dumps(schema, indent=2)}\n\nSAMPLE METADATA, REPORT-ONLY EXCEPT identifiers:\n{compact_json(sample,6000)}\n\nTARGET FUNCTION SOURCE:\n```c\n{target_source}\n```\n\nGenerate plausible hypotheses and proof questions."},
    ]

def kg_query_planning_prompt(sample: Dict[str, Any], hypotheses: List[Dict[str, Any]], initial_evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    codekg_contract = """Use only the deterministic CodeKG query interface. Put one complete function-call-style query in each query_text field.
Allowed query_text forms:
- security_context(target_function="<function>", depth=3, call_depth=2, data_depth=4, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=520)
- evidence_slice(target_function="<function>", target_statement="<suspicious expression or statement>", relation_depth=4, data_depth=4, control_depth=3, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=450)
- variable_flow(target_function="<function>", symbol="<variable>", data_depth=4)
- call_neighborhood(target_function="<function>", direction="both", call_depth=2)
- semantic_facts(target_function="<function>")
- function_context(target_function="<function>", depth=2)
- file_context(file="<relative/source/file.c>")
- shortest_path(source_node="<node-id>", target_node="<node-id>")

Prefer security_context for first-pass investigation. Prefer evidence_slice when a suspicious expression is known. Use variable_flow for suspicious symbols, call_neighborhood for caller/callee assumptions, and semantic_facts for deterministic risk/guard evidence. Do not ask for arbitrary free-form graph access. Do not classify from the query name. Final reasoning must use returned source-grounded evidence, not invented code."""
    return [
        {"role":"system", "content":"Plan source-grounded CodeKG retrieval queries to prove and disprove each hypothesis. Do not ask for report-only labels or commit messages."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nCODEKG QUERY CONTRACT:\n{codekg_contract}\n\nANSWER JSON SCHEMA:\n{schema_block(KGQueryPlan)}\n\nSAMPLE:\n{compact_json(sample,4000)}\n\nHYPOTHESES:\n{compact_json(hypotheses,12000)}\n\nINITIAL EVIDENCE:\n{compact_json(initial_evidence,10000)}"},
    ]

def hypothesis_verification_prompt(sample: Dict[str, Any], hypotheses: List[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    schema = {"verifications": [HypothesisVerification.model_json_schema()]}
    return [
        {"role":"system", "content":"Verify hypotheses using evidence. Confirmed vulnerability requires a complete chain: attacker/input control -> dangerous operation -> missing/failed guard -> unsafe use -> security impact. Suspicious code, risky API use, pointer arithmetic, or absence of a visible check in a small excerpt is insufficient unless the evidence also supports exploitability and the missing/failed guard. Use plausible_but_unproven or insufficient_evidence when any proof element is missing."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nANSWER JSON SCHEMA:\n{json.dumps(schema, indent=2)}\n\nSAMPLE:\n{compact_json(sample,4000)}\n\nHYPOTHESES:\n{compact_json(hypotheses,12000)}\n\nACCUMULATED EVIDENCE:\n{compact_json(evidence,22000)}"},
    ]

def counter_evidence_prompt(sample: Dict[str, Any], verifications: List[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    return [
        {"role":"system", "content":"You are the defense reviewer. Try to falsify every non-refuted vulnerability hypothesis using guards, early returns, trusted data origins, caller constraints, indirect checks, safe API use, allocation/length invariants, and evidence that the operation is bounded. If counter-evidence makes the proof incomplete, recommend plausible_but_unproven or a refuted status."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nANSWER JSON SCHEMA:\n{schema_block(CounterEvidenceReview)}\n\nSAMPLE:\n{compact_json(sample,4000)}\n\nCURRENT VERIFICATIONS:\n{compact_json(verifications,16000)}\n\nEVIDENCE:\n{compact_json(evidence,22000)}"},
    ]

def final_decision_prompt(sample: Dict[str, Any], verifications: List[Dict[str, Any]], counter_review: Dict[str, Any], evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    return [
        {"role":"system", "content":"Final adjudicator. Decide vulnerable only if at least one hypothesis remains confirmed_vulnerability after counter-evidence and has a complete, evidence-cited minimum proof. If local risk exists but input control, missing guard, unsafe use, or security impact is not proven, predict fixed/non-vulnerable when counter-evidence indicates safety, otherwise inconclusive. Separate local suspiciousness from confirmed vulnerability."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nANSWER JSON SCHEMA:\n{schema_block(FinalDecision)}\n\nSAMPLE:\n{compact_json(sample,4000)}\n\nVERIFICATIONS:\n{compact_json(verifications,18000)}\n\nCOUNTER REVIEW:\n{compact_json(counter_review,14000)}\n\nEVIDENCE:\n{compact_json(evidence,18000)}"},
    ]

def consistency_repair_prompt(decision: Dict[str, Any], validation_notes: List[str]) -> List[Dict[str, str]]:
    return [
        {"role":"system", "content":"Repair final-decision consistency only. You may downgrade unsupported vulnerability claims. You must not upgrade to vulnerable. Do not add new evidence. If validator notes say proof is incomplete, choose fixed/non-vulnerable when the existing decision/counter-evidence indicates safety; otherwise choose inconclusive."},
        {"role":"user", "content":f"{COMMON_TAG_CONTRACT}\n\nANSWER JSON SCHEMA:\n{schema_block(FinalDecision)}\n\nVALIDATION NOTES:\n{json.dumps(validation_notes, indent=2)}\n\nCURRENT DECISION:\n{compact_json(decision,22000)}"},
    ]
