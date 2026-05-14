from __future__ import annotations

import html
import json
import os
import urllib.parse
from pathlib import Path
from typing import Any

from vuln_commit_kg.agents.schemas import AgentTrace, Prediction
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.retrieval.evidence import EvidenceItem, EvidencePack
from vuln_commit_kg.utils.jsonl import write_json, write_jsonl


LEAK_FIELDS = [
    "sample_id",
    "ground_truth_label",
    "dataset_commit",
    "resolved_commit",
    "patch_commit",
    "project_url",
    "commit_message",
    "cve_hints",
    "cwe_hints",
]


def _safe_name(value: str | None) -> str:
    raw = value or "unknown"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)[:140]


def _pre(text: Any, limit: int | None = None) -> str:
    s = text if isinstance(text, str) else json.dumps(text, indent=2, ensure_ascii=False)
    if limit and len(s) > limit:
        s = s[:limit] + "\n... <truncated in report>"
    return f"<pre>{html.escape(s)}</pre>"


def _link_if_exists(path: str | None, label: str, root: Path | None = None) -> str:
    if not path:
        return ""
    p = Path(path)
    href = str(path)
    try:
        if root is not None and p.exists():
            # Relative links work both in the file:// report and through the
            # live dashboard server, even when the persistent KG cache is a
            # sibling of the run directory rather than inside the sample report.
            href = os.path.relpath(p.resolve(), Path(root).resolve()).replace("\\", "/")
        elif p.exists():
            href = p.resolve().as_uri()
    except Exception:
        href = str(path)
    return f'<a href="{html.escape(str(href))}">{html.escape(label)}</a>'


def _kg_dashboard_query_links(step: dict[str, Any], root: Path | None = None) -> str:
    diag = step.get("diagnostics") if isinstance(step.get("diagnostics"), dict) else {}
    params = step.get("tool_parameters") if isinstance(step.get("tool_parameters"), dict) else {}
    dashboard_path = params.get("dashboard_path") or diag.get("dashboard_path")
    query_view_path = diag.get("query_view_path") or params.get("query_view_path")
    if not dashboard_path or not query_view_path:
        return ""
    try:
        dash = Path(str(dashboard_path)).resolve()
        view = Path(str(query_view_path)).resolve()
        if root is not None and dash.exists():
            href_base = os.path.relpath(dash, Path(root).resolve()).replace("\\", "/")
        elif dash.exists():
            href_base = dash.as_uri()
        else:
            href_base = str(dashboard_path)
        view_rel = os.path.relpath(view, dash.parent).replace("\\", "/")
        qs_highlight = urllib.parse.urlencode({"query_view": view_rel, "mode": "highlight"})
        qs_filter = urllib.parse.urlencode({"query_view": view_rel, "mode": "filter"})
        view_label = _link_if_exists(str(view), "query JSON", root)
        return (
            f'<div class="queryLinks">'
            f'<a class="btn" href="{html.escape(href_base + "?" + qs_highlight)}">highlight in KG dashboard</a>'
            f'<a class="btn" href="{html.escape(href_base + "?" + qs_filter)}">show only retrieved subgraph</a>'
            f'{" | " + view_label if view_label else ""}'
            f'</div>'
        )
    except Exception:
        return ""


def _has_placeholder(value: Any) -> bool:
    bad = [
        "short vulnerability category",
        "exact statement or short description",
        "function or API name",
        "bounds/null/auth check",
        "exact vulnerable statement if any",
        "brief evidence-based explanation",
        "SELECT * FROM code",
    ]
    s = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    low = s.lower()
    return any(x.lower() in low for x in bad)


def _privacy_scan(
    *,
    sample: SecVulEvalSample,
    trace: AgentTrace,
    prediction: Prediction,
    prompting_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Stage-aware prompt metadata leakage scan.

    The post-hoc commit audit is intentionally allowed to see commit metadata
    after the final prediction. Pre-decision prompts must not see labels, CVEs,
    CWEs, commit IDs/messages, or ground-truth fields unless explicitly enabled.
    """
    pre_decision_calls = [c for c in trace.model_calls if str(c.get("name")) != "posthoc_commit_reasoning_audit"]
    posthoc_calls = [c for c in trace.model_calls if str(c.get("name")) == "posthoc_commit_reasoning_audit"]
    pre_prompts = "\n\n---PROMPT---\n\n".join(str(call.get("prompt", "")) for call in pre_decision_calls)
    posthoc_prompts = "\n\n---PROMPT---\n\n".join(str(call.get("prompt", "")) for call in posthoc_calls)
    cfg = prompting_config or {}

    def scan(prompts: str, *, posthoc: bool) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def add(field: str, value: str | None, allowed: bool = False) -> None:
            if not value:
                return
            present = value in prompts
            checks.append({
                "field": field,
                "value_preview": value[:80],
                "present_in_model_prompts": present,
                "allowed_by_stage_or_config": bool(allowed),
            })

        metadata_allowed = bool(cfg.get("include_orchestration_metadata_in_model_prompt", False))
        # The post-hoc audit is generated after the binary prediction and is
        # explicitly report-only.  It may show identifiers/commit metadata for
        # debugging semantic alignment, while pre-decision prompts remain strict.
        report_only_allowed = bool(posthoc)
        add("sample_id", sample.sample_id, report_only_allowed or metadata_allowed)
        add("ground_truth_label_field", "ground_truth_label", metadata_allowed)
        add("dataset_commit", sample.commit_id, report_only_allowed or metadata_allowed)
        add("resolved_commit", prediction.resolved_commit_id, report_only_allowed or metadata_allowed)
        add("project_url", sample.project_url, report_only_allowed or metadata_allowed)
        add("commit_message", sample.commit_message, report_only_allowed or metadata_allowed)
        for cwe in sample.cwe_list or []:
            add("cwe_hints", str(cwe), bool(cfg.get("include_cwe_hints_in_model_prompt", False)))
        for cve in sample.cve_list or []:
            add("cve_hints", str(cve), bool(cfg.get("include_cve_hints_in_model_prompt", False)))
        unexpected = [c for c in checks if c["present_in_model_prompts"] and not c["allowed_by_stage_or_config"]]
        return {
            "unexpected_leaks_found": bool(unexpected),
            "unexpected_leaks": unexpected,
            "checks": checks,
            "num_model_calls_scanned": len(posthoc_calls if posthoc else pre_decision_calls),
        }

    pre = scan(pre_prompts, posthoc=False)
    post = scan(posthoc_prompts, posthoc=True)
    return {
        "prompting_config": cfg,
        "pre_decision": pre,
        "posthoc_report_only": post,
        "unexpected_leaks_found": bool(pre.get("unexpected_leaks_found")),
        "unexpected_leaks": pre.get("unexpected_leaks", []),
        "checks": pre.get("checks", []),
        "note": "Function name, filepath, target source, evidence IDs, evidence text, and line numbers are intentionally model-visible. Dataset labels, commit IDs, and commit messages are disallowed before the final decision and allowed only inside post-hoc report-only audit/report sections.",
    }


def _initial_evidence(evidence: EvidencePack, trace: AgentTrace, *, hide: bool = False) -> list[EvidenceItem]:
    if hide:
        return []
    n = int(trace.initial_evidence_count or len(evidence.items))
    return evidence.items[:n]


def _kg_tool_evidence_items(evidence: EvidencePack, trace: AgentTrace, *, fallback_to_all: bool = False) -> list[EvidenceItem]:
    ids: list[str] = []
    for step in trace.kg_tool_steps or []:
        for raw in step.get("items", []) or []:
            if isinstance(raw, dict) and raw.get("evidence_id"):
                ids.append(str(raw["evidence_id"]))
    if not ids and fallback_to_all:
        return list(evidence.items)
    wanted = set(ids)
    return [item for item in evidence.items if str(item.evidence_id) in wanted or item.kind.startswith("tool")]


def _demo_report_options(report_options: dict[str, Any] | None) -> dict[str, Any]:
    return dict(report_options or {})



def _kind_counts(items: list[dict[str, Any]] | list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items or []:
        kind = None
        if isinstance(item, dict):
            kind = item.get("kind")
        else:
            kind = getattr(item, "kind", None)
        kind = str(kind or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _target_source_anchor(evidence: EvidencePack) -> tuple[str | None, str | None, int | None]:
    """Return target relpath/function/start-line for function-relative reporting."""
    relpath = None
    function = None
    start = None
    node_id = evidence.target_node_id or ""
    # Current node IDs look like function:src/webadmin.c:adminchild:337.
    if node_id.startswith("function:"):
        parts = node_id.split(":")
        if len(parts) >= 4:
            relpath = parts[1]
            function = parts[2]
            try:
                start = int(parts[3])
            except Exception:
                start = None
    if relpath is None or function is None:
        for item in evidence.items:
            if item.kind.startswith("target") and item.relpath and item.function:
                relpath = relpath or item.relpath
                function = function or item.function
                break
    return relpath, function, start


def _location_with_relative(item: EvidenceItem, *, target_relpath: str | None = None, target_function: str | None = None, target_start_line: int | None = None) -> str:
    abs_loc = f"{item.relpath or ''}:{item.line_start or ''}-{item.line_end or ''}"
    if target_start_line is None or item.line_start is None:
        return abs_loc
    if target_relpath and item.relpath and item.relpath != target_relpath:
        return abs_loc
    if target_function and item.function and item.function != target_function:
        return abs_loc
    try:
        rel_start = int(item.line_start) - int(target_start_line) + 1
        rel_end = int(item.line_end or item.line_start) - int(target_start_line) + 1
    except Exception:
        return abs_loc
    if rel_start <= 0:
        return abs_loc
    return f"{abs_loc}\nfunction-relative: {rel_start}-{rel_end}"


def _final_stage_raw_and_accepted(trace: AgentTrace) -> dict[str, Any]:
    primary = None
    repair = None
    for call in trace.model_calls:
        if call.get("name") == "final_decision":
            primary = call
        elif call.get("name") == "final_decision_consistency_repair":
            repair = call
    accepted = _accepted_final_json(trace)
    return {
        "raw_final_model_decision": (primary or {}).get("parsed") if isinstance(primary, dict) else None,
        "raw_final_json_status": (primary or {}).get("json_status") if isinstance(primary, dict) else None,
        "raw_final_parse_error": (primary or {}).get("parse_error") if isinstance(primary, dict) else None,
        "consistency_repair_decision": (repair or {}).get("parsed") if isinstance(repair, dict) else None,
        "accepted_final_decision": accepted,
        "validator_modified": bool(trace.final_validator_modifications),
        "validator_modifications": trace.final_validator_modifications,
    }


def _evidence_lookup(evidence: EvidencePack) -> dict[str, EvidenceItem]:
    return {str(item.evidence_id): item for item in evidence.items}


def _collect_report_only_evidence_ids(trace: AgentTrace, prediction: Prediction) -> list[str]:
    ids: list[str] = []
    ids.extend([str(x) for x in prediction.evidence_used or []])
    for stmt in prediction.vuln_statements:
        if stmt.evidence_id:
            ids.append(str(stmt.evidence_id))
    audit = trace.posthoc_commit_audit if isinstance(trace.posthoc_commit_audit, dict) else {}
    ids.extend([str(x) for x in audit.get("evidence_ids_checked", []) or []])
    # Keep deterministic order and avoid duplicates.
    seen = set()
    out = []
    for eid in ids:
        if eid and eid not in seen:
            seen.add(eid)
            out.append(eid)
    return out


def _report_only_ground_truth_comparison(sample: SecVulEvalSample, evidence: EvidencePack, trace: AgentTrace, prediction: Prediction) -> dict[str, Any]:
    lookup = _evidence_lookup(evidence)
    target_relpath, target_function, target_start = _target_source_anchor(evidence)
    evidence_rows = []
    for eid in _collect_report_only_evidence_ids(trace, prediction):
        item = lookup.get(str(eid))
        if not item:
            continue
        evidence_rows.append({
            "evidence_id": item.evidence_id,
            "kind": item.kind,
            "location": _location_with_relative(item, target_relpath=target_relpath, target_function=target_function, target_start_line=target_start),
            "function": item.function,
            "code": item.text,
        })
    audit = trace.posthoc_commit_audit if isinstance(trace.posthoc_commit_audit, dict) else {}
    return {
        "report_only_warning": "This section is generated after prediction. It may show dataset labels and commit messages for evaluation/demo only and is never placed in pre-decision prompts.",
        "ground_truth": {
            "dataset_label": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
            "is_vulnerable": bool(sample.is_vulnerable),
            "dataset_commit": sample.commit_id,
            "commit_message": sample.commit_message,
        },
        "system_prediction": {
            "is_vulnerable": bool(prediction.is_vulnerable),
            "decision_status": prediction.decision_status,
            "confidence": prediction.confidence,
            "primary_vulnerability_type": prediction.primary_vulnerability_type,
            "reasoning_summary": prediction.reasoning_summary,
            "binary_prediction_policy": prediction.binary_prediction_policy,
        },
        "raw_vs_final_decision_flow": _final_stage_raw_and_accepted(trace),
        "posthoc_commit_message_audit": audit,
        "code_evidence_used_in_final_or_audit": evidence_rows[:40],
    }

def _decision_flow(
    *,
    sample: SecVulEvalSample,
    evidence: EvidencePack,
    trace: AgentTrace,
    prediction: Prediction,
    dataset_path: str | None,
    graph_manifest: dict[str, Any] | None,
    graph_status: str | None,
    graph_dir: str | None,
    validation_artifact_dir: str | None,
    prompting_config: dict[str, Any] | None,
    report_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opts = _demo_report_options(report_options)
    initial_items = _initial_evidence(evidence, trace, hide=bool(opts.get("hide_initial_deterministic_retrieval")))
    return {
        "A_dataset_and_target_setup": {
            "dataset_file_loaded": dataset_path,
            "sample_id": sample.sample_id,
            "selected_sample": sample.sample_id,
            "dataset_label_report_only": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
            "ground_truth_label_report_only": "vulnerable" if sample.is_vulnerable else "fixed/non-vulnerable",
            "project": sample.project,
            "project_url": sample.project_url,
            "filepath": sample.filepath,
            "function": sample.func_name,
            "dataset_commit_report_only": sample.commit_id,
            "resolved_commit_report_only": prediction.resolved_commit_id,
            "resolved_commit_label_report_only": prediction.resolved_commit_label,
            "snapshot_semantics_report_only": _snapshot_semantics_from_label(prediction.resolved_commit_label),
            "snapshot_semantics_consistency_check": "ok" if _snapshot_semantics_from_label(prediction.resolved_commit_label) in {"pre_fix_parent", "patch_commit", None} else "unknown",
            "commit_message_report_only": sample.commit_message,
            "resolution_reason": _resolution_reason(prediction.resolved_commit_label),
            "target_validation_status": prediction.target_validation_status,
            "target_validation_similarity": prediction.target_validation_similarity,
            "target_validation_artifact_dir": validation_artifact_dir or prediction.target_validation_artifact_dir,
        },
        "B_kg_construction_loading": {
            "status": graph_status,
            "graph_dir": graph_dir,
            "codekg_dashboard": (graph_manifest or {}).get("dashboard_path"),
            "codekg_artifacts": (graph_manifest or {}).get("codekg_graph_dir") or graph_dir,
            "kg_version": (graph_manifest or {}).get("kg_version"),
            "backend_used": (graph_manifest or {}).get("backend_used") or (graph_manifest or {}).get("backend"),
            "backend_requested": (graph_manifest or {}).get("backend_requested"),
            "fallback_used": (graph_manifest or {}).get("fallback_used"),
            "joern_available": (graph_manifest or {}).get("joern_available"),
            "java_available": (graph_manifest or {}).get("java_available"),
            "resolved_commit_used_report_only": prediction.resolved_commit_id,
            "num_files": (graph_manifest or {}).get("num_files"),
            "num_functions": (graph_manifest or {}).get("num_functions"),
            "num_statements": (graph_manifest or {}).get("num_statements"),
            "num_macro_definitions": (graph_manifest or {}).get("num_macro_definitions"),
            "num_global_definitions": (graph_manifest or {}).get("num_global_definitions"),
            "num_nodes": (graph_manifest or {}).get("num_nodes") or (graph_manifest or {}).get("number_of_nodes"),
            "num_edges": (graph_manifest or {}).get("num_edges") or (graph_manifest or {}).get("number_of_edges"),
            "node_type_counts": (graph_manifest or {}).get("node_type_counts"),
            "edge_type_counts": (graph_manifest or {}).get("edge_type_counts"),
            "graph_quality_diagnostics": {
                "quality_metrics": (graph_manifest or {}).get("quality_metrics"),
                "quality_warnings": (graph_manifest or {}).get("quality_warnings"),
                "parse_errors": (graph_manifest or {}).get("parse_errors"),
                "skipped_files": (graph_manifest or {}).get("skipped_files"),
                "parser_confidence": ((graph_manifest or {}).get("quality_metrics") or {}).get("parser_confidence_level"),
            },
            "source_file_filters": (graph_manifest or {}).get("include_file_types"),
            "source_integrity_statement": "KG was built only from repository source code; labels/CVE/commit metadata were not inserted into KG.",
            "representation": {
                "methodology": (graph_manifest or {}).get("kg_methodology"),
                "layers": (graph_manifest or {}).get("layers"),
                "note": (graph_manifest or {}).get("kg_representation_note"),
            },
            "manifest": graph_manifest or {},
        },
        "C_initial_deterministic_retrieval": {
            "target_function_found": evidence.target_found,
            "target_function_node": evidence.target_node_id,
            "initial_evidence_items": len(initial_items),
            "evidence_ids": [i.evidence_id for i in initial_items],
        },
        "D_to_F_model_calls_and_json_repair": [
            {
                "name": c.get("name"),
                "json_status": c.get("json_status"),
                "parse_error": c.get("parse_error"),
                "repair_attempts": len(c.get("repair_attempts", [])),
                "mechanical_normalizations": c.get("mechanical_normalizations", []),
                "usage": c.get("total_stage_usage") or c.get("usage"),
            }
            for c in trace.model_calls
        ],
        "E_kg_tool_rounds": [
            {
                "round": s.get("round_index"),
                "query_index": s.get("query_index"),
                "query_object": s.get("query_object"),
                "query_type": s.get("query_type"),
                "query": s.get("query"),
                "reason": s.get("reason"),
                "source": s.get("source"),
                "status": s.get("status"),
                "returned_items": len(s.get("items", [])),
                "returned_evidence_ids": [i.get("evidence_id") for i in s.get("items", []) if isinstance(i, dict)],
                "returned_kind_counts": _kind_counts(s.get("items", [])),
                "returned_evidence_preview": s.get("items", [])[:20],
                "kg_dashboard_path": ((s.get("tool_parameters") or {}).get("dashboard_path") if isinstance(s.get("tool_parameters"), dict) else None) or ((s.get("diagnostics") or {}).get("dashboard_path") if isinstance(s.get("diagnostics"), dict) else None),
                "query_view_path": ((s.get("diagnostics") or {}).get("query_view_path") if isinstance(s.get("diagnostics"), dict) else None),
            }
            for s in trace.kg_tool_steps
        ],
        "F_hypothesis_ledger": trace.hypothesis_ledger,
        "F_verification_rounds": trace.verification,
        "G_final_prediction_and_evaluation": {
            "accepted_final_json": _accepted_final_json(trace),
            "raw_vs_accepted_decision_flow": _final_stage_raw_and_accepted(trace),
            "final_validator_modifications": trace.final_validator_modifications,
            "binary_prediction": {
                "is_vulnerable": prediction.is_vulnerable,
                "confidence": prediction.confidence,
                "primary_vulnerability_type": prediction.primary_vulnerability_type,
                "vuln_statements": [x.model_dump(mode="json") for x in prediction.vuln_statements],
                "evidence_used": prediction.evidence_used,
                "decision_status": prediction.decision_status,
                "binary_prediction_policy": prediction.binary_prediction_policy,
                "reasoning_summary": prediction.reasoning_summary,
                "parse_error": prediction.parse_error,
                "validation_notes": prediction.validation_notes,
            },
            "ground_truth_comparison_report_only": {
                "ground_truth_is_vulnerable": sample.is_vulnerable,
                "prediction_correct": prediction.is_vulnerable == sample.is_vulnerable if prediction.parse_error is None else False,
            },
        },
        "I_posthoc_commit_reasoning_audit_report_only": trace.posthoc_commit_audit,
        "J_report_only_ground_truth_vs_prediction_comparison": _report_only_ground_truth_comparison(sample, evidence, trace, prediction),
        "H_machine_readable_artifacts": {
            "index.html": "Human-readable report",
            "decision_flow.json": "Complete structured trace",
            "decision_summary.md": "Compact summary",
            "model_calls.jsonl": "One logical model stage per line, including JSON repair attempts",
            "kg_tool_calls.jsonl": "One KG tool query per line",
            "evidence_initial.json": "Deterministic evidence before KG tool follow-up; omitted when hidden by report config",
            "evidence_displayed.json": "Evidence rows displayed in the HTML demo under the active report-evidence policy",
            "evidence_accumulated.json": "All evidence after KG tool follow-up",
            "final_prediction.json": "Final parsed prediction/evaluation payload",
            "posthoc_commit_audit.json": "Report-only audit comparing final reasoning with commit-message semantics",
            "report_only_ground_truth_comparison.json": "Post-prediction side-by-side ground truth, final reasoning, commit message, and cited code evidence",
            "prompt_*.txt": "Exact model-visible prompts",
            "raw_response_*.txt": "Raw model responses",
            "parsed_response_*.json": "Parsed JSON/status per model stage",
            "repair_prompt_*.txt": "JSON repair prompts when needed",
            "repair_response_*.txt": "Raw JSON repair responses when needed",
            "privacy_scan.json": "Prompt metadata-leakage scan",
        },
    }


def _resolution_reason(label: str | None) -> str:
    if label == "pre_fix_parent_for_vulnerable":
        return "SecVulEval patch semantics: vulnerable rows are checked out at the first parent/pre-fix commit."
    if label == "patch_commit_for_fixed":
        return "SecVulEval patch semantics: fixed rows are checked out at the patch commit."
    if label:
        return f"Selected by configured commit resolution strategy: {label}."
    return "No resolved label available."



def _snapshot_semantics_from_label(label: str | None) -> str | None:
    if label == "pre_fix_parent_for_vulnerable":
        return "pre_fix_parent"
    if label == "patch_commit_for_fixed":
        return "patch_commit"
    return None


def _accepted_final_json(trace: AgentTrace) -> dict[str, Any] | None:
    if trace.final_validator_modifications:
        last = trace.final_validator_modifications[-1]
        if isinstance(last, dict) and isinstance(last.get("after"), dict):
            return last.get("after")
    repaired = None
    primary = None
    for call in trace.model_calls:
        if call.get("name") == "final_decision" and isinstance(call.get("parsed"), dict):
            primary = call.get("parsed")
        if call.get("name") == "final_decision_consistency_repair" and isinstance(call.get("parsed"), dict):
            repaired = call.get("parsed")
    return repaired or primary


def write_sample_agent_demo(
    *,
    run_dir: Path,
    sample: SecVulEvalSample,
    evidence: EvidencePack,
    trace: AgentTrace,
    prediction: Prediction,
    dataset_path: str | None = None,
    graph_manifest: dict[str, Any] | None = None,
    graph_status: str | None = None,
    graph_dir: str | None = None,
    validation_artifact_dir: str | None = None,
    prompting_config: dict[str, Any] | None = None,
    report_options: dict[str, Any] | None = None,
) -> Path:
    root = run_dir / "agent_demos" / f"sample_{_safe_name(sample.sample_id)}_{_safe_name(sample.func_name)}"
    root.mkdir(parents=True, exist_ok=True)

    opts = _demo_report_options(report_options)
    initial_items = _initial_evidence(evidence, trace, hide=bool(opts.get("hide_initial_deterministic_retrieval")))
    privacy = _privacy_scan(sample=sample, trace=trace, prediction=prediction, prompting_config=prompting_config)
    flow = _decision_flow(
        sample=sample,
        evidence=evidence,
        trace=trace,
        prediction=prediction,
        dataset_path=dataset_path,
        graph_manifest=graph_manifest,
        graph_status=graph_status,
        graph_dir=graph_dir,
        validation_artifact_dir=validation_artifact_dir,
        prompting_config=prompting_config,
        report_options=opts,
    )

    write_json(root / "sample.json", sample.model_dump(mode="json"))
    if not bool(opts.get("hide_initial_deterministic_retrieval")):
        write_json(root / "evidence_initial.json", [i.model_dump(mode="json") for i in initial_items])
    display_items = _kg_tool_evidence_items(evidence, trace) if bool(opts.get("show_only_kg_tool_evidence")) else list(evidence.items)
    write_json(root / "evidence_displayed.json", [i.model_dump(mode="json") for i in display_items])
    write_json(root / "evidence_accumulated.json", evidence.model_dump(mode="json"))
    write_json(root / "evidence_pack.json", evidence.model_dump(mode="json"))  # legacy alias
    write_json(root / "agent_trace.json", trace.model_dump(mode="json"))
    write_json(root / "final_prediction.json", prediction.model_dump(mode="json"))
    write_json(root / "prediction.json", prediction.model_dump(mode="json"))  # legacy alias
    write_json(root / "posthoc_commit_audit.json", trace.posthoc_commit_audit)
    write_json(root / "final_validator_modifications.json", trace.final_validator_modifications)
    write_json(root / "report_only_ground_truth_comparison.json", flow.get("J_report_only_ground_truth_vs_prediction_comparison", {}))
    write_json(root / "decision_flow.json", flow)
    write_json(root / "privacy_scan.json", privacy)
    write_jsonl(root / "model_calls.jsonl", trace.model_calls)
    write_jsonl(root / "kg_tool_calls.jsonl", trace.kg_tool_steps)
    (root / "target_function.c").write_text(sample.func_body or "", encoding="utf-8")
    (root / "decision_summary.md").write_text(
        _render_markdown_summary(sample, evidence, trace, prediction, flow, privacy),
        encoding="utf-8",
    )

    for i, call in enumerate(trace.model_calls, start=1):
        name = _safe_name(str(call.get("name", "call")))
        prompt_text = call.get("prompt", "")
        if not prompt_text and call.get("system"):
            prompt_text = str(call.get("system", "")) + "\n\n" + str(call.get("user", ""))
        response_text = call.get("response", call.get("raw", call.get("content", "")))
        (root / f"prompt_{i:02d}_{name}.txt").write_text(str(prompt_text), encoding="utf-8")
        (root / f"raw_response_{i:02d}_{name}.txt").write_text(str(response_text), encoding="utf-8")
        write_json(
            root / f"parsed_response_{i:02d}_{name}.json",
            {
                "json_status": call.get("json_status"),
                "parsed": call.get("parsed"),
                "parse_error": call.get("parse_error"),
                "usage": call.get("total_stage_usage") or call.get("usage"),
            },
        )
        for repair in call.get("repair_attempts", []) or []:
            attempt = int(repair.get("attempt", 0))
            (root / f"repair_prompt_{i:02d}_{name}_{attempt}.txt").write_text(str(repair.get("prompt", "")), encoding="utf-8")
            (root / f"repair_response_{i:02d}_{name}_{attempt}.txt").write_text(str(repair.get("response", "")), encoding="utf-8")
            write_json(
                root / f"repair_parsed_{i:02d}_{name}_{attempt}.json",
                {"parsed": repair.get("parsed"), "parse_error": repair.get("parse_error"), "usage": repair.get("usage")},
            )

    with (root / "evidence_items.tsv").open("w", encoding="utf-8") as f:
        f.write("evidence_id\tkind\trelpath\tfunction\tline_start\tline_end\tscope\tmatched_symbol\tmatch_type\ttrust\tscore\twhy_selected\ttext\n")
        for item in evidence.items:
            text = (item.text or "").replace("\n", "\\n").replace("\t", " ")
            why = _why_selected(item).replace("\t", " ")
            f.write(f"{item.evidence_id}\t{item.kind}\t{item.relpath or ''}\t{item.function or ''}\t{item.line_start or ''}\t{item.line_end or ''}\t{item.scope or ''}\t{item.matched_symbol or ''}\t{item.match_type or ''}\t{item.trust or ''}\t{item.score}\t{why}\t{text}\n")

    html_path = root / "index.html"
    html_path.write_text(
        _render_html(
            sample=sample,
            evidence=evidence,
            trace=trace,
            prediction=prediction,
            flow=flow,
            privacy=privacy,
            dataset_path=dataset_path,
            graph_manifest=graph_manifest,
            graph_status=graph_status,
            graph_dir=graph_dir,
            validation_artifact_dir=validation_artifact_dir,
            root=root,
            report_options=opts,
        ),
        encoding="utf-8",
    )
    return html_path


def _why_selected(item: EvidenceItem) -> str:
    if item.kind.startswith("target_risk") or item.metadata.get("risk_hits"):
        return "target statement with risky API/pattern hit"
    if item.kind.startswith("target_safety") or item.metadata.get("is_safety"):
        return "target statement classified as safety/guard evidence"
    if item.kind.startswith("target"):
        return "target function statement neighborhood"
    if "callee" in item.kind:
        return "direct callee context"
    if "caller" in item.kind:
        return "direct caller context"
    if item.kind.startswith("tool"):
        return "returned by KG tool query"
    return "deterministic retrieval result"


def _render_markdown_summary(
    sample: SecVulEvalSample,
    evidence: EvidencePack,
    trace: AgentTrace,
    prediction: Prediction,
    flow: dict[str, Any],
    privacy: dict[str, Any],
) -> str:
    placeholder_warning = any(_has_placeholder(call.get("response", "")) for call in trace.model_calls)
    final_status = next((c.get("json_status") for c in trace.model_calls if c.get("name") == "final_decision"), "unknown")
    lines = [
        f"# Agent decision summary: sample {sample.sample_id} / {sample.func_name}",
        "",
        f"- Label in dataset, report-only: {'vulnerable' if sample.is_vulnerable else 'fixed/non-vulnerable'}",
        f"- Dataset commit, report-only: {prediction.dataset_commit_id}",
        f"- Resolved KG commit, report-only: {prediction.resolved_commit_id} ({prediction.resolved_commit_label})",
        f"- Target validation: {prediction.target_validation_status} ({prediction.target_validation_similarity})",
        f"- Initial evidence items: {trace.initial_evidence_count}",
        f"- Accumulated evidence items: {len(evidence.items)}",
        f"- Final parsed prediction: is_vulnerable={prediction.is_vulnerable}, confidence={prediction.confidence}, decision_status={prediction.decision_status or 'unknown'}",
        f"- Final reasoning summary: {prediction.reasoning_summary or 'none'}",
        f"- Commit-message audit alignment: {trace.posthoc_commit_audit.get('semantic_alignment', 'not run') if isinstance(trace.posthoc_commit_audit, dict) else 'not run'}",
        f"- Final JSON status: {final_status}",
        f"- Parse error: {prediction.parse_error or 'none'}",
        f"- Pre-decision metadata leakage detected: {'YES' if privacy.get('unexpected_leaks_found') else 'no'}",
        f"- Placeholder warning: {'YES - model copied schema/placeholder text' if placeholder_warning else 'no'}",
        "",
        "## What happened",
        f"1. SecVulEval row was selected and exact target validation reported `{prediction.target_validation_status}`.",
        "2. The KG was loaded/built from repository source only; labels/CVE/commit metadata were excluded from KG contents.",
        f"3. Initial deterministic retrieval supplied {trace.initial_evidence_count} evidence items.",
        f"4. The model produced {len(trace.risk_hypotheses)} risk hypotheses and {len(trace.kg_queries)} KG queries/fallback queries.",
        f"5. The KG tool executed {len(trace.kg_tool_steps)} query steps.",
        "6. Ground truth was compared only after the final prediction.",
        "",
        "## Final prediction",
        "```json",
        json.dumps(prediction.model_dump(mode="json"), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Decision flow",
        "```json",
        json.dumps(flow, indent=2, ensure_ascii=False),
        "```",
    ]
    return "\n".join(lines) + "\n"


def _evidence_table(
    items: list[EvidenceItem],
    *,
    target_relpath: str | None = None,
    target_function: str | None = None,
    target_start_line: int | None = None,
) -> str:
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.evidence_id)}</td>"
            f"<td>{html.escape(item.kind)}</td>"
            f"<td><pre>{html.escape(_location_with_relative(item, target_relpath=target_relpath, target_function=target_function, target_start_line=target_start_line))}</pre></td>"
            f"<td>{html.escape(str(item.function or ''))}</td>"
            f"<td>{html.escape(f'{item.score:.2f}')}</td>"
            f"<td>{html.escape(str(item.scope or ''))}</td>"
            f"<td>{html.escape(str(item.match_type or ''))}<br>{html.escape(str(item.matched_symbol or ''))}</td>"
            f"<td>{html.escape(str(item.trust or ''))}</td>"
            f"<td>{html.escape(_why_selected(item))}</td>"
            f"<td><pre>{html.escape((item.text or '')[:1400])}</pre></td>"
            "</tr>"
        )
    return "<div class='tableWrap'><table><thead><tr><th>ID</th><th>Kind</th><th>Location<br><span style='font-weight:400'>absolute + function-relative when target-local</span></th><th>Function</th><th>Score</th><th>Scope</th><th>Match</th><th>Trust</th><th>Why selected</th><th>Text</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"


def _call_section(call: dict[str, Any], index: int) -> str:
    prompt_text = call.get("prompt", "")
    if not prompt_text and call.get("system"):
        prompt_text = str(call.get("system", "")) + "\n\n" + str(call.get("user", ""))
    response_text = call.get("response", call.get("raw", call.get("content", "")))
    usage = call.get("total_stage_usage") or call.get("usage", {}) or {}
    copied_placeholder = _has_placeholder(response_text)
    warning_html = '<p class="bad">Warning: response appears to copy schema/placeholder text.</p>' if copied_placeholder else ""
    repairs = []
    for repair in call.get("repair_attempts", []) or []:
        repairs.append(
            f"<details><summary>Repair attempt {html.escape(str(repair.get('attempt')))} prompt</summary>{_pre(repair.get('prompt', ''), None)}</details>"
            f"<details><summary>Repair attempt {html.escape(str(repair.get('attempt')))} raw response</summary>{_pre(repair.get('response', ''), None)}</details>"
            f"<details><summary>Repair attempt {html.escape(str(repair.get('attempt')))} parse result</summary>{_pre({'parsed': repair.get('parsed'), 'parse_error': repair.get('parse_error'), 'usage': repair.get('usage')})}</details>"
        )
    elapsed = round(float(call.get("elapsed_seconds") or 0.0), 2)
    json_status = str(call.get("json_status") or "")
    name = str(call.get("name") or "model_call")
    return (
        f"<section class='auditCard modelCall' data-audit-card data-kind='model' data-title='{html.escape(name)}'>"
        f"<div class='sectionHead'><div><div class='eyebrow'>LLM call {index}</div><h3>{html.escape(name)}</h3></div>"
        f"<div class='chipRow'><span class='chip'>{html.escape(json_status or 'json')}</span>"
        f"<span class='chip'>repairs {len(call.get('repair_attempts', []) or [])}</span><span class='chip'>{elapsed}s</span></div></div>"
        f"{warning_html}"
        f"<div class='metricStrip'><span>Prompt chars <b>{len(str(prompt_text))}</b></span><span>Response chars <b>{len(str(response_text))}</b></span>"
        f"<span>Prompt tokens <b>{html.escape(str(usage.get('prompt_tokens', '')))}</b></span><span>Completion <b>{html.escape(str(usage.get('completion_tokens', '')))}</b></span><span>Total <b>{html.escape(str(usage.get('total_tokens', '')))}</b></span></div>"
        f"<details><summary>Exact prompt visible to the model</summary>{_pre(prompt_text, None)}</details>"
        f"<details open><summary>Raw LLM response</summary>{_pre(response_text, None)}</details>"
        f"<details open><summary>JSON parse/validation result</summary>{_pre({'json_status': call.get('json_status'), 'parsed': call.get('parsed'), 'parse_error': call.get('parse_error')})}</details>"
        f"{''.join(repairs) if repairs else '<p class=\"quiet\">No JSON repair was needed for this call.</p>'}"
        f"<details><summary>Usage and timing</summary>{_pre({'usage': usage, 'elapsed_seconds': call.get('elapsed_seconds')})}</details>"
        "</section>"
    )


def _tool_section(step: dict[str, Any], *, root: Path | None = None) -> str:
    items = [EvidenceItem.model_validate(x) for x in step.get("items", [])]
    source = str(step.get("source") or "model_generated")
    if source == "fallback_generated":
        source_text = "fallback-generated because the model output could not be parsed/repaired"
    elif source == "model_generated_after_json_repair":
        source_text = "model-generated after JSON repair"
    else:
        source_text = "model-generated"
    query_links = _kg_dashboard_query_links(step, root)
    reason = step.get('reason') or (step.get('query_object') or {}).get('reason') if isinstance(step.get('query_object'), dict) else step.get('reason')
    qid = html.escape(str(step.get('query_index')))
    round_id = html.escape(str(step.get('round_index')))
    query_type = html.escape(str(step.get('query_type')))
    status = html.escape(str(step.get('status')))
    return (
        f"<section class='auditCard kgQueryCard' data-audit-card data-kind='kg' data-title='Q{qid} {query_type}'>"
        f"<div class='sectionHead'><div><div class='eyebrow'>KG query round {round_id}</div><h3>Q{qid} · {query_type}</h3></div>"
        f"<div class='chipRow'><span class='chip status'>{status}</span><span class='chip'>{len(items)} evidence rows</span><span class='chip'>{html.escape(source_text)}</span></div></div>"
        f"<div class='reasonBox'><b>Why this query was asked</b><br>{html.escape(str(reason or 'No explicit reason was recorded.'))}</div>"
        f"{query_links}"
        f"<details open><summary>Structured query object</summary>{_pre(step.get('query_object') or {'query_type': step.get('query_type'), 'query': step.get('query'), 'reason': step.get('reason')})}</details>"
        f"<details><summary>Actual KG tool parameters</summary>{_pre(step.get('tool_parameters') or {'round_index': step.get('round_index'), 'query_index': step.get('query_index'), 'query_type': step.get('query_type'), 'query': step.get('query'), 'max_items': len(items), 'source': source})}</details>"
        f"<details><summary>KG tool diagnostics</summary>{_pre(step.get('diagnostics') or {})}</details>"
        f"<h4>Returned source-grounded evidence</h4>{_evidence_table(items) if items else '<p>No evidence returned.</p>'}"
        "</section>"
    )


def _render_html(
    *,
    sample: SecVulEvalSample,
    evidence: EvidencePack,
    trace: AgentTrace,
    prediction: Prediction,
    flow: dict[str, Any],
    privacy: dict[str, Any],
    dataset_path: str | None,
    graph_manifest: dict[str, Any] | None,
    graph_status: str | None,
    graph_dir: str | None,
    validation_artifact_dir: str | None,
    root: Path,
    report_options: dict[str, Any] | None = None,
) -> str:
    opts = _demo_report_options(report_options)
    title = f"Agent Demo: sample {sample.sample_id} / {sample.func_name}"
    initial_items = _initial_evidence(evidence, trace, hide=bool(opts.get("hide_initial_deterministic_retrieval")))
    display_items = _kg_tool_evidence_items(evidence, trace) if bool(opts.get("show_only_kg_tool_evidence")) else list(evidence.items)
    target_relpath, target_function, target_start_line = _target_source_anchor(evidence)
    model_sections = "".join(_call_section(call, i) for i, call in enumerate(trace.model_calls, start=1))
    tool_sections = "".join(_tool_section(step, root=root) for step in trace.kg_tool_steps)
    validation_link = _link_if_exists(validation_artifact_dir or prediction.target_validation_artifact_dir, "target validation artifacts", root)
    graph_link = _link_if_exists(graph_dir, "KG artifacts directory", root)
    dashboard_link = _link_if_exists((graph_manifest or {}).get("dashboard_path"), "CodeKG dashboard", root)
    artifact_links = " | ".join(
        [
            '<a href="decision_flow.json">decision_flow.json</a>',
            '<a href="decision_summary.md">decision_summary.md</a>',
            '<a href="model_calls.jsonl">model_calls.jsonl</a>',
            '<a href="kg_tool_calls.jsonl">kg_tool_calls.jsonl</a>',
            '' if bool(opts.get("hide_initial_deterministic_retrieval")) else '<a href="evidence_initial.json">evidence_initial.json</a>',
            '<a href="evidence_displayed.json">evidence_displayed.json</a>',
            '<a href="evidence_accumulated.json">evidence_accumulated.json</a>',
            '<a href="final_prediction.json">final_prediction.json</a>',
            '<a href="posthoc_commit_audit.json">posthoc_commit_audit.json</a>',
            '<a href="final_validator_modifications.json">final_validator_modifications.json</a>',
            '<a href="report_only_ground_truth_comparison.json">report_only_ground_truth_comparison.json</a>',
            '<a href="privacy_scan.json">privacy_scan.json</a>',
        ]
    )
    artifact_links = " | ".join([x for x in artifact_links.split(" | ") if x.strip()])
    live_revision = int(opts.get("report_revision") or 0)
    live_poll_ms = max(1000, int(float(opts.get("autorefresh_seconds", 2) or 2) * 1000))
    live_refresh_script = ""
    if bool(opts.get("in_progress")):
        live_refresh_script = f"""
  <script>
    const INITIAL_REPORT_REVISION = {live_revision};
    const REPORT_POLL_MS = {live_poll_ms};
    async function checkReportUpdate() {{
      try {{
        const r = await fetch('live_status.json?ts=' + Date.now(), {{cache: 'no-store'}});
        if (!r.ok) return;
        const s = await r.json();
        const next = Number(s.revision || 0);
        if (next && next !== INITIAL_REPORT_REVISION) {{ window.location.reload(); }}
      }} catch (e) {{}}
    }}
    setInterval(checkReportUpdate, REPORT_POLL_MS);
  </script>
"""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --bg:#f6f8fb; --panel:#ffffff; --soft:#f8fafc; --line:#dbe3ef; --line2:#e7edf5; --text:#0f172a; --muted:#64748b; --blue:#2563eb; --green:#047857; --red:#b91c1c; --amber:#92400e; --shadow:0 12px 28px rgba(15,23,42,.08); }}
    * {{ box-sizing:border-box; }} html {{ scroll-behavior:smooth; }}
    body {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin:0; line-height:1.55; color:var(--text); background:linear-gradient(180deg,#eef4ff 0,#f8fafc 280px,#f6f8fb 100%); }}
    a {{ color:var(--blue); text-decoration:none; font-weight:700; }} a:hover {{ text-decoration:underline; }}
    .reportTop {{ position:sticky; top:0; z-index:30; background:rgba(255,255,255,.93); backdrop-filter:blur(14px); border-bottom:1px solid var(--line); box-shadow:0 1px 0 rgba(15,23,42,.04); }}
    .reportTopInner {{ max-width:1720px; margin:0 auto; padding:14px 22px; display:flex; align-items:center; justify-content:space-between; gap:18px; }}
    .brand {{ display:flex; gap:12px; align-items:center; }} .brandIcon {{ width:40px; height:40px; border-radius:14px; background:linear-gradient(135deg,#2563eb,#7c3aed); box-shadow:0 10px 22px rgba(37,99,235,.25); }}
    h1 {{ margin:0; font-size:21px; line-height:1.15; }} .subtitle {{ color:var(--muted); font-size:12px; margin-top:3px; }}
    .reportLayout {{ max-width:1720px; margin:0 auto; padding:18px 22px 34px; display:grid; grid-template-columns:270px minmax(0,1fr); gap:18px; align-items:start; }}
    .sideNav {{ position:sticky; top:86px; background:rgba(255,255,255,.96); border:1px solid var(--line); border-radius:20px; padding:14px; box-shadow:var(--shadow); max-height:calc(100vh - 106px); overflow:auto; }}
    .sideNav h2 {{ margin:0 0 9px; font-size:13px; color:#334155; text-transform:uppercase; letter-spacing:.08em; }}
    .sideNav a {{ display:block; padding:7px 9px; border-radius:10px; color:#334155; font-size:12px; font-weight:750; }} .sideNav a:hover {{ background:#eff6ff; text-decoration:none; color:#1d4ed8; }}
    .content {{ min-width:0; }}
    .hero {{ background:rgba(255,255,255,.96); border:1px solid var(--line); border-radius:24px; padding:18px; box-shadow:var(--shadow); margin-bottom:16px; }}
    .heroGrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(185px,1fr)); gap:10px; margin-top:12px; }}
    .summaryCard {{ background:var(--soft); border:1px solid var(--line2); border-radius:16px; padding:12px; }} .summaryCard .label {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; font-weight:800; }} .summaryCard .value {{ margin-top:4px; font-size:15px; font-weight:850; overflow-wrap:anywhere; }}
    section, .auditCard {{ background:rgba(255,255,255,.96); border:1px solid var(--line); border-radius:22px; padding:18px; margin:16px 0; box-shadow:var(--shadow); }}
    h2 {{ margin:28px 0 10px; font-size:19px; }} h3 {{ margin:.2rem 0 .45rem; color:#1e293b; font-size:17px; }} h4 {{ margin:14px 0 8px; }}
    .sectionHead {{ display:flex; justify-content:space-between; align-items:flex-start; gap:14px; border-bottom:1px solid var(--line2); padding-bottom:12px; margin-bottom:12px; }}
    .eyebrow {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); font-weight:850; }}
    .chipRow {{ display:flex; flex-wrap:wrap; gap:6px; justify-content:flex-end; }} .chip {{ display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; background:#eef2ff; color:#3730a3; font-size:12px; font-weight:800; }} .chip.status {{ background:#dcfce7; color:#166534; }}
    .note {{ background:#eff6ff; border:1px solid #bfdbfe; border-left:5px solid #3b82f6; border-radius:14px; padding:12px 14px; color:#1e3a8a; }}
    .ok {{ color:var(--green); font-weight:800; }} .bad {{ color:var(--red); font-weight:800; }} .quiet {{ color:var(--muted); }} code {{ background:#eef2f7; padding:2px 5px; border-radius:6px; }}
    pre {{ white-space:pre-wrap; word-break:break-word; background:#0f172a; color:#dbeafe; border:1px solid #1e293b; padding:14px; border-radius:14px; max-height:560px; overflow:auto; font-size:12px; line-height:1.48; }}
    details {{ border:1px solid var(--line2); border-radius:14px; padding:10px 12px; background:#fbfdff; margin:10px 0; }} details[open] {{ background:#fff; }} summary {{ cursor:pointer; font-weight:800; color:#334155; }}
    .tableWrap {{ overflow:auto; border:1px solid var(--line); border-radius:16px; background:white; margin-top:10px; }} table {{ border-collapse:separate; border-spacing:0; width:100%; font-size:13px; }} th, td {{ border-bottom:1px solid var(--line2); padding:10px; vertical-align:top; text-align:left; }} th {{ background:#f8fafc; color:#475569; font-size:11px; text-transform:uppercase; letter-spacing:.05em; position:sticky; top:0; }} tbody tr:hover {{ background:#f8fbff; }} td pre {{ max-height:280px; }}
    .kgQueryCard {{ border-color:#bfdbfe; background:linear-gradient(180deg,#ffffff 0,#f8fbff 100%); }} .modelCall {{ border-color:#e0e7ff; }}
    .queryLinks {{ margin:12px 0; display:flex; flex-wrap:wrap; gap:8px; align-items:center; }} .queryLinks .btn {{ display:inline-flex; text-decoration:none; background:#2563eb; color:white; padding:8px 12px; border-radius:999px; font-weight:850; font-size:12px; }} .queryLinks .btn:nth-child(2) {{ background:#334155; }}
    .reasonBox {{ background:#f8fafc; border:1px solid var(--line2); border-radius:14px; padding:11px; color:#334155; }} .metricStrip {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0; }} .metricStrip span {{ background:#f8fafc; border:1px solid var(--line2); border-radius:999px; padding:5px 9px; font-size:12px; color:#475569; }}
    .reportActions {{ display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }} .reportActions a, .reportActions button {{ border:1px solid #cbd5e1; border-radius:999px; background:white; color:#334155; padding:8px 11px; font-size:12px; font-weight:800; cursor:pointer; }}
    .searchBox {{ width:100%; border:1px solid #cbd5e1; border-radius:12px; padding:9px 11px; margin:8px 0 10px; }}
    @media (max-width: 1050px) {{ .reportLayout {{ grid-template-columns:1fr; }} .sideNav {{ position:relative; top:auto; max-height:none; }} .reportTopInner {{ align-items:flex-start; flex-direction:column; }} }}
  </style>
</head>
<body>
  <header class="reportTop"><div class="reportTopInner"><div class="brand"><div class="brandIcon"></div><div><h1>{html.escape(title)}</h1><div class="subtitle">source-only model trace · CodeKG query evidence · report-only checks separated</div></div></div><div class="reportActions"><button onclick="window.print()">Print / PDF</button><button onclick="location.reload()">Refresh</button></div></div></header>
  <div class="reportLayout"><aside class="sideNav"><h2>Audit navigation</h2><input id="auditSearch" class="searchBox" placeholder="Filter visible sections" oninput="filterAuditCards()"><nav id="toc"></nav></aside><main class="content"><div class="hero">
  <p class="note">This report shows the model-visible inference trace: source-only hypotheses, prompts, raw outputs, JSON validation/repair, KG queries, returned KG evidence, public hypothesis updates, and final prediction. It does not include hidden/private chain-of-thought.</p>
  {f'<p class="note"><b>Live status:</b> {html.escape(str(opts.get("stage") or "running"))}. This page checks <code>live_status.json</code> and reloads only when this sample report is rewritten.</p>' if bool(opts.get("in_progress")) else ""}


  <div class="heroGrid">
    <div class="summaryCard"><div class="label">Sample</div><div class="value">{html.escape(str(sample.sample_id))}</div></div>
    <div class="summaryCard"><div class="label">Project</div><div class="value">{html.escape(str(sample.project))}</div></div>
    <div class="summaryCard"><div class="label">Function</div><div class="value">{html.escape(str(sample.func_name))}</div></div>
    <div class="summaryCard"><div class="label">Prediction</div><div class="value">{'vulnerable' if prediction.is_vulnerable else 'non-vulnerable'} · {html.escape(str(prediction.confidence))}</div></div>
    <div class="summaryCard"><div class="label">KG backend</div><div class="value">{html.escape(str((graph_manifest or {}).get('backend_used') or (graph_manifest or {}).get('backend') or graph_status or 'unknown'))}</div></div>
    <div class="summaryCard"><div class="label">KG queries</div><div class="value">{len(trace.kg_tool_steps or [])}</div></div>
  </div></div>
  <h2>A. Dataset and target setup</h2>
  {_pre(flow['A_dataset_and_target_setup'])}
  <p>{validation_link if validation_link else 'No validation artifact link available.'}</p>

  <h2>B. KG construction/loading</h2>
  {_pre(flow['B_kg_construction_loading'])}
  <p><b>Source boundary:</b> KG was built only from repository source code; labels/CVE/commit metadata were not inserted into KG.</p>
  <p>{dashboard_link if dashboard_link else ''} {graph_link if graph_link else ''}</p>

  {"<h2>C. Initial deterministic retrieval</h2><p>This section is hidden by configuration. The demo focuses on hypothesis-driven KG queries and their returned evidence.</p>" if bool(opts.get("hide_initial_deterministic_retrieval")) else (("<h2>C. Initial deterministic retrieval</h2>" + _pre(flow['C_initial_deterministic_retrieval']) + _evidence_table(initial_items, target_relpath=target_relpath, target_function=target_function, target_start_line=target_start_line)) if initial_items else "<h2>C. Initial deterministic retrieval</h2><p>No initial deterministic evidence was used in this run.</p>")}

  <h2>D/F/G. LLM calls, JSON validation, repair, and final decision</h2>
  {model_sections}

  <h2>E. KG query/tool rounds</h2>
  <p class="note">Each query below has two KG-dashboard actions: <b>highlight</b> keeps the wider graph visible while emphasizing retrieved evidence, and <b>show only</b> filters the CodeKG Explorer to the exact retrieved subgraph. The text tables below are the model-visible evidence rows returned by the same query.</p>
  {tool_sections if tool_sections else '<p>No KG follow-up query steps were executed.</p>'}

  <h2>F. Hypothesis ledger and follow-up/verification rounds</h2>
  <h3>Public hypothesis ledger</h3>
  {_pre(trace.hypothesis_ledger)}
  <h3>Verification rounds</h3>
  {_pre(trace.verification)}

  <h2>G. Final decision, reasoning, and report-only evaluation</h2>
  <h3>Final public reasoning summary</h3>
  {_pre({
      "is_vulnerable": prediction.is_vulnerable,
      "confidence": prediction.confidence,
      "decision_status": prediction.decision_status,
      "primary_vulnerability_type": prediction.primary_vulnerability_type,
      "reasoning_summary": prediction.reasoning_summary,
      "evidence_used": prediction.evidence_used,
      "vuln_statements": [x.model_dump(mode="json") for x in prediction.vuln_statements],
      "parse_error": prediction.parse_error,
      "validation_notes": prediction.validation_notes,
  })}
  <h3>Final decision validator modifications</h3>
  {_pre(trace.final_validator_modifications)}
  <h3>Commit message, report-only</h3>
  {_pre(sample.commit_message or "No commit message available", None)}
  <h3>Post-hoc semantic/factual audit against commit message</h3>
  <p class="note">This audit is run after the binary prediction. It may see report-only commit metadata and is for debugging explanation quality only; it does not change the prediction.</p>
  {_pre(trace.posthoc_commit_audit)}
  <h3>Full final prediction/evaluation payload</h3>
  {_pre(flow['G_final_prediction_and_evaluation'])}

  <h2>G2. Report-only ground truth vs prediction comparison</h2>
  <p class="note">This side-by-side comparison is created only after the prediction. It shows the dataset label, final system reasoning, original commit message, post-hoc audit, and cited code evidence for academic/debugging review. It is not included in pre-decision prompts.</p>
  {_pre(flow['J_report_only_ground_truth_vs_prediction_comparison'])}

  <h2>Prompt privacy scan</h2>
  {"<p class='bad'>Unexpected answer-leaking metadata appeared in pre-decision model prompts.</p>" if privacy.get('unexpected_leaks_found') else "<p class='ok'>No unexpected answer-leaking metadata was found in pre-decision model prompts.</p>"}
  {_pre(privacy)}

  <h2>H. Machine-readable artifacts</h2>
  <p>{artifact_links}</p>
  {_pre(flow['H_machine_readable_artifacts'])}

  <h2>Target function</h2>
  {_pre(sample.func_body, None)}

  <h2>{"KG evidence returned by hypothesis-driven queries" if bool(opts.get("show_only_kg_tool_evidence")) else "Accumulated evidence after KG tool rounds"} ({len(display_items)} shown / {len(evidence.items)} total)</h2>
  {_evidence_table(display_items, target_relpath=target_relpath, target_function=target_function, target_start_line=target_start_line)}
</main></div>
<script>
function slugify(s){{return String(s||'section').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,80)||'section'}}
function buildToc(){{const toc=document.getElementById('toc'); if(!toc)return; const heads=[...document.querySelectorAll('main.content h2, main.content section h3')]; const seen={{}}; toc.innerHTML=heads.map(h=>{{let id=h.id||slugify(h.innerText); seen[id]=(seen[id]||0)+1; if(seen[id]>1)id=id+'-'+seen[id]; h.id=id; const pad=h.tagName==='H3'?' style="padding-left:18px;font-weight:650"':''; return `<a${{pad}} href="#${{id}}">${{h.innerText.replace(/\n/g,' ').slice(0,74)}}</a>`}}).join('')}}
function filterAuditCards(){{const q=(document.getElementById('auditSearch')?.value||'').toLowerCase(); document.querySelectorAll('[data-audit-card]').forEach(el=>{{el.style.display=(!q||el.innerText.toLowerCase().includes(q))?'':'none'}});}}
window.addEventListener('DOMContentLoaded', buildToc);
</script>
{live_refresh_script}</body>
</html>"""


def write_agent_demo_index(run_dir: Path) -> Path:
    demo_root = run_dir / "agent_demos"
    demo_root.mkdir(parents=True, exist_ok=True)

    runtime_by_sample: dict[str, dict[str, Any]] = {}
    rt_path = run_dir / "sample_runtime.jsonl"
    if rt_path.exists():
        for line in rt_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                runtime_by_sample[str(row.get("sample_id"))] = row
            except Exception:
                continue

    rows = []
    for path in sorted(demo_root.glob("sample_*/index.html")):
        rel = path.relative_to(demo_root).as_posix()
        parent = path.parent.name
        sid = parent.split("_", 2)[1] if parent.startswith("sample_") and "_" in parent else parent
        rt = runtime_by_sample.get(str(sid), {})
        error_type = str(rt.get("error_type") or "UNKNOWN")
        rows.append({"rel": rel, "name": parent, "sample_id": sid, "error_type": error_type, "runtime": rt})

    summary_counts: dict[str, int] = {k: 0 for k in ["TP", "FP", "TN", "FN", "INVALID", "UNKNOWN"]}
    for row in rows:
        summary_counts[row["error_type"]] = summary_counts.get(row["error_type"], 0) + 1

    row_html = []
    for row in rows:
        rt = row["runtime"]
        row_html.append(
            "<tr class='demo-row' "
            f"data-error='{html.escape(row['error_type'])}' data-project='{html.escape(str(rt.get('project') or ''))}' "
            f"data-correct='{html.escape(str(rt.get('correct')))}'>"
            f"<td><span class='badge {html.escape(row['error_type'])}'>{html.escape(row['error_type'])}</span></td>"
            f"<td>{html.escape(str(row['sample_id']))}</td>"
            f"<td>{html.escape(str(rt.get('project') or ''))}</td>"
            f"<td>{html.escape(str(rt.get('filepath') or ''))}</td>"
            f"<td>{html.escape(str(rt.get('function') or ''))}</td>"
            f"<td>{'vulnerable' if rt.get('ground_truth_is_vulnerable') else 'fixed/non-vulnerable' if rt else ''}</td>"
            f"<td>{'vulnerable' if rt.get('prediction_is_vulnerable') else 'fixed/non-vulnerable' if rt else ''}</td>"
            f"<td>{html.escape(str(rt.get('confidence') or ''))}<br><span style='font-size:11px;color:#6b7280'>{html.escape(str(rt.get('decision_status') or ''))}</span></td>"
            f"<td><a href='{html.escape(row['rel'])}'>open agent demo</a></td>"
            "</tr>"
        )

    index = demo_root / "index.html"
    index.write_text(
        """<!doctype html><html><head><meta charset='utf-8'><title>Agent demos</title>
        <style>
        :root{--bg:#f6f8fb;--panel:#fff;--line:#dbe3ef;--text:#0f172a;--muted:#64748b;--blue:#2563eb;--shadow:0 12px 28px rgba(15,23,42,.08)}*{box-sizing:border-box}body{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;margin:0;line-height:1.45;color:var(--text);background:linear-gradient(180deg,#eef4ff 0,#f8fafc 260px,#f6f8fb 100%);padding:28px}h1{margin:0 0 6px;font-size:26px}.shell{max-width:1500px;margin:0 auto}.hero{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:24px;padding:20px;box-shadow:var(--shadow);margin-bottom:16px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:#f8fafc;border:1px solid #e7edf5;border-radius:16px;padding:10px;margin-top:12px}table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px;background:white;border:1px solid var(--line);border-radius:18px;overflow:hidden;box-shadow:var(--shadow)}th,td{border-bottom:1px solid #e7edf5;padding:10px;text-align:left;vertical-align:top}th{background:#f8fafc;color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.05em}tr:hover{background:#f8fbff}button{padding:8px 12px;border:1px solid #cbd5e1;border-radius:999px;background:#fff;cursor:pointer;font-weight:800}button.active{background:#2563eb;color:white;border-color:#2563eb}.badge{font-weight:800;border-radius:999px;padding:3px 8px}.TP{background:#dcfce7;color:#166534}.TN{background:#e0f2fe;color:#075985}.FP{background:#fee2e2;color:#991b1b}.FN{background:#fef3c7;color:#92400e}.UNKNOWN,.INVALID{background:#fef3c7;color:#92400e}input{padding:9px 11px;min-width:320px;border:1px solid #cbd5e1;border-radius:12px}.small{color:var(--muted);font-size:13px}a{color:var(--blue);font-weight:800;text-decoration:none}a:hover{text-decoration:underline}
        </style>
        <script>
        function filterRows(kind){
          document.querySelectorAll('button[data-kind]').forEach(b=>b.classList.toggle('active', b.dataset.kind===kind));
          const q=(document.getElementById('search').value||'').toLowerCase();
          document.querySelectorAll('.demo-row').forEach(r=>{
            const kindOk = kind==='ALL' || r.dataset.error===kind;
            const textOk = r.innerText.toLowerCase().includes(q);
            r.style.display = (kindOk && textOk) ? '' : 'none';
          });
        }
        function applySearch(){ const active=document.querySelector('button.active'); filterRows(active?active.dataset.kind:'ALL'); }
        </script>
        </head><body><div class="shell"><div class="hero">
        <h1>Agent demo reports</h1>
        <p>Filter by prediction outcome. Each report contains source-only hypotheses, model-visible prompts, raw outputs, JSON validation/repair, KG query/tool results, public hypothesis updates, evidence, final prediction, and prompt-privacy checks.</p>
        """
        + "<p><b>Counts:</b> "
        + " | ".join(f"{html.escape(k)}={v}" for k, v in summary_counts.items())
        + "</p>"
        + "<div class='toolbar'>"
        + "".join(f"<button data-kind='{k}' onclick=\"filterRows('{k}')\">{k}</button>" for k in ["ALL", "TP", "FP", "TN", "FN", "UNKNOWN"])
        + " <input id='search' oninput='applySearch()' placeholder='search project/function/sample...' /></div>"
        + "<table><thead><tr><th>Outcome</th><th>Sample</th><th>Project</th><th>Filepath</th><th>Function</th><th>Ground truth</th><th>Prediction</th><th>Confidence</th><th>Report</th></tr></thead><tbody>"
        + "".join(row_html)
        + "</tbody></table><script>filterRows('ALL')</script></div></div></body></html>",
        encoding="utf-8",
    )
    return index
