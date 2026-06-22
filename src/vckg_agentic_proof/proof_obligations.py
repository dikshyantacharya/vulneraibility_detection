from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

from .schemas import (
    HypothesisProofLedger,
    HypothesisStatus,
    HypothesisVerification,
    KGQuery,
    MinimumVulnerabilityProof,
    ProofObligation,
    ProofObligationStatus,
    ProofObligationVerification,
)


_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")


def _blob(hypothesis: Dict[str, Any]) -> str:
    return "\n".join(str(hypothesis.get(k) or "") for k in (
        "title", "vulnerability_class", "affected_code_region", "attacker_model", "risk_summary", "required_proof_questions"
    )).lower()


def _symbols(text: str) -> List[str]:
    stop = {
        "the", "and", "for", "with", "from", "that", "this", "when", "where", "into", "return",
        "attacker", "controlled", "vulnerability", "memory", "safety", "parser", "state", "guard",
        "bounds", "overflow", "underflow", "proof", "question", "source", "input", "value", "operation",
    }
    out: List[str] = []
    for tok in _IDENTIFIER_RE.findall(text or ""):
        if tok.lower() in stop:
            continue
        if tok not in out:
            out.append(tok)
    return out[:12]


def infer_proof_family(hypothesis: Dict[str, Any], target_source: str = "") -> str:
    b = _blob(hypothesis)
    src = (target_source or "").lower()
    if re.search(r"raw\s*\+=\s*length\s*\*\s*itemsize|length\s*\*\s*itemsize|scaled.*pointer|pointer.*travers", b + "\n" + src):
        return "parser_scaled_pointer_traversal"
    if re.search(r"1\s*<<\s*length_power|shift|selector|dispatch|function pointer|choose_", b):
        return "selector_dispatch_or_shift_domain"
    if re.search(r"raw_length|end\s*=|negative|signed", b):
        return "buffer_extent_or_signed_length"
    if re.search(r"malloc|calloc|realloc|free|lifetime|null", b):
        return "allocation_lifetime"
    if re.search(r"path|file|open|stat|sprintf|snprintf|command|system|exec", b):
        return "path_file_api_misuse"
    if re.search(r"race|concurr|thread|lock|mutex|atomic|lifecycle", b):
        return "concurrency_lifecycle"
    if re.search(r"crypto|nonce|random|key|hash|encrypt|decrypt", b):
        return "crypto_algorithmic"
    return "generic_memory_or_bounds"


def build_proof_obligations(hypothesis: Dict[str, Any], target_source: str = "") -> List[ProofObligation]:
    hid = str(hypothesis.get("hypothesis_id") or "HYP-UNKNOWN")
    family = infer_proof_family(hypothesis, target_source)
    b = _blob(hypothesis) + "\n" + (target_source or "")

    def po(i: int, name: str, question: str, symbols: Iterable[str], required: bool = True, expected: str = "") -> ProofObligation:
        return ProofObligation(
            obligation_id=f"PO-{i:02d}",
            hypothesis_id=hid,
            family=family,
            name=name,
            question=question,
            needed_symbols=list(dict.fromkeys([s for s in symbols if s])),
            required=required,
            expected_evidence=expected,
        )

    if family == "parser_scaled_pointer_traversal":
        return [
            po(1, "parsed_value_origin", "Does the code show a length/count/offset value parsed from an input buffer or untrusted serialized data?", ["length", "raw", "read"], True, "assignment from read/callee using raw"),
            po(2, "scaled_state_advance", "Does the parsed or malformed value control a scaled pointer/index/state advance?", ["length", "itemsize", "raw"], True, "raw += length * itemsize or equivalent"),
            po(3, "missing_remaining_bound_guard", "Before the state advance, is there no dominating guard equivalent to value <= remaining_space / scale and no overflow check for the product/addition?", ["length", "itemsize", "raw", "end", "raw_length"], True, "guard/slice around dangerous advance"),
            po(4, "unsafe_continuation_or_accept_path", "Can the advanced pointer/index/state be used in a later loop iteration, read/write, dereference, or accept path after the advance?", ["raw", "read", "while", "end"], True, "loop continuation or later use after advance"),
            po(5, "counter_guard_or_caller_constraint", "Is there positive source evidence from callers/callees/definitions that makes the dangerous state unreachable or fully bounded?", ["raw_length", "itemsize", "length_power", "choose_int_read"], False, "caller/callee constraints or guards"),
            po(6, "callee_value_range", "If the value comes from a callee or function pointer, does that callee bound the returned value sufficiently for the dangerous operation?", ["read", "choose_int_read", "length_power", "big_endian"], False, "callee or dispatch target code"),
        ]

    if family == "selector_dispatch_or_shift_domain":
        return [
            po(1, "selector_origin", "Does the selector/domain value come from a caller, external input, or malformed serialized field?", ["length_power", "big_endian"], True),
            po(2, "domain_guard", "Is there a dominating guard constraining the selector before it is used in a shift, array lookup, or dispatch?", ["length_power", "choose_int_read"], True),
            po(3, "unsafe_use_after_bad_selector", "If the selector is invalid, can execution still reach a shift, function-pointer call, array lookup, or read/write?", ["length_power", "read", "choose_int_read"], True),
            po(4, "counter_constraint", "Do callers or callees positively prove the invalid selector state is unreachable?", ["length_power", "choose_int_read"], False),
        ]

    if family == "buffer_extent_or_signed_length":
        return [
            po(1, "extent_origin", "Does the buffer extent/length come from an external or caller-controlled value?", ["raw_length", "raw"], True),
            po(2, "extent_guard", "Is there a guard proving the extent is non-negative and within the actual allocation/buffer?", ["raw_length", "end", "raw"], True),
            po(3, "unsafe_extent_use", "Can the computed extent/end pointer be used in a comparison, dereference, copy, or parser accept path unsafely?", ["end", "raw", "raw_length"], True),
            po(4, "counter_constraint", "Do callers positively constrain the extent to a safe range?", ["raw_length"], False),
        ]

    # Generic fallback constructed from hypothesis symbols.
    syms = _symbols(b)
    risky = str(hypothesis.get("affected_code_region") or "risky operation")
    return [
        po(1, "value_or_object_origin", "Does source code show the risky value/object can be caller-controlled, external, or malformed?", syms, True),
        po(2, "dangerous_operation", f"Does source code show the dangerous operation `{risky}` or an equivalent sink?", syms, True),
        po(3, "missing_guard_or_invariant", "Is the required guard/invariant missing or non-dominating for the same value and operation?", syms, True),
        po(4, "reachable_unsafe_use_or_impact", "Is there a reachable unsafe use, accept path, crash, memory access, or security consequence?", syms, True),
        po(5, "positive_counter_evidence", "Does source code positively refute this hypothesis via guard, caller invariant, callee invariant, or unreachable path?", syms, False),
    ]


def obligation_queries(sample: Dict[str, Any], hypothesis: Dict[str, Any], obligation: ProofObligation, *, target_file: str = "") -> List[KGQuery]:
    fn = str(sample.get("function") or sample.get("func_name") or sample.get("target_function") or "")
    hid = obligation.hypothesis_id
    oid = obligation.obligation_id.replace("PO-", "")
    name = obligation.name
    syms = obligation.needed_symbols or []
    region = str(hypothesis.get("affected_code_region") or "")
    q: List[KGQuery] = []

    def add(idx: int, purpose: str, text: str, vars: List[str] | None = None) -> None:
        q.append(KGQuery(query_id=f"QPO-{hid}-{oid}-{idx:02d}", hypothesis_id=hid, purpose=purpose, query_text=text, variables=vars or [], expected_evidence=purpose, limit=8))

    if name in {"parsed_value_origin", "value_or_object_origin", "selector_origin", "extent_origin"}:
        for i, s in enumerate([x for x in syms if x not in {"read", "while", "choose_int_read"}][:2], 1):
            add(i, f"Variable/source flow for {s} required by {name}", f'variable_flow(target_function="{fn}", symbol="{s}", data_depth=4)', [s])
        add(3, f"Incoming callers and argument construction for {name}", f'call_neighborhood(target_function="{fn}", direction="in", call_depth=3)')
    elif name in {"scaled_state_advance", "dangerous_operation", "unsafe_extent_use"}:
        stmt = region or " ".join(syms[:3]) or fn
        add(1, f"Exact source slice for dangerous operation in {name}", f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=4, data_depth=4, control_depth=3, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=450)', syms[:3])
    elif name in {"missing_remaining_bound_guard", "missing_guard_or_invariant", "domain_guard", "extent_guard"}:
        stmt = region or ("while" if "while" in syms else "guard")
        add(1, f"Guard-dominance slice for {name}", f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=4, data_depth=4, control_depth=4, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=520)', syms[:3])
        add(2, f"Semantic guard facts for {name}", f'semantic_facts(target_function="{fn}")')
    elif name in {"unsafe_continuation_or_accept_path", "unsafe_use_after_bad_selector", "reachable_unsafe_use_or_impact"}:
        add(1, f"Loop/body and outgoing use context for {name}", f'evidence_slice(target_function="{fn}", target_statement="while", relation_depth=4, data_depth=4, control_depth=4, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=520)')
        add(2, f"Outgoing callees and helper behavior for {name}", f'call_neighborhood(target_function="{fn}", direction="out", call_depth=3)')
    elif name in {"counter_guard_or_caller_constraint", "counter_constraint", "positive_counter_evidence"}:
        add(1, f"Expanded security context for counter-evidence {name}", f'security_context(target_function="{fn}", depth=4, call_depth=3, data_depth=5, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=900)')
        add(2, f"Caller constraints for counter-evidence {name}", f'call_neighborhood(target_function="{fn}", direction="in", call_depth=4)')
        if target_file:
            add(3, f"File definitions/types/constants for counter-evidence {name}", f'file_context(file="{target_file}")')
    elif name == "callee_value_range":
        # Function-pointer friendly: get outgoing calls, target file, and any obvious resolver function.
        add(1, "Outgoing call neighborhood for function-pointer/callee resolution", f'call_neighborhood(target_function="{fn}", direction="out", call_depth=3)')
        if "choose_int_read" in syms or "choose_int_read" in _blob(hypothesis):
            add(2, "Resolver function context for function-pointer return", 'function_context(target_function="choose_int_read", depth=3)')
        if target_file:
            add(3, "File context for dispatch tables, typedefs, and concrete callees", f'file_context(file="{target_file}")')
    else:
        add(1, f"General function context for {name}", f'security_context(target_function="{fn}", depth=3, call_depth=2, data_depth=4, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=520)')
    return q[:4]


def summarize_ledger(hypothesis_id: str, family: str, obligations: List[ProofObligation], results: List[ProofObligationVerification]) -> HypothesisProofLedger:
    by_oid = {r.obligation_id: r for r in results}
    required = [o for o in obligations if o.required]
    required_proven = 0
    required_missing: List[str] = []
    supporting: List[str] = []
    counters: List[str] = []
    notes: List[str] = []
    for o in obligations:
        r = by_oid.get(o.obligation_id)
        if not r:
            if o.required:
                required_missing.append(o.name)
            continue
        supporting.extend(r.evidence_ids or [])
        counters.extend(r.counter_evidence_ids or [])
        if o.required and r.result == ProofObligationStatus.proven:
            required_proven += 1
        elif o.required:
            required_missing.append(o.name)
        if r.result == ProofObligationStatus.refuted:
            notes.append(f"{o.name} refuted")
    status_hint = "complete" if required_proven == len(required) and not counters else "incomplete"
    if any((by_oid.get(o.obligation_id) and by_oid[o.obligation_id].result == ProofObligationStatus.refuted) for o in obligations if o.required):
        status_hint = "refuted"
    return HypothesisProofLedger(
        hypothesis_id=hypothesis_id,
        family=family,
        obligations=obligations,
        obligation_results=results,
        status_hint=status_hint,
        required_proven=required_proven,
        required_total=len(required),
        required_missing=required_missing,
        counter_evidence_ids=sorted(dict.fromkeys(counters)),
        supporting_evidence_ids=sorted(dict.fromkeys(supporting)),
        notes=notes,
    )


def verification_from_ledger(hypothesis: Dict[str, Any], ledger: HypothesisProofLedger) -> Dict[str, Any]:
    hid = str(hypothesis.get("hypothesis_id") or ledger.hypothesis_id)
    family = ledger.family
    if ledger.status_hint == "refuted":
        status = HypothesisStatus.refuted_by_guard.value
        local_risk = False
        confirmed = False
    elif ledger.status_hint == "complete":
        status = HypothesisStatus.confirmed_vulnerability.value
        local_risk = True
        confirmed = True
    else:
        status = HypothesisStatus.plausible_but_unproven.value
        local_risk = bool(ledger.supporting_evidence_ids)
        confirmed = False

    by_name = {r.obligation_id: r for r in ledger.obligation_results}
    def explain(names: Iterable[str]) -> str:
        parts: List[str] = []
        for o in ledger.obligations:
            if o.name in names:
                r = by_name.get(o.obligation_id)
                if r and r.result in {ProofObligationStatus.proven, ProofObligationStatus.partially_proven}:
                    parts.append(r.explanation or o.name)
        return "; ".join(parts)[:650]

    unsafe_text = explain(["unsafe_continuation_or_accept_path", "unsafe_use_after_bad_selector", "reachable_unsafe_use_or_impact"])
    impact_text = "; ".join([
        r.explanation for r in ledger.obligation_results
        if r.result == ProofObligationStatus.proven
        and ("impact" in r.explanation.lower() or "read" in r.explanation.lower() or "crash" in r.explanation.lower()
             or "write" in r.explanation.lower() or "memory" in r.explanation.lower())
    ])[:650]
    if ledger.status_hint == "complete" and not impact_text:
        if ledger.family == "parser_scaled_pointer_traversal":
            impact_text = "A malformed parsed length can corrupt parser pointer/index traversal, causing a subsequent out-of-bounds read/write, invalid accept path, memory disclosure, or crash if the proven unsafe continuation is reachable."
        else:
            impact_text = "The proven dangerous operation and reachable unsafe use establish a source-grounded security impact for this vulnerability family."

    proof = MinimumVulnerabilityProof(
        input_control=explain(["parsed_value_origin", "value_or_object_origin", "selector_origin", "extent_origin"]),
        dangerous_operation=explain(["scaled_state_advance", "dangerous_operation", "unsafe_extent_use"]),
        missing_or_failed_guard=explain(["missing_remaining_bound_guard", "missing_guard_or_invariant", "domain_guard", "extent_guard"]),
        unsafe_use=unsafe_text,
        security_impact=impact_text,
        cited_evidence_ids=ledger.supporting_evidence_ids[:20],
    )
    missing = list(ledger.required_missing)
    if ledger.status_hint == "incomplete" and not missing:
        missing = ["Required proof obligations were not all proven with sufficient confidence."]
    explanation = (
        f"Proof-ledger family={family}: {ledger.required_proven}/{ledger.required_total} required obligations proven. "
        f"Missing: {', '.join(missing) if missing else 'none'}."
    )
    return HypothesisVerification(
        hypothesis_id=hid,
        status=status,
        local_risk_present=local_risk,
        confirmed_security_vulnerability=confirmed,
        proof=proof,
        supporting_evidence_ids=ledger.supporting_evidence_ids[:30],
        counter_evidence_ids=ledger.counter_evidence_ids[:30],
        missing_evidence=missing,
        explanation=explanation,
        target_relevance="direct" if local_risk else "unknown",
        relevance_reason="Derived from proof-obligation ledger rather than whole-hypothesis free-form verification.",
    ).model_dump(mode="json")
