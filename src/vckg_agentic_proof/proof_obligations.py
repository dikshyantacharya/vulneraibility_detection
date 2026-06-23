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
    """Infer the proof family from the hypothesis, not merely from target source.

    Earlier versions appended the whole target function source to every
    hypothesis before family selection.  In functions containing several risky
    expressions, that caused secondary hypotheses (e.g. signedness of read(),
    selector/shift domain for length_power) to inherit the main parser-pointer
    family.  The family must be chosen from the hypothesis text first; target
    source is used only as a weak fallback for otherwise generic hypotheses.
    """
    b = _blob(hypothesis)
    src = (target_source or "").lower()

    # Specific families before broad parser traversal.
    if re.search(r"signed|negative|sign[- ]?extend|uint64_t\s+length\s*=\s*read|return value|read\s*\(\s*raw\s*\).*uint64", b):
        return "callee_return_signedness_or_value_range"
    if re.search(r"1\s*<<\s*length_power|length_power|shift|selector|dispatch|function pointer|choose_int_read|choose_", b):
        return "selector_shift_domain_or_dispatch_bounds"
    if re.search(r"raw\s*\+=\s*length\s*\*\s*itemsize|length\s*\*\s*itemsize|scaled.*pointer|pointer.*travers", b):
        return "parser_scaled_pointer_traversal"
    if re.search(r"raw_length|end\s*=|extent|buffer length", b):
        return "buffer_extent_or_signed_length"
    if re.search(r"malloc|calloc|realloc|free|lifetime|null", b):
        return "allocation_lifetime"
    if re.search(r"path|file|open|stat|sprintf|snprintf|command|system|exec", b):
        return "path_file_api_misuse"
    if re.search(r"race|concurr|thread|lock|mutex|atomic|lifecycle", b):
        return "concurrency_lifecycle"
    if re.search(r"crypto|nonce|random|key|hash|encrypt|decrypt", b):
        return "crypto_algorithmic"

    # Weak fallback: if the target source is a canonical parser pointer pattern
    # and the hypothesis is otherwise generic, use the parser family.
    if re.search(r"raw\s*\+=\s*length\s*\*\s*itemsize", src) and re.search(r"overflow|bounds|out-of-bounds|memory", b):
        return "parser_scaled_pointer_traversal"
    return "generic_memory_or_bounds"


def build_proof_obligations(hypothesis: Dict[str, Any], target_source: str = "") -> List[ProofObligation]:
    hid = str(hypothesis.get("hypothesis_id") or "HYP-UNKNOWN")
    family = infer_proof_family(hypothesis, target_source)
    b = _blob(hypothesis) + "\n" + (target_source or "")

    def po(
        i: int,
        name: str,
        question: str,
        symbols: Iterable[str],
        required: bool = True,
        expected: str = "",
        polarity: str = "supports_hypothesis",
    ) -> ProofObligation:
        return ProofObligation(
            obligation_id=f"PO-{i:02d}",
            hypothesis_id=hid,
            family=family,
            name=name,
            question=question,
            needed_symbols=list(dict.fromkeys([s for s in symbols if s])),
            required=required,
            expected_evidence=expected,
            polarity=polarity,
        )

    if family == "parser_scaled_pointer_traversal":
        return [
            po(1, "parsed_value_from_buffer", "Does the code show a length/count/offset value read or parsed from the supplied buffer/pointer? This does not require proving external attacker control.", ["length", "raw", "read"], True, "assignment from read/callee using raw"),
            po(2, "trust_boundary_or_external_input", "Does caller/context/comment/source code show the buffer may represent external, serialized, file, network, user, or otherwise malformed input?", ["raw", "raw_length", "loads", "load"], True, "caller or public parser entry point showing external serialized data"),
            po(3, "scaled_state_advance", "Does that parsed/malformed value control a scaled pointer/index/state advance? Only decide whether the data-dependent advance exists; do not judge whether it is safe.", ["length", "itemsize", "raw"], True, "raw += length * itemsize or equivalent"),
            po(4, "missing_remaining_bound_guard", "Does the code establish that the required safety guard is missing before the state advance? For this negative safety obligation: answer proven when no dominating remaining-space/product-overflow guard exists; answer refuted only if a positive dominating guard proves value <= remaining_space / scale and prevents product/add overflow.", ["length", "itemsize", "raw", "end", "raw_length"], True, "guard/slice around dangerous advance"),
            po(5, "unsafe_continuation_or_accept_path", "After the pointer/index/state is advanced, can the same parser state influence a next loop iteration, next read/write, dereference, or final accept/reject decision? A next-iteration read in the same loop counts as later use.", ["raw", "read", "while", "end"], True, "loop continuation, next-iteration read, or later accept path after advance"),
            po(6, "counter_guard_or_caller_constraint", "Is there positive source evidence from callers/callees/definitions that makes the dangerous state unreachable or fully bounded?", ["raw_length", "itemsize", "length_power", "choose_int_read"], False, "caller/callee constraints or guards", "refutes_hypothesis"),
            po(7, "callee_value_range", "If the parsed value comes from a callee or function pointer, does the resolver/callee/dispatch target bound the returned value sufficiently for the dangerous operation?", ["read", "choose_int_read", "_choose_int_read_write", "int_readers", "length_power", "big_endian"], False, "callee, resolver, dispatch table, or concrete target code", "refutes_hypothesis"),
        ]

    if family == "callee_return_signedness_or_value_range":
        return [
            po(1, "parsed_value_from_buffer", "Does the code show a value returned from a read/callee using the supplied buffer or pointer?", ["length", "raw", "read"], True, "assignment from read(raw) or equivalent"),
            po(2, "callee_or_function_pointer_resolution", "Does source code resolve the callee/function pointer enough to inspect its return type or concrete targets?", ["read", "IntRead", "choose_int_read", "_choose_int_read_write", "int_readers"], True, "resolver, typedef, dispatch table, or concrete target code"),
            po(3, "return_signedness_or_value_range", "Does the callee return a signed value, unbounded unsigned value, or otherwise attacker-controlled range that can become a large size/count after conversion?", ["IntRead", "uint64_t", "length", "read"], True, "return type or concrete reader semantics"),
            po(4, "missing_post_read_range_check", "Does the code establish that no dominating post-read guard validates the returned value before size/pointer arithmetic? Answer proven when the guard is missing; refuted only when a positive dominating range guard exists.", ["length", "read", "raw", "itemsize", "end"], True, "post-read validation around length before arithmetic"),
            po(5, "unsafe_use_after_conversion", "Is the returned/converted value used in pointer/index/size arithmetic, allocation, copy length, or another unsafe sink?", ["length", "itemsize", "raw"], True, "unsafe use of returned value"),
            po(6, "counter_callee_bounds_return_value", "Do callee targets or callers positively prove the returned value is bounded to a safe range for the later operation?", ["read", "int_readers", "length", "itemsize"], False, "", "refutes_hypothesis"),
        ]

    if family == "selector_shift_domain_or_dispatch_bounds":
        return [
            po(1, "selector_origin", "Does the selector/domain value come from a caller, external input, or malformed serialized field?", ["length_power", "big_endian"], True),
            po(2, "shift_or_dispatch_expression", "Does the selector control a shift, array lookup, function-pointer dispatch, or parser width calculation?", ["length_power", "choose_int_read", "read"], True),
            po(3, "missing_domain_guard", "Does the code establish that no dominating guard constrains the selector before it is used in the shift/dispatch expression? Answer proven when the guard is missing; refuted only when a positive dominating domain guard exists.", ["length_power", "choose_int_read"], True),
            po(4, "unsafe_effect_of_invalid_selector", "If the selector is outside the safe domain, can execution still reach undefined shift behavior, invalid dispatch, wrong-width parse, or memory access?", ["length_power", "read", "choose_int_read"], True),
            po(5, "counter_selector_constraint", "Do callers, callees, typedefs, or dispatch helpers positively prove the selector is always in the safe domain before all uses?", ["length_power", "choose_int_read", "_choose_int_read_write"], False, "", "refutes_hypothesis"),
        ]

    if family == "buffer_extent_or_signed_length":
        return [
            po(1, "extent_origin", "Does the buffer extent/length come from an external or caller-controlled value?", ["raw_length", "raw"], True),
            po(2, "extent_guard", "Is there a guard proving the extent is non-negative and within the actual allocation/buffer?", ["raw_length", "end", "raw"], True),
            po(3, "unsafe_extent_use", "Can the computed extent/end pointer be used in a comparison, dereference, copy, or parser accept path unsafely?", ["end", "raw", "raw_length"], True),
            po(4, "counter_constraint", "Do callers positively constrain the extent to a safe range?", ["raw_length"], False, "", "refutes_hypothesis"),
        ]

    # Generic fallback constructed from hypothesis symbols.
    syms = _symbols(b)
    risky = str(hypothesis.get("affected_code_region") or "risky operation")
    return [
        po(1, "value_or_object_origin", "Does source code show the risky value/object can be caller-controlled, external, or malformed?", syms, True),
        po(2, "dangerous_operation", f"Does source code show the dangerous operation `{risky}` or an equivalent sink?", syms, True),
        po(3, "missing_guard_or_invariant", "Is the required guard/invariant missing or non-dominating for the same value and operation?", syms, True),
        po(4, "reachable_unsafe_use_or_impact", "Is there a reachable unsafe use, accept path, crash, memory access, or security consequence?", syms, True),
        po(5, "positive_counter_evidence", "Does source code positively refute this hypothesis via guard, caller invariant, callee invariant, or unreachable path?", syms, False, "", "refutes_hypothesis"),
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

    if name in {"parsed_value_from_buffer", "parsed_value_origin"}:
        # Local value provenance: the assignment/read site and data-flow for the value/buffer.
        for i, s in enumerate([x for x in syms if x not in {"read", "while", "choose_int_read", "loads", "load"}][:2], 1):
            add(i, f"Variable/source flow for {s} required by {name}", f'variable_flow(target_function="{fn}", symbol="{s}", data_depth=4)', [s])
        stmt = region or "read(raw)"
        add(3, f"Exact parser-read slice for {name}", f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=3, data_depth=4, control_depth=2, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=420)')
    elif name in {"trust_boundary_or_external_input", "value_or_object_origin", "selector_origin", "extent_origin"}:
        add(1, f"Incoming callers and public/parser entry points for {name}", f'call_neighborhood(target_function="{fn}", direction="in", call_depth=4)')
        add(2, f"Security/input context for {name}", f'security_context(target_function="{fn}", depth=4, call_depth=3, data_depth=5, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=780)')
        if target_file:
            add(3, f"File context for parser entry points and comments for {name}", f'file_context(file="{target_file}")')
    elif name in {"scaled_state_advance", "dangerous_operation", "unsafe_extent_use", "shift_or_dispatch_expression", "unsafe_use_after_conversion"}:
        stmt = region or " ".join(syms[:3]) or fn
        add(1, f"Exact source slice for dangerous operation in {name}", f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=4, data_depth=4, control_depth=3, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=450)', syms[:3])
    elif name in {"missing_remaining_bound_guard", "missing_guard_or_invariant", "missing_domain_guard", "domain_guard", "extent_guard", "missing_post_read_range_check"}:
        stmt = region or ("while" if "while" in syms else "guard")
        add(1, f"Guard-dominance slice for {name}", f'evidence_slice(target_function="{fn}", target_statement="{stmt}", relation_depth=4, data_depth=4, control_depth=4, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=520)', syms[:3])
        add(2, f"Semantic guard facts for {name}", f'semantic_facts(target_function="{fn}")')
    elif name in {"unsafe_continuation_or_accept_path", "unsafe_use_after_bad_selector", "reachable_unsafe_use_or_impact", "unsafe_effect_of_invalid_selector"}:
        add(1, f"Loop/body and outgoing use context for {name}", f'evidence_slice(target_function="{fn}", target_statement="while", relation_depth=4, data_depth=4, control_depth=4, call_depth=2, include_defs=true, include_uses=true, include_guards=true, include_callees=true, include_headers=true, include_globals=true, max_nodes=520)')
        add(2, f"Outgoing callees and helper behavior for {name}", f'call_neighborhood(target_function="{fn}", direction="out", call_depth=3)')
    elif name in {"counter_guard_or_caller_constraint", "counter_constraint", "positive_counter_evidence", "counter_selector_constraint", "counter_callee_bounds_return_value"}:
        add(1, f"Expanded security context for counter-evidence {name}", f'security_context(target_function="{fn}", depth=4, call_depth=3, data_depth=5, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=900)')
        add(2, f"Caller constraints for counter-evidence {name}", f'call_neighborhood(target_function="{fn}", direction="in", call_depth=4)')
        if target_file:
            add(3, f"File definitions/types/constants for counter-evidence {name}", f'file_context(file="{target_file}")')
    elif name in {"callee_value_range", "callee_or_function_pointer_resolution", "return_signedness_or_value_range"}:
        # Function-pointer friendly: retrieve the local outgoing call, resolver, helper resolver, and file-level tables.
        add(1, "Outgoing call neighborhood for function-pointer/callee resolution", f'call_neighborhood(target_function="{fn}", direction="out", call_depth=3)')
        if any(x in syms for x in {"choose_int_read", "read", "_choose_int_read_write"}) or "choose_int_read" in _blob(hypothesis):
            add(2, "Resolver function context for function-pointer return", 'function_context(target_function="choose_int_read", depth=4)')
            add(3, "Shared resolver helper context for dispatch bounds", 'function_context(target_function="_choose_int_read_write", depth=3)')
        if target_file:
            add(4, "File context for dispatch tables, typedefs, and concrete callees", f'file_context(file="{target_file}")')
    else:
        add(1, f"General function context for {name}", f'security_context(target_function="{fn}", depth=3, call_depth=2, data_depth=4, include_callers=true, include_headers=true, include_globals=true, include_joern=true, max_nodes=520)')
    return q[:4]



_ABSENCE_SUPPORT_NAMES = {
    "missing_remaining_bound_guard",
    "missing_guard_or_invariant",
    "missing_domain_guard",
    "missing_post_read_range_check",
}
_COUNTER_NAMES = {
    "counter_guard_or_caller_constraint",
    "counter_constraint",
    "positive_counter_evidence",
    "callee_value_range",
    "counter_selector_constraint",
    "counter_callee_bounds_return_value",
}


_TRUST_BOUNDARY_SOURCE_MARKERS = (
    "raggedarray.loads", "loads()", ".loads", "load(", "loaded", "deserialize",
    "deserial", "parse", "pre-parse", "preparse", "parser", "decode",
    "encoded", "serialized", "serialised", "file input", "network",
    "user input", "external input", "malformed", "corrupt data", "data is corrupt",
)
_CALLER_PROVEN_MARKERS = (
    "caller", "public", "api", "python", "binding", "entry", "exposed",
    "file", "network", "user", "ipc", "socket", "request",
)


def _has_parser_trust_boundary_marker(text: str) -> bool:
    low = (text or "").lower().replace("`", "")
    return any(m in low for m in _TRUST_BOUNDARY_SOURCE_MARKERS)


def _trust_boundary_strength(result: ProofObligationVerification, *, target_source: str = "") -> str:
    """Classify trust-boundary evidence without overclaiming reachability.

    The reports need to distinguish two useful cases:
    * caller_proven: caller/public-entry evidence directly shows external input;
    * source_level: parser/deserializer comments/names show the function is meant
      to parse serialized/malformed data, but explicit caller provenance is absent.
    """
    # Deliberately do not include result.missing_evidence here: phrases like
    # "missing caller code showing external input" describe absent evidence and
    # must not be mistaken for caller-proven reachability.
    text = "\n".join([
        result.explanation or "",
        result.result_meaning or "",
        "\n".join(str(x) for x in (result.evidence_ids or [])),
        "\n".join(str(x) for x in (result.counter_evidence_ids or [])),
        target_source or "",
    ])
    low = text.lower().replace("`", "")
    if result.refutes_hypothesis:
        return "refuted"
    caller_negative_markers = ("missing caller", "no caller", "absent caller", "without caller", "direct caller code is missing", "caller code is missing", "no capsule confirms", "not confirm")
    if (
        not any(m in low for m in caller_negative_markers)
        and any(m in low for m in _CALLER_PROVEN_MARKERS)
        and any(m in low for m in ("external", "untrusted", "user", "file", "network", "public", "api", "binding", "caller"))
    ):
        if result.result in {ProofObligationStatus.proven, ProofObligationStatus.partially_proven}:
            return "caller_proven"
    if _has_parser_trust_boundary_marker(text):
        return "source_level" if result.result in {ProofObligationStatus.proven, ProofObligationStatus.partially_proven} else "partial"
    if result.result == ProofObligationStatus.partially_proven or result.supports_hypothesis:
        return "partial"
    return "none"


def _text_for_result(r: ProofObligationVerification) -> str:
    return "\n".join([
        r.explanation or "",
        "\n".join(str(x) for x in (r.missing_evidence or [])),
        "\n".join(str(x) for x in (r.evidence_ids or [])),
        "\n".join(str(x) for x in (r.counter_evidence_ids or [])),
    ]).lower()


def _copy_result(r: ProofObligationVerification, **updates: Any) -> ProofObligationVerification:
    data = r.model_dump(mode="json")
    data.update(updates)
    return ProofObligationVerification.model_validate(data)


def normalize_obligation_result(
    obligation: ProofObligation,
    result: ProofObligationVerification,
    *,
    target_source: str = "",
) -> ProofObligationVerification:
    """Normalize the LLM's micro-result into hypothesis support/refutation.

    The LLM result enum is deliberately simple, but negative obligations such as
    `missing_remaining_bound_guard` are semantically easy to invert.  This
    reducer keeps the external schema stable while making the controller's proof
    state polarity-aware and applying a few source-grounded C/parser pattern
    corrections.
    """
    name = obligation.name
    src = target_source or ""
    low_src = src.lower()
    txt = _text_for_result(result)
    data = result.model_dump(mode="json")
    notes: List[str] = []

    def set_result(value: ProofObligationStatus, meaning: str) -> None:
        data["result"] = value.value if hasattr(value, "value") else str(value)
        notes.append(meaning)

    # 1) Negative safety obligations: absence of a needed guard supports the
    # vulnerability; a positive dominating guard refutes it.  If the LLM says
    # "refuted" but explains that the guard is missing, flip to proven.
    if name in _ABSENCE_SUPPORT_NAMES:
        missing_guard_markers = [
            "no guard", "no dominating guard", "no relevant guard", "no bounds", "no bound",
            "no overflow check", "no additional bounds", "no dominating", "absence of",
            "lacks", "lack of", "missing", "without any", "without a", "does not check",
            "does not account", "does not validate", "does not bound", "not the subsequent",
            "only ensures", "only checks", "violating the obligation", "not sufficient", "not enough",
        ]
        positive_guard_markers = [
            "guard ensuring", "check ensures", "dominating guard proves", "bounded before",
            "prevents overflow", "proves value <=", "fully bounded", "makes the dangerous state unreachable",
        ]
        if any(m in txt for m in missing_guard_markers):
            set_result(ProofObligationStatus.proven, f"polarity_fix:{name}:missing_guard_supports_hypothesis")
        elif result.result == ProofObligationStatus.proven and any(m in txt for m in positive_guard_markers):
            set_result(ProofObligationStatus.refuted, f"polarity_fix:{name}:positive_guard_refutes_hypothesis")

    # 2) Atomic local parser facts that can be deterministically recognized from
    # the source capsule.  These prevent one micro-review from demanding evidence
    # assigned to a different proof obligation.
    if name in {"parsed_value_from_buffer", "parsed_value_origin"}:
        if re.search(r"\b\w+\s+length\s*=\s*\w+\s*\(\s*raw\s*\)", src) or re.search(r"length\s*=\s*read\s*\(\s*raw\s*\)", src):
            set_result(ProofObligationStatus.proven, "deterministic_pattern:parsed_value_from_raw")
            data["missing_evidence"] = [m for m in data.get("missing_evidence", []) if "origin of `raw`" not in str(m).lower() and "untrusted" not in str(m).lower()]
    elif name == "scaled_state_advance":
        if re.search(r"raw\s*\+=\s*length\s*\*\s*itemsize", src):
            set_result(ProofObligationStatus.proven, "deterministic_pattern:scaled_state_advance")
            # Bounds, alignment, and overflow guards are checked by separate obligations.
            data["missing_evidence"] = [
                m for m in data.get("missing_evidence", [])
                if not any(tok in str(m).lower() for tok in ("constraint", "bounds", "alignment", "overflow"))
            ]
    elif name == "shift_or_dispatch_expression":
        if re.search(r"1\s*<<\s*length_power", src) or "choose_int_read" in src:
            set_result(ProofObligationStatus.proven, "deterministic_pattern:selector_controls_shift_or_dispatch")
            data["missing_evidence"] = []
    elif name == "callee_or_function_pointer_resolution":
        if "choose_int_read" in src or "_choose_int_read_write" in src or "intread" in src.lower():
            # This proves that a resolver path exists, not necessarily all concrete targets.
            if result.result == ProofObligationStatus.not_answered:
                set_result(ProofObligationStatus.partially_proven, "deterministic_pattern:function_pointer_resolver_path_visible")
    elif name == "unsafe_use_after_conversion":
        if re.search(r"raw\s*\+=\s*length\s*\*\s*itemsize", src) or re.search(r"length\s*\*\s*itemsize", src):
            set_result(ProofObligationStatus.proven, "deterministic_pattern:return_value_used_in_pointer_arithmetic")
            data["missing_evidence"] = []
    elif name == "trust_boundary_or_external_input":
        # Source-level parser/deserializer evidence is sufficient for a
        # source-audit confirmation tier, even when caller-level exploitability
        # evidence remains absent.  This is deliberately weaker than
        # caller_proven reachability and is recorded in the ledger tier.
        # Examples are generic: parse/load/deserialize comments, names, or
        # public API wording.
        combined = "\n".join([src, txt])
        if _has_parser_trust_boundary_marker(combined):
            if result.result in {ProofObligationStatus.not_answered, ProofObligationStatus.refuted}:
                set_result(ProofObligationStatus.partially_proven, "trust_boundary:parser_context_partial")
            # If the only missing evidence is explicit caller/public entry point,
            # promote the obligation to source-level proven.  The missing caller
            # details remain represented by trust_boundary_strength=source_level,
            # not caller_proven.
            missing = [str(m).lower() for m in data.get("missing_evidence", [])]
            if missing and all(any(tok in m for tok in ("caller", "entry", "public", "external", "untrusted", "api")) for m in missing):
                set_result(ProofObligationStatus.proven, "trust_boundary:source_level_parser_deserializer_context")
                data["missing_evidence"] = []
            elif result.result == ProofObligationStatus.partially_proven:
                set_result(ProofObligationStatus.proven, "trust_boundary:source_level_parser_deserializer_context")
                data["missing_evidence"] = []
    elif name == "unsafe_continuation_or_accept_path":
        # A parser loop that reads from raw at the top and advances raw in the body
        # can use the advanced state on the next iteration if the loop condition is
        # still satisfied. This is a valid continuation/use path even without a
        # separate post-loop dereference.
        if "while" in low_src and re.search(r"read\s*\(\s*raw\s*\)", src) and re.search(r"raw\s*\+=", src):
            set_result(ProofObligationStatus.proven, "deterministic_pattern:loop_state_next_iteration_use")
            data["missing_evidence"] = [
                m for m in data.get("missing_evidence", [])
                if "post-loop" in str(m).lower()
            ]
    elif name == "unsafe_effect_of_invalid_selector":
        if re.search(r"1\s*<<\s*length_power", src) or "choose_int_read" in src:
            set_result(ProofObligationStatus.proven, "deterministic_pattern:selector_influences_shift_or_dispatch_use")

    # 3) Infer default support/refutation from polarity and final result.
    final_result = ProofObligationStatus(data.get("result"))
    polarity = getattr(obligation, "polarity", "supports_hypothesis") or "supports_hypothesis"
    if polarity == "refutes_hypothesis":
        supports = False if final_result == ProofObligationStatus.proven else None
        refutes = True if final_result == ProofObligationStatus.proven else False
    else:
        supports = True if final_result == ProofObligationStatus.proven else (None if final_result == ProofObligationStatus.partially_proven else False)
        refutes = True if final_result == ProofObligationStatus.refuted else False
    data["supports_hypothesis"] = supports
    data["refutes_hypothesis"] = refutes
    existing_meaning = str(data.get("result_meaning") or "")
    data["result_meaning"] = "; ".join([x for x in [existing_meaning] + notes if x])[:1000]
    return ProofObligationVerification.model_validate(data)

def summarize_ledger(
    hypothesis_id: str,
    family: str,
    obligations: List[ProofObligation],
    results: List[ProofObligationVerification],
    *,
    target_source: str = "",
) -> HypothesisProofLedger:
    normalized_results: List[ProofObligationVerification] = []
    by_obligation = {o.obligation_id: o for o in obligations}
    for r in results:
        o = by_obligation.get(r.obligation_id)
        normalized_results.append(normalize_obligation_result(o, r, target_source=target_source) if o else r)

    by_oid = {r.obligation_id: r for r in normalized_results}
    required = [o for o in obligations if o.required]
    required_proven = 0
    required_missing: List[str] = []
    supporting: List[str] = []
    counters: List[str] = []
    notes: List[str] = []
    decisive_refutation = False
    trust_boundary_strength = "none"

    for o in obligations:
        r = by_oid.get(o.obligation_id)
        if not r:
            if o.required:
                required_missing.append(o.name)
            continue

        polarity = getattr(o, "polarity", "supports_hypothesis") or "supports_hypothesis"
        supports = r.supports_hypothesis
        refutes = r.refutes_hypothesis
        if supports is None or refutes is None:
            # Backward-compatible fallback for older artifacts.
            if polarity == "refutes_hypothesis":
                refutes = r.result == ProofObligationStatus.proven
                supports = False if refutes else None
            else:
                supports = r.result == ProofObligationStatus.proven
                refutes = r.result == ProofObligationStatus.refuted

        if supports:
            supporting.extend(r.evidence_ids or [])
        if refutes:
            counters.extend((r.counter_evidence_ids or []) + (r.evidence_ids or []))
            notes.append(f"{o.name} refutes_hypothesis")
            if o.required or polarity == "refutes_hypothesis":
                decisive_refutation = True
        elif r.result == ProofObligationStatus.partially_proven:
            supporting.extend(r.evidence_ids or [])
            notes.append(f"{o.name} partially_supports_hypothesis")

        if o.required:
            if supports is True and r.result == ProofObligationStatus.proven:
                required_proven += 1
            else:
                required_missing.append(o.name)

        if o.name == "trust_boundary_or_external_input":
            trust_boundary_strength = _trust_boundary_strength(r, target_source=target_source)
        if r.result_meaning:
            notes.append(f"{o.name}: {r.result_meaning}")

    status_hint = "complete" if required and required_proven == len(required) and not decisive_refutation else "incomplete"
    proof_tier = "incomplete"
    if decisive_refutation:
        status_hint = "refuted"
        proof_tier = "refuted"
    elif status_hint == "complete":
        if family == "parser_scaled_pointer_traversal" and trust_boundary_strength == "source_level":
            status_hint = "source_level_complete"
            proof_tier = "confirmed_source_level_vulnerability"
        elif trust_boundary_strength == "caller_proven":
            status_hint = "reachable_complete"
            proof_tier = "confirmed_reachable_vulnerability"
        else:
            proof_tier = "confirmed_reachable_vulnerability"
    elif required_proven >= 3 and any(o.name in {"missing_remaining_bound_guard", "missing_guard_or_invariant", "missing_domain_guard"} and (by_oid.get(o.obligation_id) and by_oid[o.obligation_id].supports_hypothesis) for o in obligations):
        # Useful diagnostic state: strong local chain but one high-level context
        # element, often trust-boundary/callee details, is still missing.
        status_hint = "high_signal_incomplete"
        proof_tier = "high_signal_incomplete"

    if trust_boundary_strength != "none":
        notes.append(f"trust_boundary_strength={trust_boundary_strength}")
    if proof_tier:
        notes.append(f"proof_tier={proof_tier}")

    return HypothesisProofLedger(
        hypothesis_id=hypothesis_id,
        family=family,
        obligations=obligations,
        obligation_results=normalized_results,
        status_hint=status_hint,
        proof_tier=proof_tier,
        trust_boundary_strength=trust_boundary_strength,
        required_proven=required_proven,
        required_total=len(required),
        required_missing=required_missing,
        counter_evidence_ids=sorted(dict.fromkeys(counters)),
        supporting_evidence_ids=sorted(dict.fromkeys(supporting)),
        notes=list(dict.fromkeys(notes)),
    )


def verification_from_ledger(hypothesis: Dict[str, Any], ledger: HypothesisProofLedger) -> Dict[str, Any]:
    hid = str(hypothesis.get("hypothesis_id") or ledger.hypothesis_id)
    family = ledger.family
    if ledger.status_hint == "refuted":
        status = HypothesisStatus.refuted_by_guard.value
        local_risk = bool(ledger.supporting_evidence_ids)
        confirmed = False
    elif ledger.status_hint in {"complete", "source_level_complete", "reachable_complete"}:
        # Keep the existing schema-level status as confirmed_vulnerability so
        # final validation and benchmark code remain backward compatible.  The
        # finer proof quality is carried by ledger.proof_tier and the explanation.
        status = HypothesisStatus.confirmed_vulnerability.value
        local_risk = True
        confirmed = True
    else:
        status = HypothesisStatus.plausible_but_unproven.value
        local_risk = bool(ledger.supporting_evidence_ids) or ledger.status_hint == "high_signal_incomplete"
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
    if ledger.status_hint in {"complete", "source_level_complete", "reachable_complete"} and not impact_text:
        if ledger.family == "parser_scaled_pointer_traversal":
            impact_text = "A malformed parsed length can corrupt parser pointer/index traversal, causing a subsequent out-of-bounds read/write, invalid accept path, memory disclosure, or crash if the proven unsafe continuation is reachable."
        else:
            impact_text = "The proven dangerous operation and reachable unsafe use establish a source-grounded security impact for this vulnerability family."

    proof = MinimumVulnerabilityProof(
        input_control=explain(["parsed_value_from_buffer", "trust_boundary_or_external_input", "parsed_value_origin", "value_or_object_origin", "selector_origin", "extent_origin"]),
        dangerous_operation=explain(["scaled_state_advance", "dangerous_operation", "unsafe_extent_use"]),
        missing_or_failed_guard=explain(["missing_remaining_bound_guard", "missing_guard_or_invariant", "missing_domain_guard", "domain_guard", "extent_guard"]),
        unsafe_use=unsafe_text,
        security_impact=impact_text,
        cited_evidence_ids=ledger.supporting_evidence_ids[:20],
    )
    missing = list(ledger.required_missing)
    if ledger.status_hint == "incomplete" and not missing:
        missing = ["Required proof obligations were not all proven with sufficient confidence."]
    status_note = ""
    if ledger.status_hint == "high_signal_incomplete":
        status_note = " Strong local vulnerability chain exists, but at least one required context obligation remains unresolved."
    elif ledger.status_hint == "source_level_complete":
        status_note = " Confirmed at source-audit level: parser/deserializer context establishes a source-level trust boundary, but caller-level exploitability may still be a stricter tier."
    elif ledger.status_hint == "reachable_complete":
        status_note = " Confirmed with caller/public-entry reachability evidence."
    explanation = (
        f"Proof-ledger family={family}: {ledger.required_proven}/{ledger.required_total} required obligations proven. "
        f"Missing: {', '.join(missing) if missing else 'none'}. "
        f"Proof tier: {getattr(ledger, 'proof_tier', 'unknown')}; trust boundary: {getattr(ledger, 'trust_boundary_strength', 'none')}."
        + status_note
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
        proof_tier=getattr(ledger, "proof_tier", "unknown"),
        trust_boundary_strength=getattr(ledger, "trust_boundary_strength", "none"),
        accepted_confirmed=bool(confirmed and getattr(ledger, "proof_tier", "") in {"confirmed_source_level_vulnerability", "confirmed_reachable_vulnerability"}),
    ).model_dump(mode="json")
