from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from pydantic import BaseModel, ValidationError

from vuln_commit_kg.utils.text import strip_code_fence


BUNDLE_QUERY_TYPE_ALIASES: dict[str, str] = {
    "buffer_write_bundle": "buffer_write_bundle",
    "input_validation_bundle": "input_validation_bundle",
    "callee_summary_bundle": "callee_summary_bundle",
    "global_state_bundle": "global_state_bundle",
    "macro_definition_bundle": "global_state_bundle",
    "global_definition_bundle": "global_state_bundle",
    "integer_overflow_bundle": "integer_overflow_bundle",
    "format_string_bundle": "format_string_bundle",
    "path_traversal_bundle": "path_traversal_bundle",
    "lifetime_ownership_bundle": "lifetime_ownership_bundle",
    "caller_input_bundle": "caller_input_bundle",
}

ALLOWED_QUERY_TYPES = {
    "evidence_bundle", "guard_dominance", "callee", "caller", "safety", "risk",
    "statement", "variable", "type", "global", "search",
}

SCOPE_ALIASES = {
    "target": "target_function",
    "target function": "target_function",
    "target-function": "target_function",
    "function_under_test": "target_function",
    "current_function": "target_function",
    "adminchild": "target_function",  # common model mistake for this paired test; source-only, not label-derived
    "repo": "project",
    "repository": "project",
    "project_global": "global",
}

DECISION_STATUS_ALIASES = {
    "safe": "non_vulnerable",
    "not_vulnerable": "non_vulnerable",
    "non-vulnerable": "non_vulnerable",
    "non vulnerable": "non_vulnerable",
    "vuln": "vulnerable",
    "vulnerable_confirmed": "vulnerable",
    "unknown": "inconclusive",
    "uncertain": "inconclusive",
    "needs_more_evidence": "inconclusive",
}

UPLOAD_VERDICT_ALIASES = {
    # Model outputs often use this when upload_path_assessment.present=false.
    # The schema only permits unsafe/safe/unresolved; no upload path is an
    # unresolved/not-applicable upload assessment, not a parse failure.
    "not_present": "unresolved",
    "not present": "unresolved",
    "absent": "unresolved",
    "none": "unresolved",
    "n/a": "unresolved",
    "na": "unresolved",
    "not_applicable": "unresolved",
}


def strip_markdown_fences(text: str) -> str:
    cleaned = (text or "").strip()
    cleaned = strip_code_fence(cleaned).strip()
    fence = re.fullmatch(r"```(?:json|JSON)?\s*(.*?)\s*```", cleaned, flags=re.S)
    if fence:
        cleaned = fence.group(1).strip()
    return cleaned


def _find_balanced_json_span(text: str) -> tuple[int, int] | None:
    """Return the first balanced JSON object/array span while respecting strings."""
    start = None
    for i, ch in enumerate(text):
        if ch in "[{":
            start = i
            break
    if start is None:
        return None

    stack = [text[start]]
    in_string = False
    escape = False
    for j in range(start + 1, len(text)):
        ch = text[j]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            stack.append(ch)
        elif ch in "]}":
            if not stack:
                break
            top = stack[-1]
            expected = "}" if top == "{" else "]"
            if ch == expected:
                stack.pop()
            else:
                # Mismatched brackets are left to json.loads for the exact error;
                # keep scanning because a later span may still close cleanly.
                stack.pop()
            if not stack:
                return start, j + 1
    return None


def _escape_illegal_json_backslashes(text: str) -> str:
    # Escape invalid JSON backslashes without changing valid JSON escapes.
    return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)


def _remove_control_chars(text: str) -> str:
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def extract_answer_tag_payload(text: str) -> tuple[str, dict[str, Any]]:
    """Return the JSON-bearing payload from <answer>...</answer> when present.

    Qwen-style models often emit useful public analysis before the schema object.
    The orchestrator may explicitly ask for <thinking>...</thinking> followed by
    <answer>...</answer>.  When a complete answer tag is present, only that
    payload is parsed/repaired.  When tags are absent or incomplete, the caller
    must treat the whole response as the repair source, exactly preserving older
    behavior.
    """
    raw = str(text or "")
    # Accept common case/spacing variants such as <ANSWER >.
    thinking_open_pat = re.compile(r"<\s*thinking\b[^>]*>", flags=re.I)
    thinking_close_pat = re.compile(r"<\s*/\s*thinking\s*>", flags=re.I)
    thinking_opens = list(thinking_open_pat.finditer(raw))
    thinking_closes = list(thinking_close_pat.finditer(raw))
    thinking_complete = bool(thinking_opens and any(cl.start() >= thinking_opens[0].end() for cl in thinking_closes))

    open_pat = re.compile(r"<\s*answer\b[^>]*>", flags=re.I)
    close_pat = re.compile(r"<\s*/\s*answer\s*>", flags=re.I)
    opens = list(open_pat.finditer(raw))
    closes = list(close_pat.finditer(raw))
    if not opens:
        return raw, {
            "thinking_tag_found": bool(thinking_opens),
            "thinking_tag_complete": thinking_complete,
            "answer_tag_found": False,
            "answer_tag_complete": False,
            "extraction": "whole_response_no_answer_tag",
        }
    # Use the last complete answer block so a copied schema/example earlier in the
    # response cannot beat the final answer.
    for op in reversed(opens):
        close = next((cl for cl in closes if cl.start() >= op.end()), None)
        if close is not None:
            payload = raw[op.end():close.start()].strip()
            return payload, {
                "thinking_tag_found": bool(thinking_opens),
                "thinking_tag_complete": thinking_complete,
                "answer_tag_found": True,
                "answer_tag_complete": True,
                "extraction": "answer_tag",
                "answer_payload_chars": len(payload),
            }
    return raw, {
        "thinking_tag_found": bool(thinking_opens),
        "thinking_tag_complete": thinking_complete,
        "answer_tag_found": True,
        "answer_tag_complete": False,
        "extraction": "whole_response_incomplete_answer_tag",
    }


def _iter_balanced_json_spans(text: str):
    """Yield balanced object/array spans in order while respecting strings.

    This is more robust than stopping at the first brace: free-form model text can
    contain C function bodies or markdown examples before the actual JSON answer.
    """
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] not in "[{":
            i += 1
        if i >= n:
            return
        start = i
        stack = [text[start]]
        in_string = False
        escape = False
        j = start + 1
        while j < n:
            ch = text[j]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                j += 1
                continue
            if ch == '"':
                in_string = True
            elif ch in "[{":
                stack.append(ch)
            elif ch in "]}":
                top = stack[-1] if stack else None
                expected = "}" if top == "{" else "]"
                if ch == expected:
                    stack.pop()
                    if not stack:
                        yield start, j + 1
                        i = j + 1
                        break
                else:
                    # Not JSON; resume after this opener.
                    break
            j += 1
        else:
            return
        if stack:
            i = start + 1


def _strip_trailing_commas(text: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", text)


def _close_truncated_json(text: str) -> str | None:
    """Best-effort repair for provider-truncated JSON objects/arrays.

    This is deliberately conservative: it only starts from the first JSON opener,
    respects strings/escapes, optionally closes a dangling string, strips trailing
    commas, and appends the missing closing delimiters. It is mainly useful for
    report/audit schemas with defaults when the provider cuts output at max_tokens.
    """
    cleaned = strip_markdown_fences(text)
    start = None
    for i, ch in enumerate(cleaned):
        if ch in "[{":
            start = i
            break
    if start is None:
        return None
    candidate = cleaned[start:]
    stack: list[str] = []
    in_string = False
    escape = False
    last_non_ws = ""
    for ch in candidate:
        if not ch.isspace():
            last_non_ws = ch
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            stack.append(ch)
        elif ch in "]}":
            if stack:
                top = stack[-1]
                if (top == "{" and ch == "}") or (top == "[" and ch == "]"):
                    stack.pop()
                else:
                    # mismatched closing bracket; still try to recover by popping
                    stack.pop()
    repaired = candidate.rstrip()
    if in_string:
        # If truncation occurred after a backslash escape, drop the dangling escape.
        if repaired.endswith("\\"):
            repaired = repaired[:-1]
        repaired += '"'
    repaired = repaired.rstrip()
    if repaired.endswith(":"):
        repaired += " null"
    elif repaired.endswith(","):
        repaired = repaired[:-1]
    closers = []
    for opener in reversed(stack):
        closers.append("}" if opener == "{" else "]")
    repaired = _strip_trailing_commas(repaired + "".join(closers))
    return repaired


def _loads_with_salvage(candidate: str) -> Any:
    errors: list[Exception] = []
    variants = [candidate, _escape_illegal_json_backslashes(candidate), _remove_control_chars(_escape_illegal_json_backslashes(candidate))]
    seen: set[str] = set()
    for variant in variants:
        if variant in seen:
            continue
        seen.add(variant)
        try:
            return json.loads(variant)
        except Exception as exc:
            errors.append(exc)
    raise errors[-1]


def extract_json_value(text: str) -> Any:
    cleaned = strip_markdown_fences(text)
    try:
        return _loads_with_salvage(cleaned)
    except Exception as direct_exc:
        # Try every balanced JSON-looking span, not just the first brace.  This
        # lets us parse responses that contain public prose or C code before the
        # final JSON object.
        last_exc: Exception = direct_exc
        for span in _iter_balanced_json_spans(cleaned):
            candidate = cleaned[span[0]:span[1]]
            try:
                return _loads_with_salvage(candidate)
            except Exception as span_exc:
                last_exc = span_exc
        repaired = _close_truncated_json(cleaned)
        if repaired:
            try:
                return _loads_with_salvage(repaired)
            except Exception as repaired_exc:
                raise ValueError(str(repaired_exc)) from repaired_exc
        raise ValueError("No JSON object or array found in model response") from last_exc


def extract_json_object(text: str) -> dict[str, Any]:
    value = extract_json_value(text)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object, got {type(value).__name__}")
    return value


def _normalize_query_object(obj: dict[str, Any], notes: list[str], path: str) -> None:
    if "type" in obj and "query_type" not in obj:
        obj["query_type"] = obj.pop("type")
        notes.append(f"{path}: renamed type -> query_type")
    qtype_raw = obj.get("query_type")
    if isinstance(qtype_raw, str):
        qtype = re.sub(r"[^a-z0-9_]+", "_", qtype_raw.strip().lower()).strip("_")
        if qtype in BUNDLE_QUERY_TYPE_ALIASES:
            bundle = BUNDLE_QUERY_TYPE_ALIASES[qtype]
            obj["query_type"] = "evidence_bundle"
            obj.setdefault("bundle_type", bundle)
            query = str(obj.get("query") or "").strip()
            if not query or re.sub(r"\s+", "_", query.lower()) in {"bundle", "evidence_bundle", qtype}:
                obj["query"] = obj.get("symbol") or bundle
            notes.append(f"{path}: normalized query_type={qtype_raw!r} to evidence_bundle/bundle_type={bundle!r}")
        elif qtype not in ALLOWED_QUERY_TYPES:
            # Common model outputs use bundle-shaped names without the _bundle suffix.
            bundle_candidate = f"{qtype}_bundle"
            if bundle_candidate in BUNDLE_QUERY_TYPE_ALIASES:
                bundle = BUNDLE_QUERY_TYPE_ALIASES[bundle_candidate]
                obj["query_type"] = "evidence_bundle"
                obj.setdefault("bundle_type", bundle)
                obj.setdefault("query", obj.get("symbol") or bundle)
                notes.append(f"{path}: normalized query_type={qtype_raw!r} to evidence_bundle/bundle_type={bundle!r}")
            else:
                obj["query_type"] = qtype
    if "match_type" in obj and "match" not in obj:
        obj["match"] = obj.pop("match_type")
        notes.append(f"{path}: renamed match_type -> match")
    if "continue_" in obj and "continue" not in obj:
        obj["continue"] = obj.pop("continue_")
        notes.append(f"{path}: renamed continue_ -> continue")
    scope = obj.get("scope")
    if isinstance(scope, str):
        norm = re.sub(r"\s+", " ", scope.strip().lower())
        mapped = SCOPE_ALIASES.get(norm)
        if mapped:
            obj["scope"] = mapped
            notes.append(f"{path}: normalized scope={scope!r} -> {mapped!r}")
        elif re.fullmatch(r"[A-Za-z_]\w*", scope) and norm not in {"target_function", "project", "global", "callee", "caller"}:
            # A bare function name in scope almost always means the target function.
            obj["scope"] = "target_function"
            notes.append(f"{path}: normalized bare function scope={scope!r} -> 'target_function'")


def _normalize_value(value: Any, notes: list[str], path: str = "$", *, in_query: bool = False) -> Any:
    if isinstance(value, list):
        return [_normalize_value(v, notes, f"{path}[{idx}]", in_query=in_query) for idx, v in enumerate(value)]
    if isinstance(value, dict):
        obj = deepcopy(value)
        if "continue_" in obj and "continue" not in obj:
            obj["continue"] = obj.pop("continue_")
            notes.append(f"{path}: renamed continue_ -> continue")
        if "decision_status" in obj and isinstance(obj.get("decision_status"), str):
            raw = obj["decision_status"]
            norm = re.sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_")
            mapped = DECISION_STATUS_ALIASES.get(norm)
            if mapped:
                obj["decision_status"] = mapped
                notes.append(f"{path}: normalized decision_status={raw!r} -> {mapped!r}")
        if "verdict" in obj and isinstance(obj.get("verdict"), str):
            raw = obj["verdict"]
            norm = re.sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_")
            mapped = UPLOAD_VERDICT_ALIASES.get(norm) or UPLOAD_VERDICT_ALIASES.get(raw.strip().lower())
            if mapped:
                obj["verdict"] = mapped
                notes.append(f"{path}: normalized verdict={raw!r} -> {mapped!r}")
        # FinalDecisionResponse mechanical consistency fixes.  These are schema
        # invariants, not semantic edits: if the model itself says
        # is_vulnerable=false, the final schema forbids a vulnerability type and
        # vuln_statements.  Keep the detailed risk explanation in
        # unresolved_hypotheses/reasoning_summary.
        if obj.get("is_vulnerable") is False:
            if obj.get("primary_vulnerability_type") is not None:
                obj["primary_vulnerability_type"] = None
                notes.append(f"{path}: cleared primary_vulnerability_type because is_vulnerable=false")
            if obj.get("vuln_statements"):
                obj["vuln_statements"] = []
                notes.append(f"{path}: cleared vuln_statements because is_vulnerable=false")
            if obj.get("decision_status") == "vulnerable":
                obj["decision_status"] = "inconclusive" if obj.get("unresolved_hypotheses") else "non_vulnerable"
                notes.append(f"{path}: corrected decision_status because is_vulnerable=false")
        # Normalize children first, then the query object itself so generated keys are preserved.
        for k, v in list(obj.items()):
            obj[k] = _normalize_value(v, notes, f"{path}.{k}", in_query=(k == "kg_queries" or in_query))
        if "query_type" in obj or "type" in obj:
            _normalize_query_object(obj, notes, path)
        return obj
    return value


def normalize_json_object_for_schema(obj: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Apply lossless, mechanical normalizations before any LLM repair.

    This deliberately does not delete hypotheses, kg_queries, or vulnerable statements.
    It only fixes schema-level aliases that otherwise trigger expensive/destructive repair.
    """
    notes: list[str] = []
    normalized = _normalize_value(obj, notes)
    assert isinstance(normalized, dict)
    return normalized, notes


def parse_and_validate_with_normalization(text: str, schema_model: type[BaseModel]) -> tuple[dict[str, Any], BaseModel, list[str]]:
    obj = extract_json_object(text)
    normalized, notes = normalize_json_object_for_schema(obj)
    try:
        parsed = schema_model.model_validate(normalized)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc
    return normalized, parsed, notes


def _payload_from_json_answer_key(text: str) -> tuple[str, dict[str, Any]] | None:
    """Recover provider-JSON-mode responses shaped as {"thinking": str, "answer": {...}}.

    Some OpenAI-compatible providers enforce ``response_format={"type":"json_object"}``.
    In that mode a model cannot emit literal XML tags, even when the prompt asks
    for <thinking>...</thinking><answer>...</answer>.  Qwen-style models often
    satisfy both constraints by returning a JSON wrapper with keys named
    ``thinking`` and ``answer``.  Treat that as a transport-level wrapper and
    validate only the nested answer object.
    """
    try:
        value = extract_json_value(text)
    except Exception:
        return None
    if not isinstance(value, dict) or "answer" not in value:
        return None
    answer = value.get("answer")
    if isinstance(answer, str):
        payload = answer.strip()
    else:
        payload = json.dumps(answer, ensure_ascii=False)
    return payload, {
        "thinking_tag_found": False,
        "thinking_tag_complete": False,
        "answer_tag_found": False,
        "answer_tag_complete": False,
        "json_key_thinking_found": "thinking" in value,
        "json_key_answer_found": True,
        "extraction": "json_key_answer_wrapper",
        "answer_payload_chars": len(payload),
    }


def parse_and_validate_tagged_output(
    text: str,
    schema_model: type[BaseModel],
    *,
    require_answer_tag: bool = False,
) -> tuple[dict[str, Any], BaseModel, list[str], dict[str, Any], str]:
    """Parse model output for schema validation.

    Preferred format is literal <thinking>...</thinking><answer>JSON</answer>.
    For reliability, valid provider-JSON-mode wrappers and bare schema JSON are
    also accepted and recorded in mechanical_normalizations instead of causing
    deterministic fallbacks.  This keeps the agent robust when a provider forces
    JSON-only output or when the model ignores XML tags but still returns a valid
    schema object.
    """
    payload, tag_info = extract_answer_tag_payload(text)
    parse_errors: list[str] = []

    # Best case: a complete <answer> block exists.  Parse it even if the public
    # <thinking> block is missing; the answer JSON is the contractually important
    # part for the pipeline.
    if tag_info.get("answer_tag_complete"):
        try:
            obj, parsed, notes = parse_and_validate_with_normalization(payload, schema_model)
            prefix = [f"answer_extraction: {tag_info.get('extraction')}"]
            if require_answer_tag and not tag_info.get("thinking_tag_complete"):
                prefix.append("answer_extraction: missing_thinking_tag_but_answer_tag_valid")
            return obj, parsed, prefix + notes, tag_info, payload
        except Exception as exc:
            parse_errors.append(f"answer_tag_payload: {exc}")

    # Provider JSON mode frequently returns {"thinking": "...", "answer": {...}}.
    keyed = _payload_from_json_answer_key(text)
    if keyed is not None:
        keyed_payload, keyed_info = keyed
        try:
            obj, parsed, notes = parse_and_validate_with_normalization(keyed_payload, schema_model)
            prefix = ["answer_extraction: json_key_answer_wrapper_accepted"]
            if require_answer_tag:
                prefix.append("answer_extraction: literal_xml_tags_missing_but_json_wrapper_valid")
            return obj, parsed, prefix + notes, keyed_info, keyed_payload
        except Exception as exc:
            parse_errors.append(f"json_key_answer_wrapper: {exc}")

    # Last-resort compatibility: accept valid bare schema JSON.  The report will
    # explicitly say tags were missing, but the agent should not throw away valid
    # hypotheses/final decisions and fall back to weak deterministic queries.
    try:
        obj, parsed, notes = parse_and_validate_with_normalization(text, schema_model)
        bare_info = dict(tag_info)
        bare_info["extraction"] = "bare_schema_json"
        bare_info["answer_payload_chars"] = len(str(text or ""))
        prefix = ["answer_extraction: bare_schema_json_accepted_missing_tags"]
        return obj, parsed, prefix + notes, bare_info, str(text or "")
    except Exception as exc:
        parse_errors.append(f"bare_schema_json: {exc}")

    if require_answer_tag:
        tag_msg = "Required <thinking>...</thinking><answer>...</answer> wrapper was not found or could not be validated"
        raise ValueError(f"{tag_msg}; parse attempts: {' | '.join(parse_errors)}")
    raise ValueError("Could not parse schema-valid JSON from model response: " + " | ".join(parse_errors))


def parse_and_validate(text: str, schema_model: type[BaseModel]) -> tuple[dict[str, Any], BaseModel]:
    obj, parsed, _notes = parse_and_validate_with_normalization(text, schema_model)
    return obj, parsed
