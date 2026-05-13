PURPOSE_HINTS = {
    "prove": "Find direct evidence supporting the vulnerability hypothesis.",
    "disprove": "Find guards, safe data origins, early returns, caller constraints, or other refuting evidence.",
    "guard_search": "Find all guard conditions involving risky variables and related size/index/pointer variables.",
    "caller_constraint": "Find callers and constraints on arguments passed into the target function.",
    "callee_summary": "Find callee behavior for helper functions used by the target function.",
    "patch_delta": "Find changed statements between vulnerable and fixed commits for the same function.",
    "dataflow": "Trace definitions, assignments, transformations, and uses of risky variables.",
}
def enrich_query_text(query):
    purpose = query.get("purpose", ""); base = query.get("query_text", ""); variables = ", ".join(query.get("variables") or [])
    return f"{base}\nPurpose: {purpose}. {PURPOSE_HINTS.get(purpose, '')}\nVariables: {variables}".strip()
