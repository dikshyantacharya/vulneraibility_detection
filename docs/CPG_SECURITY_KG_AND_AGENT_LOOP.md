# CPG-inspired security KG and grounded agent loop

This project now uses a dependency-light, source-only CPG-inspired graph representation for local calibration runs.
It is **not** a full compiler-aware Joern/Clang/CodeQL CPG, but it follows the same layered design so the project can later swap in a true CPG extractor.

## Graph representation

The KG is a directed, edge-labeled, attributed multigraph with these layers:

1. **Core code layer**
   - `Project`, `Commit`, `File`, `Function`, `Statement`, `CallExpression`, `LocalVariable`, `Parameter`.
2. **Program-analysis layer**
   - `CONTAINS`, `FILE_HAS_FUNCTION`, `FUNCTION_HAS_STATEMENT`, `AST_CHILD`, `CFG_NEXT`, `FUNCTION_CALLS_NAME`, `FUNCTION_CALLS_FUNCTION`, `CALLS`, `DECLARES`, `DEFINES_VARIABLE`, `USES_VARIABLE`, `DEF_USE`.
3. **Security overlay**
   - `SecurityRisk`, `SafetyCheck`, `HAS_RISK`, `STATEMENT_HAS_RISK`, `STATEMENT_HAS_SAFETY_CHECK`, `EVIDENCE_FOR`.
4. **Retrieval-evidence layer**
   - Evidence items carry `scope`, `matched_symbol`, `match_type`, and `trust` so the agent can tell target-function evidence from lower-trust project-wide text evidence.

## Important limitation

The current builder is still regex/lightweight-source based. It does not use compiler flags, macro expansion, template instantiation, full CFG, alias analysis, or interprocedural data-flow. The manifest records this as:

```text
kg_methodology = cpg_inspired_source_only_security_overlay
```

For final high-quality C/C++ analysis, a Joern/Clang/CodeQL/PhASAR backend can feed the same schema with stronger facts.

## Agent loop improvements

The current agent loop is now:

```text
line-numbered target function only
→ source-only hypotheses
→ scoped exact-symbol KG queries
→ target-scoped KG evidence
→ public hypothesis status updates
→ duplicate/placeholder query rejection
→ final decision with evidence-consistency repair
```

## Query grounding rules

- `variable: buf` defaults to `scope=target_function` and `match=exact_identifier`.
- It does not match `tmpbuf`, `inbuf`, or `bufsize`.
- Project/global search only happens when the query explicitly asks for that scope.
- Placeholder queries such as `concrete_identifier_or_API` are rejected.
- Duplicate queries are filtered.

## Final decision consistency

The final prediction is checked so that:

- every cited evidence ID exists;
- cited line numbers match evidence locations;
- reasons mentioning APIs/variables are lexically consistent with cited evidence text;
- low-trust evidence is not silently used as a vulnerable statement;
- an additional consistency-repair model call is made if the final JSON is structurally valid but semantically inconsistent.

## Report additions

The agent demo index now supports filtering by `TP`, `FP`, `TN`, `FN`, and search by sample/project/function.
Sample demos include report-only commit message metadata and KG representation details.
