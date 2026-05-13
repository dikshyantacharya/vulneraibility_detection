# Evidence grounding and API-readiness improvements

This version keeps the existing CLI, validation, KG cache, scaling analysis, and agent-demo workflow, but strengthens the contract between the LLM and the KG tool.

## Implemented changes

1. **Executable `wanted_evidence`**
   - KG queries now carry `wanted_evidence` into the tool execution trace.
   - Variable queries return category-balanced slices rather than the first few text matches.
   - Diagnostics report `category_counts` and `missing_wanted_evidence`.

2. **Category-balanced variable slices**
   Variable queries can return separate evidence for:
   - declaration
   - allocation/definition
   - writes
   - bounds checks / guards
   - sinks / risky calls
   - lifetime/free
   - fallback uses

3. **Target-scoped exact-symbol matching**
   - `variable: buf` defaults to target-function scope and exact identifier matching.
   - It does not intentionally match `tmpbuf`, `inbuf`, or project-wide substrings unless project scope is requested.

4. **Lightweight lexical binding**
   - Model queries may include `source_line` from the source-only hypothesis.
   - The KG tool converts function-relative source lines to file lines and chooses the closest visible declaration before that line.
   - This helps distinguish shadowed variables such as outer `buf` and block-local `char buf[256]`.

5. **Intent-aware duplicate filtering**
   - Duplicate filtering now considers query type, query string, scope, match mode, wanted evidence, and source line.
   - A second query for the same variable is allowed if it asks for a materially different slice such as `writes` and `bounds_checks`.

6. **Final risk-evidence audit**
   - Before the final decision, the agent adds a public audit entry listing target-local risky writes/sinks, guards, and variable-slice evidence.
   - The final prompt explicitly asks the model to inspect all risk/guard evidence, not only the weakest hypothesis ledger item.

7. **Evidence-consistency repair remains active**
   - Final JSON is checked for unknown evidence IDs, line mismatches, and lexical mismatch between cited reason and cited evidence text.
   - Inconsistent final decisions trigger a consistency-repair model call.

8. **Tri-state decision status**
   - The JSON schema now includes `decision_status`: `vulnerable`, `non_vulnerable`, or `inconclusive`.
   - `is_vulnerable` remains available for benchmark binary scoring.

## What is still intentionally not claimed

The KG remains a dependency-light, source-only, CPG-inspired representation. It is not yet a full compiler-aware Joern/Clang/CodeQL CPG. The manifest and reports state this explicitly.

## What to inspect before paid API runs

For each sample report, inspect:

- `KG query/tool rounds` → actual KG tool parameters include `scope`, `match`, `wanted_evidence`, `source_line`, and category diagnostics.
- `Returned evidence` → check that variable queries return writes/sinks/guards, not only declarations.
- `Final risk evidence audit` in the hypothesis ledger.
- `final_prediction.json` → distinguish `decision_status` from the binary `is_vulnerable` field.
- `privacy_scan.json` → ensure commit messages, labels, CVE/CWE hints, and commits are report-only unless explicitly configured.
