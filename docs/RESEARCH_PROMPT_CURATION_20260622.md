# Research Agentic Proof Prompt Curation — 2026-06-22

This patch improves the **research-side** LLM + CodeKG agentic proof loop. It does not modify the Student Challenge agent contract.

## Main changes

1. **Universal source-only hypothesis prompt**
   - Removed project/function-specific negative rules such as `/proc/%d/environ`.
   - Replaced them with general C/C++ vulnerability-family guidance: memory safety, integer/bounds, parser/state, allocation/lifetime, path/file, command/API misuse, protocol/access-control, concurrency/lifecycle, and crypto/algorithmic misuse.
   - Keeps the requirement that hypotheses must be source-grounded and testable by later CodeKG retrieval.

2. **Curated evidence cards before LLM verification**
   - Added `src/vckg_agentic_proof/evidence_curator.py`.
   - Stage 04, Stage 05, and Stage 06 now receive `CURATED ... EVIDENCE` instead of raw accumulated evidence.
   - The curator removes graph-only noise from model-visible prompts: `line_start`, `line_end`, `score`, large CodeKG query summaries, standalone parameter nodes, duplicate snippets, and low-value isolated declarations such as `int i;`.
   - Evidence IDs are preserved for citation.
   - File/function identity is retained only when useful for source orientation.

3. **Cleaner code snippets**
   - CodeKG snippets like `512 | int x = ...` are normalized to normal source code.
   - Trailing repeated labels such as `fillBuffer\nmain.c` are removed.

4. **Human-like audit orientation**
   - Evidence is grouped into roles such as `target_risky_operation_or_guard`, `caller_context`, `callee_context`, `related_function_context`, `definition_or_constant`, `semantic_fact`, and `deterministic_source_fact`.
   - The LLM receives selected high-value evidence plus a compact index of available-but-not-shown evidence, so it can ask targeted follow-up queries instead of being forced to reason from a graph dump.

5. **Prompt truncation visibility**
   - `pipeline.py` now records `prompt_has_truncation_marker` in model call records and live events.
   - If `...<truncated>...` appears in the model-visible prompt, the trace will explicitly show it.

## Important files changed

```text
src/vckg_agentic_proof/evidence_curator.py
src/vckg_agentic_proof/prompts.py
src/vuln_commit_kg/orchestration/pipeline.py
```

## Expected effect in the next run

In `model_calls.jsonl` and the dashboard flow report, Stage 04 should now show:

```text
CURATED ACCUMULATED EVIDENCE
```

instead of raw `ACCUMULATED EVIDENCE` containing repeated line metadata and graph scores. The prompt should be shorter and more focused on code relationships that matter for vulnerability proof: caller inputs, callee transformations, guards, constants, allocations, and dangerous operations.
