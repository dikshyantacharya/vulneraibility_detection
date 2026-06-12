# Agentic Proof Architecture Improvements — 2026-06-12

This patch focuses on the failure mode observed in `count_rows`: the system found the dangerous expression (`raw += length * itemsize`) but stopped retrieval too early and then accepted weak counter-evidence as if it proved safety.

## Changes

1. **Evidence-loop guardrail**
   - The controller no longer blindly stops when `needs_more_evidence=false` if the same gap-analysis response contains queryable high/medium-priority gaps and concrete follow-up queries.
   - This prevents contradictory gap plans from ending the loop before caller/input-source evidence is retrieved.

2. **Conservative final-decision validation**
   - A `fixed/non-vulnerable` decision with unresolved local-risk hypotheses is converted to evidence-incomplete and scored through the forced-binary path.
   - Missing attacker-control evidence alone is not treated as positive safety evidence.
   - Confirmed non-vulnerable status now requires local risks to be positively refuted by guards, caller constraints, patched logic, safe invariants, or irrelevance.

3. **Prompt hardening**
   - Source-only hypotheses now emphasize parsed length/count fields, pointer wraparound, and missing checks before pointer advancement.
   - KG query planning now asks for caller/input-source retrieval when attacker control is part of the proof chain.
   - Verification and counter-evidence prompts now explicitly distinguish selector variables such as `length_power` from parsed runtime values such as `length = read(raw)`.
   - Defense review is instructed not to treat a reader-selection guard as a bound on the value returned by that reader.

4. **Hypothesis schema robustness**
   - Common LLM alias typo `hypotheses_id` is normalized to `hypothesis_id` so hypotheses are not silently lost.

5. **Regression tests**
   - Added `tests/test_agentic_architecture_guardrails.py` for:
     - contradictory gap-plan continuation,
     - unresolved local risk preventing confirmed non-vulnerable decisions,
     - `hypotheses_id` alias normalization.

## Verification performed in this sandbox

Because the uploaded zip does not include `src/vuln_commit_kg/data`, full pipeline tests that import dataset modules cannot run here. The following checks were run successfully:

```powershell
python -m py_compile src/vckg_agentic_proof/adapter.py src/vckg_agentic_proof/prompts.py src/vckg_agentic_proof/schemas.py src/vckg_agentic_proof/validator.py
PYTHONPATH=src pytest tests/test_agentic_architecture_guardrails.py tests/test_agentic_flow_loop.py::TestIterativeLoopDisabled tests/test_agentic_flow_loop.py::TestIterativeLoopEnabled tests/test_agentic_flow_loop.py::TestLoopStoppingRules tests/test_agentic_flow_loop.py::TestDuplicateQueryDedup tests/test_agentic_prompt_hygiene.py::TestStage02PromptHygiene -q
```

Result: 23 selected tests passed; compile checks passed.
