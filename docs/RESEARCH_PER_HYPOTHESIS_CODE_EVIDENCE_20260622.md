# Research Agentic Proof Upgrade — Per-Hypothesis Code Evidence

This patch changes the research-side agentic vulnerability flow, not the Student Challenge evaluator.

## Main behavioral change

The proof loop now verifies one hypothesis at a time:

1. Generate source-only hypotheses from the target function.
2. For each hypothesis independently:
   - ask the LLM for a targeted CodeKG query plan for that hypothesis only;
   - retrieve source-code evidence from CodeKG;
   - verify only that hypothesis against a code evidence bundle;
   - if unresolved, ask for follow-up CodeKG queries for that hypothesis only;
   - repeat until the hypothesis is confirmed, refuted, exhausted, or the iteration limit is reached.
3. Run counter-evidence review and final adjudication over the accumulated per-hypothesis results.

This avoids sending all hypotheses and all retrieved graph snippets into one large verification prompt.

## Prompt changes

- Stage 01 no longer asks for a fixed 3–6 hypotheses. It asks for all distinct, source-grounded, plausible hypotheses.
- Stage 02 query planning is now general and code-retrieval oriented. It no longer contains buffer-parser-specific examples.
- Stage 04 verification is general and vulnerability-family-aware without target-function-specific examples.
- Stage 05/06 prompts use source-code evidence bundles instead of curated summary cards.

## Evidence-format change

The LLM-facing verification evidence is now `SOURCE CODE EVIDENCE BUNDLE`, built by:

```text
src/vckg_agentic_proof/code_evidence.py
```

The bundle contains only source-code sections, for example:

- target function source;
- caller functions;
- callee functions;
- related helper functions;
- definitions, constants, macros, typedefs, structs;
- focused guard/sink/source code slices.

It deliberately omits:

- graph score;
- line_start / line_end;
- raw CodeKG query summaries;
- semantic summary cards;
- isolated parameter nodes;
- isolated trivial declarations such as `int i;`.

Code snippets are normalized by removing `512 |`-style line prefixes and repeated trailing labels such as function/file names.

## Important config

`AgenticProofConfig.per_hypothesis_verification` defaults to `True`.

The iterative follow-up loop still respects `AgenticProofConfig.iterative_evidence_loop`. Existing dashboard configurations that already enable the evidence loop will run the new per-hypothesis follow-up strategy.

## Trace impact

New stage names include the hypothesis id, for example:

```text
02_kg_query_planning__HYP-01
03_retrieval__HYP-01
04_hypothesis_verification__HYP-01
04_evidence_gap__HYP-01_iter1
03_followup_retrieval__HYP-01_iter1
04_hypothesis_done__HYP-01
```

Prompt call events also record `prompt_has_truncation_marker`, so reports can show whether the actual model-visible prompt contained `...<truncated>...`.
