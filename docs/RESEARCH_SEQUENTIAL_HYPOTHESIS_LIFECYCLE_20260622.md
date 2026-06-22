# Research Agentic Proof: Sequential Hypothesis Lifecycle

This patch changes the research-side LLM + CodeKG audit controller from a global counter-review model into a sequential, stabilized, one-hypothesis-at-a-time lifecycle.

## Key behavior

1. The system still generates hypotheses once from the target source.
2. Hypotheses are then sanitized, lightly deduplicated, ranked, and traced under `01_hypothesis_normalization`.
3. Each hypothesis is processed independently:
   - `02_kg_query_planning__HYP-*`
   - `03_retrieval__HYP-*`
   - `04_hypothesis_verification__HYP-*`
   - optional evidence-gap retrieval loop
   - terminal verification when evidence is exhausted
   - immediate `05_counter_evidence_review__HYP-*`
   - `05_hypothesis_proof_state__HYP-*`
4. The controller moves to the next hypothesis only after the current hypothesis has been proof-gated and counter-reviewed.
5. A raw LLM `confirmed_vulnerability` is treated only as a proposal. It becomes stopping evidence only if it survives proof-gating and local counter-review as `accepted_confirmed`.
6. If `stop_on_confirmed_vulnerability=true`, the audit stops only after `accepted_confirmed_after_local_counter_review`, not after raw verification.
7. Stage 06 receives the stabilized hypothesis states and an aggregate of all local counter-review findings.

## Report visibility

The text report now surfaces:

- hypothesis normalization notes,
- review order,
- per-hypothesis local counter-review stages,
- pre-counter and post-counter status,
- whether the hypothesis became `accepted_confirmed`,
- early stop only when an accepted confirmed vulnerability survives counter-review,
- more controller events before truncating the event summary.

## Important distinction

This patch enforces the sequential lifecycle. It does not yet fully replace hypothesis-level verification with atomic proof-obligation micro-verification. That remains the next larger architecture step if you want each proof obligation to become its own LLM call and ledger row.
