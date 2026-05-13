# Agentic prompting strategy

This project now separates the model-visible agent loop into explicit public stages.
The goal is to keep the LLM label/commit agnostic while making the KG interaction
look like an auditable investigation rather than one repeated monolithic prompt.

## Stage 1: source-only hypothesis generation

The first model call sees only:

- strict JSON/output rules;
- filepath/function orientation;
- the target function source.

It does **not** receive the initial deterministic KG evidence table. That table is
still saved in the report for auditability and remains available to the orchestrator,
but the model must first inspect the target function itself and decide which
hypotheses and KG queries are worth pursuing.

Expected output:

- `risk_hypotheses`: source-only candidate risks with line numbers / short code
  references;
- `kg_queries`: structured KG queries that would confirm or rule out each
  hypothesis.

## Stage 2+: KG evidence verification

The orchestrator executes the model's structured KG queries. The next prompt receives:

- the public hypothesis/query ledger so far;
- only the new KG evidence returned by the latest KG tool round;
- instructions to update hypothesis status.

The model should mark each relevant hypothesis as:

- `confirmed_vulnerable`;
- `ruled_out_safe`;
- `unresolved`;
- `needs_more_evidence`.

Only unresolved hypotheses should generate new KG queries. Duplicate KG queries are
filtered before execution so the agent does not repeatedly ask the same question.

## Final decision

The final call receives:

- the target function;
- the public hypothesis ledger;
- retrieved KG evidence;
- final decision schema.

The final schema includes `confirmed_hypotheses`, `ruled_out_hypotheses`, and
`unresolved_hypotheses` in addition to the binary decision. The final prompt warns
that a risky API alone is not enough; the decision must be based on concrete target
function evidence and must cite matching evidence IDs.

## What is not exposed

The reports expose public structured reasoning summaries and hypothesis ledgers. They
do not ask the model to reveal hidden/private chain-of-thought. Dataset labels,
commit IDs, patch commits, CVE/CWE hints, and project URLs remain excluded from model
prompts unless explicitly enabled in the prompting config.
