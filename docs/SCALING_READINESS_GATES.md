# Scaling readiness gates added after the 3proxy/adminchild paired run

This revision keeps the LLM central, but strengthens source-only evidence completeness before scaling.

## Why another revision was needed

The paired 3proxy/adminchild demo showed that the pipeline was operationally stable, but the model still focused on generic `sprintf` risk and did not reliably decide from the actual admin configuration upload path. The validator correctly downgraded unsupported vulnerable claims to inconclusive, but KG/retrieval/reporting still needed hardening before larger datasets or stronger models.

## Implemented gates

1. **Mandatory source-only upload/config evidence gate**
   - Triggered only from target source patterns: `contentlen`, `sockgetlinebuf`, `buf[i]`, `decodeurl`, and `fprintf`.
   - Retrieves content-length declaration/parsing, counter types, read-bound expression, NUL write, decode, file write, loop progress, `sockgetlinebuf`, and `LINESIZE` definition.
   - Marked as `mandatory_source_evidence_gate`; it is a retrieval-completeness guard, not a classifier.

2. **Semantic upload-loop audit**
   - Detects the pre-fix signed `contentlen/l` + remaining-length clamp + `buf[i]=0` pattern as unsafe audit evidence.
   - Detects the fixed unsigned counters + `l < contentlen` + `min(contentlen-l, LINESIZE-1)` read-bound pattern as safe audit evidence.
   - Exposes these findings to the final prompt and consistency checks as source-only evidence.

3. **Cleaner target vocabulary**
   - Strips comments/string literals before macro/callee extraction.
   - Extracts parameters and comma-separated local declarations, including `i`, `contentlen`, `l`, `error`, `username`, `param`, and shadowed locals.

4. **Cleaner macro/global retrieval**
   - Prefers same-file definitions and definitions before the query line.
   - Avoids flooding reports with unrelated `RETURN` definitions from other files.
   - Keeps at most one alternate definition for shadowed size-like constants such as `LINESIZE`.

5. **Report-only audit metadata fix**
   - Populates prediction/report metadata before post-hoc audit runs.
   - The audit prompt now receives resolved commit, resolved label, and target-validation metadata instead of empty fields.

6. **Final prompt and evidence budget improvements**
   - Final prompt includes risk/guard/upload evidence and semantic safety audit.
   - AcademicCloud configs retain quality-first behavior with `max_evidence_items_after_tools: 240`.

## Local acceptance command

```bash
vckg run --config configs/29_one_function_academiccloud_api.yaml
```

Before scaling, inspect both generated agent demos and verify:

- sample 14569 retrieves and cites signed upload-loop unsafe evidence;
- sample 14570 retrieves and cites the bounded upload-loop mitigation evidence;
- `LINESIZE` is resolved first to the same-file definition;
- report-only audit metadata is complete;
- post-hoc commit audit does not call unrelated `sprintf` reasoning fully aligned with the upload/config commit message;
- final decisions are either correct or low-confidence inconclusive, not high-confidence wrong.
