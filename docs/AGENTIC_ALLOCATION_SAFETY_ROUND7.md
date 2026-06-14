# Agentic Audit Round 7: Allocation-Safety Precision/Recall Layer

This round adds a generic, label-free allocation-safety layer for the agentic proof pipeline.

## Motivation

The previous architecture over-corrected toward precision and missed vulnerable functions that used raw `malloc`, `calloc`, or `realloc` results before a visible failure check. It also still produced false positives when the source used the project `safe_calloc` wrapper or a bounded read inside a safe allocation.

## Added deterministic source facts

- `raw_malloc_without_null_check_before_use`
- `raw_calloc_without_null_check_before_use`
- `raw_realloc_assignment_without_temp`
- `safe_calloc_allocation_wrapper_used`
- `bounded_read_within_safe_allocation`

These facts are inferred only from target source text. They do not use true labels, sample IDs, commit messages, or benchmark metadata.

## Validator behavior

- Raw dynamic allocation used before a visible safety check is a high-signal uncovered vulnerability pattern unless covered by a stronger target-specific guard such as dynamic buffer growth.
- `safe_calloc` is positive allocation-safety evidence for zero-size/allocation-failure hypotheses unless a separate pre-call arithmetic overflow is completely proven.
- `safe_calloc(N)` followed by `fread(..., N-1, ...)` refutes fixed-buffer/header-read overflow hypotheses.
- Dynamic growth in the `/proc/%d/environ` family remains safety evidence against the original fixed-size-buffer overflow class; residual unchecked `realloc` does not automatically force vulnerable.

## Expected effect

This should recover vulnerable raw-allocation cases such as raw `malloc`/`calloc` followed by `snprintf`, `fread`, `memset`, indexed writes, or direct `realloc`, while keeping wrapper-based fixed variants non-vulnerable.
