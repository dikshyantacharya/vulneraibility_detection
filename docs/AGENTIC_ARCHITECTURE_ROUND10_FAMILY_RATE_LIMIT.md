# Agentic architecture round 10: family-aware proof routing and SAIA/GWDG rate limiting

This round is label-free: it does not place true labels, sample ids, commit messages, or project URLs into model-visible prompts.

## Main changes

1. **Local API scheduler for SAIA/GWDG quotas**
   - Dashboard-generated research runs now schedule requests below the observed limits: 9/minute, 190/hour, 390/day, 2900/month.
   - The scheduler persists recent request timestamps under `cache/api_rate_limits`, so restarting the dashboard does not immediately burst over the provider quota.
   - Provider 429/rate-limit errors are retried with waits, without probing the quota endpoint repeatedly.

2. **Valid CodeKG query enforcement**
   - Non-call query strings such as `length`, `raw`, `header`, or `in` are rewritten into `variable_flow(...)` when possible.
   - Arbitrary free-form or placeholder query text is dropped and no longer wastes the loop budget.

3. **Family-aware deterministic source facts**
   - Adds routing facts for protocol/network trust boundaries, crypto/algorithmic transforms, parser/state-machine code, access-control/privileged surfaces, and length/offset-sensitive operations.
   - These facts guide verification and final validation beyond source-local memory bugs.

4. **Family-specific proof guidance**
   - Prompts now distinguish allocation, parser/state, protocol/access-control, crypto/algorithmic, integer/bounds, path/file, and lifecycle proof obligations.
   - Counter-evidence must dominate the exact dangerous operation/value and protect the same value domain.

## Quota note

The observed headers were roughly 10/min, 200/hour, 400/day, 3000/month. This project deliberately schedules below those values. Do not enable high API parallelism for 50+ function runs unless the provider quota is increased.
