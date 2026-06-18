# Student Evaluation Defaults Round 11

This update makes local student KG evaluation easier to run from the dashboard.

## KG API key default

The local student KG API now defaults to `dev-key-KG` consistently in:

- `student-system-creator serve`
- `student-system-creator evaluate`
- `student-system-creator validate-challenge`
- dashboard Evaluate Solution form
- challenge API config defaults

This is not an LLM key. It is only the bearer token used by the local KG API.

## Train row limit

`evaluate` now supports:

```powershell
--train-limit 20
```

When set, only the first N rows from `train.csv` are loaded into `solution.py` via `train_rows` and passed to `agent.fit(...)`. The test/evaluation limit remains controlled separately by `--limit`.

The frontend Evaluate Solution page now has a `train row limit` field. Leave it blank to use all train rows.
