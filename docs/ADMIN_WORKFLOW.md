# Admin workflow & challenge-integrity protection

This dashboard runs in two modes. The toggle is in the top bar; the default is
set by `default_mode` in settings.

## Admin mode 🔓

Full visibility: labels, vulnerable/safe counts, `repo_key`, `graph_dir`,
resolved commits, private registry, validation/evaluation reports, packaging.

## Student preview mode 🎓

Simulates what a student release exposes. The backend masks data in
`dashboard/inventory.py` — student mode **never** returns:

- `label` on any function/kg row
- `repo_key`, `graph_dir`, full `resolved_commit`
- vulnerable/safe aggregate counts
- the alias map or original (un-anonymized) kg ids

## End-to-end admin workflow

1. **Build / Resume** — launch a build (config-driven, selected projects, selected
   functions, balanced target, or resume). Watch it on the Live Dashboard.
2. **Validate** — run validation; review errors/warnings; export the report.
3. **KG Explorer** — inspect any graph in-browser; filter node types; read source.
4. **Evaluate** — start the KG retrieval API (`serve`), then run a `solution.py`;
   review accuracy/precision/recall/F1 and the confusion matrix.
5. **Agent Audit** — inspect the q1/q2/q3 agent query flow from evaluation logs.
6. **Package** — package the RAID/student bundle (with disk warnings).

## Leakage protection

The Overview page and `GET /api/dashboard/leakage` scan every public kg id for the
tokens `vuln`, `safe`, `label`, `_true`, `_false`. Any match is flagged red — a
public release must show **Clean**. Because the registry stores anonymized ids
(e.g. `kg_b723cef8afdd910141b6`), a clean check confirms the original
vuln/safe-bearing ids were not leaked into public artifacts.

## Files that must stay private

The dashboard never serves these to student mode and never exposes them as static
files:

- `private/test_labels.csv`
- `private/kg_registry_private.json`
- `private/kg_id_alias_map_private.json`
- any original kg id containing `vuln` / `safe`

When preparing a public release, switch to **Student preview** and confirm the
Functions/KG pages show no labels and the leakage check is Clean before packaging.
