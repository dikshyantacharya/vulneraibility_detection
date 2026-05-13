# Joern-primary KG backend, semantic enrichment, storage, and visualization

This project now supports two KG modes:

1. `kg.backend: joern` or `auto`: Joern is used as the primary C/C++ Code Property Graph backend when `joern-parse` and `joern-export` are available on `PATH`.
2. `kg.backend: lightweight`: the original dependency-light VCKG C/C++ source parser is used.

`auto` is recommended for development: it tries Joern first and falls back to the existing lightweight graph if Joern is not installed or a Joern export cannot be parsed.

## Full pipeline with Joern-first KG

```powershell
vckg run --config configs/46_curriculum_1_function_agentic_proof_joern_qwen397b.yaml
```

The existing `configs/45_curriculum_1_function_agentic_proof_qwen397b.yaml` has also been updated to use:

```yaml
kg:
  version: project_v6_joern_primary_semantic_overlay
  backend: auto
  semantic_enrichment_enabled: true
  storage_export_graphml: true
  storage_export_csv: true
  visualization_enabled: true
```

## Check Joern availability

```powershell
vckg joern-doctor
```

Expected when Joern is installed:

```text
joern-parse: C:\...\joern-parse.bat
joern-export: C:\...\joern-export.bat
joern: C:\...\joern.bat
available_for_primary_kg: True
```

If it says unavailable, the pipeline still works in `auto` mode via the lightweight fallback.

## Standalone KG build for any local C/C++ project

This builds only the KG, exports storage artifacts, and writes the interactive HTML dashboard. It does not call the LLM.

```powershell
vckg build-project-kg `
  --source C:\path\to\project-or-worktree `
  --out outputs\kg_inspect\my_project `
  --backend auto `
  --project my_project `
  --commit local `
  --target-function count_rows
```

Outputs:

```text
nodes.jsonl
edges.jsonl
manifest.json
nodes.csv
edges.csv
graph.graphml
kg_stats.json
kg_query_contract.json
kg_dashboard.html
```

Open `kg_dashboard.html` in the browser for graph search, navigation, query-contract inspection, and target-function-centered visualization.

## View an existing KG cache

```powershell
vckg view-kg `
  --graph-dir cache\kg\...\project_v6_joern_primary_semantic_overlay\... `
  --target-function count_rows
```

## Query an existing KG

```powershell
vckg query-kg `
  --graph-dir cache\kg\...\project_v6_joern_primary_semantic_overlay\... `
  --kind semantic_facts `
  --target-function count_rows `
  --risk-terms pointer,size,bounds `
  --limit 80 `
  --write-dashboard
```

Or pass a full JSON query:

```powershell
vckg query-kg `
  --graph-dir cache\kg\... `
  --query-json '{"kind":"guards","target_function":"count_rows","symbols":["raw","length","itemsize"],"limit":80}' `
  --write-dashboard
```

## LLM query contract

The LLM should return only a JSON object like this:

```json
{
  "kind": "function_context | node_neighborhood | free_text | risk_paths | guards | calls | semantic_facts | source_to_sink",
  "target_function": "count_rows",
  "symbols": ["raw", "length", "itemsize"],
  "risk_terms": ["pointer", "size", "bounds"],
  "depth": 2,
  "limit": 80
}
```

Recommended query kinds:

- `function_context`: inspect the target function neighborhood.
- `semantic_facts`: inspect pointer, bounds, size, allocation, dereference, and guard facts.
- `guards`: retrieve candidate safety checks around symbols.
- `calls`: inspect caller/callee context.
- `risk_paths` or `source_to_sink`: retrieve risk-oriented evidence around a target function.
- `free_text`: search arbitrary strings, APIs, variables, or graph properties.

The dashboard embeds this same contract under `kg_query_contract.json`, so the query format is visible without reading code.

## Semantic enrichment

After the base CPG is created, VCKG adds a proof-oriented semantic overlay:

- `POINTER_ADVANCE`
- `POINTER_DEREFERENCE`
- `SIZE_ARITHMETIC`
- `BOUNDS_CHECK`
- `ALLOCATION_SIZE`
- `RAW_COPY_OR_READ`
- `ERROR_OR_NULL_GUARD`

This overlay is deliberately conservative and queryable. It does not replace compiler-level pointer/value-flow analysis. The config already reserves `semantic_enrichment_mode: svf_optional` for a future SVF/PhASAR-backed extension.
