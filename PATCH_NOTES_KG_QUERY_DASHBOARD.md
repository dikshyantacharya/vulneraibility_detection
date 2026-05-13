# Patch: audit-query-driven CodeKG dashboard views

This patch adds a direct connection between hypothesis-driven KG queries in the audit report and the interactive CodeKG Explorer.

## Added behavior

- CodeKG dashboard defaults to a light theme.
- Every executed CodeKG agent query now writes a compact retrieval artifact:
  - `<graph_dir>/retrieval_views/<query-id>.json`
- Each retrieval artifact contains:
  - structured query object
  - LLM query reason, when available
  - retrieved node ids
  - retrieved edge ids
  - diagnostics and evidence summary
  - bounded text preview of top retrieved nodes
- The agent demo audit report now shows query cards `Q1`, `Q2`, ... with:
  - why the LLM asked the query
  - structured query object
  - exact KG tool parameters
  - diagnostics
  - returned model-visible evidence text
  - direct links into the CodeKG dashboard
- Each query card provides two dashboard modes:
  - `highlight in KG dashboard`: keeps wider graph context visible and emphasizes retrieved nodes/edges
  - `show only retrieved subgraph`: hides unrelated nodes/edges and shows only the query result

## Main changed files

- `src/codekg/dashboard.py`
- `src/vuln_commit_kg/kg/codekg_adapter.py`
- `src/vuln_commit_kg/agents/reporting.py`
- `tests/test_codekg_integration_smoke.py`
