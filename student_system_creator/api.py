r"""
Minimal standalone KG query runner.

No REST server.
No HTTP POST.
No dashboard.

It directly reads kg_registry_private.json, picks a valid KG id from that
registry, loads the graph folder, executes one CodeKG query, and prints result.

Run:
    python api.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codekg_s.query import GraphQueryEngine
from kg_s.codekg_adapter import (
    _engine_kwargs,
    normalize_codekg_result,
    parse_codekg_query_object,
)


# ---------------------------------------------------------------------------
# Global config
# ---------------------------------------------------------------------------

THIS_FILE_DIR = Path(__file__).resolve().parent

# Works if this file is placed either in:
#   vulnerability_detection/api.py
# or:
#   vulnerability_detection/student_system_creator/api.py
if (THIS_FILE_DIR / "outputs").exists():
    PROJECT_ROOT = THIS_FILE_DIR
elif THIS_FILE_DIR.name == "student_system_creator" and (THIS_FILE_DIR.parent / "outputs").exists():
    PROJECT_ROOT = THIS_FILE_DIR.parent
else:
    PROJECT_ROOT = Path.cwd().resolve()

KG_REGISTRY_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "student_challenge"
    / "vckg_codekg_student_challenge"
    / "private"
    / "kg_registry_private.json"
)

MAX_NODES_PER_QUERY = 500



# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _load_registry() -> dict[str, Any]:
    if not KG_REGISTRY_PATH.exists():
        raise FileNotFoundError(
            f"KG registry not found:\n{KG_REGISTRY_PATH}\n\n"
            f"PROJECT_ROOT is currently:\n{PROJECT_ROOT}"
        )

    with KG_REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _entries() -> dict[str, dict[str, Any]]:
    registry = _load_registry()
    entries = registry.get("entries") or {}
    if not isinstance(entries, dict) or not entries:
        raise RuntimeError(f"No registry entries found in {KG_REGISTRY_PATH}")
    return entries


def list_kg_ids(limit: int = 10) -> None:
    entries = _entries()
    print(f"Registry: {KG_REGISTRY_PATH}")
    print(f"Total KGs: {len(entries)}")
    print()
    for i, (kg_id, entry) in enumerate(entries.items()):
        if i >= limit:
            break
        print(f"{i + 1}. {kg_id}")
        print(f"   function: {entry.get('function_name')}")
        print(f"   file:     {entry.get('filepath')}")
        print()



def graph_dir_for_kg_id(kg_id: str) -> Path:
    entries = _entries()
    entry = entries.get(kg_id)
    if not entry:
        raise KeyError(f"Unknown kg_id: {kg_id}")

    raw_graph_dir = Path(str(entry.get("graph_dir") or ""))
    graph_dir = (
        raw_graph_dir
        if raw_graph_dir.is_absolute()
        else KG_REGISTRY_PATH.parent / raw_graph_dir
    ).resolve()

    if not (graph_dir / "graph.json").exists():
        raise FileNotFoundError(f"graph.json not found for kg_id={kg_id}: {graph_dir}")

    return graph_dir


# ---------------------------------------------------------------------------
# Main KG query function
# ---------------------------------------------------------------------------

def query_kg(kg_id: str, query: str | dict[str, Any]) -> dict[str, Any]:
    """
    Directly execute a KG query from disk.

    Parameters
    ----------
    kg_id:
        A real KG id from kg_registry_private.json.
    query:
        Either a CodeKG function-call-style query string:
            semantic_facts(target_function="some_function")

        Or a parsed query dict:
            {"kind": "semantic_facts", "target_function": "some_function"}
    """
    kg_id = str(kg_id).strip()
    if not kg_id:
        raise ValueError("kg_id cannot be empty")

    if isinstance(query, str):
        parsed_query = parse_codekg_query_object(query)
    elif isinstance(query, dict):
        parsed_query = parse_codekg_query_object(query)
    else:
        raise TypeError("query must be a string or dict")



    parsed_query["max_nodes"] = min(
        int(parsed_query.get("max_nodes") or MAX_NODES_PER_QUERY),
        MAX_NODES_PER_QUERY,
    )

    graph_dir = graph_dir_for_kg_id(kg_id)
    engine = GraphQueryEngine(graph_dir)

    raw_result = engine.run(parsed_query["kind"], **_engine_kwargs(parsed_query))

    if raw_result.get("error"):
        raise RuntimeError(str(raw_result["error"]))

    diagnostics = normalize_codekg_result(
        raw_result,
        query=parsed_query,
        graph_dir=engine.graph_dir,
    )

    return {
        "kg_id": kg_id,
        "graph_dir": str(graph_dir),
        "query": parsed_query,
        "result": raw_result,
        "diagnostics": diagnostics,
    }


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("PROJECT_ROOT:", PROJECT_ROOT)

    kg_id = "kg_redcarpet__redcarpet__022e0e59f19e__a699c82292b1__rndr_quote__safe_ea1383e790"

    print("******************")

    query = f'semantic_facts(target_function="rndr_quote")'

    print("Running test query:")
    print("KG_ID:", kg_id)
    print("TARGET_FUNCTION:", "rndr_quote")
    print("QUERY:", query)
    print()

    output = query_kg(kg_id, query)
    diagnostics = output.get("diagnostics") or {}

    print("Retrieved nodes:", diagnostics.get("retrieved_node_count"))
    print("Retrieved edges:", diagnostics.get("retrieved_edge_count"))
    print("Important functions:", diagnostics.get("important_functions"))
    print("Important variables:", diagnostics.get("important_variables"))

    print("\nFULL RESULT PREVIEW:")
    print(json.dumps(output, indent=2, ensure_ascii=False))
