"""
Integration helper for the VCKG runner.

Use this file as a guide if your existing runner has different names.

The key invariant is:

    selected_samples_for_run = select_samples_from_config(...)
    resolved_samples = resolve_commits(selected_samples_for_run)
    runnable_samples = build_or_load_kgs(resolved_samples)
    classify(runnable_samples)

Never pass the original candidate pool to classification after a validating selector
has reduced the run to a smaller subset.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
import logging

from vckg.selection.function_curriculum import select_function_curriculum_pairs

LOG = logging.getLogger(__name__)


def select_samples_from_config(all_samples: Sequence[Any], config: Mapping[str, Any]) -> list[Any]:
    """
    Adapter to be called from your existing run pipeline after loading the dataset.

    Expected config shape:

    sample_selection:
      mode: function_curriculum
      target_functions: 5
      inventory_path: cache/repo_inventory/project_inventory.jsonl
      require_complete_pairs: true
      one_function_per_project: false
    """
    sel = config.get("sample_selection", {}) or {}
    mode = sel.get("mode", "")

    if mode not in {"function_curriculum", "smallest_project_functions", "project_complexity_curriculum"}:
        raise ValueError(
            "selection_integration.select_samples_from_config only handles curriculum modes. "
            "Keep your existing selector for other modes."
        )

    return select_function_curriculum_pairs(
        all_samples,
        target_functions=int(sel.get("target_functions", sel.get("num_functions", 5))),
        inventory_path=sel.get("inventory_path"),
        require_complete_pairs=bool(sel.get("require_complete_pairs", True)),
        one_function_per_project=bool(sel.get("one_function_per_project", False)),
        logger=LOG,
    )


def enforce_selected_subset(stage_name: str, samples: Sequence[Any], expected_count: int | None = None) -> None:
    """
    Guard against the exact bug visible in your log:
    selected_samples=10 but classification starts with 160.
    """
    n = len(samples)
    if expected_count is not None and n != expected_count:
        raise RuntimeError(
            f"{stage_name}: selected sample propagation failed. "
            f"Expected {expected_count} samples, got {n}. "
            f"Do not pass candidate_samples/all_samples into this stage."
        )

    LOG.info("%s | selected_samples=%s", stage_name, n)
