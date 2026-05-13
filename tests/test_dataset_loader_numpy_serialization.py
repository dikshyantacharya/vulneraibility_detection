from __future__ import annotations

import json

import numpy as np

from vuln_commit_kg.data.dataset_loader import _normalize_row
from vuln_commit_kg.utils.jsonl import to_jsonable


def test_dataset_sample_with_numpy_arrays_model_dumps_to_json() -> None:
    row = {
        "idx": np.array([7]),
        "project": np.array(["demo"]),
        "filepath": np.array(["src/demo.c"]),
        "function_name": np.array(["target"]),
        "func_before": "int target(void) { return 0; }",
        "label": np.array([1]),
        "cve": np.array(["CVE-0000-0001", "CVE-0000-0002"]),
        "metadata_array": np.array([1, 2, 3]),
        "metadata_nested": {"scores": np.array([0.1, 0.2])},
    }

    sample = _normalize_row(row, 0)
    payload = sample.model_dump(mode="json")

    assert payload["idx"] == 7
    assert payload["project"] == "demo"
    assert payload["cve_list"] == ["CVE-0000-0001", "CVE-0000-0002"]
    assert payload["metadata_array"] == [1, 2, 3]
    assert payload["metadata_nested"] == {"scores": [0.1, 0.2]}
    json.dumps(payload)
    json.dumps(to_jsonable(sample))
