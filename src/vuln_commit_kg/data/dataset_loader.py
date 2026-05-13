from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

import pandas as pd

from .schema import SecVulEvalSample, _to_builtin


def _is_missing(value: Any) -> bool:
    value = _to_builtin(value)
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (bytes, bytearray)):
        return len(value) == 0
    if isinstance(value, float):
        return math.isnan(value)
    if isinstance(value, (list, tuple, set)):
        return len(value) == 0
    try:
        missing = pd.isna(value)
    except Exception:
        return False
    if isinstance(missing, bool):
        return missing
    # pd.isna(list/array) returns an array-like object; do not coerce it to bool.
    return False


def _text_value(value: Any, default: str = "") -> str:
    value = _to_builtin(value)
    if _is_missing(value):
        return default
    if isinstance(value, (list, tuple, set)):
        parts = [_text_value(v, "") for v in value]
        parts = [p for p in parts if p]
        return parts[0] if len(parts) == 1 else ",".join(parts)
    return str(value)


def _optional_text(value: Any) -> str | None:
    text = _text_value(value, "")
    return text if text else None


def _row_get(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    lower = {str(k).lower(): k for k in row.keys()}
    for name in names:
        key = name if name in row else lower.get(name.lower())
        if key is None:
            continue
        value = _to_builtin(row[key])
        if not _is_missing(value):
            return value
    return default


def _norm_url(row: dict[str, Any]) -> str | None:
    return _optional_text(_row_get(row, "project_url", "repo_url", "repository_url", "url", "github_url", "repo"))


def _norm_project(row: dict[str, Any]) -> str:
    project = _row_get(row, "project", "project_name", "repository", "repo", "repo_name", "name")
    if not _is_missing(project):
        return _text_value(project)
    url = _norm_url(row)
    if url:
        return str(url).rstrip("/").split("/")[-1].removesuffix(".git")
    return "unknown_project"


def _norm_func_body(row: dict[str, Any]) -> str:
    val = _row_get(row, "func_body", "function_body", "target_function", "function", "source", "code", "func_before", "vulnerable_function", "fixed_function")
    return _text_value(val, "")


def _norm_func_name(row: dict[str, Any]) -> str:
    val = _row_get(row, "func_name", "function_name", "target_func", "target_function_name", "symbol", "name")
    if not _is_missing(val):
        return _text_value(val)
    import re
    body = _norm_func_body(row)
    m = re.search(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", body)
    return m.group(1) if m else "unknown_function"


def _norm_label(row: dict[str, Any]) -> Any:
    return _row_get(row, "is_vulnerable", "vulnerable", "label", "target", "ground_truth", "is_buggy", default=False)


_NORMALIZED_FIELD_ALIASES = {
    # Canonical fields plus common dataset aliases consumed by _normalize_row.
    # These must not be forwarded again via **extra_fields, otherwise Python raises
    # "got multiple values for keyword argument ..." before Pydantic can handle extras.
    "idx", "index",
    "sample_id", "id",
    "project", "project_name", "repository", "repo", "repo_name", "name",
    "project_url", "repo_url", "repository_url", "url", "github_url",
    "filepath", "file_path", "path", "filename", "file",
    "func_name", "function_name", "target_func", "target_function_name", "symbol",
    "func_body", "function_body", "target_function", "function", "source", "code",
    "func_before", "vulnerable_function", "fixed_function",
    "commit_id", "commit", "commit_hash", "dataset_commit", "before_commit",
    "fix_commit", "patch_commit_id",
    "commit_message", "message", "fix_message",
    "is_vulnerable", "vulnerable", "label", "target", "ground_truth", "is_buggy",
    "cve_list", "cves", "cve",
    "cwe_list", "cwes", "cwe",
}


def _extra_fields(row: dict[str, Any]) -> dict[str, Any]:
    consumed = {name.lower() for name in _NORMALIZED_FIELD_ALIASES}
    return {k: _to_builtin(v) for k, v in row.items() if str(k).lower() not in consumed}


def _safe_int(value: Any, default: int) -> int:
    if _is_missing(value):
        return int(default)
    try:
        return int(_text_value(value))
    except Exception:
        return int(default)


def _normalize_row(row: dict[str, Any], idx: int) -> SecVulEvalSample:
    sample_id = _row_get(row, "sample_id", "id", "idx", "index", default=str(idx))
    return SecVulEvalSample(
        idx=_safe_int(_row_get(row, "idx", "index", default=idx), idx),
        sample_id=_text_value(sample_id, str(idx)),
        project=_norm_project(row),
        project_url=_norm_url(row),
        filepath=_text_value(_row_get(row, "filepath", "file_path", "path", "filename", "file", default=""), ""),
        func_name=_norm_func_name(row),
        func_body=_norm_func_body(row),
        commit_id=_optional_text(_row_get(row, "commit_id", "commit", "commit_hash", "dataset_commit", "before_commit", "fix_commit", "patch_commit_id")),
        commit_message=_optional_text(_row_get(row, "commit_message", "message", "fix_message")),
        is_vulnerable=_norm_label(row),
        cve_list=_row_get(row, "cve_list", "cves", "cve", default=[]),
        cwe_list=_row_get(row, "cwe_list", "cwes", "cwe", default=[]),
        **_extra_fields(row),
    )


def _read_file(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        for key in ("rows", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        return []
    if suffix in {".csv", ".tsv"}:
        return pd.read_csv(path, sep="	" if suffix == ".tsv" else ",").to_dict("records")
    if suffix in {".parquet", ".pq"}:
        return pd.read_parquet(path).to_dict("records")
    if suffix in {".arrow", ".feather"}:
        try:
            import pyarrow.feather as feather
            return feather.read_feather(path).to_pandas().to_dict("records")
        except Exception:
            try:
                import pyarrow.ipc as ipc
                with path.open("rb") as f:
                    reader = ipc.RecordBatchFileReader(f)
                    return reader.read_all().to_pandas().to_dict("records")
            except Exception:
                try:
                    import pyarrow.ipc as ipc
                    with path.open("rb") as f:
                        reader = ipc.open_stream(f)
                        return reader.read_all().to_pandas().to_dict("records")
                except Exception as exc:
                    raise RuntimeError(f"Could not read Arrow dataset {path}: {exc}") from exc
    raise ValueError(f"Unsupported dataset format: {path}")


def load_samples(path: str, mode: str = "file", logger: logging.Logger | None = None) -> list[SecVulEvalSample]:
    if mode == "smoke":
        return smoke_samples()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset path not found: {p}")
    rows = _read_file(p)
    samples = [_normalize_row(dict(row), idx) for idx, row in enumerate(rows)]
    if logger:
        logger.info("Loaded %s samples from %s", len(samples), p)
    return samples


def smoke_samples() -> list[SecVulEvalSample]:
    body = """int count_rows(char *raw, int length) {
  if (raw == NULL) return -1;
  int rows = 0;
  for (int i = 0; i < length; i++) if (raw[i] == '\n') rows++;
  return rows;
}
"""
    return [SecVulEvalSample(idx=0, sample_id="smoke-0", project="smoke", project_url=None, filepath="sample.c", func_name="count_rows", func_body=body, commit_id="local", is_vulnerable=False)]
