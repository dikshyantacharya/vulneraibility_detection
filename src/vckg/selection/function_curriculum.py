"""
Function-curriculum sample selection for VCKG.

Goal
----
Select exactly N target functions, each represented by a vulnerable/fixed pair,
ordered by ascending project complexity.

This module is intentionally defensive because SecVulEval-derived rows and
repo-inventory rows often evolve over time. It accepts dictionaries, dataclasses,
pandas rows, or pyarrow-derived rows, and it normalizes field names at runtime.

Definitions
-----------
Target function:
    Unique tuple of:
      project_url/project, filepath, function, patch/fix commit identity.

Pair:
    Two samples for the same target function:
      - vulnerable sample resolved to pre-fix parent commit
      - fixed/non-vulnerable sample resolved to patch commit

Project complexity:
    Primary: eligible source files or source files in repo inventory.
    Secondary: total source bytes, file count, function count, node/edge count if available.
    Fallback: stable lexical ordering by project and function.

Expected output:
    A flat list of selected sample records, length == 2 * target_functions
    unless `require_complete_pairs=False`.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable, Iterable, Mapping, Sequence
from pathlib import Path
import hashlib
import json
import logging
import math
import re

LOG = logging.getLogger(__name__)


VULN_LABELS = {
    "vulnerable",
    "vuln",
    "1",
    1,
    True,
}

FIXED_LABELS = {
    "fixed",
    "non-vulnerable",
    "non_vulnerable",
    "safe",
    "0",
    0,
    False,
}


@dataclass(frozen=True)
class PairKey:
    project: str
    project_url: str
    filepath: str
    function: str
    patch_commit: str


@dataclass(frozen=True)
class Complexity:
    score: tuple
    eligible_source_files: int | None = None
    files_scanned: int | None = None
    source_bytes: int | None = None
    functions: int | None = None
    nodes: int | None = None
    edges: int | None = None
    source: str = "fallback"


@dataclass
class CandidatePair:
    key: PairKey
    vulnerable: Any
    fixed: Any
    complexity: Complexity
    inventory_rank: int
    dataset_order: int


def _row_get(row: Any, *names: str, default: Any = None) -> Any:
    """Best-effort field lookup across dicts, dataclasses, objects, and pandas rows."""
    if row is None:
        return default

    if isinstance(row, Mapping):
        for name in names:
            if name in row and row[name] is not None:
                return row[name]

    # pandas Series or pyarrow scalar-like mappings sometimes expose get().
    get = getattr(row, "get", None)
    if callable(get):
        for name in names:
            try:
                value = get(name, None)
                if value is not None:
                    return value
            except Exception:
                pass

    for name in names:
        if hasattr(row, name):
            value = getattr(row, name)
            if value is not None:
                return value

    return default


def _norm_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _norm_commit(value: Any) -> str:
    s = _norm_str(value)
    return s[:40]


def _norm_label(value: Any) -> str:
    if isinstance(value, bool):
        return "vulnerable" if value else "fixed"
    if isinstance(value, int):
        return "vulnerable" if value == 1 else "fixed"
    s = _norm_str(value).lower()
    s = s.replace("_", "-")
    if s in {"vulnerable", "vuln", "yes", "true", "1"}:
        return "vulnerable"
    if s in {"fixed", "non-vulnerable", "nonvulnerable", "safe", "false", "0"}:
        return "fixed"
    return s


def _is_vulnerable(row: Any) -> bool:
    raw = _row_get(row, "label", "target", "is_vulnerable", "vulnerable", "ground_truth")
    return raw in VULN_LABELS or _norm_label(raw) == "vulnerable"


def _is_fixed(row: Any) -> bool:
    raw = _row_get(row, "label", "target", "is_vulnerable", "vulnerable", "ground_truth")
    return raw in FIXED_LABELS or _norm_label(raw) == "fixed"


def _patch_commit(row: Any) -> str:
    return _norm_commit(_row_get(
        row,
        "patch_commit",
        "fix_commit",
        "fixed_commit",
        "commit",
        "dataset_commit",
        "after_commit",
        "commit_hash",
    ))


def _sample_id(row: Any) -> str:
    return _norm_str(_row_get(row, "id", "sample_id", "idx", "index", default=""))


def _project(row: Any) -> str:
    project = _norm_str(_row_get(row, "project", "repo", "repository", "project_name", default=""))
    if project:
        return project
    url = _norm_str(_row_get(row, "project_url", "repo_url", "url", default=""))
    return url.rstrip("/").split("/")[-1] if url else ""


def _project_url(row: Any) -> str:
    return _norm_str(_row_get(row, "project_url", "repo_url", "url", "repository_url", default=""))


def _filepath(row: Any) -> str:
    return _norm_str(_row_get(row, "filepath", "file_path", "path", "filename", "file", default=""))


def _function(row: Any) -> str:
    return _norm_str(_row_get(row, "function", "function_name", "func_name", "target_function", "symbol", default=""))


def _pair_key(row: Any) -> PairKey:
    return PairKey(
        project=_project(row),
        project_url=_project_url(row),
        filepath=_filepath(row),
        function=_function(row),
        patch_commit=_patch_commit(row),
    )


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, float) and math.isnan(value):
            return None
        return int(value)
    except Exception:
        return None


def _stable_hash_int(*parts: str, modulo: int = 10_000_000) -> int:
    h = hashlib.sha1("::".join(parts).encode("utf-8", errors="ignore")).hexdigest()
    return int(h[:12], 16) % modulo


def complexity_from_row_or_inventory(row: Any, inventory: Mapping[str, Mapping[str, Any]] | None = None) -> Complexity:
    """
    Compute a stable ascending complexity tuple.

    Preferred fields:
      eligible_source_files, source_files, files_scanned, source_bytes, functions, nodes, edges.

    The tuple is ordered from most important to least important:
      source-file count, source bytes, functions, nodes, edges, lexical fallback hash.
    """
    project = _project(row)
    project_url = _project_url(row)

    inv = None
    if inventory:
        inv = (
            inventory.get(project_url)
            or inventory.get(project)
            or inventory.get(project.lower())
            or inventory.get(project_url.lower())
        )

    def val(*names: str) -> int | None:
        for source in (row, inv):
            if source is None:
                continue
            x = _safe_int(_row_get(source, *names))
            if x is not None:
                return x
        return None

    eligible_source_files = val(
        "eligible_source_files",
        "source_files",
        "num_source_files",
        "c_cpp_files",
        "project_source_files",
        "files",
    )
    files_scanned = val("files_scanned", "total_files", "repo_files", "file_count")
    source_bytes = val("source_bytes", "total_source_bytes", "bytes", "repo_bytes")
    functions = val("functions", "function_count", "num_functions")
    nodes = val("nodes", "kg_nodes", "node_count")
    edges = val("edges", "kg_edges", "edge_count")

    source = "inventory" if inv else "row_or_fallback"

    # Unknown values are pushed later, but the lexical fallback keeps deterministic ordering.
    inf = 10**12
    primary_files = eligible_source_files if eligible_source_files is not None else files_scanned
    stable = _stable_hash_int(project, project_url)

    score = (
        primary_files if primary_files is not None else inf,
        source_bytes if source_bytes is not None else inf,
        functions if functions is not None else inf,
        nodes if nodes is not None else inf,
        edges if edges is not None else inf,
        project.lower(),
        project_url.lower(),
        stable,
    )

    return Complexity(
        score=score,
        eligible_source_files=eligible_source_files,
        files_scanned=files_scanned,
        source_bytes=source_bytes,
        functions=functions,
        nodes=nodes,
        edges=edges,
        source=source,
    )


def load_inventory(path: str | Path | None) -> dict[str, dict[str, Any]]:
    """
    Load optional project inventory.

    Supported formats:
      - JSON list of objects
      - JSON object keyed by project/project_url
      - JSONL, one object per line

    Returns keys for both project and project_url when present.
    """
    if not path:
        return {}

    p = Path(path)
    if not p.exists():
        LOG.warning("function_curriculum.inventory_missing | path=%s", p)
        return {}

    rows: list[dict[str, Any]] = []
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return {}

    if p.suffix.lower() == ".jsonl":
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        rows.append(obj)
                except json.JSONDecodeError:
                    LOG.warning("function_curriculum.inventory_bad_jsonl_line | path=%s", p)
    else:
        obj = json.loads(text)
        if isinstance(obj, list):
            rows.extend([x for x in obj if isinstance(x, dict)])
        elif isinstance(obj, dict):
            # Either already keyed inventory or one project object.
            if any(isinstance(v, dict) for v in obj.values()):
                for k, v in obj.items():
                    if isinstance(v, dict):
                        vv = dict(v)
                        vv.setdefault("project", k)
                        rows.append(vv)
            else:
                rows.append(obj)

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        project = _norm_str(_row_get(row, "project", "repo", "repository", "project_name", default=""))
        url = _norm_str(_row_get(row, "project_url", "repo_url", "url", "repository_url", default=""))
        for key in {project, url, project.lower(), url.lower()}:
            if key:
                out[key] = row
    return out


def group_candidate_pairs(
    samples: Sequence[Any],
    *,
    inventory: Mapping[str, Mapping[str, Any]] | None = None,
    require_complete_pairs: bool = True,
) -> list[CandidatePair]:
    grouped: dict[PairKey, dict[str, Any]] = {}
    first_order: dict[PairKey, int] = {}

    for idx, row in enumerate(samples):
        key = _pair_key(row)
        if not key.project or not key.filepath or not key.function:
            continue

        bucket = grouped.setdefault(key, {})
        first_order.setdefault(key, idx)

        if _is_vulnerable(row):
            bucket["vulnerable"] = row
        elif _is_fixed(row):
            bucket["fixed"] = row
        else:
            # Unknown labels are ignored so they cannot contaminate paired evaluation.
            continue

    pairs: list[CandidatePair] = []
    for key, bucket in grouped.items():
        vuln = bucket.get("vulnerable")
        fixed = bucket.get("fixed")

        if require_complete_pairs and (vuln is None or fixed is None):
            continue
        if vuln is None and fixed is None:
            continue

        representative = vuln if vuln is not None else fixed
        comp = complexity_from_row_or_inventory(representative, inventory)
        pairs.append(
            CandidatePair(
                key=key,
                vulnerable=vuln,
                fixed=fixed,
                complexity=comp,
                inventory_rank=_safe_int(_row_get(representative, "inventory_rank", "rank", default=None)) or 10**12,
                dataset_order=first_order[key],
            )
        )

    return pairs


def select_function_curriculum_pairs(
    samples: Sequence[Any],
    *,
    target_functions: int,
    inventory_path: str | Path | None = None,
    inventory: Mapping[str, Mapping[str, Any]] | None = None,
    require_complete_pairs: bool = True,
    one_function_per_project: bool = False,
    logger: logging.Logger | None = None,
) -> list[Any]:
    """
    Select exactly `target_functions` target function pairs if available.

    Sort policy:
      1. project complexity ascending
      2. inventory rank if present
      3. project name
      4. filepath
      5. function name
      6. dataset order

    Returns:
      Flat list in pair order:
        [vuln_1, fixed_1, vuln_2, fixed_2, ...]
    """
    log = logger or LOG
    if target_functions <= 0:
        raise ValueError("target_functions must be positive")

    inv = dict(inventory or {})
    if inventory_path:
        inv.update(load_inventory(inventory_path))

    log.info(
        "function_curriculum.selection.start | target_functions=%s | candidates=%s | sort=project_complexity_asc",
        target_functions,
        len(samples),
    )

    pairs = group_candidate_pairs(samples, inventory=inv, require_complete_pairs=require_complete_pairs)

    pairs.sort(
        key=lambda p: (
            p.complexity.score,
            p.inventory_rank,
            p.key.project.lower(),
            p.key.filepath.lower(),
            p.key.function.lower(),
            p.dataset_order,
        )
    )

    selected: list[CandidatePair] = []
    used_projects: set[str] = set()

    for pair in pairs:
        project_key = pair.key.project_url or pair.key.project
        if one_function_per_project and project_key in used_projects:
            continue

        selected.append(pair)
        used_projects.add(project_key)

        c = pair.complexity
        log.info(
            "function_curriculum.selected_pair | rank=%s | project=%s | function=%s | filepath=%s | "
            "complexity_files=%s | source_bytes=%s | functions=%s | nodes=%s | edges=%s | vuln_id=%s | fixed_id=%s",
            len(selected),
            pair.key.project,
            pair.key.function,
            pair.key.filepath,
            c.eligible_source_files if c.eligible_source_files is not None else c.files_scanned,
            c.source_bytes,
            c.functions,
            c.nodes,
            c.edges,
            _sample_id(pair.vulnerable),
            _sample_id(pair.fixed),
        )

        if len(selected) >= target_functions:
            break

    selected_samples: list[Any] = []
    for pair in selected:
        if pair.vulnerable is not None:
            selected_samples.append(pair.vulnerable)
        if pair.fixed is not None:
            selected_samples.append(pair.fixed)

    log.info(
        "function_curriculum.selection.summary | requested_functions=%s | available_pairs=%s | "
        "selected_pairs=%s | selected_samples=%s | one_function_per_project=%s",
        target_functions,
        len(pairs),
        len(selected),
        len(selected_samples),
        one_function_per_project,
    )

    if len(selected) < target_functions:
        log.warning(
            "function_curriculum.selection_shortfall | requested_functions=%s | selected_pairs=%s | "
            "available_pairs=%s",
            target_functions,
            len(selected),
            len(pairs),
        )

    return selected_samples


def selected_sample_ids(samples: Sequence[Any]) -> set[str]:
    """Utility for guard checks in the runner."""
    return {_sample_id(s) for s in samples if _sample_id(s)}
