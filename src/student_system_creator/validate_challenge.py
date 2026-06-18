from __future__ import annotations

import argparse
import csv
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore[assignment]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_registry_entries(obj: Any):
    if isinstance(obj, dict):
        if ("kg_id" in obj or "knowledge_graph_id" in obj) and ("graph_dir" in obj or "kg_dir" in obj):
            yield obj
        else:
            for value in obj.values():
                yield from _walk_registry_entries(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_registry_entries(item)


def _kg_id(row: dict[str, Any]) -> str:
    return str(row.get("knowledge_graph_id") or row.get("kg_id") or row.get("graph_id") or "")


def _function_name(row: dict[str, Any], registry_entry: dict[str, Any] | None = None) -> str:
    for key in ("function_name", "target_function"):
        if row.get(key):
            return str(row[key])
    if registry_entry:
        for key in ("function_name", "target_function", "function"):
            val = registry_entry.get(key)
            if val and "\n" not in str(val):
                return str(val)
    body = str(row.get("function") or "")
    # Conservative extraction for C/C++ function definitions. This is only a fallback.
    m = re.search(r"([A-Za-z_][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*\{", body)
    if m:
        return m.group(1).split("::")[-1]
    kg = _kg_id(row)
    parts = kg.split("__")
    if len(parts) >= 5:
        return parts[-3]
    return ""


def _resolve_graph_dir(private_root: Path, entry: dict[str, Any]) -> Path:
    raw = Path(str(entry.get("graph_dir") or entry.get("kg_dir") or ""))
    return raw if raw.is_absolute() else private_root / raw


def _iter_nodes_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _graph_contains_function(graph_dir: Path, function_name: str) -> tuple[bool, dict[str, Any] | None]:
    # Prefer nodes.jsonl because it is streamable for large graphs.
    nodes_jsonl = graph_dir / "nodes.jsonl"
    for node in _iter_nodes_jsonl(nodes_jsonl) or []:
        ntype = str(node.get("type") or node.get("kind") or "")
        name = str(node.get("name") or node.get("label") or "")
        attrs = node.get("attrs") or {}
        attr_name = str(attrs.get("name") or attrs.get("full_name") or "")
        if ntype.lower() == "function" and function_name in {name, attr_name, attr_name.split("::")[-1]}:
            return True, node
    # Fallback to graph.json, if present and not too large to parse.
    graph_json = graph_dir / "graph.json"
    if graph_json.exists() and graph_json.stat().st_size < 500_000_000:
        try:
            data = _load_json(graph_json)
            nodes = data.get("nodes") if isinstance(data, dict) else []
            for node in nodes or []:
                if not isinstance(node, dict):
                    continue
                ntype = str(node.get("type") or node.get("kind") or "")
                name = str(node.get("name") or node.get("label") or "")
                attrs = node.get("attrs") or {}
                attr_name = str(attrs.get("name") or attrs.get("full_name") or "")
                if ntype.lower() == "function" and function_name in {name, attr_name, attr_name.split("::")[-1]}:
                    return True, node
        except Exception:
            pass
    return False, None


def _possible_snapshot_paths(repo_worktrees: Path, repo_key: str, resolved_commit: str) -> list[Path]:
    paths = []
    if repo_key and resolved_commit:
        paths.append(repo_worktrees / repo_key / resolved_commit)
        paths.append(repo_worktrees / repo_key / resolved_commit[:12])
    if repo_key and repo_worktrees.exists():
        base = repo_worktrees / repo_key
        if base.exists():
            for p in base.glob(f"{resolved_commit[:12]}*"):
                paths.append(p)
    return [p for p in dict.fromkeys(paths) if p.exists()]


def _source_contains_function(snapshot: Path, filepath: str, project: str, function_name: str) -> tuple[bool, str | None]:
    rels = []
    if filepath:
        rels.append(Path(filepath))
        # Dataset paths often include the project name as prefix while worktrees do not.
        parts = Path(filepath).parts
        if parts and parts[0].lower() == str(project or "").lower():
            rels.append(Path(*parts[1:]))
        # Also try suffix paths by filename.
        rels.extend([p for p in snapshot.rglob(Path(filepath).name)][:20])
    checked = set()
    for rel in rels:
        path = rel if rel.is_absolute() else snapshot / rel
        if path in checked or not path.exists() or not path.is_file():
            continue
        checked.add(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if re.search(rf"\b{re.escape(function_name)}\s*\(", text):
            return True, str(path)
    return False, None


def _api_function_check(api_base: str, kg_id: str, function_name: str, timeout: float, api_key: str | None = None) -> tuple[bool, dict[str, Any] | None, str | None]:
    if requests is None:
        return False, None, "requests is not installed"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    query = {"kind": "function_context", "target_function": function_name, "depth": 1, "max_nodes": 100}
    try:
        resp = requests.post(f"{api_base.rstrip('/')}/api/v1/kgs/{kg_id}/query", json=query, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return False, None, f"status={resp.status_code}: {resp.text[:300]}"
        data = resp.json()
    except Exception as exc:
        return False, None, str(exc)
    text = json.dumps(data, ensure_ascii=False).lower()
    count = data.get("retrieved_node_count") or data.get("node_count") or 0
    try:
        count_i = int(count)
    except Exception:
        count_i = 0
    ok = count_i > 0 and function_name.lower() in text
    return ok, data, None if ok else "function not visible in API response"


def validate_challenge(
    challenge: str | Path,
    *,
    api_base: str | None = None,
    api_key: str | None = "dev-key-KG",
    api_timeout: float = 30.0,
    limit: int | None = None,
    repo_worktrees: str | Path | None = None,
    require_api: bool = False,
    require_source_snapshot: bool = False,
    write_report: str | Path | None = None,
    progress_every: int = 10,
) -> tuple[bool, dict[str, Any]]:
    root = Path(challenge).resolve()
    public = root / "public"
    private = root / "private"
    registry_path = private / "kg_registry_private.json"
    labels_path = private / "test_labels.csv"
    kg_store = private / "kg_store"

    errors: list[str] = []
    warnings: list[str] = []
    checks = Counter()
    backend_counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    label_counts: Counter[int] = Counter()
    source_status_counts: Counter[str] = Counter()

    print(f"validate_challenge.start | challenge={root}", flush=True)
    for p in [public / "train.csv", public / "test.csv", public / "sample_submission.csv", registry_path, labels_path, kg_store]:
        if not p.exists():
            errors.append(f"missing required artifact: {p}")
    if errors:
        return False, {"errors": errors, "warnings": warnings}

    train_rows = _read_csv(public / "train.csv")
    test_rows = _read_csv(public / "test.csv")
    label_rows = _read_csv(labels_path)
    rows = train_rows + test_rows
    if limit is not None:
        rows = rows[: int(limit)]
    labels_by_sample = {str(r.get("sample_id")): int(r.get("vulnerability", 0)) for r in label_rows if r.get("sample_id")}

    registry_data = _load_json(registry_path)
    entries_list = list(_walk_registry_entries(registry_data))
    entries = {str(e.get("knowledge_graph_id") or e.get("kg_id")): e for e in entries_list}
    kg_folders = [p for p in kg_store.iterdir() if p.is_dir()]

    print(
        f"validate_challenge.inventory | registry_entries={len(entries)} | kg_folders={len(kg_folders)} | train_rows={len(train_rows)} | test_rows={len(test_rows)} | checked_rows={len(rows)}",
        flush=True,
    )

    if len(entries) != len(kg_folders):
        warnings.append(f"registry entries ({len(entries)}) != kg folders ({len(kg_folders)})")
    if len(entries) < len(train_rows) + len(test_rows):
        errors.append(f"registry entries ({len(entries)}) < public rows ({len(train_rows)+len(test_rows)})")

    seen_rows = set()
    start = time.time()
    for i, row in enumerate(rows, 1):
        sample_id = str(row.get("sample_id") or "")
        kg_id = _kg_id(row)
        if not kg_id:
            errors.append(f"row {i}: missing knowledge_graph_id")
            continue
        if kg_id in seen_rows:
            errors.append(f"duplicate public kg_id in checked rows: {kg_id}")
        seen_rows.add(kg_id)
        entry = entries.get(kg_id)
        if not entry:
            errors.append(f"row {i}: kg_id missing from registry: {kg_id}")
            continue
        fn = _function_name(row, entry)
        if not fn:
            errors.append(f"row {i}: cannot determine function name for kg_id={kg_id}")
            continue
        if str(entry.get("function_name") or "") != fn:
            errors.append(f"row {i}: function mismatch csv={fn!r} registry={entry.get('function_name')!r} kg_id={kg_id}")

        split = str(entry.get("split") or "unknown")
        split_counts[split] += 1
        try:
            label = int(entry.get("label"))
            if label not in (0, 1):
                errors.append(f"row {i}: invalid registry label={label} kg_id={kg_id}")
            label_counts[label] += 1
        except Exception:
            errors.append(f"row {i}: missing/invalid registry label kg_id={kg_id}")

        if sample_id in labels_by_sample and int(entry.get("label", -1)) != labels_by_sample[sample_id]:
            errors.append(f"row {i}: private test label mismatch sample={sample_id} kg_id={kg_id}")
        if "vulnerability" in row and str(row.get("vulnerability", "")) != "" and int(row["vulnerability"]) != int(entry.get("label", -1)):
            errors.append(f"row {i}: train label mismatch sample={sample_id} kg_id={kg_id}")

        graph_dir = _resolve_graph_dir(private, entry)
        if not graph_dir.exists():
            errors.append(f"row {i}: graph_dir missing: {graph_dir}")
            continue
        for name in ["manifest.json", "graph.json", "nodes.jsonl", "edges.jsonl"]:
            if not (graph_dir / name).exists():
                errors.append(f"row {i}: KG artifact missing: {graph_dir/name}")
        manifest = {}
        if (graph_dir / "manifest.json").exists():
            try:
                manifest = _load_json(graph_dir / "manifest.json")
            except Exception as exc:
                errors.append(f"row {i}: manifest parse failed: {exc}")
        backend = manifest.get("backend") or manifest.get("backend_used") or manifest.get("diagnostics", {}).get("backend") or manifest.get("build", {}).get("backend") or "unknown"
        backend_counts[str(backend)] += 1

        ok_fn, fn_node = _graph_contains_function(graph_dir, fn)
        if ok_fn:
            checks["kg_contains_function"] += 1
        else:
            errors.append(f"row {i}: KG does not contain Function node for {fn!r} kg_id={kg_id}")

        if repo_worktrees:
            repo_root = Path(repo_worktrees)
            snapshot_paths = _possible_snapshot_paths(repo_root, str(entry.get("repo_key") or ""), str(entry.get("resolved_commit") or ""))
            if not snapshot_paths:
                msg = f"row {i}: source snapshot missing under {repo_root} for repo_key={entry.get('repo_key')} commit={entry.get('resolved_commit')}"
                if require_source_snapshot:
                    errors.append(msg)
                else:
                    warnings.append(msg)
                    source_status_counts["missing_snapshot"] += 1
            else:
                found_source = False
                found_at = None
                for snap in snapshot_paths[:3]:
                    found_source, found_at = _source_contains_function(snap, str(entry.get("filepath") or ""), str(entry.get("project") or ""), fn)
                    if found_source:
                        break
                if found_source:
                    source_status_counts["source_contains_function"] += 1
                else:
                    msg = f"row {i}: source snapshot exists but function/file not found fn={fn} kg_id={kg_id}"
                    if require_source_snapshot:
                        errors.append(msg)
                    else:
                        warnings.append(msg)
                        source_status_counts["source_missing_function"] += 1

        if api_base:
            ok_api, data, api_err = _api_function_check(api_base, kg_id, fn, api_timeout, api_key=api_key)
            if ok_api:
                checks["api_function_context"] += 1
            else:
                msg = f"row {i}: API function_context failed kg_id={kg_id} fn={fn}: {api_err}"
                if require_api:
                    errors.append(msg)
                else:
                    warnings.append(msg)

        if i == 1 or i % max(1, progress_every) == 0 or i == len(rows):
            elapsed = time.time() - start
            rate = i / elapsed if elapsed > 0 else 0.0
            eta = (len(rows) - i) / rate if rate > 0 else 0.0
            print(
                f"validate_challenge.progress | checked={i}/{len(rows)} | errors={len(errors)} | warnings={len(warnings)} | rate={rate:.2f}/s | eta={eta:.1f}s | last={fn}",
                flush=True,
            )

    summary = {
        "ok": not errors,
        "challenge": str(root),
        "registry_entries": len(entries),
        "kg_folders": len(kg_folders),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "checked_rows": len(rows),
        "backend_counts": dict(backend_counts),
        "split_counts": dict(split_counts),
        "label_counts": {str(k): v for k, v in label_counts.items()},
        "checks": dict(checks),
        "source_status_counts": dict(source_status_counts),
        "errors": errors[:500],
        "warnings": warnings[:500],
        "error_count": len(errors),
        "warning_count": len(warnings),
    }
    report_path = Path(write_report) if write_report else root / "private" / "validation_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"validate_challenge.done | ok={summary['ok']} | checked={len(rows)} | errors={len(errors)} | warnings={len(warnings)} | report={report_path}",
        flush=True,
    )
    print("Backend counts:", dict(backend_counts), flush=True)
    print("Split counts:", dict(split_counts), flush=True)
    print("Label counts:", dict(label_counts), flush=True)
    if errors:
        print("First errors:", flush=True)
        for e in errors[:10]:
            print(f"  - {e}", flush=True)
    if warnings:
        print("First warnings:", flush=True)
        for w in warnings[:10]:
            print(f"  - {w}", flush=True)
    return not errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate public/private challenge consistency and KG retrievability.")
    parser.add_argument("--challenge", default="outputs/student_challenge/vckg_codekg_student_challenge")
    parser.add_argument("--api-base", default=None, help="Optional running KG API base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="dev-key-KG")
    parser.add_argument("--api-timeout", type=float, default=30.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--repo-worktrees", default=None, help="Optional admin worktree cache, e.g. cache/worktrees, for source snapshot checks")
    parser.add_argument("--require-api", action="store_true", help="Fail if API function_context checks fail")
    parser.add_argument("--require-source-snapshot", action="store_true", help="Fail if source snapshot checks fail")
    parser.add_argument("--write-report", default=None)
    parser.add_argument("--progress-every", type=int, default=10)
    args = parser.parse_args(argv)
    ok, _ = validate_challenge(
        args.challenge,
        api_base=args.api_base,
        api_key=args.api_key,
        api_timeout=args.api_timeout,
        limit=args.limit,
        repo_worktrees=args.repo_worktrees,
        require_api=args.require_api,
        require_source_snapshot=args.require_source_snapshot,
        write_report=args.write_report,
        progress_every=args.progress_every,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
