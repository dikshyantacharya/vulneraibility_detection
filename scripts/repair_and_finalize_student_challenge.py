from __future__ import annotations

import argparse
import csv
import json
import random
import re
import secrets
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


LABEL_COLUMNS = ["vulnerability", "label", "is_vulnerable"]
KG_COLUMNS = ["knowledge_graph_id", "kg_id"]
ID_COLUMNS = ["sample_id", "id"]
FUNCTION_COLUMNS = ["function", "Function", "target_function"]


def read_csv(path: Path):
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), list(reader.fieldnames or [])


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def first_present(row: dict[str, Any], names: list[str]) -> str:
    for name in names:
        value = row.get(name)
        if value not in [None, ""]:
            return str(value)
    return ""


def norm_label(value: Any) -> str:
    s = str(value).strip().lower()
    if s in {"1", "true", "vulnerable", "vuln", "yes"}:
        return "1"
    if s in {"0", "false", "safe", "non-vulnerable", "not_vulnerable", "no"}:
        return "0"
    return str(value).strip()


def opaque(prefix: str, used: set[str], nbytes: int = 10) -> str:
    while True:
        value = f"{prefix}_{secrets.token_hex(nbytes)}"
        if value not in used:
            used.add(value)
            return value


def collect_bad_kg_ids(report_path: Path) -> set[str]:
    if not report_path.exists():
        print(f"WARNING: validation report not found: {report_path}")
        return set()

    text = report_path.read_text(encoding="utf-8", errors="replace")
    bad = set()

    patterns = [
        r"kg_id=([^\s:,\}\]\)]+)",
        r'"kg_id"\s*:\s*"([^"]+)"',
        r'"knowledge_graph_id"\s*:\s*"([^"]+)"',
    ]

    for pattern in patterns:
        for m in re.finditer(pattern, text):
            kg = m.group(1).strip().strip('"').strip("'")
            if kg:
                bad.add(kg)

    return bad



def registry_graphs(registry_data: Any) -> dict[str, dict[str, Any]]:
    """
    Robustly extract KG registry records from several possible registry schemas.

    Supported examples:
      {"graphs": {"kg_x": {"graph_dir": "...", ...}}}
      {"registry": {"kg_x": {"graph_dir": "...", ...}}}
      {"items": [{"kg_id": "kg_x", "graph_dir": "..."}]}
      [{"kg_id": "kg_x", "graph_dir": "..."}]
      {"kg_x": {"graph_dir": "..."}}
    """
    graphs: dict[str, dict[str, Any]] = {}

    container_names = {
        "graphs",
        "registry",
        "items",
        "entries",
        "data",
        "kg_registry",
        "knowledge_graphs",
    }

    def is_graph_record(obj: Any) -> bool:
        return (
            isinstance(obj, dict)
            and any(obj.get(k) for k in ["graph_dir", "kg_dir", "graph_path", "path"])
        )

    def normalize_record(kg_id: str, rec: dict[str, Any]) -> dict[str, Any]:
        out = dict(rec)

        if not out.get("graph_dir"):
            for alt in ["kg_dir", "graph_path", "path"]:
                if out.get(alt):
                    out["graph_dir"] = out[alt]
                    break

        out.setdefault("kg_id", kg_id)
        out.setdefault("knowledge_graph_id", kg_id)
        return out

    def visit(obj: Any, parent_key: str | None = None):
        if isinstance(obj, dict):
            if is_graph_record(obj):
                kg_id = (
                    obj.get("kg_id")
                    or obj.get("knowledge_graph_id")
                    or obj.get("id")
                )

                if not kg_id and parent_key and parent_key not in container_names:
                    kg_id = parent_key

                if kg_id:
                    graphs[str(kg_id)] = normalize_record(str(kg_id), obj)

            for key, value in obj.items():
                # Also support {"kg_x": "private/kg_store/kg_x"} style mappings.
                if isinstance(value, str) and str(key).startswith("kg_"):
                    if "\\" in value or "/" in value:
                        graphs[str(key)] = normalize_record(
                            str(key),
                            {"graph_dir": value},
                        )
                else:
                    visit(value, str(key))

        elif isinstance(obj, list):
            for item in obj:
                visit(item, parent_key)

    visit(registry_data)

    if not graphs:
        if isinstance(registry_data, dict):
            keys = list(registry_data.keys())[:30]
            raise RuntimeError(
                f"Unsupported registry format. Top-level keys={keys}"
            )
        raise RuntimeError(
            f"Unsupported registry format. Top-level type={type(registry_data)}"
        )

    return graphs


def graph_dir_from_record(rec: dict[str, Any]) -> str:
    for key in ["graph_dir", "kg_dir", "graph_path", "path"]:
        value = rec.get(key)
        if value:
            return str(value)
    return ""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--train-per-class", type=int, default=30)
    parser.add_argument("--test-per-class", type=int, default=120)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--delete-unreferenced-kg-folders", action="store_true")
    args = parser.parse_args()

    root = Path(args.challenge)
    public = root / "public"
    private = root / "private"

    train_csv = public / "train.csv"
    test_csv = public / "test.csv"
    labels_csv = private / "test_labels.csv"
    registry_json = private / "kg_registry_private.json"
    report_json = private / "validation_report.json"
    sample_submission_csv = public / "sample_submission.csv"

    if not registry_json.exists():
        raise SystemExit(f"Missing registry: {registry_json}")

    backup = root / f"backup_before_repair_finalize_seed_{args.seed}"
    backup.mkdir(exist_ok=True)

    for p in [train_csv, test_csv, labels_csv, registry_json, sample_submission_csv, report_json]:
        if p.exists():
            shutil.copy2(p, backup / p.name)

    train_rows, _ = read_csv(train_csv)
    test_rows, _ = read_csv(test_csv)
    label_rows, _ = read_csv(labels_csv)

    labels_by_sample: dict[str, str] = {}

    for r in train_rows:
        sid = first_present(r, ID_COLUMNS)
        lab = first_present(r, LABEL_COLUMNS)
        if sid and lab != "":
            labels_by_sample[sid] = norm_label(lab)

    for r in label_rows:
        sid = first_present(r, ID_COLUMNS)
        lab = first_present(r, LABEL_COLUMNS)
        if sid and lab != "":
            labels_by_sample[sid] = norm_label(lab)

    registry_data = json.loads(registry_json.read_text(encoding="utf-8"))
    old_graphs = registry_graphs(registry_data)

    bad_kg_ids = collect_bad_kg_ids(report_json)

    all_rows = []
    for split_name, rows in [("train", train_rows), ("test", test_rows)]:
        for r in rows:
            sid = first_present(r, ID_COLUMNS)
            kg = first_present(r, KG_COLUMNS)
            fn = first_present(r, FUNCTION_COLUMNS)
            lab = labels_by_sample.get(sid)

            if not sid or not kg or not fn:
                continue
            if lab not in {"0", "1"}:
                continue
            if kg not in old_graphs:
                continue
            if kg in bad_kg_ids:
                continue

            all_rows.append({
                "old_sample_id": sid,
                "old_kg_id": kg,
                "function": fn,
                "label": lab,
                "old_split": split_name,
            })

    by_label = defaultdict(list)
    for r in all_rows:
        by_label[r["label"]].append(r)

    rng = random.Random(args.seed)
    for lab in by_label:
        rng.shuffle(by_label[lab])

    selected_train = []
    selected_test = []

    for lab in ["0", "1"]:
        rows = by_label.get(lab, [])

        train_take = min(args.train_per_class, len(rows))
        selected_train.extend(rows[:train_take])

        remaining = rows[train_take:]
        test_take = min(args.test_per_class, len(remaining))
        selected_test.extend(remaining[:test_take])

    rng.shuffle(selected_train)
    rng.shuffle(selected_test)

    active_rows = selected_train + selected_test

    used_sample_ids = set()
    used_kg_ids = set()
    sample_alias = {}
    kg_alias = {}

    for r in active_rows:
        sample_alias[r["old_sample_id"]] = opaque("case", used_sample_ids, 8)
        kg_alias[r["old_kg_id"]] = opaque("kg", used_kg_ids, 10)

    new_graphs = {}
    alias_map = {}

    for old_kg, new_kg in kg_alias.items():
        rec = dict(old_graphs[old_kg])
        rec["original_kg_id_private"] = old_kg
        rec["kg_id"] = new_kg
        rec["knowledge_graph_id"] = new_kg

        # Keep physical graph_dir unchanged. Students will never see the private registry.
        new_graphs[new_kg] = rec
        alias_map[new_kg] = {
            "original_kg_id": old_kg,
            "graph_dir": graph_dir_from_record(rec),
        }

    train_out = []
    test_out = []
    labels_out = []
    submission_out = []

    for r in selected_train:
        train_out.append({
            "sample_id": sample_alias[r["old_sample_id"]],
            "function": r["function"],
            "knowledge_graph_id": kg_alias[r["old_kg_id"]],
            "vulnerability": r["label"],
        })

    for r in selected_test:
        sid = sample_alias[r["old_sample_id"]]
        test_out.append({
            "sample_id": sid,
            "function": r["function"],
            "knowledge_graph_id": kg_alias[r["old_kg_id"]],
        })
        labels_out.append({
            "sample_id": sid,
            "vulnerability": r["label"],
        })
        submission_out.append({
            "sample_id": sid,
            "prediction": 0,
        })

    # Check no public ID leaks vuln/safe.
    leaked = []
    for name, rows in [("train", train_out), ("test", test_out), ("sample_submission", submission_out)]:
        for i, row in enumerate(rows, start=2):
            sid = str(row.get("sample_id", "")).lower()
            kg = str(row.get("knowledge_graph_id", "")).lower()
            if any(x in sid for x in ["vuln", "safe", "label", "true", "false"]):
                leaked.append((name, i, "sample_id", sid))
            if any(x in kg for x in ["vuln", "safe", "label", "true", "false"]):
                leaked.append((name, i, "knowledge_graph_id", kg))

    print("bad kg ids from validation:", len(bad_kg_ids))
    print("valid usable rows after removal:", len(all_rows), Counter(r["label"] for r in all_rows))
    print("planned train:", len(train_out), Counter(r["vulnerability"] for r in train_out))
    print("planned test:", len(test_out), Counter(r["vulnerability"] for r in labels_out))
    print("planned registry entries:", len(new_graphs))
    print("backup:", backup)
    print("public ID leaks:", len(leaked))

    if leaked:
        for item in leaked[:20]:
            print("LEAK:", item)
        raise SystemExit("Public ID leak detected; aborting.")

    if args.dry_run:
        print("Dry run only. No files changed.")
        return

    write_csv(train_csv, train_out, ["sample_id", "function", "knowledge_graph_id", "vulnerability"])
    write_csv(test_csv, test_out, ["sample_id", "function", "knowledge_graph_id"])
    write_csv(labels_csv, labels_out, ["sample_id", "vulnerability"])
    write_csv(sample_submission_csv, submission_out, ["sample_id", "prediction"])

    new_registry = {
        "schema": "vckg_codekg_private_registry_alias_v1",
        "graphs": new_graphs,
        "notes": [
            "Public knowledge_graph_id values are opaque aliases.",
            "Physical graph_dir paths remain private.",
            "Do not distribute private/kg_registry_private.json, private/test_labels.csv, or private/kg_store to students.",
        ],
    }

    registry_json.write_text(json.dumps(new_registry, indent=2), encoding="utf-8")
    (private / "kg_id_alias_map_private.json").write_text(
        json.dumps(alias_map, indent=2),
        encoding="utf-8",
    )

    if args.delete_unreferenced_kg_folders:
        kg_store = private / "kg_store"
        referenced_dirs = set()
        for rec in new_graphs.values():
            gd = graph_dir_from_record(rec)
            if not gd:
                continue
            p = Path(gd)
            if not p.is_absolute():
                p = private / p
            referenced_dirs.add(p.resolve())

        deleted = 0
        if kg_store.exists():
            for folder in kg_store.iterdir():
                if folder.is_dir() and folder.resolve() not in referenced_dirs:
                    shutil.rmtree(folder, ignore_errors=True)
                    deleted += 1
        print("deleted unreferenced private kg folders:", deleted)

    print("Repair + finalization complete.")
    print("Alias map:", private / "kg_id_alias_map_private.json")


if __name__ == "__main__":
    main()
