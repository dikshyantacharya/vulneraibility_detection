from __future__ import annotations

import argparse
import csv
import json
import random
import re
import shutil
import secrets
from pathlib import Path
from collections import Counter, defaultdict


LABEL_COLUMNS = ["vulnerability", "label", "is_vulnerable"]
KG_COLUMNS = ["knowledge_graph_id", "kg_id"]
ID_COLUMNS = ["sample_id", "id"]


def read_csv(path: Path):
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), list(reader.fieldnames or [])


def write_csv(path: Path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def first_present(row, names):
    for name in names:
        if name in row and row[name] not in [None, ""]:
            return row[name]
    return ""


def norm_label(v):
    s = str(v).strip().lower()
    if s in {"1", "true", "vulnerable", "vuln", "yes"}:
        return "1"
    if s in {"0", "false", "safe", "non-vulnerable", "not_vulnerable", "no"}:
        return "0"
    return str(v).strip()


def opaque(prefix: str, used: set[str], nbytes: int = 10) -> str:
    while True:
        value = f"{prefix}_{secrets.token_hex(nbytes)}"
        if value not in used:
            used.add(value)
            return value


def walk_registry_entries(obj):
    if isinstance(obj, dict):
        if ("graph_dir" in obj or "kg_dir" in obj) and ("kg_id" in obj or "knowledge_graph_id" in obj):
            yield obj
        else:
            for value in obj.values():
                yield from walk_registry_entries(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_registry_entries(item)


def registry_to_graphs_dict(registry_data):
    entries = list(walk_registry_entries(registry_data))
    graphs = {}
    for e in entries:
        old_id = e.get("kg_id") or e.get("knowledge_graph_id")
        if not old_id:
            continue
        graphs[str(old_id)] = dict(e)
    return graphs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--train-per-class", type=int, default=300)
    parser.add_argument("--test-per-class", type=int, default=300)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--keep-extra-train", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.challenge)
    public = root / "public"
    private = root / "private"

    train_csv = public / "train.csv"
    test_csv = public / "test.csv"
    labels_csv = private / "test_labels.csv"
    registry_json = private / "kg_registry_private.json"
    submission_csv = public / "sample_submission.csv"

    if not registry_json.exists():
        raise SystemExit(f"Missing registry: {registry_json}")

    train_rows, train_fields = read_csv(train_csv)
    test_rows, test_fields = read_csv(test_csv)
    label_rows, label_fields = read_csv(labels_csv)

    label_by_sample = {}

    for r in train_rows:
        sid = str(first_present(r, ID_COLUMNS))
        lab = first_present(r, LABEL_COLUMNS)
        if sid and lab != "":
            label_by_sample[sid] = norm_label(lab)

    for r in label_rows:
        sid = str(first_present(r, ID_COLUMNS))
        lab = first_present(r, LABEL_COLUMNS)
        if sid and lab != "":
            label_by_sample[sid] = norm_label(lab)

    all_rows_by_key = {}

    for split_name, rows in [("train", train_rows), ("test", test_rows)]:
        for r in rows:
            sid = str(first_present(r, ID_COLUMNS))
            kg = str(first_present(r, KG_COLUMNS))
            if not sid or not kg:
                continue
            lab = label_by_sample.get(sid)
            if lab not in {"0", "1"}:
                continue
            key = kg
            rr = dict(r)
            rr["_old_sample_id"] = sid
            rr["_old_kg_id"] = kg
            rr["_label"] = lab
            rr["_old_split"] = split_name
            all_rows_by_key[key] = rr

    registry_data = json.loads(registry_json.read_text(encoding="utf-8"))
    graphs_by_old_id = registry_to_graphs_dict(registry_data)

    usable_rows = []
    missing_registry = []

    for r in all_rows_by_key.values():
        kg = r["_old_kg_id"]
        if kg in graphs_by_old_id:
            usable_rows.append(r)
        else:
            missing_registry.append(kg)

    by_label = defaultdict(list)
    for r in usable_rows:
        by_label[r["_label"]].append(r)

    rng = random.Random(args.seed)
    for lab in by_label:
        rng.shuffle(by_label[lab])

    print("Available usable rows by label:", {k: len(v) for k, v in by_label.items()})
    print("Rows missing registry:", len(missing_registry))

    selected_train = []
    selected_test = []

    for lab in ["0", "1"]:
        rows = by_label.get(lab, [])
        test_take = min(args.test_per_class, len(rows))
        selected_test.extend(rows[:test_take])

        remaining = rows[test_take:]
        train_take = min(args.train_per_class, len(remaining))
        selected_train.extend(remaining[:train_take])

        if args.keep_extra_train:
            selected_train.extend(remaining[train_take:])

    rng.shuffle(selected_train)
    rng.shuffle(selected_test)

    active_rows = selected_train + selected_test

    used_sample_ids = set()
    used_kg_ids = set()
    sample_alias = {}
    kg_alias = {}

    for r in active_rows:
        sample_alias[r["_old_sample_id"]] = opaque("case", used_sample_ids, 8)
        kg_alias[r["_old_kg_id"]] = opaque("kg", used_kg_ids, 10)

    # Build new private registry with opaque KG IDs.
    new_graphs = {}
    alias_map = {}

    for old_kg, new_kg in kg_alias.items():
        rec = dict(graphs_by_old_id[old_kg])
        rec["original_kg_id_private"] = old_kg
        rec["kg_id"] = new_kg
        rec["knowledge_graph_id"] = new_kg
        new_graphs[new_kg] = rec
        alias_map[new_kg] = {
            "original_kg_id": old_kg,
            "graph_dir": rec.get("graph_dir") or rec.get("kg_dir"),
        }

    # Backup.
    backup = root / f"release_alias_backup_seed_{args.seed}"
    backup.mkdir(exist_ok=True)

    for p in [train_csv, test_csv, labels_csv, submission_csv, registry_json]:
        if p.exists():
            shutil.copy2(p, backup / p.name)

    # Determine public fields.
    source_fields = []
    for fields in [test_fields, train_fields]:
        for f in fields:
            if f not in source_fields and f not in LABEL_COLUMNS:
                source_fields.append(f)

    if "sample_id" not in source_fields:
        source_fields.insert(0, "sample_id")
    if "knowledge_graph_id" not in source_fields:
        source_fields.append("knowledge_graph_id")

    # Remove possible leaked/private helper columns.
    source_fields = [
        f for f in source_fields
        if not f.startswith("_") and f not in {"kg_id", "id"}
    ]

    train_out = []
    test_out = []
    labels_out = []
    submission_out = []

    def publicize(r, include_label: bool):
        out = {}
        for k, v in r.items():
            if k.startswith("_"):
                continue
            if k in LABEL_COLUMNS:
                continue
            if k in {"id", "kg_id"}:
                continue
            out[k] = v

        out["sample_id"] = sample_alias[r["_old_sample_id"]]
        out["knowledge_graph_id"] = kg_alias[r["_old_kg_id"]]

        # Defensive: ensure no old vuln/safe KG ID leaks.
        leaked = str(out["knowledge_graph_id"]).lower()
        if "vuln" in leaked or "safe" in leaked:
            raise RuntimeError(f"Leaking label in alias: {out['knowledge_graph_id']}")

        if include_label:
            out["vulnerability"] = r["_label"]

        return out

    for r in selected_train:
        train_out.append(publicize(r, include_label=True))

    for r in selected_test:
        row = publicize(r, include_label=False)
        test_out.append(row)
        labels_out.append({
            "sample_id": row["sample_id"],
            "vulnerability": r["_label"],
        })
        submission_out.append({
            "sample_id": row["sample_id"],
            "prediction": 0,
        })

    train_fields_final = list(source_fields)
    if "vulnerability" not in train_fields_final:
        train_fields_final.append("vulnerability")

    test_fields_final = list(source_fields)

    print("\nFinal planned split:")
    print("  train:", len(train_out), Counter(r["vulnerability"] for r in train_out))
    print("  test:", len(test_out), Counter(r["vulnerability"] for r in labels_out))
    print("  active registry entries:", len(new_graphs))
    print("  backup:", backup)

    if args.dry_run:
        print("\nDry run only; no files changed.")
        return

    write_csv(train_csv, train_out, train_fields_final)
    write_csv(test_csv, test_out, test_fields_final)
    write_csv(labels_csv, labels_out, ["sample_id", "vulnerability"])
    write_csv(submission_csv, submission_out, ["sample_id", "prediction"])

    new_registry = {
        "schema": "vckg_codekg_private_registry_alias_v1",
        "graphs": new_graphs,
        "notes": [
            "Public knowledge_graph_id values are opaque aliases.",
            "Physical graph_dir paths may point to internal private folders.",
            "Do not distribute this registry or private/kg_store to students.",
        ],
    }

    registry_json.write_text(json.dumps(new_registry, indent=2), encoding="utf-8")
    (private / "kg_id_alias_map_private.json").write_text(
        json.dumps(alias_map, indent=2),
        encoding="utf-8",
    )

    print("\nWrote final anonymized release split.")
    print("Alias map:", private / "kg_id_alias_map_private.json")


if __name__ == "__main__":
    main()
