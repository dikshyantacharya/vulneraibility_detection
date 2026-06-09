from __future__ import annotations

import argparse
import json
import shutil
import time
from collections import Counter
from pathlib import Path

from vuln_commit_kg.data.dataset_loader import load_samples
from vuln_commit_kg.logging_utils import setup_logging
from vuln_commit_kg.utils.jsonl import write_jsonl

from .config import ChallengeCreatorConfig
from .kg_materializer import ChallengeKGMaterializer
from .selection import load_project_size_scores, select_candidate_samples, split_records
from .writer import write_challenge_outputs
from .progress import fmt_duration, progress_eta
from .records import ChallengeRecord


def _load_existing_records(path: Path, logger) -> list[ChallengeRecord]:
    records: list[ChallengeRecord] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            records.append(ChallengeRecord(**obj))
        except Exception as exc:
            logger.warning("student_challenge.resume.skip_bad_record | path=%s | error=%s", path, exc)
    # Deduplicate by sample_id, keeping the latest record.
    by_sample = {str(r.sample_id): r for r in records}
    return list(by_sample.values())


def _write_ready_outputs(root: Path, cfg: ChallengeCreatorConfig, records: list, logger, *, partial: bool) -> tuple[int, int]:
    if not records:
        return 0, 0
    train, test = split_records(records, cfg)
    write_challenge_outputs(root=root, cfg=cfg, train=train, test=test, all_records=train + test)
    logger.info(
        "%s | root=%s | train=%d | test=%d | total=%d | api_registry=%s",
        "student_challenge.partial_written" if partial else "student_challenge.outputs_written",
        root,
        len(train),
        len(test),
        len(records),
        root / "private" / "kg_registry_private.json",
    )
    return len(train), len(test)


def build_challenge(
    config_path: str | Path,
    *,
    limit: int | None = None,
    dry_run: bool = False,
    backend: str | None = None,
    overwrite: bool | None = None,
    progress_every: int = 1,
) -> Path:
    cfg = ChallengeCreatorConfig.load(config_path)
    if backend:
        cfg.kg.backend = backend  # type: ignore[assignment]
    if overwrite is not None:
        cfg.output.overwrite = bool(overwrite)
    root = Path(cfg.output.root) / cfg.output.challenge_name
    if root.exists() and cfg.output.overwrite:
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    work_dir = root / "build_logs"
    work_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(work_dir, "INFO", True)
    cfg.save(root / "resolved_student_challenge_config.yaml")

    logger.info(
        "student_challenge.start | root=%s | backend=%s | kg_cache=%s | overwrite=%s | size_order=%s",
        root,
        cfg.kg.backend,
        cfg.kg.cache_dir,
        cfg.output.overwrite,
        cfg.selection.order_by_project_size,
    )
    samples = load_samples(cfg.input.dataset_path, cfg.input.dataset_mode, logger)
    candidates = select_candidate_samples(samples, cfg)
    if limit is not None:
        candidates = candidates[: int(limit)]

    candidate_projects = {s.project for s in candidates}
    candidate_repo_keys = {f"{s.project_url}|{s.project}" for s in candidates}
    candidate_labels = Counter(int(s.is_vulnerable) for s in candidates)
    size_scores = load_project_size_scores(cfg.input.repo_inventory_dir)
    logger.info(
        "student_challenge.candidates | samples=%d | projects=%d | repo_keys=%d | vulnerable=%d | safe=%d | dry_run=%s",
        len(candidates),
        len(candidate_projects),
        len(candidate_repo_keys),
        candidate_labels.get(1, 0),
        candidate_labels.get(0, 0),
        dry_run,
    )
    logger.info(
        "student_challenge.plan | requested_test_projects=%d | requested_test_functions=%d | max_functions_per_project=%d | project_size_entries=%d | write_partial_every=%d",
        cfg.selection.test_projects,
        cfg.selection.test_functions,
        cfg.selection.max_functions_per_project,
        len(size_scores),
        cfg.output.write_partial_every,
    )
    write_jsonl(work_dir / "candidate_samples.jsonl", [s.model_dump(mode="json") for s in candidates])
    if dry_run:
        logger.info(
            "student_challenge.dry_run_done | root=%s | candidates=%d | projects=%d | vulnerable=%d | safe=%d",
            root,
            len(candidates),
            len(candidate_projects),
            candidate_labels.get(1, 0),
            candidate_labels.get(0, 0),
        )
        return root

    private_kg_store = root / "private" / "kg_store" if cfg.kg.copy_kg_artifacts and cfg.kg.kg_store_mode == "copy" else None
    if private_kg_store:
        private_kg_store.mkdir(parents=True, exist_ok=True)
    materializer = ChallengeKGMaterializer(cfg, work_dir=work_dir, logger=logger)
    records = [] if cfg.output.overwrite else _load_existing_records(work_dir / "materialized_records.jsonl", logger)
    resumed_sample_ids = {str(r.sample_id) for r in records}
    if records:
        logger.info("student_challenge.resume | existing_records=%d | materialized_records=%s", len(records), work_dir / "materialized_records.jsonl")
    status_counts: Counter[str] = Counter()
    if records:
        status_counts["ready"] = len(records)
    label_counts: Counter[int] = Counter(int(r.vulnerability) for r in records)
    start = time.time()
    last_progress = start
    last_partial_write_ready = 0
    progress_every = max(1, int(progress_every or 1))
    interrupted = False

    for i, sample in enumerate(candidates, 1):
        if str(sample.sample_id) in resumed_sample_ids:
            if i % max(1, progress_every) == 0:
                logger.info("student_challenge.resume.skip_existing | %d/%d | sample=%s | project=%s", i, len(candidates), sample.sample_id, sample.project)
            continue
        item_start = time.time()
        logger.info(
            "student_challenge.materialize.start | %d/%d | sample=%s | project=%s | function=%s | label=%s",
            i,
            len(candidates),
            sample.sample_id,
            sample.project,
            sample.func_name,
            int(sample.is_vulnerable),
        )
        try:
            rec = materializer.materialize_sample(sample, private_kg_store=private_kg_store)
        except KeyboardInterrupt:
            interrupted = True
            logger.warning("student_challenge.interrupt_requested | processed=%d/%d | ready=%d", i - 1, len(candidates), len(records))
            break
        except Exception as exc:
            logger.exception("student_challenge.materialize_failed | sample=%s | project=%s | error=%s", sample.sample_id, sample.project, exc)
            rec = None
            status_counts["failed"] += 1
        else:
            if rec is not None:
                records.append(rec)
                label_counts[int(rec.vulnerability)] += 1
                status_counts["ready"] += 1
            else:
                status_counts["skipped"] += 1

        item_elapsed = time.time() - item_start
        elapsed, rate, eta = progress_eta(start, i, len(candidates))
        ready = status_counts.get("ready", 0)
        should_log_progress = (i % progress_every == 0) or (time.time() - last_progress >= 30) or i == len(candidates)
        if should_log_progress:
            last_progress = time.time()
            logger.info(
                "student_challenge.progress | processed=%d/%d | ready=%d | skipped=%d | failed=%d | vuln=%d | safe=%d | required_test_projects=%d | required_test_functions=%d | last=%s/%s | last_time=%s | elapsed=%s | rate=%.2f samples/min | eta=%s",
                i,
                len(candidates),
                ready,
                status_counts.get("skipped", 0),
                status_counts.get("failed", 0),
                label_counts.get(1, 0),
                label_counts.get(0, 0),
                cfg.selection.test_projects,
                cfg.selection.test_functions,
                sample.project,
                sample.func_name,
                fmt_duration(item_elapsed),
                fmt_duration(elapsed),
                rate * 60.0,
                eta,
            )

        every = int(cfg.output.write_partial_every or 0)
        if every > 0 and ready and ready - last_partial_write_ready >= every:
            try:
                _write_ready_outputs(root, cfg, records, logger, partial=True)
                last_partial_write_ready = ready
            except Exception as exc:
                logger.warning("student_challenge.partial_write_failed | ready=%d | error=%s", ready, exc)

    if not records:
        raise RuntimeError("No challenge records were materialized. Check dataset/cache/repo settings.")

    train_n, test_n = _write_ready_outputs(root, cfg, records, logger, partial=interrupted)
    summary = {
        "root": str(root),
        "train": train_n,
        "test": test_n,
        "total": len(records),
        "interrupted": interrupted,
        "status_counts": dict(status_counts),
        "label_counts": dict(label_counts),
        "elapsed_seconds": round(time.time() - start, 3),
    }
    (work_dir / "build_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(
        "student_challenge.done | root=%s | train=%d | test=%d | total=%d | ready=%d | skipped=%d | failed=%d | interrupted=%s | elapsed=%s",
        root,
        train_n,
        test_n,
        len(records),
        status_counts.get("ready", 0),
        status_counts.get("skipped", 0),
        status_counts.get("failed", 0),
        interrupted,
        fmt_duration(time.time() - start),
    )
    if interrupted:
        logger.warning(
            "student_challenge.partial_ready | interrupted=True | usable_public=%s | usable_private=%s | package_now_with=student-system-creator package-raid --challenge %s --out dist/vckg_codekg_raid_bundle --overwrite",
            root / "public",
            root / "private",
            root,
        )
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a student CodeKG vulnerability challenge from existing VCKG caches.")
    parser.add_argument("--config", default="student_system_creator/configs/default.yaml")
    parser.add_argument("--limit", type=int, default=None, help="Temporarily limit selected candidate samples for smoke testing")
    parser.add_argument("--dry-run", action="store_true", help="Only select/write candidate rows; do not create worktrees or build KGs")
    parser.add_argument("--backend", choices=["auto", "joern", "heuristic", "tree-sitter", "treesitter", "tree_sitter"], default=None, help="Temporarily override kg.backend from the config")
    parser.add_argument("--overwrite", action="store_true", help="Delete and recreate the challenge output folder before building")
    parser.add_argument("--progress-every", type=int, default=1, help="Print compact build progress every N candidate samples")
    args = parser.parse_args(argv)
    root = build_challenge(args.config, limit=args.limit, dry_run=args.dry_run, backend=args.backend, overwrite=True if args.overwrite else None, progress_every=args.progress_every)
    print(f"Challenge created: {root}")
    print(f"Student release: {root / 'public'}")
    print(f"Private registry: {root / 'private' / 'kg_registry_private.json'}")
    print(f"Package RAID: student-system-creator package-raid --challenge {root} --out dist/vckg_codekg_raid_bundle --overwrite")
    print(f"Start API: student-system-creator serve --registry {root / 'private' / 'kg_registry_private.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
