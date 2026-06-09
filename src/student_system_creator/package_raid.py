from __future__ import annotations

import argparse
import json
import os
import shutil
import textwrap
import time
import zipfile
from pathlib import Path


_IGNORE_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".git",
    ".venv",
    "outputs",
    "cache",
    "dist",
    "models",
    "tools",
}


def _fmt_bytes(n: int) -> str:
    f = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if f < 1024.0 or unit == "TB":
            return f"{f:.1f} {unit}" if unit != "B" else f"{int(f)} B"
        f /= 1024.0
    return f"{n} B"


def _fmt_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "unknown"
    try:
        seconds = int(max(0, float(seconds)))
    except Exception:
        return "unknown"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _copytree(src: Path, dst: Path, *, ignore_names: set[str] | None = None) -> None:
    ignore_names = ignore_names or set()
    if dst.exists():
        shutil.rmtree(dst)

    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {n for n in names if n in ignore_names or n.endswith(".pyc") or n.endswith(".pyo")}

    shutil.copytree(src, dst, ignore=ignore)


def _should_ignore(path: Path, names: set[str]) -> bool:
    return any(part in names for part in path.parts) or path.name.endswith(".pyc") or path.name.endswith(".pyo")


def _scan_files(src: Path, *, ignore_names: set[str] | None = None) -> tuple[list[tuple[Path, int]], int]:
    ignore_names = ignore_names or set()
    files: list[tuple[Path, int]] = []
    total = 0
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if _should_ignore(rel, ignore_names):
            continue
        try:
            if p.is_file():
                size = p.stat().st_size
                files.append((p, size))
                total += size
        except OSError:
            continue
    return files, total


def _progress_line(
    *,
    phase: str,
    done: int,
    total: int,
    files_done: int,
    files_total: int,
    start: float,
    last_path: Path | None = None,
) -> str:
    elapsed = time.time() - start
    pct = (done / total * 100.0) if total else 100.0
    rate = done / elapsed if elapsed > 0 else 0.0
    eta = (total - done) / rate if rate > 0 and total > 0 else None
    tail = f" | last={last_path}" if last_path else ""
    return (
        f"package_raid.{phase}.progress | "
        f"{_fmt_bytes(done)}/{_fmt_bytes(total)} ({pct:.1f}%) | "
        f"files={files_done}/{files_total} | rate={_fmt_bytes(int(rate))}/s | "
        f"elapsed={_fmt_duration(elapsed)} | eta={_fmt_duration(eta)}{tail}"
    )


def _copytree_progress(
    src: Path,
    dst: Path,
    *,
    label: str,
    ignore_names: set[str] | None = None,
    progress_every_seconds: float = 2.0,
) -> int:
    """Copy a tree with size/ETA progress logs and return bytes copied."""
    ignore_names = ignore_names or set()
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    t_scan = time.time()
    print(f"package_raid.{label}.scan | src={src}", flush=True)
    files, total = _scan_files(src, ignore_names=ignore_names)
    print(
        f"package_raid.{label}.scan.done | files={len(files)} | size={_fmt_bytes(total)} | time={time.time() - t_scan:.1f}s",
        flush=True,
    )

    start = time.time()
    last_log = start
    copied = 0
    files_done = 0
    for path, size in files:
        rel = path.relative_to(src)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(path, target)
        except OSError as exc:
            print(f"package_raid.{label}.warning | copy_failed={rel} | error={exc}", flush=True)
            continue
        copied += size
        files_done += 1
        now = time.time()
        if now - last_log >= progress_every_seconds:
            print(
                _progress_line(
                    phase=label,
                    done=copied,
                    total=total,
                    files_done=files_done,
                    files_total=len(files),
                    start=start,
                    last_path=rel,
                ),
                flush=True,
            )
            last_log = now

    print(
        _progress_line(
            phase=label,
            done=copied,
            total=total,
            files_done=files_done,
            files_total=len(files),
            start=start,
        ),
        flush=True,
    )
    print(f"package_raid.{label}.done | copied={_fmt_bytes(copied)} | files={files_done} | time={time.time() - start:.1f}s", flush=True)
    return copied


def _zip_dir(src: Path, zip_path: Path, *, label: str = "zip", progress_every_seconds: float = 2.0) -> None:
    if zip_path.exists():
        zip_path.unlink()
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    t_scan = time.time()
    print(f"package_raid.{label}.scan | src={src}", flush=True)
    files, total = _scan_files(src, ignore_names=set())
    print(
        f"package_raid.{label}.scan.done | files={len(files)} | size={_fmt_bytes(total)} | time={time.time() - t_scan:.1f}s",
        flush=True,
    )
    start = time.time()
    last_log = start
    done = 0
    files_done = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path, size in files:
            arcname = path.relative_to(src.parent)
            zf.write(path, arcname)
            done += size
            files_done += 1
            now = time.time()
            if now - last_log >= progress_every_seconds:
                print(
                    _progress_line(
                        phase=label,
                        done=done,
                        total=total,
                        files_done=files_done,
                        files_total=len(files),
                        start=start,
                        last_path=arcname,
                    ),
                    flush=True,
                )
                last_log = now
    print(
        _progress_line(
            phase=label,
            done=done,
            total=total,
            files_done=files_done,
            files_total=len(files),
            start=start,
        ),
        flush=True,
    )
    try:
        zip_size = zip_path.stat().st_size
    except OSError:
        zip_size = 0
    print(
        f"package_raid.{label}.done | zip={zip_path} | zip_size={_fmt_bytes(zip_size)} | input={_fmt_bytes(done)} | time={time.time() - start:.1f}s",
        flush=True,
    )


def _dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _load_manifest(challenge: Path) -> dict:
    p = challenge / "private" / "dataset_manifest.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _copy_project_sources(project_root: Path, out: Path) -> None:
    src_dir = project_root / "src"
    if not src_dir.exists():
        raise FileNotFoundError(f"Cannot find source package directory: {src_dir}")
    _copytree(src_dir, out / "src", ignore_names=_IGNORE_NAMES)
    for name in ["pyproject.toml", "requirements.txt", "README.md"]:
        if (project_root / name).exists():
            shutil.copy2(project_root / name, out / name)


def _write_dockerfile(out: Path) -> None:
    _write(
        out / "Dockerfile",
        r'''
        FROM python:3.12-slim

        ENV PYTHONUNBUFFERED=1 \
            PYTHONDONTWRITEBYTECODE=1 \
            PIP_NO_CACHE_DIR=1

        WORKDIR /app

        RUN apt-get update \
            && apt-get install -y --no-install-recommends gcc g++ git curl \
            && rm -rf /var/lib/apt/lists/*

        COPY pyproject.toml requirements.txt README.md ./
        COPY src ./src
        COPY public ./public
        COPY private ./private

        RUN python -m pip install --upgrade pip setuptools wheel \
            && python -m pip install -e ".[api]"

        EXPOSE 8000

        CMD ["student-system-creator", "serve", "--registry", "/app/private/kg_registry_private.json", "--host", "0.0.0.0", "--port", "8000", "--engine-cache-size", "16", "--slow-query-seconds", "5"]
        ''',
    )


def _write_compose(out: Path) -> None:
    _write(
        out / "docker-compose.yml",
        r'''
        services:
          kg-api:
            build: .
            ports:
              - "8000:8000"
            command:
              [
                "student-system-creator", "serve",
                "--registry", "/app/private/kg_registry_private.json",
                "--host", "0.0.0.0",
                "--port", "8000",
                "--engine-cache-size", "16",
                "--slow-query-seconds", "5"
              ]

          evaluator:
            build: .
            depends_on:
              - kg-api
            volumes:
              - ./submissions:/submissions
              - ./outputs:/outputs
            command:
              [
                "python", "-m", "student_system_creator.evaluator.run_submission",
                "--solution", "/submissions/solution.py",
                "--input", "/app/public/test.csv",
                "--labels", "/app/private/test_labels.csv",
                "--api-base", "http://kg-api:8000",
                "--out", "/outputs/eval_run",
                "--query-timeout-seconds", "30"
              ]

          validator:
            build: .
            depends_on:
              - kg-api
            volumes:
              - ./outputs:/outputs
            command:
              [
                "student-system-creator", "validate-challenge",
                "--challenge", "/app",
                "--api-base", "http://kg-api:8000",
                "--require-api",
                "--write-report", "/outputs/validation_report.json"
              ]
        ''',
    )


def _write_scripts(out: Path) -> None:
    _write(out / "build.sh", """#!/usr/bin/env bash
set -euo pipefail
docker compose build
""")
    _write(out / "run_api.sh", """#!/usr/bin/env bash
set -euo pipefail
docker compose up kg-api
""")
    _write(out / "run_eval.sh", """#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm evaluator
""")
    _write(out / "run_validate.sh", """#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm validator
""")
    _write(out / "build.ps1", """docker compose build
""")
    _write(out / "run_api.ps1", """docker compose up kg-api
""")
    _write(out / "run_eval.ps1", """docker compose run --rm evaluator
""")
    _write(out / "run_validate.ps1", """docker compose run --rm validator
""")
    for name in ["build.sh", "run_api.sh", "run_eval.sh", "run_validate.sh"]:
        try:
            os.chmod(out / name, 0o755)
        except OSError:
            pass


def _write_readme(out: Path, manifest: dict, private_size: int) -> None:
    _write(
        out / "README_RAID.md",
        f'''
        # VCKG CodeKG RAID Bundle

        This bundle is self-contained for evaluation. The Code Knowledge Graphs are already built and stored under `private/kg_store/`.
        Joern is **not** required inside this Docker image because the graphs are precomputed.

        ## Contents

        - `public/`: files that may be released to students.
        - `private/`: hidden labels, KG registry, and KG artifacts. Do not give this folder to students.
        - `submissions/solution.py`: placeholder student submission used by the evaluator.
        - `src/`: evaluator, API server, validator, and CodeKG retrieval code.
        - `Dockerfile` and `docker-compose.yml`: containerized API, validator, and evaluator.

        ## Two perspectives

        ### Student perspective

        Students receive only `student_release.zip`, which contains `public/`. They see train rows with labels, test rows without labels, and `student_kit/solution.py`. Their agent can request KG evidence by returning structured query actions. During development, they may call the hosted KG API. During final evaluation, the evaluator runs their submitted `solution.py` and executes the KG queries for them.

        ### Organizer / environment perspective

        The RAID bundle keeps `private/` hidden. The `kg-api` service serves `/api/v1/kgs/<knowledge_graph_id>/query`; the `evaluator` service runs submitted `solution.py`; the `validator` service checks registry rows, KG artifacts, labels, and target-function retrievability before release.

        ## Dataset summary

        - Train rows: {manifest.get('train_rows', 'unknown')}
        - Test rows: {manifest.get('test_rows', 'unknown')}
        - Total records: {manifest.get('total_records', 'unknown')}
        - Private KG store size: {_fmt_bytes(private_size)}

        ## Run locally

        Build image:

        ```bash
        docker compose build
        ```

        Start the KG API:

        ```bash
        docker compose up kg-api
        ```

        In a second terminal, validate the challenge package:

        ```bash
        docker compose run --rm validator
        ```

        Then evaluate `submissions/solution.py`:

        ```bash
        docker compose run --rm evaluator
        ```

        Results are written to:

        ```text
        outputs/eval_run/
        ```

        Expected output files:

        - `predictions.csv`
        - `traces.json`
        - `score.json` or `metrics.json`

        ## Student contract

        Students submit a single `solution.py` file exposing:

        ```python
        def build_agent(config: dict):
            return MyAgent(config)
        ```

        The returned object must implement:

        ```python
        def step(self, sample: dict, observation: dict, budget: dict) -> dict:
            ...
        ```

        The evaluator controls recursion, KG-query limits, and scoring.
        ''',
    )


def package_raid(
    *,
    challenge: str | Path,
    out: str | Path,
    project_root: str | Path = ".",
    overwrite: bool = False,
    make_zip: bool = True,
    progress_every_seconds: float = 2.0,
) -> Path:
    challenge = Path(challenge).resolve()
    out = Path(out).resolve()
    project_root = Path(project_root).resolve()
    if not challenge.exists():
        raise FileNotFoundError(f"challenge folder not found: {challenge}")
    for required in [challenge / "public", challenge / "private" / "kg_registry_private.json", challenge / "private" / "kg_store"]:
        if not required.exists():
            raise FileNotFoundError(f"required challenge artifact missing: {required}")
    if out.exists():
        if not overwrite:
            raise FileExistsError(f"Output already exists: {out}. Use --overwrite.")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    print(f"package_raid.start | challenge={challenge} | out={out}", flush=True)

    _copytree_progress(
        challenge / "public",
        out / "public",
        label="copy_public",
        ignore_names=_IGNORE_NAMES,
        progress_every_seconds=progress_every_seconds,
    )
    print("package_raid.copy_private.start | private/kg_store can take time for large challenges", flush=True)
    _copytree_progress(
        challenge / "private",
        out / "private",
        label="copy_private",
        ignore_names={"__pycache__"},
        progress_every_seconds=progress_every_seconds,
    )
    private_size = _dir_size(out / "private")
    print(f"package_raid.copy_private.done | private_size={_fmt_bytes(private_size)}", flush=True)

    print("package_raid.copy_sources.start | source packages", flush=True)
    _copy_project_sources(project_root, out)
    print("package_raid.copy_sources.done", flush=True)

    submissions = out / "submissions"
    submissions.mkdir(exist_ok=True)
    starter = out / "public" / "student_kit" / "solution.py"
    if starter.exists():
        shutil.copy2(starter, submissions / "solution.py")
    else:
        (submissions / "solution.py").write_text("def build_agent(config):\n    raise NotImplementedError\n", encoding="utf-8")
    (out / "outputs").mkdir(exist_ok=True)

    manifest = _load_manifest(challenge)
    _write_dockerfile(out)
    _write_compose(out)
    _write_scripts(out)
    _write_readme(out, manifest, private_size)

    student_zip = out.parent / "student_release.zip"
    raid_zip = out.parent / f"{out.name}.zip"
    if make_zip:
        print(f"package_raid.zip_student.start | {student_zip}", flush=True)
        _zip_dir(out / "public", student_zip, label="zip_student", progress_every_seconds=progress_every_seconds)
        print(f"package_raid.zip_raid.start | {raid_zip}", flush=True)
        _zip_dir(out, raid_zip, label="zip_raid", progress_every_seconds=progress_every_seconds)

    summary = {
        "challenge": str(challenge),
        "out": str(out),
        "student_release_zip": str(student_zip) if make_zip else None,
        "raid_bundle_zip": str(raid_zip) if make_zip else None,
        "private_size_bytes": private_size,
        "elapsed_seconds": round(time.time() - t0, 3),
    }
    (out / "package_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"package_raid.done | out={out} | elapsed={time.time() - t0:.1f}s", flush=True)
    if make_zip:
        print(f"RAID bundle zip: {raid_zip}", flush=True)
        print(f"Student release zip: {student_zip}", flush=True)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package a built student challenge into a RAID/Docker-ready bundle.")
    parser.add_argument("--challenge", default="outputs/student_challenge/vckg_codekg_student_challenge")
    parser.add_argument("--out", default="dist/vckg_codekg_raid_bundle")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-zip", action="store_true")
    parser.add_argument(
        "--progress-every-seconds",
        type=float,
        default=2.0,
        help="Print copy/zip progress at this interval in seconds.",
    )
    args = parser.parse_args(argv)
    package_raid(
        challenge=args.challenge,
        out=args.out,
        project_root=args.project_root,
        overwrite=args.overwrite,
        make_zip=not args.no_zip,
        progress_every_seconds=args.progress_every_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
