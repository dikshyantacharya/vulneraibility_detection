from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .heuristic import HeuristicBackend
from .joern_import import ingest_joern_export

TOOL_NAMES = ("joern", "joern-parse", "joern-export")
WINDOWS_EXTENSIONS = (".bat", ".cmd", ".exe", ".ps1", "")
POSIX_EXTENSIONS = ("", ".sh")
JOERN_MIN_JAVA_MAJOR = 19


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _candidate_roots(extra_roots: Optional[Iterable[str | os.PathLike[str]]] = None) -> List[Path]:
    roots: List[Path] = []
    seen: set[str] = set()

    def add(pathish: str | os.PathLike[str] | None) -> None:
        if not pathish:
            return
        try:
            p = Path(pathish).expanduser()
        except Exception:
            return
        key = str(p).lower() if platform.system().lower().startswith("win") else str(p)
        if key not in seen:
            roots.append(p)
            seen.add(key)

    if extra_roots:
        for root in extra_roots:
            add(root)

    add(os.environ.get("CODEKG_JOERN_HOME"))
    add(os.environ.get("JOERN_HOME"))

    cwd = Path.cwd()
    home = Path.home()
    project = _project_root()
    for base in (cwd, project, home):
        add(base / "tools" / "joern-cli")
        add(base / "tools" / "joern" / "joern-cli")
        add(base / "joern-cli")
        add(base / "joern" / "joern-cli")
        add(base / "bin" / "joern" / "joern-cli")

    if platform.system().lower().startswith("win"):
        add(Path(os.environ.get("LOCALAPPDATA", str(home))) / "CodeKG" / "joern-cli")
        add(Path("C:/tools/joern-cli"))
        add(Path("C:/joern-cli"))
        add(Path("C:/Program Files/joern-cli"))

    return roots


def _is_executable_candidate(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    if platform.system().lower().startswith("win"):
        return True
    return os.access(path, os.X_OK)


def _find_tool_in_root(root: Path, tool: str) -> Optional[str]:
    roots = [root]
    if root.name.lower() != "joern-cli":
        roots.append(root / "joern-cli")
    exts = WINDOWS_EXTENSIONS if platform.system().lower().startswith("win") else POSIX_EXTENSIONS
    for r in roots:
        for ext in exts:
            candidate = r / f"{tool}{ext}"
            if _is_executable_candidate(candidate):
                return str(candidate.resolve())
    return None


def detect_joern(extra_roots: Optional[Iterable[str | os.PathLike[str]]] = None) -> Dict[str, Optional[str]]:
    """Detect Joern CLI tools from PATH, CODEKG_JOERN_HOME/JOERN_HOME, and local project folders."""
    found: Dict[str, Optional[str]] = {}
    for tool in TOOL_NAMES:
        found[tool] = shutil.which(tool)

    missing = [tool for tool, path in found.items() if not path]
    if missing:
        roots = _candidate_roots(extra_roots)
        for tool in missing:
            for root in roots:
                match = _find_tool_in_root(root, tool)
                if match:
                    found[tool] = match
                    break
    return found


def _java_candidates() -> List[str]:
    candidates: List[str] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        exe = "java.exe" if platform.system().lower().startswith("win") else "java"
        candidates.append(str(Path(java_home).expanduser() / "bin" / exe))
    path_java = shutil.which("java")
    if path_java:
        candidates.append(path_java)
    # Stable known install locations on Windows. This does not replace PATH/JAVA_HOME,
    # but it lets doctor produce a better message when Java was installed by an MSI.
    if platform.system().lower().startswith("win"):
        for base in (Path("C:/Program Files/Eclipse Adoptium"), Path("C:/Program Files/Microsoft"), Path("C:/Program Files/Java")):
            if base.exists():
                for candidate in sorted(base.glob("**/bin/java.exe"), reverse=True):
                    candidates.append(str(candidate))
    # Deduplicate preserving order.
    seen: set[str] = set()
    out: List[str] = []
    for c in candidates:
        key = c.lower() if platform.system().lower().startswith("win") else c
        if key not in seen and Path(c).exists():
            seen.add(key)
            out.append(c)
    return out


def _parse_java_major(version_text: str) -> Optional[int]:
    match = re.search(r'version\s+"([^"]+)"', version_text)
    if not match:
        match = re.search(r'openjdk\s+([0-9][^\s]*)', version_text, flags=re.IGNORECASE)
    if not match:
        return None
    raw = match.group(1).strip()
    if raw.startswith("1."):
        parts = raw.split(".")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    first = re.match(r"(\d+)", raw)
    return int(first.group(1)) if first else None


def detect_java(min_major: int = JOERN_MIN_JAVA_MAJOR) -> Dict[str, object]:
    """Return Java runtime information needed by Joern."""
    candidates = _java_candidates()
    if not candidates:
        return {
            "path": None,
            "version": None,
            "major": None,
            "ok": False,
            "reason": f"Java/JDK was not found. Joern requires a JVM; install JDK {min_major}+ and reopen PowerShell.",
        }
    last_error = ""
    for candidate in candidates:
        try:
            proc = subprocess.run([candidate, "-version"], capture_output=True, text=True, timeout=20)
            text = (proc.stdout or "") + (proc.stderr or "")
            first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
            major = _parse_java_major(text)
            ok = bool(major and major >= min_major and proc.returncode == 0)
            return {
                "path": str(Path(candidate).resolve()),
                "version": first_line or text.strip() or f"returncode={proc.returncode}",
                "major": major,
                "ok": ok,
                "reason": None if ok else f"Detected Java major={major}; Joern expects JDK {min_major}+.",
            }
        except Exception as exc:  # pragma: no cover - environment specific
            last_error = str(exc)
    return {
        "path": candidates[0] if candidates else None,
        "version": None,
        "major": None,
        "ok": False,
        "reason": f"Java was detected but could not be executed: {last_error}",
    }


def joern_available(extra_roots: Optional[Iterable[str | os.PathLike[str]]] = None, require_java: bool = True) -> bool:
    tools = detect_joern(extra_roots=extra_roots)
    tools_ok = bool(tools.get("joern-parse") and tools.get("joern-export"))
    if not tools_ok:
        return False
    return bool(detect_java().get("ok")) if require_java else True


def _command_for_subprocess(path: str) -> List[str]:
    p = Path(path)
    if platform.system().lower().startswith("win"):
        suffix = p.suffix.lower()
        # PowerShell scripts are not directly executable from subprocess on Windows.
        if suffix == ".ps1":
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(p)]
        # Running .bat/.cmd via cmd.exe is more robust when paths contain spaces
        # and avoids CreateProcess quirks around batch-file execution.
        if suffix in {".bat", ".cmd"}:
            return ["cmd.exe", "/d", "/s", "/c", str(p)]
    return [str(p)]


class JoernBackend(HeuristicBackend):
    """Joern-first backend with deterministic normalized CodeKG output.

    Joern is used for CPG parse/export when the CLI and a compatible JVM are
    available. CodeKG still runs its deterministic extractor afterwards to produce
    stable dashboard nodes/edges and to keep a comparable schema across backends.
    Raw Joern artifacts are stored under out_dir/joern.
    """

    name = "joern"

    def __init__(self, strict: bool = False, timeout_seconds: int = 900, language: str = "C") -> None:
        super().__init__(backend_label="joern_plus_heuristic")
        self.strict = strict
        self.timeout_seconds = timeout_seconds
        self.language = language

    def build(self, source_dir: Path, out_dir: Path, logger):
        source_dir = source_dir.resolve()
        out_dir = out_dir.resolve()
        joern_dir = out_dir / "joern"
        joern_dir.mkdir(parents=True, exist_ok=True)
        # On Windows, the run-local cache path can easily exceed legacy path
        # limits once the run id, project key, commit hash, KG version, and config
        # hash are nested together. Java/Joern and subprocess.Popen may then fail
        # before the process starts with: [WinError 267] The directory name is
        # invalid. Keep canonical artifacts under out_dir/joern, but run Joern in
        # a short temporary workspace and copy raw artifacts back afterwards.
        joern_work_dir = self._select_joern_work_dir(joern_dir, logger)
        joern_work_dir.mkdir(parents=True, exist_ok=True)
        if joern_work_dir != joern_dir:
            logger.info("Using short Joern workspace: %s -> %s", joern_work_dir, joern_dir)
        tools = detect_joern()
        java_info = detect_java()
        logger.info("Joern availability check: %s", json.dumps(tools, indent=2))
        logger.info("Java/JVM check: %s", json.dumps(java_info, indent=2))
        tools_ok = bool(tools.get("joern-parse") and tools.get("joern-export"))
        joern_ok = bool(tools_ok and java_info.get("ok"))
        cpg_path = joern_work_dir / "cpg.bin"
        export_dir = joern_work_dir / "export"
        command_results = []

        parse_succeeded = False
        export_succeeded = False

        if joern_ok:
            logger.info(
                "Selected Joern tools: joern-parse=%s joern-export=%s",
                tools.get("joern-parse"),
                tools.get("joern-export"),
            )
            # Force the C/C++ frontend by default. Without --language, Joern auto-selects
            # the frontend based on the most common supported file type in the input tree,
            # which can incorrectly choose PYTHONSRC for Python-packaged C extensions.
            parse_attempts = [
                _command_for_subprocess(tools["joern-parse"]) + [str(source_dir), "--language", self.language, "--output", str(cpg_path)],  # type: ignore[index]
                _command_for_subprocess(tools["joern-parse"]) + [str(source_dir), "--language", self.language, "-o", str(cpg_path)],  # type: ignore[index]
                _command_for_subprocess(tools["joern-parse"]) + [str(source_dir), "--language", self.language],  # type: ignore[index]
            ]
            for parse_cmd in parse_attempts:
                result = self._run(parse_cmd, logger, cwd=joern_work_dir)
                command_results.append(result)
                discovered = self._discover_cpg(joern_work_dir, preferred=cpg_path)
                if result.get("returncode") == 0 and discovered:
                    cpg_path = discovered
                    parse_succeeded = True
                    logger.info("Joern CPG detected: %s", cpg_path)
                    break
            if not parse_succeeded:
                logger.warning("Joern parse did not produce an expected CPG file in %s", joern_work_dir)

            if cpg_path.exists():
                export_attempts = [
                    _command_for_subprocess(tools["joern-export"]) + [str(cpg_path), "--repr", "all", "--out", str(export_dir)],  # type: ignore[index]
                    _command_for_subprocess(tools["joern-export"]) + ["--repr", "all", "--out", str(export_dir), str(cpg_path)],  # type: ignore[index]
                    _command_for_subprocess(tools["joern-export"]) + [str(cpg_path), "--out", str(export_dir)],  # type: ignore[index]
                    _command_for_subprocess(tools["joern-export"]) + ["--repr", "all", "--format", "graphml", "--out", str(export_dir), str(cpg_path)],  # type: ignore[index]
                ]
                for cmd in export_attempts:
                    if export_dir.exists():
                        shutil.rmtree(export_dir, ignore_errors=True)
                    result = self._run(cmd, logger, cwd=joern_work_dir)
                    command_results.append(result)
                    if result.get("returncode") == 0:
                        export_succeeded = True
                        logger.info("Joern export completed into: %s", export_dir)
                        break
        else:
            if not tools_ok:
                msg = "Joern tools are not fully available; joern-parse/joern-export were not detected."
            else:
                msg = str(java_info.get("reason") or "Java/JDK is not usable for Joern.")
            if self.strict:
                raise RuntimeError(f"Joern was required, but it is not runnable: {msg}")
            logger.warning("%s Using deterministic fallback extractor.", msg)

        if self.strict and not parse_succeeded:
            self._sync_joern_workspace(joern_work_dir, joern_dir, logger)
            raise RuntimeError(
                "Joern was required, but joern-parse did not successfully create a CPG. "
                f"Check {joern_dir / 'joern_commands.log'} and build.log for command output."
            )

        graph, diagnostics = super().build(source_dir, out_dir, logger)
        joern_import_stats = {}
        if export_succeeded and export_dir.exists():
            joern_import_stats = ingest_joern_export(graph, export_dir, source_dir, logger)
        diagnostics.backend_requested = "joern"
        diagnostics.backend_used = "joern_plus_heuristic" if joern_ok and parse_succeeded else "heuristic"
        diagnostics.joern_available = bool(joern_ok and parse_succeeded)
        diagnostics.joern_tools = tools
        diagnostics.tool_versions["java"] = java_info
        diagnostics.tool_versions["joern_commands"] = command_results
        diagnostics.tool_versions["joern_detection_roots"] = [str(p) for p in _candidate_roots()]
        diagnostics.counters["joern_parse_succeeded"] = int(parse_succeeded)
        diagnostics.counters["joern_export_succeeded"] = int(export_succeeded)
        diagnostics.tool_versions["joern_language_requested"] = self.language
        diagnostics.tool_versions["joern_work_dir"] = str(joern_work_dir)
        diagnostics.tool_versions["joern_artifact_dir"] = str(joern_dir)
        diagnostics.tool_versions["joern_import"] = joern_import_stats
        self._sync_joern_workspace(joern_work_dir, joern_dir, logger)
        diagnostics.counters["joern_imported_files"] = int(joern_import_stats.get("files", 0) if joern_import_stats else 0)
        diagnostics.counters["joern_imported_nodes"] = int(joern_import_stats.get("nodes", 0) if joern_import_stats else 0)
        diagnostics.counters["joern_imported_edges"] = int(joern_import_stats.get("edges", 0) if joern_import_stats else 0)
        diagnostics.counters["joern_overlay_edges"] = int(joern_import_stats.get("overlays", 0) if joern_import_stats else 0)
        if joern_ok and parse_succeeded:
            diagnostics.parser_confidence = "medium-high"
            diagnostics.quality_warnings.append({
                "code": "joern_normalization_note",
                "message": "Joern CPG parse succeeded. Normalized dashboard artifacts include deterministic CodeKG entities plus imported Joern export overlay nodes/edges where the export format was readable. Raw Joern artifacts are stored under out_dir/joern.",
            })
        return graph, diagnostics

    def _select_joern_work_dir(self, joern_dir: Path, logger) -> Path:
        """Return a subprocess-safe workspace for Joern.

        The canonical raw Joern artifact directory remains out_dir/joern. On
        Windows, using that directory as cwd can fail when the path is long.
        """
        if not platform.system().lower().startswith("win"):
            return joern_dir
        try:
            resolved = joern_dir.resolve()
        except Exception:
            resolved = joern_dir
        # Keep well below MAX_PATH because Joern creates nested files below cwd.
        if len(str(resolved)) < 180:
            return joern_dir
        base = Path(tempfile.gettempdir()) / "codekg_joern"
        base.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix="run_", dir=str(base)))
        logger.warning(
            "Joern artifact path is long on Windows (%d chars); running Joern in short workspace %s and copying artifacts back to %s",
            len(str(resolved)), workspace, joern_dir,
        )
        return workspace

    def _sync_joern_workspace(self, joern_work_dir: Path, joern_dir: Path, logger) -> None:
        if joern_work_dir == joern_dir:
            return
        try:
            joern_dir.mkdir(parents=True, exist_ok=True)
            for child in joern_work_dir.iterdir():
                dest = joern_dir / child.name
                if child.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest, ignore_errors=True)
                    shutil.copytree(child, dest)
                else:
                    shutil.copy2(child, dest)
        except Exception as exc:  # pragma: no cover - platform/path dependent
            logger.warning("Could not copy Joern workspace artifacts back to %s: %s", joern_dir, exc)

    def _discover_cpg(self, joern_dir: Path, preferred: Path) -> Optional[Path]:
        if preferred.exists():
            return preferred
        candidates = sorted(joern_dir.rglob("*.bin"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None

    def _run(self, cmd, logger, cwd: Path):
        safe_cmd = [str(c) for c in cmd if c]
        command_line = " ".join(f'\"{c}\"' if " " in c else c for c in safe_cmd)
        logger.info("Running Joern command: %s", command_line)
        log_path = cwd / "joern_commands.log"
        start = time.monotonic()
        lines: List[str] = []
        try:
            with log_path.open("a", encoding="utf-8", errors="ignore") as lf:
                lf.write(f"\n$ {command_line}\n")
                proc = subprocess.Popen(
                    safe_cmd,
                    cwd=str(cwd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )
                assert proc.stdout is not None
                while True:
                    line = proc.stdout.readline()
                    if line:
                        clean = line.rstrip()
                        lines.append(clean)
                        lf.write(line)
                        lf.flush()
                        logger.info("[joern] %s", clean)
                    elif proc.poll() is not None:
                        break
                    elif time.monotonic() - start > self.timeout_seconds:
                        proc.kill()
                        msg = f"Joern command timed out after {self.timeout_seconds}s"
                        lf.write(msg + "\n")
                        logger.error(msg)
                        return {"cmd": safe_cmd, "returncode": None, "error": msg, "stdout_tail": "\n".join(lines[-80:])}
                    else:
                        time.sleep(0.1)
                returncode = proc.wait(timeout=5)
                elapsed = time.monotonic() - start
                logger.info("Joern command return code: %s elapsed=%.1fs", returncode, elapsed)
                lf.write(f"[returncode={returncode} elapsed={elapsed:.1f}s]\n")
                return {"cmd": safe_cmd, "returncode": returncode, "stdout_tail": "\n".join(lines[-80:]), "elapsed_seconds": round(elapsed, 3)}
        except KeyboardInterrupt:
            logger.warning("Interrupted while Joern command was running; terminating child process if still alive.")
            raise
        except Exception as exc:
            logger.warning("Joern command failed before completion: %s", exc)
            return {"cmd": safe_cmd, "returncode": None, "error": str(exc), "stdout_tail": "\n".join(lines[-80:])}
