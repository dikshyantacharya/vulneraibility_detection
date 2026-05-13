from __future__ import annotations

import logging
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GitResult:
    cmd: list[str]
    cwd: str | None
    returncode: int
    stdout: str
    stderr: str


class GitError(RuntimeError):
    def __init__(self, result: GitResult):
        self.result = result
        super().__init__(
            f"Git command failed with code {result.returncode}: {' '.join(result.cmd)}\n"
            f"STDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
        )


class GitRunner:
    def __init__(self, logger: logging.Logger, timeout_seconds: int = 1800):
        self.logger = logger
        self.timeout_seconds = timeout_seconds

    def _popen_kwargs(self) -> dict:
        # On Windows, CREATE_NEW_PROCESS_GROUP lets us terminate the git process
        # tree on Ctrl+C instead of leaving clone/fetch running after the terminal
        # is closed. On POSIX, start_new_session gives the same process-group kill.
        if os.name == "nt":
            return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
        return {"start_new_session": True}

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                proc.terminate()
            else:
                os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                if os.name == "nt":
                    proc.kill()
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def run(self, args: list[str], cwd: str | Path | None = None, check: bool = True) -> GitResult:
        cmd = ["git", *args]
        cwd_str = str(cwd) if cwd is not None else None
        self.logger.debug(f"git cwd={cwd_str or '.'}: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            cwd=cwd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **self._popen_kwargs(),
        )
        try:
            stdout, stderr = proc.communicate(timeout=self.timeout_seconds)
        except KeyboardInterrupt:
            self.logger.warning("git.interrupted | terminating: %s", " ".join(cmd))
            self._terminate_process(proc)
            raise
        except subprocess.TimeoutExpired:
            self.logger.warning("git.timeout | terminating after %ss: %s", self.timeout_seconds, " ".join(cmd))
            self._terminate_process(proc)
            stdout, stderr = proc.communicate(timeout=2) if proc.poll() is not None else ("", "")
            result = GitResult(cmd=cmd, cwd=cwd_str, returncode=proc.returncode or -9, stdout=stdout or "", stderr=(stderr or "") + "\nTIMEOUT")
            raise GitError(result)
        result = GitResult(cmd=cmd, cwd=cwd_str, returncode=proc.returncode, stdout=stdout or "", stderr=stderr or "")
        if check and proc.returncode != 0:
            raise GitError(result)
        return result

    def run_passthrough(self, args: list[str], cwd: str | Path | None = None, check: bool = True) -> GitResult:
        """Run git with stdout/stderr attached while remaining interrupt-safe."""
        cmd = ["git", *args]
        cwd_str = str(cwd) if cwd is not None else None
        self.logger.info("git cwd=%s: %s", cwd_str or ".", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            cwd=cwd_str,
            text=True,
            **self._popen_kwargs(),
        )
        try:
            proc.wait(timeout=self.timeout_seconds)
        except KeyboardInterrupt:
            self.logger.warning("git.interrupted | terminating: %s", " ".join(cmd))
            self._terminate_process(proc)
            raise
        except subprocess.TimeoutExpired:
            self.logger.warning("git.timeout | terminating after %ss: %s", self.timeout_seconds, " ".join(cmd))
            self._terminate_process(proc)
            result = GitResult(cmd=cmd, cwd=cwd_str, returncode=proc.returncode or -9, stdout="", stderr="TIMEOUT")
            raise GitError(result)
        result = GitResult(cmd=cmd, cwd=cwd_str, returncode=proc.returncode, stdout="", stderr="")
        if check and proc.returncode != 0:
            raise GitError(result)
        return result
