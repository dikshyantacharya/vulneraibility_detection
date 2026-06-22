from __future__ import annotations

import logging
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import psutil

from utils_s.jsonl import append_jsonl


@dataclass
class ProfileEvent:
    name: str
    seconds: float
    rss_mb_start: float
    rss_mb_end: float
    rss_mb_delta: float
    status: str = "ok"


def rss_mb() -> float:
    try:
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def fmt_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m{sec:04.1f}s"
    hours, rem = divmod(minutes, 60)
    return f"{int(hours)}h{int(rem):02d}m{sec:04.1f}s"


class _SafeWriter:
    """Stream wrapper that replaces unencodable characters instead of raising.

    On Windows with a legacy cp1252 console, Rich's Unicode box-drawing chars
    (━, │, etc.) and any non-cp1252 characters in log messages cause
    UnicodeEncodeError.  This wrapper intercepts write() and silently replaces
    characters that cannot be encoded to the underlying stream's encoding.
    """

    def __init__(self, wrapped: object, orig_enc: str) -> None:
        self._wrapped = wrapped
        self._orig_enc = orig_enc
        self.encoding = "utf-8"  # report UTF-8 to Rich so it emits Unicode freely

    def write(self, text: str) -> int:
        try:
            text.encode(self._orig_enc)
        except UnicodeEncodeError:
            text = text.encode(self._orig_enc, errors="replace").decode(self._orig_enc)
        return self._wrapped.write(text)  # type: ignore[attr-defined]

    def flush(self) -> None:
        if hasattr(self._wrapped, "flush"):
            self._wrapped.flush()  # type: ignore[attr-defined]

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        if hasattr(self._wrapped, "fileno"):
            try:
                return self._wrapped.fileno()  # type: ignore[attr-defined]
            except Exception:
                pass
        import io
        raise io.UnsupportedOperation("fileno")


def _safe_console_stream(stream: object) -> object:
    """Return a write-safe stream for the given console stream.

    If the stream uses a narrow encoding (cp1252, ascii, etc.) that cannot
    represent all Unicode characters, wrap it so UnicodeEncodeError is never
    raised — instead unrepresentable characters are replaced with '?'.
    """
    enc = (getattr(stream, "encoding", None) or "utf-8").lower().replace("-", "").replace("_", "")
    if enc in ("utf8", "utf8sig"):
        return stream  # already safe
    # Prefer wrapping the underlying binary buffer (real terminal on Windows)
    if hasattr(stream, "buffer"):
        import io
        try:
            return io.TextIOWrapper(
                stream.buffer,  # type: ignore[attr-defined]
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
            )
        except Exception:
            pass
    # Fallback: proxy wrapper (handles StringIO in tests and other custom streams)
    return _SafeWriter(stream, getattr(stream, "encoding", "ascii") or "ascii")


def setup_logging(run_dir: Path | None, level: str = "INFO", use_rich: bool = True) -> logging.Logger:
    logger = logging.getLogger("vckg")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    fmt = "%(asctime)s | %(levelname)-7s | %(message)s"
    datefmt = "%H:%M:%S"
    if use_rich:
        try:
            from rich.console import Console
            from rich.logging import RichHandler

            # Wrap stdout in an encoding-safe stream so cp1252 / ascii Windows
            # consoles do not raise UnicodeEncodeError on Unicode log messages.
            _safe_out = _safe_console_stream(sys.stdout)
            _console = Console(
                file=_safe_out,  # type: ignore[arg-type]
                markup=True,
                highlight=False,
                safe_box=True,  # ASCII box chars in tracebacks instead of Unicode
            )
            console_handler = RichHandler(
                console=_console,
                rich_tracebacks=True,
                markup=True,
                show_path=False,
                show_time=True,
                log_time_format="%H:%M:%S",
            )
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        except Exception:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    logger.addHandler(console_handler)

    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(run_dir / "run.log", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        logger.addHandler(file_handler)

    return logger


def log_kv(logger: logging.Logger, title: str, **items: object) -> None:
    """Emit a compact multi-line block that is easy to scan in console and run.log."""
    if not items:
        logger.info("[bold]%-18s[/]", title)
        return
    lines = [f"[bold]{title}[/]"]
    for key, value in items.items():
        lines.append(f"  - {key}: {value}")
    logger.info("\n".join(lines))


@contextmanager
def profile(logger: logging.Logger, run_dir: Path | None, name: str) -> Iterator[None]:
    start = time.perf_counter()
    mem0 = rss_mb()
    status = "ok"
    try:
        logger.info(f"[bold cyan]START[/] {name} | rss={mem0:.1f} MB")
        yield
    except Exception:
        status = "error"
        raise
    finally:
        elapsed = time.perf_counter() - start
        mem1 = rss_mb()
        event = ProfileEvent(
            name=name,
            seconds=elapsed,
            rss_mb_start=mem0,
            rss_mb_end=mem1,
            rss_mb_delta=mem1 - mem0,
            status=status,
        )
        logger.info(
            f"[bold green]END[/] {name} | {fmt_seconds(elapsed)} | rss={mem1:.1f} MB | "
            f"delta={mem1 - mem0:+.1f} MB | {status}"
        )
        if run_dir is not None:
            append_jsonl(run_dir / "profile_events.jsonl", event)


class ProgressMeter:
    """Periodic progress logger with percent, ETA, rate, and memory.

    It deliberately emits normal log lines instead of a terminal-only animated bar so the
    same progress is preserved in outputs/runs/<run>/run.log for debugging.
    """

    def __init__(
        self,
        logger: logging.Logger,
        total: int | None,
        label: str,
        log_every: int = 1,
        log_every_seconds: float = 5.0,
        show_memory: bool = True,
    ):
        self.logger = logger
        self.total = total if total is not None and total > 0 else None
        self.label = label
        self.log_every = max(log_every, 1)
        self.log_every_seconds = max(log_every_seconds, 0.1)
        self.show_memory = show_memory
        self.start = time.perf_counter()
        self.last_log = self.start
        self.done = 0

    def update(self, n: int = 1, extra: str = "", force: bool = False) -> None:
        self.done += n
        now = time.perf_counter()
        due_count = self.done == 1 or self.done % self.log_every == 0
        due_time = (now - self.last_log) >= self.log_every_seconds
        due_end = self.total is not None and self.done >= self.total
        if not (force or due_count or due_time or due_end):
            return
        self.last_log = now
        elapsed = now - self.start
        rate = self.done / elapsed if elapsed > 0 else 0.0
        if self.total is not None:
            pct = min(100.0, 100.0 * self.done / self.total)
            remain = max(0.0, (self.total - self.done) / rate) if rate > 0 else 0.0
            base = (
                f"{self.label}: {self.done}/{self.total} ({pct:5.1f}%) | "
                f"elapsed={fmt_seconds(elapsed)} | eta={fmt_seconds(remain)} | rate={rate:.2f}/s"
            )
        else:
            base = f"{self.label}: {self.done} | elapsed={fmt_seconds(elapsed)} | rate={rate:.2f}/s"
        if self.show_memory:
            base += f" | rss={rss_mb():.1f} MB"
        if extra:
            base += f" | {extra}"
        self.logger.info(base)

    def finish(self, extra: str = "") -> None:
        if self.total is not None and self.done < self.total:
            self.done = self.total
        self.update(n=0, extra=extra, force=True)
