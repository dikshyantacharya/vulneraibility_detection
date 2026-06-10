"""Standard dashboard event schema + durable JSONL writer."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DashboardEvent:
    type: str
    job_id: str
    timestamp: str = field(default_factory=utcnow_iso)
    phase: str | None = None
    level: str = "info"
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DashboardEvent":
        return cls(
            type=raw.get("type", "log"),
            job_id=raw.get("job_id", ""),
            timestamp=raw.get("timestamp") or utcnow_iso(),
            phase=raw.get("phase"),
            level=raw.get("level", "info"),
            message=raw.get("message", ""),
            data=raw.get("data") or {},
        )


class EventSink:
    """Append events to a JSONL file (thread-safe) and fan out to listeners."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._listeners: list[Any] = []

    def add_listener(self, fn: Any) -> None:
        with self._lock:
            self._listeners.append(fn)

    def remove_listener(self, fn: Any) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    def emit(self, event: DashboardEvent) -> DashboardEvent:
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(event)
            except Exception:
                pass
        return event

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out
