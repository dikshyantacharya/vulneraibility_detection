"""Dashboard settings: configurable paths + defaults, persisted to JSON.

Nothing here is hardcoded to a single machine; every path defaults to a value
relative to the project root and can be overridden via the settings file, CLI
flags, or the POST /api/dashboard/settings endpoint.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DashboardSettings:
    project_root: str = "."
    config_path: str = "student_system_creator/configs/default.yaml"
    challenge_root: str = "outputs/student_challenge/vckg_codekg_student_challenge"
    outputs_root: str = "outputs/student_challenge"
    jobs_root: str = "outputs/dashboard/jobs"
    cache_dir: str = "cache"
    frontend_dist: str = "frontend/dist"
    host: str = "127.0.0.1"
    port: int = 8080
    api_port: int = 8000
    default_mode: str = "admin"  # admin | student
    joern_home: str = "tools/joern-cli"
    max_engine_cache_size: int = 8
    slow_query_seconds: float = 10.0
    theme: str = "light"
    external_env_path: str = "C:/Users/DikshyantAcharya/Personal/env"
    # Suppress routine uvicorn access logs for high-frequency/no-op routes
    # (health/jobs/disk/ws) while still logging errors + job lifecycle.
    quiet_access_logs: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None) -> "DashboardSettings":
        s = cls()
        if path and Path(path).exists():
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for k, v in data.items():
                if hasattr(s, k):
                    setattr(s, k, v)
                else:
                    s.extra[k] = v
        return s

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def update(self, patch: dict[str, Any]) -> None:
        for k, v in (patch or {}).items():
            if hasattr(self, k) and k not in ("project_root",):
                setattr(self, k, v)
            else:
                self.extra[k] = v

    def resolve(self, attr: str) -> Path:
        """Resolve a path attribute relative to project_root if not absolute."""
        raw = Path(getattr(self, attr))
        if raw.is_absolute():
            return raw
        return (Path(self.project_root) / raw).resolve()
