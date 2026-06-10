"""Read-only inventory + report loaders for the dashboard.

PRIVACY: in "student" (public-preview) mode this module must never expose
labels for test rows, the original (un-anonymized) kg ids, the alias map, or the
private registry. "admin" mode exposes everything. The mode switch below is the
only place that decides what leaves the server.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Mode = Literal["admin", "student"]

# Substrings that must NOT appear in any id surfaced to a student preview.
LEAKY_TOKENS = ("vuln", "safe", "label", "_true", "_false")


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@dataclass
class ChallengePaths:
    root: Path

    @property
    def public(self) -> Path:
        return self.root / "public"

    @property
    def private(self) -> Path:
        return self.root / "private"

    @property
    def registry(self) -> Path:
        return self.private / "kg_registry_private.json"

    @property
    def alias_map(self) -> Path:
        return self.private / "kg_id_alias_map_private.json"

    @property
    def validation_report(self) -> Path:
        return self.private / "validation_report.json"

    @property
    def build_summary(self) -> Path:
        return self.root / "build_summary.json"

    @property
    def test_labels(self) -> Path:
        return self.private / "test_labels.csv"


class ChallengeInventory:
    """Lazily loads + caches the challenge registry/CSVs for one challenge dir."""

    def __init__(self, challenge_root: str | Path) -> None:
        self.paths = ChallengePaths(Path(challenge_root).resolve())
        self._registry: dict[str, Any] | None = None

    @property
    def exists(self) -> bool:
        return self.paths.registry.exists()

    def _registry_entries(self) -> dict[str, dict[str, Any]]:
        if self._registry is None:
            data = _read_json(self.paths.registry) or {}
            self._registry = data.get("entries") or {}
        return self._registry

    def kgs(self, mode: Mode = "admin") -> list[dict[str, Any]]:
        entries = self._registry_entries()
        out: list[dict[str, Any]] = []
        for kg_id, e in entries.items():
            item = {
                "knowledge_graph_id": kg_id,
                "sample_id": e.get("sample_id"),
                "project": e.get("project"),
                "filepath": e.get("filepath"),
                "function_name": e.get("function_name"),
                "split": e.get("split"),
                "resolved_commit_prefix": str(e.get("resolved_commit") or "")[:12],
                "target_status": e.get("target_status"),
            }
            if mode == "admin":
                item["label"] = e.get("label")
                item["repo_key"] = e.get("repo_key")
                item["graph_dir"] = e.get("graph_dir")
            out.append(item)
        return out

    def kg_detail(self, kg_id: str, mode: Mode = "admin") -> dict[str, Any] | None:
        e = self._registry_entries().get(kg_id)
        if not e:
            return None
        detail = {
            "knowledge_graph_id": kg_id,
            "sample_id": e.get("sample_id"),
            "project": e.get("project"),
            "filepath": e.get("filepath"),
            "function_name": e.get("function_name"),
            "split": e.get("split"),
            "resolved_commit_prefix": str(e.get("resolved_commit") or "")[:12],
            "target_status": e.get("target_status"),
            "target_similarity": e.get("target_similarity"),
        }
        if mode == "admin":
            detail["label"] = e.get("label")
            detail["repo_key"] = e.get("repo_key")
            detail["graph_dir"] = e.get("graph_dir")
            detail["resolved_commit"] = e.get("resolved_commit")
        return detail

    def graph_dir(self, kg_id: str) -> Path | None:
        e = self._registry_entries().get(kg_id)
        if not e:
            return None
        raw = Path(str(e.get("graph_dir") or ""))
        return raw if raw.is_absolute() else self.paths.private / raw

    def projects(self, mode: Mode = "admin") -> list[dict[str, Any]]:
        by_project: dict[str, dict[str, Any]] = {}
        for e in self._registry_entries().values():
            proj = e.get("project") or "unknown"
            p = by_project.setdefault(
                proj,
                {
                    "project_id": proj,
                    "project": proj,
                    "repo_key": e.get("repo_key"),
                    "project_url": e.get("project_url"),
                    "function_count": 0,
                    "kg_built": 0,
                    "vuln": 0,
                    "safe": 0,
                    "splits": Counter(),
                },
            )
            p["function_count"] += 1
            p["kg_built"] += 1
            p["splits"][e.get("split") or "?"] += 1
            if mode == "admin":
                if e.get("label") == 1:
                    p["vuln"] += 1
                elif e.get("label") == 0:
                    p["safe"] += 1
        out = []
        for p in by_project.values():
            p["splits"] = dict(p["splits"])
            if mode != "admin":
                p.pop("vuln", None)
                p.pop("safe", None)
                p.pop("repo_key", None)
            out.append(p)
        out.sort(key=lambda x: x["function_count"])  # smallest-to-biggest
        return out

    def functions(self, mode: Mode = "admin") -> list[dict[str, Any]]:
        return self.kgs(mode=mode)

    def validation_report(self) -> dict[str, Any] | None:
        return _read_json(self.paths.validation_report)

    def build_summary(self) -> dict[str, Any] | None:
        return _read_json(self.paths.build_summary)

    def label_balance(self, mode: Mode = "admin") -> dict[str, Any]:
        if mode != "admin":
            return {}
        c: Counter = Counter()
        for e in self._registry_entries().values():
            c[str(e.get("label"))] += 1
        return dict(c)

    def split_counts(self) -> dict[str, int]:
        c: Counter = Counter()
        for e in self._registry_entries().values():
            c[str(e.get("split"))] += 1
        return dict(c)

    def leakage_check(self) -> dict[str, Any]:
        """Public-safety check: surface any public id containing leaky tokens."""
        flagged: list[dict[str, Any]] = []
        for kg_id in self._registry_entries():
            low = kg_id.lower()
            hit = [t for t in LEAKY_TOKENS if t in low]
            if hit:
                flagged.append({"knowledge_graph_id": kg_id, "tokens": hit})
        return {"ok": not flagged, "flagged": flagged, "checked": len(self._registry_entries())}


def discover_challenges(outputs_root: str | Path) -> list[dict[str, Any]]:
    """Find built challenge folders under an outputs root."""
    root = Path(outputs_root)
    found: list[dict[str, Any]] = []
    if not root.exists():
        return found
    for reg in root.glob("**/private/kg_registry_private.json"):
        challenge = reg.parent.parent
        found.append({"challenge_root": str(challenge), "name": challenge.name})
    return found
