from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional
import hashlib
import json


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    raw = "|".join(str(p) for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:length]
    return f"{prefix}:{digest}"


def normalize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [normalize_scalar(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize_scalar(v) for k, v in value.items()}
    return str(value)


@dataclass
class Node:
    id: str
    type: str
    label: str
    name: Optional[str] = None
    file: Optional[str] = None
    function: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return normalize_scalar(d)


@dataclass
class Edge:
    source: str
    target: str
    type: str
    id: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = stable_id("edge", self.source, self.target, self.type, json.dumps(self.attrs, sort_keys=True))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return normalize_scalar(d)
