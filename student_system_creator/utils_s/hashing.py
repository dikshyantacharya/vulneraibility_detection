from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def stable_hash(value: Any, n: int = 16) -> str:
    payload = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:n]


def url_hash(url: str, n: int = 12) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:n]


def safe_name(text: str, max_len: int = 80) -> str:
    text = re.sub(r"https?://", "", text)
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    text = text.strip("._-")
    return (text[:max_len] or "unknown")
