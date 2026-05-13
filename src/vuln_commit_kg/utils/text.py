from __future__ import annotations

import re
from difflib import SequenceMatcher


def normalize_code(text: str | None) -> str:
    text = text or ""
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(a: str | None, b: str | None) -> float:
    aa = normalize_code(a)
    bb = normalize_code(b)
    if not aa or not bb:
        return 0.0
    return SequenceMatcher(None, aa, bb).ratio()


def truncate_middle(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    half = max(1, (max_chars - 30) // 2)
    return text[:half] + "\n... <truncated> ...\n" + text[-half:]


def strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2:
            return "\n".join(lines[1:-1]).strip()
    return text
