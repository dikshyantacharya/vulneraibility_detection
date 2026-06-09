from __future__ import annotations

import math
import time
from typing import Optional


def fmt_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "?"
    try:
        s = max(0, int(float(seconds)))
    except Exception:
        return "?"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{sec:02d}s"
    if m:
        return f"{m}m{sec:02d}s"
    return f"{sec}s"


def progress_eta(start_time: float, processed: int, total: int) -> tuple[float, float, str]:
    elapsed = time.time() - start_time
    rate = processed / elapsed if elapsed > 0 and processed > 0 else 0.0
    remaining = max(0, total - processed)
    eta = remaining / rate if rate > 0 else math.inf
    return elapsed, rate, fmt_duration(eta if math.isfinite(eta) else None)


def short_id(value: object, length: int = 12) -> str:
    text = str(value or "")
    return text[:length]
