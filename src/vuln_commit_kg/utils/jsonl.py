from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable


def to_jsonable(obj: Any) -> Any:
    """Return a JSON-serializable representation of common pipeline objects.

    This intentionally handles NumPy/Pandas/Arrow values because dataset rows may
    carry extension arrays or scalars into sample extras, manifests, live events,
    or report records.  It also falls back from Pydantic JSON mode to Python mode
    so one unknown nested type cannot crash a run artifact write.
    """
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    if isinstance(obj, float):
        try:
            import math
            return None if math.isnan(obj) else obj
        except Exception:
            return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
    if hasattr(obj, "as_py"):
        try:
            return to_jsonable(obj.as_py())
        except Exception:
            pass
    if hasattr(obj, "item") and not isinstance(obj, (str, bytes, bytearray)):
        try:
            item = obj.item()
            if item is not obj:
                return to_jsonable(item)
        except Exception:
            pass
    if hasattr(obj, "tolist") and not isinstance(obj, (str, bytes, bytearray)):
        try:
            return to_jsonable(obj.tolist())
        except Exception:
            pass
    if hasattr(obj, "model_dump"):
        try:
            return to_jsonable(obj.model_dump(mode="json"))
        except Exception:
            return to_jsonable(obj.model_dump(mode="python"))
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_jsonable(getattr(obj, k)) for k in obj.__dataclass_fields__}
    if isinstance(obj, dict):
        return {str(to_jsonable(k)): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]
    try:
        import pandas as pd
        missing = pd.isna(obj)
        if isinstance(missing, bool) and missing:
            return None
    except Exception:
        pass
    return obj


def write_json(path: str | Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(data), indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def append_jsonl(path: str | Path, row: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(to_jsonable(row), ensure_ascii=False, default=str) + "\n")


def write_jsonl(path: str | Path, rows: Iterable[Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(to_jsonable(row), ensure_ascii=False, default=str) + "\n")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
