from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field, ConfigDict, field_validator, computed_field, model_validator


def _to_builtin(v: Any) -> Any:
    """Recursively convert Arrow/Pandas/NumPy values to JSON-safe Python values.

    SecVulEval Arrow rows can contain list/array/scalar extension values, and
    Pydantic v2's ``model_dump(mode='json')`` raises on unknown types such as
    ``numpy.ndarray`` if they remain in allowed extra fields.  This sanitizer is
    intentionally dependency-optional so the package still imports without NumPy.
    """
    if v is None:
        return None
    if isinstance(v, (str, int, bool)):
        return v
    if isinstance(v, float):
        try:
            import math
            return None if math.isnan(v) else v
        except Exception:
            return v
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, Path):
        return str(v)
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return str(v)
    if hasattr(v, "as_py"):
        try:
            return _to_builtin(v.as_py())
        except Exception:
            pass
    # NumPy/Pandas scalar containers.  Keep this before ``tolist`` so np scalar
    # values become plain ints/bools/strings rather than object wrappers.
    if hasattr(v, "item") and not isinstance(v, (str, bytes, bytearray)):
        try:
            item = v.item()
            if item is not v:
                return _to_builtin(item)
        except Exception:
            pass
    # NumPy arrays, Pandas extension arrays, Arrow-backed list-ish columns.
    if hasattr(v, "tolist") and not isinstance(v, (str, bytes, bytearray)):
        try:
            return _to_builtin(v.tolist())
        except Exception:
            pass
    if isinstance(v, dict):
        return {str(_to_builtin(k)): _to_builtin(val) for k, val in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_to_builtin(x) for x in v]
    try:
        import pandas as pd
        missing = pd.isna(v)
        if isinstance(missing, bool) and missing:
            return None
    except Exception:
        pass
    return v


def _norm_list(v: Any) -> list[str]:
    v = _to_builtin(v)
    if v is None:
        return []
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                import ast
                value = ast.literal_eval(s)
                return _norm_list(value)
            except Exception:
                pass
        return [x.strip() for x in s.replace(";", ",").split(",") if x.strip()]
    if isinstance(v, (list, tuple, set)):
        out: list[str] = []
        for x in v:
            x = _to_builtin(x)
            if isinstance(x, (list, tuple, set)):
                out.extend(_norm_list(x))
                continue
            s = str(x).strip() if x is not None else ""
            if s:
                out.append(s)
        return out
    s = str(v).strip()
    return [s] if s else []


class SecVulEvalSample(BaseModel):
    """Normalized dataset row used by the vulnerability pipeline."""

    model_config = ConfigDict(extra="allow")

    idx: int = 0
    sample_id: str = ""
    project: str = ""
    project_url: str | None = None
    filepath: str = ""
    func_name: str = ""
    func_body: str = ""
    commit_id: str | None = None
    commit_message: str | None = None
    is_vulnerable: bool = False
    cve_list: list[str] = Field(default_factory=list)
    cwe_list: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sanitize_input(cls, v: Any) -> Any:
        return _to_builtin(v)

    @field_validator("project", "filepath", "func_name", "func_body", "sample_id", mode="before")
    @classmethod
    def _coerce_required_text(cls, v: Any) -> str:
        v = _to_builtin(v)
        if v is None:
            return ""
        if isinstance(v, list):
            return ",".join(str(x) for x in v if x is not None)
        return str(v)

    @field_validator("project_url", "commit_id", "commit_message", mode="before")
    @classmethod
    def _coerce_optional_text(cls, v: Any) -> str | None:
        v = _to_builtin(v)
        if v is None:
            return None
        if isinstance(v, list):
            s = ",".join(str(x) for x in v if x is not None).strip()
            return s or None
        s = str(v).strip()
        return s or None

    @field_validator("cve_list", "cwe_list", mode="before")
    @classmethod
    def _coerce_list(cls, v: Any) -> list[str]:
        return _norm_list(v)

    @field_validator("is_vulnerable", mode="before")
    @classmethod
    def _coerce_label(cls, v: Any) -> bool:
        v = _to_builtin(v)
        if isinstance(v, (list, tuple, set)):
            v = next(iter(v), False)
            v = _to_builtin(v)
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        s = str(v).strip().lower().replace("_", "-")
        return s in {"1", "true", "yes", "vulnerable", "vuln", "buggy"}

    @computed_field
    @property
    def display_name(self) -> str:
        label = "vulnerable" if self.is_vulnerable else "fixed/non-vulnerable"
        return f"{self.sample_id or self.idx}:{self.project}:{self.filepath}:{self.func_name}:{label}"
