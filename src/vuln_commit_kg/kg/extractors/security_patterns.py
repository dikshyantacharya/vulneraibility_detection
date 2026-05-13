from __future__ import annotations

import re
from dataclasses import dataclass


RISKY_APIS = {
    "gets": "CWE-242",
    "strcpy": "CWE-120",
    "strncpy": "CWE-120",
    "strcat": "CWE-120",
    "sprintf": "CWE-120",
    "vsprintf": "CWE-120",
    "scanf": "CWE-20",
    "sscanf": "CWE-20",
    "memcpy": "CWE-120",
    "memmove": "CWE-120",
    "malloc": "CWE-789",
    "calloc": "CWE-789",
    "realloc": "CWE-789",
    "free": "CWE-416",
    "system": "CWE-78",
    "popen": "CWE-78",
    "execve": "CWE-78",
    "execl": "CWE-78",
    "execlp": "CWE-78",
    "execvp": "CWE-78",
}

SAFETY_KEYWORDS = [
    "if", "assert", "sizeof", "strlen", "strnlen", "bounds", "check", "validate", "limit", "clamp",
    "return", "goto fail", "errno", "NULL", "nullptr",
]


@dataclass
class PatternHit:
    kind: str
    value: str
    cwe: str | None = None


def find_risky_calls(statement: str) -> list[PatternHit]:
    hits: list[PatternHit] = []
    for api, cwe in RISKY_APIS.items():
        if re.search(r"\b" + re.escape(api) + r"\s*\(", statement):
            hits.append(PatternHit(kind="risky_api", value=api, cwe=cwe))
    return hits


def is_safety_statement(statement: str) -> bool:
    low = statement.lower()
    if re.match(r"\s*if\s*\(", statement):
        return True
    return any(k.lower() in low for k in SAFETY_KEYWORDS)
