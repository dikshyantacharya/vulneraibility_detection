from __future__ import annotations

"""
Minimal hardcoded student agent for the VCKG evaluator.

No LLM. No registry access. No direct REST calls.
The evaluator handles KG access when this agent returns {"action": "query"}.

Evaluator contract:
    def build_agent(config: dict): ...
    agent.step(sample: dict, observation: dict, budget: dict) -> dict
"""

import hashlib
import json
import re
from typing import Any, Dict

STUDENT_AGENT_VERSION = "minimal_hardcoded_kg_asker_v1"


def _text(x: Any, limit: int = 20000) -> str:
    try:
        return json.dumps(x, ensure_ascii=False, sort_keys=True)[:limit]
    except Exception:
        return str(x)[:limit]


def _function_name(sample: Dict[str, Any]) -> str:
    for key in ("function_name", "target_function", "name", "target"):
        value = sample.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = sample.get("function")
    if isinstance(value, str) and value.strip() and "\n" not in value and "{" not in value:
        return value.strip()
    return "target_function"


def _source(sample: Dict[str, Any]) -> str:
    for key in ("target_function_source", "function_source", "source", "code", "body"):
        value = sample.get(key)
        if isinstance(value, str) and value.strip():
            return value
    value = sample.get("function")
    if isinstance(value, str) and ("\n" in value or "{" in value):
        return value
    return ""


def _sample_id(sample: Dict[str, Any]) -> str:
    for key in ("sample_id", "id", "row_id"):
        if sample.get(key) is not None:
            return str(sample[key])
    basis = (_function_name(sample) + "\n" + _source(sample))[:2000]
    return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]


def _remaining_queries(budget: Dict[str, Any]) -> int:
    for key in ("remaining_queries", "queries_remaining", "max_queries_remaining"):
        try:
            if budget.get(key) is not None:
                return int(budget[key])
        except Exception:
            pass
    return 3


def _suspicious_statement(src: str) -> str | None:
    patterns = [
        r".*\bstrcpy\s*\(.*;",
        r".*\bsprintf\s*\(.*;",
        r".*\bgets\s*\(.*;",
        r".*\bmemcpy\s*\(.*;",
        r".*\brealloc\s*\(.*;",
        r".*\bmalloc\s*\(.*;",
        r".*\+=\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*.*;",
    ]
    for pat in patterns:
        match = re.search(pat, src)
        if match:
            return " ".join(match.group(0).strip().split())[:240]
    return None


def _queries(fn: str, src: str) -> list[dict[str, Any]]:
    queries = [
        {
            "kind": "security_context",
            "target_function": fn,
            "depth": 3,
            "call_depth": 2,
            "data_depth": 4,
            "max_nodes": 350,
        },
        {
            "kind": "semantic_facts",
            "target_function": fn,
            "max_nodes": 300,
        },
        {
            "kind": "call_neighborhood",
            "target_function": fn,
            "direction": "both",
            "call_depth": 2,
            "max_nodes": 300,
        },
    ]
    stmt = _suspicious_statement(src)
    if stmt:
        queries.append(
            {
                "kind": "evidence_slice",
                "target_function": fn,
                "target_statement": stmt,
                "relation_depth": 4,
                "data_depth": 4,
                "control_depth": 3,
                "call_depth": 2,
                "max_nodes": 350,
            }
        )
    return queries


def _predict(src: str, observation: Dict[str, Any]) -> tuple[int, float, str]:
    text = (src + "\n" + _text(observation)).lower()

    if "gets(" in text or "strcpy(" in text or "strcat(" in text:
        return 1, 0.75, "High-risk unbounded string/buffer operation was found."

    if "sprintf(" in text and "snprintf(" not in text:
        return 1, 0.70, "sprintf appears without an obvious bounded snprintf replacement."

    dangerous_terms = [
        "memcpy(", "memmove(", "realloc(", "malloc(", "calloc(",
        "recvfrom(", "listen(", "bind(", "length *", "size *", "offset +=", "idx++",
    ]
    safety_terms = [
        "snprintf(", "strncpy(", "safe_malloc", "safe_calloc", "xmalloc", "xcalloc",
        "guard", "bounds", "bounded", "checked", "validated", "return -1", "if (",
    ]

    danger_score = sum(1 for term in dangerous_terms if term in text)
    safety_score = sum(1 for term in safety_terms if term in text)

    if danger_score >= 3 and safety_score < 3:
        return 1, 0.65, f"Multiple risky source/KG signals found: danger_score={danger_score}, safety_score={safety_score}."

    return 0, 0.60, f"No strong complete vulnerability signal found by this minimal agent: danger_score={danger_score}, safety_score={safety_score}."


class MinimalHardcodedStudentAgent:
    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.asked: set[str] = set()
        self.trace: dict[str, list[dict[str, Any]]] = {}
        print(f"student.solution.build_agent | version={STUDENT_AGENT_VERSION}", flush=True)

    def step(self, sample: Dict[str, Any], observation: Dict[str, Any], budget: Dict[str, Any]) -> Dict[str, Any]:
        sid = _sample_id(sample)
        fn = _function_name(sample)
        src = _source(sample)
        self.trace.setdefault(sid, [])

        force_final = bool(budget.get("force_final")) or _remaining_queries(budget) <= 0

        if sid not in self.asked and not force_final:
            self.asked.add(sid)
            queries = _queries(fn, src)
            self.trace[sid].append({"stage": "02_kg_query_planning", "queries": queries})
            return {
                "action": "query",
                "stage": "02_kg_query_planning",
                "reason": "Minimal hardcoded agent asks basic KG evidence before final decision.",
                "queries": queries,
                "agentic_trace": self.trace[sid],
                "student_solution_version": STUDENT_AGENT_VERSION,
            }

        prediction, confidence, reason = _predict(src, observation)
        self.trace[sid].append(
            {
                "stage": "final_decision",
                "prediction": prediction,
                "confidence": confidence,
                "reason": reason,
            }
        )
        return {
            "action": "final",
            "stage": "final_decision",
            "prediction": int(prediction),
            "confidence": float(confidence),
            "reason": reason,
            "decision_status": "minimal_binary_vulnerable" if prediction else "minimal_binary_non_vulnerable",
            "agentic_trace": self.trace[sid],
            "student_solution_version": STUDENT_AGENT_VERSION,
        }


def build_agent(config: Dict[str, Any] | None = None):
    return MinimalHardcodedStudentAgent(config or {})
