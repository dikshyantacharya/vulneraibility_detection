from __future__ import annotations
import json, re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Type, TypeVar
from pydantic import BaseModel
T = TypeVar("T", bound=BaseModel)
ANSWER_RE = re.compile(r"<answer>\s*(.*?)\s*</answer>", re.I | re.S)
ANALYSIS_RE = re.compile(r"<analysis>\s*(.*?)\s*</analysis>", re.I | re.S)
CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.I | re.S)

@dataclass
class ParsedTaggedJson:
    analysis: str
    answer_text: str
    parsed: Dict[str, Any]
    used_repair: bool = False
    raw_text: str = ""

class TaggedJsonParseError(ValueError):
    pass

def extract_answer_text(raw_text: str) -> tuple[str, str]:
    raw_text = raw_text or ""
    analysis_match = ANALYSIS_RE.search(raw_text)
    answer_match = ANSWER_RE.search(raw_text)
    analysis = analysis_match.group(1).strip() if analysis_match else ""
    if answer_match:
        return analysis, answer_match.group(1).strip()
    fence = CODE_FENCE_RE.search(raw_text)
    if fence:
        return analysis, fence.group(1).strip()
    return analysis, raw_text.strip()

def _strip_json_noise(answer_text: str) -> str:
    text = (answer_text or "").strip()
    m = CODE_FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    starts = [i for i in [text.find("{"), text.find("[")] if i >= 0]
    if starts:
        text = text[min(starts):]
    end = max(text.rfind("}"), text.rfind("]"))
    if end >= 0:
        text = text[: end + 1]
    return text

def parse_json_answer(raw_text: str) -> ParsedTaggedJson:
    analysis, answer_text = extract_answer_text(raw_text)
    cleaned = _strip_json_noise(answer_text)
    try:
        parsed = json.loads(cleaned)
    except Exception as e:
        raise TaggedJsonParseError(f"Could not parse <answer> JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise TaggedJsonParseError("Top-level <answer> JSON must be an object.")
    return ParsedTaggedJson(analysis=analysis, answer_text=answer_text, parsed=parsed, raw_text=raw_text)

def build_json_repair_prompt(raw_text: str, answer_text: Optional[str], schema_name: str, schema_json: Dict[str, Any]) -> list[dict[str, str]]:
    repair_target = answer_text if answer_text is not None else raw_text
    return [
        {"role": "system", "content": "You repair malformed JSON only. Do not add new security reasoning. Return exactly <analysis>brief repair note</analysis><answer>{valid JSON object}</answer>."},
        {"role": "user", "content": f"SCHEMA NAME: {schema_name}\nJSON SCHEMA:\n{json.dumps(schema_json, indent=2)}\n\nMALFORMED OUTPUT:\n{repair_target}\n\nRepair JSON conservatively."},
    ]

def parse_model_object(raw_text: str, model_cls: Type[T], *, llm_repair: Optional[Callable[[list[dict[str, str]]], str]] = None) -> tuple[T, ParsedTaggedJson]:
    try:
        parsed = parse_json_answer(raw_text)
        return model_cls.model_validate(parsed.parsed), parsed
    except Exception:
        if llm_repair is None:
            raise
        _, answer_text = extract_answer_text(raw_text)
        prompt = build_json_repair_prompt(raw_text, answer_text if answer_text else raw_text, model_cls.__name__, model_cls.model_json_schema())
        repaired_text = llm_repair(prompt)
        repaired = parse_json_answer(repaired_text)
        repaired.used_repair = True
        return model_cls.model_validate(repaired.parsed), repaired
