from __future__ import annotations

from typing import Sequence

from vuln_commit_kg.agents.schemas import Prediction


def usage_summary(preds: Sequence[Prediction]) -> dict:
    prompt = completion = total = 0
    cost = 0.0
    estimated = True
    for p in preds:
        u = p.usage or {}
        prompt += int(u.get("prompt_tokens", 0))
        completion += int(u.get("completion_tokens", 0))
        total += int(u.get("total_tokens", 0))
        cost += float(u.get("cost_total_usd", 0.0))
        estimated = bool(estimated and u.get("estimated", True))
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "cost_total_usd": cost,
        "estimated": estimated,
        "num_predictions": len(preds),
        "avg_total_tokens_per_prediction": total / len(preds) if preds else 0.0,
        "avg_cost_usd_per_prediction": cost / len(preds) if preds else 0.0,
    }
