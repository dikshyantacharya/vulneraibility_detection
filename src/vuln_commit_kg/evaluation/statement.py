from __future__ import annotations

import re
from typing import Sequence

from vuln_commit_kg.agents.schemas import Prediction
from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.utils.text import similarity


def split_gold_statements(text: str | None) -> list[str]:
    if not text:
        return []
    # Handles JSON-ish strings, semicolon-separated code, and newline lists.
    parts = re.split(r"\n+|(?<=;)\s+", str(text))
    return [p.strip(" \t\r\n'\"[]") for p in parts if p.strip(" \t\r\n'\"[]")]


def statement_metrics(samples: Sequence[SecVulEvalSample], preds: Sequence[Prediction], threshold: float = 0.84) -> dict:
    pred_by_id = {p.sample_id: p for p in preds}
    total_gold = total_pred = matched = 0
    rows = []
    for s in samples:
        p = pred_by_id.get(s.sample_id)
        if not p:
            continue
        gold = split_gold_statements(getattr(s, "changed_statements", None))
        pred = [vs.statement or "" for vs in p.vuln_statements if vs.statement]
        sample_matched = 0
        used_pred = set()
        for g in gold:
            best_i, best_sim = None, 0.0
            for i, pr in enumerate(pred):
                if i in used_pred:
                    continue
                sim = similarity(g, pr)
                if sim > best_sim:
                    best_i, best_sim = i, sim
            if best_i is not None and best_sim >= threshold:
                sample_matched += 1
                used_pred.add(best_i)
        total_gold += len(gold)
        total_pred += len(pred)
        matched += sample_matched
        rows.append({
            "sample_id": s.sample_id,
            "gold_count": len(gold),
            "pred_count": len(pred),
            "matched": sample_matched,
        })
    precision = matched / total_pred if total_pred else 0.0
    recall = matched / total_gold if total_gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "statement_precision": precision,
        "statement_recall": recall,
        "statement_f1": f1,
        "total_gold_statements": total_gold,
        "total_pred_statements": total_pred,
        "matched_statements": matched,
        "rows": rows,
    }
