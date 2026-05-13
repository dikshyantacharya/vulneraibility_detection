from __future__ import annotations

from typing import Sequence

from vuln_commit_kg.agents.schemas import Prediction
from vuln_commit_kg.data.schema import SecVulEvalSample


INVALID_DECISION_STATUSES = {"parse_failed", "inconclusive", "invalid", "error"}


def _is_valid_binary_prediction(p: Prediction) -> bool:
    if p.parse_error:
        return False
    if str(p.decision_status or "") in INVALID_DECISION_STATUSES:
        return False
    return True


def binary_metrics(samples: Sequence[SecVulEvalSample], preds: Sequence[Prediction]) -> dict:
    """Binary metrics with invalid/inconclusive predictions separated.

    A failed final JSON parse must not silently become a true negative. The
    ordinary accuracy/precision/recall/F1 are computed on valid binary decisions
    only, while `accuracy_all_invalid_as_wrong` is also provided for conservative
    reporting.
    """
    by_id = {p.sample_id: p for p in preds}
    tp = tn = fp = fn = invalid = missing = 0
    rows = []
    for s in samples:
        p = by_id.get(s.sample_id)
        if p is None:
            missing += 1
            rows.append({"sample_id": s.sample_id, "true": bool(s.is_vulnerable), "pred": None, "outcome": "MISSING", "confidence": None})
            continue
        y = bool(s.is_vulnerable)
        valid = _is_valid_binary_prediction(p)
        if not valid:
            invalid += 1
            rows.append({
                "sample_id": s.sample_id,
                "true": y,
                "pred": bool(p.is_vulnerable),
                "valid_binary_prediction": False,
                "outcome": "INVALID",
                "decision_status": p.decision_status,
                "parse_error": p.parse_error,
                "confidence": p.confidence,
            })
            continue
        yhat = bool(p.is_vulnerable)
        if y and yhat:
            tp += 1
            outcome = "TP"
        elif not y and not yhat:
            tn += 1
            outcome = "TN"
        elif not y and yhat:
            fp += 1
            outcome = "FP"
        else:
            fn += 1
            outcome = "FN"
        rows.append({"sample_id": s.sample_id, "true": y, "pred": yhat, "valid_binary_prediction": True, "outcome": outcome, "confidence": p.confidence, "decision_status": p.decision_status})
    n_valid = tp + tn + fp + fn
    n_total = n_valid + invalid + missing
    accuracy = (tp + tn) / n_valid if n_valid else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    balanced_accuracy = (recall + specificity) / 2 if n_valid else 0.0
    accuracy_all_invalid_as_wrong = (tp + tn) / n_total if n_total else 0.0

    # Compatibility metrics are provided only for comparison with earlier runs.
    # They map inconclusive/invalid parse-failure predictions through the boolean
    # is_vulnerable field, so they must not be used as the primary scientific metric.
    c_tp = c_tn = c_fp = c_fn = 0
    for s in samples:
        p = by_id.get(s.sample_id)
        if p is None:
            continue
        y = bool(s.is_vulnerable)
        yhat = bool(p.is_vulnerable)
        if y and yhat:
            c_tp += 1
        elif not y and not yhat:
            c_tn += 1
        elif not y and yhat:
            c_fp += 1
        else:
            c_fn += 1
    c_n = c_tp + c_tn + c_fp + c_fn
    c_precision = c_tp / (c_tp + c_fp) if c_tp + c_fp else 0.0
    c_recall = c_tp / (c_tp + c_fn) if c_tp + c_fn else 0.0
    c_f1 = 2 * c_precision * c_recall / (c_precision + c_recall) if c_precision + c_recall else 0.0

    return {
        "n": n_valid,
        "n_total": n_total,
        "valid_predictions": n_valid,
        "invalid_predictions": invalid,
        "missing_predictions": missing,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "false_positive_count": fp,
        "false_negative_count": fn,
        "true_positive_count": tp,
        "true_negative_count": tn,
        "accuracy": accuracy,
        "accuracy_all_invalid_as_wrong": accuracy_all_invalid_as_wrong,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "balanced_accuracy": balanced_accuracy,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "rows": rows,
        "strict": {
            "n": n_valid,
            "invalid_predictions": invalid,
            "missing_predictions": missing,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "balanced_accuracy": balanced_accuracy,
            "policy": "primary metric: only vulnerable/non_vulnerable decision_status values are valid; inconclusive/parse_failed are abstentions",
        },
        "compatibility_invalid_mapped_through_boolean": {
            "n": c_n,
            "tp": c_tp,
            "tn": c_tn,
            "fp": c_fp,
            "fn": c_fn,
            "accuracy": (c_tp + c_tn) / c_n if c_n else 0.0,
            "precision": c_precision,
            "recall": c_recall,
            "f1": c_f1,
            "policy": "secondary comparison only: invalid/inconclusive predictions are scored via the raw is_vulnerable boolean",
        },
    }
