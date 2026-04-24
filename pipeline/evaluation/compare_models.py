from __future__ import annotations

"""
Model comparison and confusion matrix metrics.

Provides pure functions to compute confusion counts (TP/TN/FP/FN)
and derive precision, recall, F1, and accuracy from those counts.
"""

from typing import Any  # Standard library: generic type hints


def confusion_counts(rows: list[dict[str, Any]], *, actual_key: str, predicted_key: str) -> dict[str, int]:
    """Count true/false positives/negatives from a list of row dicts."""
    tp = tn = fp = fn = 0
    for row in rows:
        actual = str(row.get(actual_key)).strip().lower() in {"1", "true", "phishing", "yes"}
        predicted = str(row.get(predicted_key)).strip().lower() in {"1", "true", "phishing", "yes"}
        if actual and predicted:
            tp += 1
        elif not actual and not predicted:
            tn += 1
        elif predicted and not actual:
            fp += 1
        else:
            fn += 1
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def metrics_from_counts(counts: dict[str, int]) -> dict[str, float]:
    """Derive accuracy, precision, recall, and F1 from confusion counts."""
    tp = counts["tp"]
    tn = counts["tn"]
    fp = counts["fp"]
    fn = counts["fn"]
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
