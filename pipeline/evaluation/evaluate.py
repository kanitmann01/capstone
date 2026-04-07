from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from typing import Callable


ProgressCallback = Callable[[dict[str, Any]], None]
ScoreFunction = Callable[[str, ProgressCallback | None], dict[str, Any]]


@dataclass
class EvaluationRow:
    index: int
    url: str
    actual_is_phishing: bool | None
    scanned_url: str
    risk_score: float | None
    predicted_is_phishing: bool | None
    matched_ground_truth: bool | None
    prediction_label: str = ""
    score_breakdown: dict[str, Any] = field(default_factory=dict)
    api_error: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    total_rows: int
    scored_rows: int
    error_rows: int
    tp: int
    tn: int
    fp: int
    fn: int
    rows: list[EvaluationRow] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        precision = self.precision
        recall = self.recall
        return (2 * precision * recall / (precision + recall)) if precision + recall else 0.0


def parse_label(value: Any) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "t", "yes", "y", "phishing"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "clean"}:
        return False
    raise ValueError(f"Unsupported label value: {value!r}")


def evaluate_csv(
    input_csv: str | Path,
    output_csv: str | Path,
    *,
    scorer: ScoreFunction,
    threshold: float = 30.0,
    progress_callback: ProgressCallback | None = None,
) -> EvaluationResult:
    input_path = Path(input_csv)
    output_path = Path(output_csv)
    with input_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Input CSV is missing a header row")
        if "url" not in reader.fieldnames or "is_phishing" not in reader.fieldnames:
            raise ValueError("Input CSV missing required columns: url, is_phishing")
        rows = list(reader)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(reader.fieldnames) + [
        "risk_score",
        "final_score",
        "rules_score",
        "fasttext_score",
        "legacy_score",
        "structured_ml_score",
        "prediction",
        "verdict",
        "predicted_is_phishing",
        "matched_ground_truth",
        "api_error",
    ]
    total_rows = len(rows)
    scored_rows = 0
    error_rows = 0
    tp = tn = fp = fn = 0
    output_rows: list[EvaluationRow] = []
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index, row in enumerate(rows, start=1):
            url = (row.get("url") or "").strip()
            actual = parse_label(row.get("is_phishing"))
            row_output = dict(row)
            try:
                payload = scorer(url, progress_callback)
                scores = dict(payload.get("scores") or {})
                final_value = scores.get("final")
                if final_value is None:
                    final_value = payload.get("risk_score")
                final_score = float(final_value or 0)
                rules_score = scores.get("rules")
                fasttext_score = scores.get("fasttext")
                legacy_score = scores.get("legacy")
                structured_ml_score = scores.get("structured_ml")
                prediction_label = str(payload.get("prediction") or payload.get("verdict", {}).get("label") or "unknown")
                predicted = final_score >= threshold
                matched = predicted == actual
                row_output.update(
                    {
                        "risk_score": f"{final_score:.2f}",
                        "final_score": f"{final_score:.2f}",
                        "rules_score": "" if rules_score is None else f"{float(rules_score):.2f}",
                        "fasttext_score": "" if fasttext_score is None else f"{float(fasttext_score):.2f}",
                        "legacy_score": "" if legacy_score is None else f"{float(legacy_score):.2f}",
                        "structured_ml_score": "" if structured_ml_score is None else f"{float(structured_ml_score):.2f}",
                        "prediction": prediction_label,
                        "verdict": str((payload.get("verdict") or {}).get("status") or ""),
                        "predicted_is_phishing": str(predicted).lower(),
                        "matched_ground_truth": str(matched).lower(),
                        "api_error": "",
                    }
                )
                output_rows.append(
                    EvaluationRow(
                        index=index,
                        url=url,
                        actual_is_phishing=actual,
                        scanned_url=str(payload.get("url") or url),
                        risk_score=final_score,
                        predicted_is_phishing=predicted,
                        matched_ground_truth=matched,
                        prediction_label=prediction_label,
                        score_breakdown={
                            "final": final_score,
                            "rules": rules_score,
                            "fasttext": fasttext_score,
                            "legacy": legacy_score,
                            "structured_ml": structured_ml_score,
                        },
                        details=payload,
                    )
                )
                scored_rows += 1
                if actual and predicted:
                    tp += 1
                elif not actual and not predicted:
                    tn += 1
                elif predicted and not actual:
                    fp += 1
                else:
                    fn += 1
            except Exception as exc:
                error_rows += 1
                row_output.update(
                    {
                        "risk_score": "",
                        "final_score": "",
                        "rules_score": "",
                        "fasttext_score": "",
                        "legacy_score": "",
                        "structured_ml_score": "",
                        "prediction": "",
                        "verdict": "",
                        "predicted_is_phishing": "",
                        "matched_ground_truth": "",
                        "api_error": str(exc),
                    }
                )
                output_rows.append(
                    EvaluationRow(
                        index=index,
                        url=url,
                        actual_is_phishing=actual,
                        scanned_url=url,
                        risk_score=None,
                        predicted_is_phishing=None,
                        matched_ground_truth=None,
                        api_error=str(exc),
                    )
                )
            writer.writerow(row_output)

    return EvaluationResult(
        total_rows=total_rows,
        scored_rows=scored_rows,
        error_rows=error_rows,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        rows=output_rows,
    )


def build_report_payload(result: EvaluationResult) -> dict[str, Any]:
    false_positives = [
        {
            "url": row.url,
            "risk_score": row.risk_score,
            "prediction": row.prediction_label,
            "score_breakdown": row.score_breakdown,
            "details": row.details,
        }
        for row in result.rows
        if row.predicted_is_phishing is True and row.actual_is_phishing is False
    ][:5]
    false_negatives = [
        {
            "url": row.url,
            "risk_score": row.risk_score,
            "prediction": row.prediction_label,
            "score_breakdown": row.score_breakdown,
            "details": row.details,
        }
        for row in result.rows
        if row.predicted_is_phishing is False and row.actual_is_phishing is True
    ][:5]
    return {
        "summary": {
            "total_rows": result.total_rows,
            "scored_rows": result.scored_rows,
            "error_rows": result.error_rows,
            "accuracy": round(result.accuracy, 4),
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "f1": round(result.f1, 4),
        },
        "confusion_matrix": {
            "tp": result.tp,
            "tn": result.tn,
            "fp": result.fp,
            "fn": result.fn,
        },
        "threshold_sweep": build_threshold_sweep_payload(result),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def build_threshold_sweep_payload(
    result: EvaluationResult,
    thresholds: list[float] | None = None,
) -> list[dict[str, Any]]:
    sweep_thresholds = thresholds or [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90]
    rows = [row for row in result.rows if row.risk_score is not None and row.actual_is_phishing is not None]
    sweep: list[dict[str, Any]] = []
    for threshold in sweep_thresholds:
        tp = tn = fp = fn = 0
        for row in rows:
            predicted = float(row.risk_score or 0) >= float(threshold)
            actual = bool(row.actual_is_phishing)
            if actual and predicted:
                tp += 1
            elif not actual and not predicted:
                tn += 1
            elif predicted and not actual:
                fp += 1
            else:
                fn += 1
        counts = {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
        metrics = {
            "accuracy": round((tp + tn) / (tp + tn + fp + fn), 4) if (tp + tn + fp + fn) else 0.0,
            "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
            "f1": round((2 * (tp / (tp + fp) if tp + fp else 0.0) * (tp / (tp + fn) if tp + fn else 0.0)) / ((tp / (tp + fp) if tp + fp else 0.0) + (tp / (tp + fn) if tp + fn else 0.0)), 4) if (tp + fp) and (tp + fn) and ((tp / (tp + fp)) + (tp / (tp + fn))) else 0.0,
        }
        sweep.append(
            {
                "threshold": float(threshold),
                **counts,
                **metrics,
            }
        )
    return sweep
