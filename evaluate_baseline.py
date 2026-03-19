from __future__ import annotations

import argparse
import csv
from collections import Counter
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any
from typing import Callable

import requests


DEFAULT_ENDPOINT = "http://localhost:8000/scan/combined"
DEFAULT_THRESHOLD = 50.0
DEFAULT_TIMEOUT = 15
CHECK_NAMES = ("heuristics", "content", "ssl", "domain_age", "threat_intel", "ml")

TRUTHY_VALUES = {"1", "true", "t", "yes", "y"}
FALSY_VALUES = {"0", "false", "f", "no", "n"}

ProgressCallback = Callable[[dict[str, Any]], None]
ScoreFunction = Callable[[str, ProgressCallback | None], dict[str, Any]]


@dataclass
class RowEvaluation:
    index: int
    url: str
    actual_is_phishing: bool | None
    scanned_url: str
    risk_score: float | None
    predicted_is_phishing: bool | None
    matched_ground_truth: bool | None
    api_error: str = ""
    contributing_checks: list[str] = field(default_factory=list)
    unknown_checks: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "url": self.url,
            "actual_is_phishing": self.actual_is_phishing,
            "scanned_url": self.scanned_url,
            "risk_score": self.risk_score,
            "predicted_is_phishing": self.predicted_is_phishing,
            "matched_ground_truth": self.matched_ground_truth,
            "api_error": self.api_error,
            "contributing_checks": list(self.contributing_checks),
            "unknown_checks": list(self.unknown_checks),
            "details": self.details,
        }


@dataclass
class EvaluationResult:
    total_rows: int
    scored_rows: int
    error_rows: int
    tp: int
    tn: int
    fp: int
    fn: int
    threshold: float = DEFAULT_THRESHOLD
    output_csv: str | None = None
    rows: list[RowEvaluation] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        if total == 0:
            return 0.0
        return (self.tp + self.tn) / total

    @property
    def precision(self) -> float:
        predicted_positive = self.tp + self.fp
        if predicted_positive == 0:
            return 0.0
        return self.tp / predicted_positive

    @property
    def recall(self) -> float:
        actual_positive = self.tp + self.fn
        if actual_positive == 0:
            return 0.0
        return self.tp / actual_positive

    @property
    def f1(self) -> float:
        precision = self.precision
        recall = self.recall
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)


def parse_label(value: Any) -> bool:
    normalized = str(value).strip().lower()
    if normalized in TRUTHY_VALUES:
        return True
    if normalized in FALSY_VALUES:
        return False
    raise ValueError(
        "Unsupported is_phishing value "
        f"{value!r}. Expected one of: {sorted(TRUTHY_VALUES | FALSY_VALUES)}"
    )


def classify_score(risk_score: float, threshold: float) -> bool:
    return risk_score >= threshold


def build_check_states(default_state: str = "pending") -> dict[str, str]:
    return {name: default_state for name in CHECK_NAMES}


def score_url(
    url: str,
    endpoint: str,
    timeout: int,
    session: requests.Session,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    del progress_callback
    response = session.post(endpoint, json={"url": url}, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    if "risk_score" not in payload:
        raise ValueError("API response missing 'risk_score'")
    return payload


def _blank_output_row(source_row: dict[str, Any], threshold: float) -> dict[str, Any]:
    row_output = dict(source_row)
    row_output.update(
        {
            "api_scanned_url": "",
            "risk_score": "",
            "score_threshold": threshold,
            "predicted_is_phishing": "",
            "matched_ground_truth": "",
            "api_error": "",
        }
    )
    return row_output


def _build_progress_event(
    *,
    event_type: str,
    row_index: int,
    total_rows: int,
    processed_rows: int,
    scored_rows: int,
    error_rows: int,
    threshold: float,
    url: str,
    check_states: dict[str, str] | None = None,
    row: RowEvaluation | None = None,
    **extra: Any,
) -> dict[str, Any]:
    payload = {
        "type": event_type,
        "row_index": row_index,
        "total_rows": total_rows,
        "processed_rows": processed_rows,
        "scored_rows": scored_rows,
        "error_rows": error_rows,
        "threshold": threshold,
        "url": url,
        "check_states": dict(check_states or {}),
    }
    if row is not None:
        payload["row"] = row.as_dict()
    payload.update(extra)
    return payload


def evaluate_csv(
    input_csv: str | Path,
    output_csv: str | Path,
    endpoint: str = DEFAULT_ENDPOINT,
    threshold: float = DEFAULT_THRESHOLD,
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
    scorer: ScoreFunction | None = None,
    progress_callback: ProgressCallback | None = None,
) -> EvaluationResult:
    input_path = Path(input_csv)
    output_path = Path(output_csv)

    with input_path.open("r", newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("Input CSV is missing a header row")

        fieldnames = list(reader.fieldnames)
        required_columns = {"url", "is_phishing"}
        missing_columns = required_columns.difference(fieldnames)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Input CSV missing required columns: {missing}")
        input_rows = list(reader)

    extra_columns = [
        "api_scanned_url",
        "risk_score",
        "score_threshold",
        "predicted_is_phishing",
        "matched_ground_truth",
        "api_error",
    ]
    output_fieldnames = fieldnames + extra_columns
    output_path.parent.mkdir(parents=True, exist_ok=True)

    client = session or requests.Session()
    should_close = session is None
    score_fn = scorer or (
        lambda url, row_progress: score_url(
            url=url,
            endpoint=endpoint,
            timeout=timeout,
            session=client,
            progress_callback=row_progress,
        )
    )

    total_rows = len(input_rows)
    scored_rows = 0
    error_rows = 0
    tp = tn = fp = fn = 0
    evaluated_rows: list[RowEvaluation] = []

    if progress_callback:
        progress_callback(
            {
                "type": "job_started",
                "total_rows": total_rows,
                "processed_rows": 0,
                "scored_rows": 0,
                "error_rows": 0,
                "threshold": threshold,
            }
        )

    try:
        with output_path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=output_fieldnames)
            writer.writeheader()

            for index, row in enumerate(input_rows, start=1):
                url = (row.get("url") or "").strip()
                row_output = _blank_output_row(row, threshold)
                check_states = build_check_states()

                if progress_callback:
                    progress_callback(
                        _build_progress_event(
                            event_type="row_started",
                            row_index=index,
                            total_rows=total_rows,
                            processed_rows=len(evaluated_rows),
                            scored_rows=scored_rows,
                            error_rows=error_rows,
                            threshold=threshold,
                            url=url,
                            check_states=check_states,
                        )
                    )

                actual_is_phishing: bool | None = None
                row_result = RowEvaluation(
                    index=index,
                    url=url,
                    actual_is_phishing=None,
                    scanned_url=url,
                    risk_score=None,
                    predicted_is_phishing=None,
                    matched_ground_truth=None,
                )

                try:
                    if not url:
                        raise ValueError("Missing URL value")

                    actual_is_phishing = parse_label(row.get("is_phishing"))

                    def emit_row_progress(event: dict[str, Any]) -> None:
                        event_type = str(event.get("type", "row_progress"))
                        check_name = event.get("check")
                        if event_type == "check_started" and check_name in check_states:
                            check_states[str(check_name)] = "running"
                        elif event_type == "check_completed" and check_name in check_states:
                            result_status = str(event.get("status", "ok"))
                            check_states[str(check_name)] = (
                                "completed" if result_status == "ok" else "unknown"
                            )

                        if progress_callback:
                            progress_callback(
                                _build_progress_event(
                                    event_type=event_type,
                                    row_index=index,
                                    total_rows=total_rows,
                                    processed_rows=len(evaluated_rows),
                                    scored_rows=scored_rows,
                                    error_rows=error_rows,
                                    threshold=threshold,
                                    url=url,
                                    check_states=check_states,
                                    **{key: value for key, value in event.items() if key != "type"},
                                )
                            )

                    payload = score_fn(url, emit_row_progress)
                    risk_score = float(payload["risk_score"])
                    predicted_is_phishing = classify_score(risk_score, threshold)
                    matched_ground_truth = predicted_is_phishing == actual_is_phishing
                    contributing_checks = list(payload.get("contributing_checks") or [])
                    unknown_checks = list(payload.get("unknown_checks") or [])
                    details = payload.get("details") or {}

                    row_output.update(
                        {
                            "api_scanned_url": payload.get("url", url),
                            "risk_score": f"{risk_score:.2f}",
                            "predicted_is_phishing": str(predicted_is_phishing).lower(),
                            "matched_ground_truth": str(matched_ground_truth).lower(),
                        }
                    )

                    row_result = RowEvaluation(
                        index=index,
                        url=url,
                        actual_is_phishing=actual_is_phishing,
                        scanned_url=payload.get("url", url),
                        risk_score=risk_score,
                        predicted_is_phishing=predicted_is_phishing,
                        matched_ground_truth=matched_ground_truth,
                        contributing_checks=contributing_checks,
                        unknown_checks=unknown_checks,
                        details=details,
                    )

                    scored_rows += 1
                    if predicted_is_phishing and actual_is_phishing:
                        tp += 1
                    elif not predicted_is_phishing and not actual_is_phishing:
                        tn += 1
                    elif predicted_is_phishing and not actual_is_phishing:
                        fp += 1
                    else:
                        fn += 1
                except Exception as exc:
                    error_rows += 1
                    row_output["api_error"] = str(exc)
                    row_result = RowEvaluation(
                        index=index,
                        url=url,
                        actual_is_phishing=actual_is_phishing,
                        scanned_url=url,
                        risk_score=None,
                        predicted_is_phishing=None,
                        matched_ground_truth=None,
                        api_error=str(exc),
                    )

                writer.writerow(row_output)
                evaluated_rows.append(row_result)

                if progress_callback:
                    progress_callback(
                        _build_progress_event(
                            event_type="row_completed",
                            row_index=index,
                            total_rows=total_rows,
                            processed_rows=len(evaluated_rows),
                            scored_rows=scored_rows,
                            error_rows=error_rows,
                            threshold=threshold,
                            url=url,
                            check_states=check_states,
                            row=row_result,
                        )
                    )
    finally:
        if should_close:
            client.close()

    result = EvaluationResult(
        total_rows=total_rows,
        scored_rows=scored_rows,
        error_rows=error_rows,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        threshold=threshold,
        output_csv=str(output_path),
        rows=evaluated_rows,
    )
    if progress_callback:
        progress_callback(
            {
                "type": "job_completed",
                "total_rows": result.total_rows,
                "processed_rows": result.total_rows,
                "scored_rows": result.scored_rows,
                "error_rows": result.error_rows,
                "threshold": result.threshold,
            }
        )
    return result


def build_report_payload(result: EvaluationResult, row_limit: int = 250) -> dict[str, Any]:
    interesting_rows = sorted(
        result.rows,
        key=lambda row: (
            0 if row.api_error else 1,
            0 if row.matched_ground_truth is False else 1,
            -(row.risk_score or 0),
            row.index,
        ),
    )[:row_limit]

    score_bins = [
        {
            "label": f"{start}-{start + 9}" if start < 90 else "90-100",
            "range_start": start,
            "range_end": 100 if start == 90 else start + 9,
            "total": 0,
            "phishing": 0,
            "legitimate": 0,
        }
        for start in range(0, 100, 10)
    ]
    unknown_counts: Counter[str] = Counter()
    contributing_counts: Counter[str] = Counter()
    error_counts: Counter[str] = Counter()

    for row in result.rows:
        if row.risk_score is not None:
            bin_index = min(int(row.risk_score // 10), len(score_bins) - 1)
            bucket = score_bins[bin_index]
            bucket["total"] += 1
            if row.actual_is_phishing is True:
                bucket["phishing"] += 1
            elif row.actual_is_phishing is False:
                bucket["legitimate"] += 1

        contributing_counts.update(row.contributing_checks)
        unknown_counts.update(row.unknown_checks)
        if row.api_error:
            error_counts[row.api_error] += 1

    return {
        "summary": {
            "total_rows": result.total_rows,
            "scored_rows": result.scored_rows,
            "error_rows": result.error_rows,
            "threshold": result.threshold,
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
        "score_distribution": score_bins,
        "check_activity": {
            "contributing": [
                {"check": name, "count": count}
                for name, count in contributing_counts.most_common()
            ],
            "unknown": [
                {"check": name, "count": count}
                for name, count in unknown_counts.most_common()
            ],
        },
        "errors": [
            {"message": message, "count": count}
            for message, count in error_counts.most_common(8)
        ],
        "rows": [row.as_dict() for row in interesting_rows],
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate baseline phishing labels against the scanner API."
    )
    parser.add_argument(
        "input_csv",
        help="Path to the baseline CSV containing 'url' and 'is_phishing' columns.",
    )
    parser.add_argument(
        "output_csv",
        help="Path to write the enriched CSV with score and prediction columns.",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"Combined scan endpoint to call. Default: {DEFAULT_ENDPOINT}",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Predict phishing when risk_score >= threshold. Default: {DEFAULT_THRESHOLD}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    return parser


def print_summary(result: EvaluationResult) -> None:
    print("Evaluation complete")
    print(f"total_rows: {result.total_rows}")
    print(f"scored_rows: {result.scored_rows}")
    print(f"error_rows: {result.error_rows}")
    print(f"TP: {result.tp}")
    print(f"TN: {result.tn}")
    print(f"FP: {result.fp}")
    print(f"FN: {result.fn}")
    print(f"accuracy: {result.accuracy:.4f}")
    print(f"precision: {result.precision:.4f}")
    print(f"recall: {result.recall:.4f}")
    print(f"f1: {result.f1:.4f}")


def main() -> int:
    args = build_argument_parser().parse_args()
    result = evaluate_csv(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        endpoint=args.endpoint,
        threshold=args.threshold,
        timeout=args.timeout,
    )
    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
