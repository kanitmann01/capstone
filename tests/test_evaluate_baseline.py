import csv

import pytest

from evaluate_baseline import build_report_payload
from evaluate_baseline import classify_score
from evaluate_baseline import evaluate_csv
from evaluate_baseline import parse_label


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, endpoint, json, timeout):
        self.calls.append({"endpoint": endpoint, "json": json, "timeout": timeout})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_parse_label_supports_common_boolean_formats():
    assert parse_label("1") is True
    assert parse_label("true") is True
    assert parse_label("Yes") is True
    assert parse_label("0") is False
    assert parse_label("false") is False
    assert parse_label("No") is False


def test_parse_label_rejects_unknown_values():
    with pytest.raises(ValueError):
        parse_label("maybe")


def test_classify_score_uses_inclusive_threshold():
    assert classify_score(50.0, 50.0) is True
    assert classify_score(49.99, 50.0) is False


def test_evaluate_csv_writes_predictions_and_metrics(tmp_path):
    input_csv = tmp_path / "baseline.csv"
    output_csv = tmp_path / "baseline_scored.csv"

    with input_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "is_phishing"])
        writer.writeheader()
        writer.writerow({"url": "https://phish.example/login", "is_phishing": "1"})
        writer.writerow({"url": "https://safe.example", "is_phishing": "0"})
        writer.writerow({"url": "https://unknown.example", "is_phishing": "1"})

    session = FakeSession(
        [
            FakeResponse({"url": "https://phish.example/login", "risk_score": 87.2}),
            FakeResponse({"url": "https://safe.example/", "risk_score": 12.0}),
            RuntimeError("scanner timed out"),
        ]
    )

    result = evaluate_csv(
        input_csv=input_csv,
        output_csv=output_csv,
        endpoint="http://localhost:8000/scan/combined",
        threshold=50.0,
        timeout=5,
        session=session,
    )

    assert result.total_rows == 3
    assert result.scored_rows == 2
    assert result.error_rows == 1
    assert result.tp == 1
    assert result.tn == 1
    assert result.fp == 0
    assert result.fn == 0
    assert result.accuracy == 1.0

    with output_csv.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["risk_score"] == "87.20"
    assert rows[0]["predicted_is_phishing"] == "true"
    assert rows[0]["matched_ground_truth"] == "true"

    assert rows[1]["risk_score"] == "12.00"
    assert rows[1]["predicted_is_phishing"] == "false"
    assert rows[1]["matched_ground_truth"] == "true"

    assert rows[2]["risk_score"] == ""
    assert rows[2]["predicted_is_phishing"] == ""
    assert rows[2]["matched_ground_truth"] == ""
    assert rows[2]["api_error"] == "scanner timed out"

    assert session.calls == [
        {
            "endpoint": "http://localhost:8000/scan/combined",
            "json": {"url": "https://phish.example/login"},
            "timeout": 5,
        },
        {
            "endpoint": "http://localhost:8000/scan/combined",
            "json": {"url": "https://safe.example"},
            "timeout": 5,
        },
        {
            "endpoint": "http://localhost:8000/scan/combined",
            "json": {"url": "https://unknown.example"},
            "timeout": 5,
        },
    ]


def test_evaluate_csv_requires_expected_columns(tmp_path):
    input_csv = tmp_path / "baseline.csv"
    output_csv = tmp_path / "baseline_scored.csv"

    with input_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url"])
        writer.writeheader()
        writer.writerow({"url": "https://example.com"})

    with pytest.raises(ValueError, match="missing required columns"):
        evaluate_csv(input_csv=input_csv, output_csv=output_csv)


def test_evaluate_csv_supports_progress_callback_and_custom_scorer(tmp_path):
    input_csv = tmp_path / "baseline.csv"
    output_csv = tmp_path / "baseline_scored.csv"
    progress_events = []

    with input_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "is_phishing"])
        writer.writeheader()
        writer.writerow({"url": "https://phish.example/login", "is_phishing": "1"})

    def fake_scorer(url, progress_callback=None):
        assert url == "https://phish.example/login"
        if progress_callback:
            progress_callback({"type": "check_started", "check": "heuristics"})
            progress_callback(
                {"type": "check_completed", "check": "heuristics", "status": "ok", "risk_score": 35}
            )
            progress_callback({"type": "check_started", "check": "content"})
            progress_callback(
                {"type": "check_completed", "check": "content", "status": "ok", "risk_score": 50}
            )
            progress_callback({"type": "check_started", "check": "ml"})
            progress_callback(
                {"type": "check_completed", "check": "ml", "status": "ok", "risk_score": 88}
            )
        return {
            "url": url,
            "risk_score": 88.0,
            "contributing_checks": ["heuristics", "content", "ml"],
            "unknown_checks": [],
            "details": {
                "heuristics": {"status": "ok", "risk_score": 35},
                "content": {"status": "ok", "risk_score": 50},
                "ml": {"status": "ok", "risk_score": 88},
            },
        }

    result = evaluate_csv(
        input_csv=input_csv,
        output_csv=output_csv,
        threshold=50.0,
        scorer=fake_scorer,
        progress_callback=progress_events.append,
    )

    assert result.scored_rows == 1
    assert result.rows[0].risk_score == 88.0
    assert result.rows[0].details["content"]["risk_score"] == 50
    assert progress_events[0]["type"] == "job_started"
    assert progress_events[1]["type"] == "row_started"
    assert progress_events[2]["type"] == "check_started"
    assert progress_events[-2]["type"] == "row_completed"
    assert progress_events[-1]["type"] == "job_completed"
    assert progress_events[-2]["row"]["matched_ground_truth"] is True
    assert progress_events[-2]["check_states"]["ml"] == "completed"

    report = build_report_payload(result)
    assert report["confusion_matrix"]["tp"] == 1
    assert report["summary"]["f1"] == 1.0
    assert report["check_activity"]["contributing"][0]["check"] == "heuristics"
