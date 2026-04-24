from __future__ import annotations

"""
CLI script: run a capstone evaluation experiment on a labeled CSV.

Scores every row using ``AppService.scan_url()`` and writes the
enriched results plus an accuracy/precision/recall/F1 summary.
"""

import argparse  # Standard library: command-line argument parsing
from pathlib import Path  # Standard library: filesystem path abstraction

from app.service import AppService  # Project-local: core application service orchestrator
from pipeline.evaluation.evaluate import build_report_payload  # Project-local: report formatter
from pipeline.evaluation.evaluate import evaluate_csv  # Project-local: CSV evaluation runner


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Run capstone evaluation experiments.")
    parser.add_argument("input_csv", help="Labeled CSV with url and is_phishing columns.")
    parser.add_argument("output_csv", help="Where to write the scored CSV.")
    parser.add_argument("--threshold", type=float, default=50.0, help="Decision threshold for the report.")
    return parser


def main() -> int:
    """Entry point: parse args, run experiment, print report summary."""
    args = build_parser().parse_args()
    service = AppService()

    result = evaluate_csv(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        threshold=args.threshold,
        scorer=lambda url, progress_callback=None: service.scan_url(url),
    )
    report = build_report_payload(result)
    print("Experiment complete")
    print(f"accuracy: {report['summary']['accuracy']}")
    print(f"precision: {report['summary']['precision']}")
    print(f"recall: {report['summary']['recall']}")
    print(f"f1: {report['summary']['f1']}")
    print(f"output_csv: {Path(args.output_csv).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
