from __future__ import annotations

"""
CLI script: evaluate a held-out set of live URLs against the detector.

Reads a labeled CSV, runs each URL through ``AppService.scan_url()``,
and writes scored results plus an accuracy/precision/recall summary.
"""

import argparse  # Standard library: command-line argument parsing
import csv  # Standard library: CSV reading
from pathlib import Path  # Standard library: filesystem path abstraction

from app.service import AppService  # Project-local: core application service orchestrator
from pipeline.evaluation.evaluate import evaluate_csv  # Project-local: CSV evaluation runner
from pipeline.evaluation.evaluate import build_report_payload  # Project-local: report formatter


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Evaluate a held-out set of live URLs.")
    parser.add_argument("input_csv", help="Labeled CSV with url and is_phishing columns.")
    parser.add_argument("output_csv", help="Where to write the scored evaluation CSV.")
    parser.add_argument("--threshold", type=float, default=None)
    return parser


def main() -> int:
    """Entry point: parse args, evaluate URLs, print report summary."""
    args = build_parser().parse_args()
    service = AppService()
    threshold = service.config.final_score_threshold if args.threshold is None else args.threshold
    result = evaluate_csv(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        threshold=threshold,
        scorer=lambda url, progress_callback=None: service.scan_url(url),
    )
    report = build_report_payload(result)
    print("Live evaluation complete")
    print(f"rows: {report['summary']['total_rows']}")
    print(f"scored_rows: {report['summary']['scored_rows']}")
    print(f"precision: {report['summary']['precision']}")
    print(f"recall: {report['summary']['recall']}")
    print(f"f1: {report['summary']['f1']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
