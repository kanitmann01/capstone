from __future__ import annotations

import argparse
import csv
from pathlib import Path

from app.service import AppService
from pipeline.evaluation.evaluate import evaluate_csv
from pipeline.evaluation.evaluate import build_report_payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a held-out set of live URLs.")
    parser.add_argument("input_csv", help="Labeled CSV with url and is_phishing columns.")
    parser.add_argument("output_csv", help="Where to write the scored evaluation CSV.")
    parser.add_argument("--threshold", type=float, default=50.0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    service = AppService()
    result = evaluate_csv(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        threshold=args.threshold,
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
