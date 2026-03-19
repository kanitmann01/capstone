from __future__ import annotations

import argparse

from scanner.feed_ingest import ThreatFeedCache
from scanner.ml_training import generate_feature_dataset
from scanner.service import ScanService
from scanner.settings import ScannerSettings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate an ML-ready phishing feature dataset from labeled URLs.",
    )
    parser.add_argument("input_csv", help="Input CSV with url and is_phishing columns.")
    parser.add_argument("output_csv", help="Output CSV path for extracted features.")
    parser.add_argument(
        "--label-source",
        default="manual",
        help="Short label-source description stored with each output row.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = ScannerSettings.from_env()
    feed_cache = ThreatFeedCache(settings)
    scan_service = ScanService(settings, feed_cache)
    summary = generate_feature_dataset(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        scan_service=scan_service,
        label_source=args.label_source,
    )
    print("Feature dataset generated")
    print(f"input_rows: {summary.input_rows}")
    print(f"usable_rows: {summary.usable_rows}")
    print(f"skipped_rows: {summary.skipped_rows}")
    print(f"positive_rows: {summary.positive_rows}")
    print(f"negative_rows: {summary.negative_rows}")
    print(f"output_csv: {summary.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
