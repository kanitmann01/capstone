from __future__ import annotations

"""
CLI script: generate an ML-ready phishing feature dataset from labeled URLs.

Orchestrates a ``ScanService`` to fetch and analyse each URL, then delegates
to ``generate_feature_dataset`` to extract structured features and write a
CSV suitable for model training.
"""

import argparse  # Standard library: command-line argument parsing

from scanner.feed_ingest import ThreatFeedCache  # Project-local: threat-intel cache
from scanner.ml_training import generate_feature_dataset  # Project-local: feature extraction pipeline
from scanner.service import ScanService  # Project-local: combined scanner service
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser."""
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
    """Entry point: parse args, generate feature dataset, print summary."""
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
