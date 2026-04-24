from __future__ import annotations

"""
CLI script: capture page snapshots from a CSV into the SQLite dataset store.

Reads a CSV with a ``url`` column (and optionally ``label`` / ``is_phishing``),
fetches each page, extracts content/brand signals, and persists the snapshot
via ``BrandLoginDatasetStore``.
"""

import argparse  # Standard library: command-line argument parsing
import csv  # Standard library: CSV reading
from pathlib import Path  # Standard library: filesystem path abstraction

from scanner.content import ContentScanner  # Project-local: HTML fetch and content analysis
from scanner.dataset_store import BrandLoginDatasetStore  # Project-local: SQLite persistence
from scanner.dataset_store import SnapshotRecord  # Project-local: immutable snapshot dataclass
from scanner.normalization import normalize_input_url  # Project-local: URL canonicalisation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Capture page snapshots into the brand-login SQLite dataset store.",
    )
    parser.add_argument("input_csv", help="CSV with at least a url column.")
    parser.add_argument(
        "--db-path",
        default=None,
        help="SQLite database path. Defaults to CAPSTONE_DATASET_DB from settings.",
    )
    parser.add_argument(
        "--source-feed",
        default="manual",
        help="Short source label stored with each snapshot row.",
    )
    return parser


def main() -> int:
    """Entry point: parse args, capture snapshots, print summary."""
    args = build_parser().parse_args()
    settings = ScannerSettings.from_env()
    store_path = Path(args.db_path or settings.brand_dataset_db_path)
    store = BrandLoginDatasetStore(store_path)

    total_rows = 0
    stored_rows = 0
    skipped_rows = 0

    with Path(args.input_csv).open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a url column.")
        for row in reader:
            total_rows += 1
            url = (row.get("url") or "").strip()
            if not url:
                skipped_rows += 1
                continue
            label_raw = (row.get("label") or row.get("is_phishing") or "").strip().lower()
            label = 1 if label_raw in {"1", "true", "yes", "y"} else 0 if label_raw in {"0", "false", "no", "n"} else None
            try:
                target = normalize_input_url(url)
                scanner = ContentScanner(target, settings)
                result = scanner.run_checks()
                record = SnapshotRecord.create(
                    url=url,
                    normalized_url=target.normalized_url,
                    host=target.host,
                    source_feed=args.source_feed,
                    source_label=str(row.get("source_label") or ""),
                    raw_html=scanner.html_content,
                    visible_text=result.get("visible_text", ""),
                    page_title=result.get("page_title", ""),
                    detected_brand=str(result.get("detected_brand") or ""),
                    host_provider=str(result.get("host_provider") or ""),
                    extraction=result,
                    label=label,
                    notes=str(result.get("error") or ""),
                )
                store.add_snapshot(record)
                stored_rows += 1
            except Exception as exc:
                skipped_rows += 1
                print(f"Skipping {url}: {exc}")

    print("Snapshot capture complete")
    print(f"total_rows: {total_rows}")
    print(f"stored_rows: {stored_rows}")
    print(f"skipped_rows: {skipped_rows}")
    print(f"db_path: {store.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
