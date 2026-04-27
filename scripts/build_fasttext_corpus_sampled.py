"""Build a small sampled FastText corpus for quick training.

Usage:
    python scripts/build_fasttext_corpus_sampled.py data/processed/capstone_v2_train.csv --sample-size 500
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

from app.service import AppService


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a sampled FastText corpus.")
    parser.add_argument(
        "input_csv", help="Labeled CSV with url and is_phishing columns."
    )
    parser.add_argument(
        "--sample-size", type=int, default=500, help="Number of rows to sample."
    )
    parser.add_argument("--output", default=None, help="Output corpus path.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    args = parser.parse_args()

    random.seed(args.random_state)

    with open(args.input_csv, "r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    sample = random.sample(rows, min(args.sample_size, len(rows)))

    sample_path = Path(".cache/capstone_v2_train_sample.csv")
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    with sample_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["url", "is_phishing", "host", "source", "split"]
        )
        writer.writeheader()
        writer.writerows(sample)

    service = AppService()
    result = service.export_fasttext_corpus_from_csv(
        sample_path, args.output or service.config.fasttext_corpus_path
    )
    print("FastText corpus generated (sampled)")
    print(f"rows: {result['rows']}")
    print(f"corpus_path: {result['corpus_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
