"""Batch-run the HF BERT classifier on the eval set and cache results.

This separates the slow BERT inference from the benchmark runner so the
latter never has to load the model live.

Usage:
    python scripts/cache_hf_bert_eval.py

Output:
    .cache/evaluations/hf_bert_eval_cache.json
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.comparators.hf_url_classifier import score_url as hf_score


EVAL_CSV = Path("data/processed/capstone_v2_test.csv")
CACHE_PATH = Path(".cache/evaluations/hf_bert_eval_cache.json")


def main() -> int:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    with EVAL_CSV.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))

    print(f"Running HF BERT on {len(rows)} URLs (one-time, ~5-10 min on CPU) ...")
    cache: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(rows, start=1):
        url = row["url"]
        try:
            result = hf_score(url)
        except Exception as exc:
            result = {
                "lens": "hf_url_classifier",
                "risk_score": 0.0,
                "predicted_is_phishing": False,
                "error": str(exc),
            }
        cache[url] = result
        if idx % 10 == 0:
            print(f"  {idx}/{len(rows)} done")

    with CACHE_PATH.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    print(f"Cached {len(cache)} results to {CACHE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
