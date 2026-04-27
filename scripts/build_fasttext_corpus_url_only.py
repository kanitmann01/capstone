"""Build a URL-only FastText corpus without network fetching.

This is a fast fallback for capstone benchmarking when full snapshot
extraction is too slow. It generates FastText lines purely from URL
structure, brand recognition, and heuristics.

Usage:
    python scripts/build_fasttext_corpus_url_only.py data/processed/capstone_v2_train.csv --output data/processed/fasttext_corpus_v2.txt
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.brand_recognition import BrandRecognitionDetector
from scanner.heuristics import URLHeuristics
from scanner.normalization import normalize_input_url


def clean_text(text: str) -> str:
    """Normalise text for FastText tokenisation."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def serialize_url_only(url: str, label: str, detector: BrandRecognitionDetector) -> str:
    """Generate a FastText training line from URL features only."""
    target = normalize_input_url(url)
    tokens: list[str] = []

    # Host tokens
    host = clean_text(target.host)
    if host:
        tokens.append(f"__domain__{host}")

    # Path tokens
    path = clean_text(target.path)
    if path and path != "/":
        tokens.append(f"__path__{path}")

    # Query tokens
    query = clean_text(target.query)
    if query:
        tokens.append(f"__query__{query}")

    # Heuristics
    heuristics = URLHeuristics(target).run_checks()
    if heuristics.get("is_ip_address"):
        tokens.append("__signal__ip_address")
    if heuristics.get("excessive_length"):
        tokens.append("__signal__excessive_length")
    if heuristics.get("suspicious_chars"):
        tokens.append("__signal__suspicious_chars")
    if heuristics.get("keyword_masking"):
        tokens.append("__signal__keyword_masking")

    # Brand recognition
    brand_result = detector.analyze_url(url)
    if brand_result.get("status") == "scam":
        matched = brand_result.get("matched_brand", "")
        if matched:
            tokens.append(f"__brand__{clean_text(matched)}")
        threat = brand_result.get("threat_type", "")
        if threat:
            tokens.append(f"__signal__{threat}")
    elif brand_result.get("matched_brand"):
        matched = brand_result.get("matched_brand", "")
        if matched:
            tokens.append(f"__brand__{clean_text(matched)}")

    # URL length buckets
    url_len = len(url)
    if url_len > 100:
        tokens.append("__feature__very_long_url")
    elif url_len > 60:
        tokens.append("__feature__long_url")

    # Subdomain depth
    subdomain_count = target.host.count(".")
    if subdomain_count > 2:
        tokens.append("__feature__deep_subdomain")

    # HTTPS
    if target.scheme == "https":
        tokens.append("__feature__https")
    else:
        tokens.append("__feature__http")

    if not tokens:
        tokens.append("__feature__url_only")

    label_text = (
        "phishing"
        if str(label).strip().lower() in {"1", "true", "phishing"}
        else "clean"
    )
    return f"__label__{label_text} {' '.join(tokens)}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a URL-only FastText corpus.")
    parser.add_argument(
        "input_csv", help="Labeled CSV with url and is_phishing columns."
    )
    parser.add_argument(
        "--output",
        default="data/processed/fasttext_corpus_v2.txt",
        help="Output corpus path.",
    )
    args = parser.parse_args()

    detector = BrandRecognitionDetector()
    lines: list[str] = []

    with open(args.input_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = (row.get("url") or "").strip()
            label = row.get("is_phishing") or "0"
            if not url:
                continue
            lines.append(serialize_url_only(url, label, detector))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    print(f"URL-only FastText corpus generated: {len(lines)} lines")
    print(f"corpus_path: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
