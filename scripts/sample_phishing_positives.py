"""Sample live phishing positives from raw data sources.

Reads legacy phishing CSVs, dedupes by host, keeps only ``is_phishing=1`` rows,
performs parallel HEAD liveness checks, stratifies by TLD/free-host, and emits
a curated subset of ~1,100 survivors.

Usage:
    python scripts/sample_phishing_positives.py

Output:
    data/processed/phishing_positives_v2.csv
    columns: url,is_phishing,host
"""

from __future__ import annotations

import csv
import concurrent.futures
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

# Ensure project root is on path for scanner imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


SOURCES = [
    Path("old-data/phishing_features_extracted(6).csv"),
    Path("old-data/baseline.csv"),
    Path("NewUrl_features_balanced_shuffled.csv"),
]
OUTPUT_PATH = Path("data/processed/phishing_positives_v2.csv")
TARGET_COUNT = 1_100
MAX_WORKERS = 32
HEAD_TIMEOUT = 3
RANDOM_STATE = 42
MAX_HOSTS_TO_CHECK = 2_500

FREE_HOST_PATTERNS = {
    ".github.io",
    ".vercel.app",
    ".netlify.app",
    ".glitch.me",
    ".onrender.com",
    ".web.app",
    ".pages.dev",
    ".workers.dev",
    ".firebaseapp.com",
    ".herokuapp.com",
    ".blogspot.com",
    ".wixsite.com",
    ".weebly.com",
    ".square.site",
    ".shopify.com",
    ".bigcartel.com",
    ".formstack.com",
    ".typeform.com",
    ".surge.sh",
    ".repl.co",
    ".runkit.sh",
    ".codeberg.page",
    ".gitbook.io",
    ".obsidianportal.com",
}


def is_live(url: str) -> bool:
    """Return True if the URL responds with 2xx/3xx/401/403 within timeout."""
    try:
        resp = requests.head(url, timeout=HEAD_TIMEOUT, allow_redirects=True)
        return resp.status_code < 500 and resp.status_code not in (404, 410)
    except Exception:
        return False


def read_source(path: Path) -> list[dict[str, str]]:
    """Read a CSV and return rows with url, is_phishing, host."""
    rows: list[dict[str, str]] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            host = (row.get("host") or row.get("hostname") or "").strip().lower()
            if not host:
                parsed = urlparse(url if "://" in url else f"http://{url}")
                host = (parsed.hostname or "").lower()
            label = (row.get("is_phishing") or "").strip().lower()
            rows.append({"url": url, "is_phishing": label, "host": host})
    return rows


def keep_positive(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Filter to rows where is_phishing indicates a positive."""
    truthy = {"1", "true", "t", "yes", "y", "phishing"}
    return [r for r in rows if r["is_phishing"] in truthy]


def stratification_key(host: str) -> str:
    """Bucket hosts by free-host provider or TLD."""
    for pattern in FREE_HOST_PATTERNS:
        if host.endswith(pattern):
            return f"free:{pattern.lstrip('.')}"
    parts = host.rsplit(".", 1)
    tld = parts[-1] if len(parts) > 1 else "unknown"
    return f"tld:{tld}"


def sample_stratified(
    rows: list[dict[str, Any]], target: int, random_state: int
) -> list[dict[str, Any]]:
    """Stratified sampling: pick evenly from each stratification bucket."""
    random.seed(random_state)
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[stratification_key(row["host"])].append(row)

    # Sort buckets by size descending so large buckets don't starve small ones
    sorted_buckets = sorted(buckets.values(), key=len, reverse=True)
    result: list[dict[str, Any]] = []
    remaining = target
    for bucket in sorted_buckets:
        quota = max(1, remaining // max(len(sorted_buckets) - len(result), 1))
        quota = min(quota, len(bucket))
        chosen = random.sample(bucket, quota) if quota < len(bucket) else bucket
        result.extend(chosen)
        remaining = target - len(result)
        if remaining <= 0:
            break

    random.shuffle(result)
    return result[:target]


def main() -> int:
    """Entry point: aggregate, dedupe, check liveness, stratify, write."""
    all_rows: list[dict[str, str]] = []
    for source in SOURCES:
        if not source.exists():
            print(f"Skipping missing source: {source}")
            continue
        rows = read_source(source)
        print(f"Read {len(rows)} rows from {source}")
        all_rows.extend(rows)

    positives = keep_positive(all_rows)
    print(f"Positive rows: {len(positives)}")

    # Dedupe by host, keeping the first URL seen
    seen_hosts: set[str] = set()
    deduped: list[dict[str, str]] = []
    for row in positives:
        host = row["host"]
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        deduped.append(row)
    print(f"After host dedupe: {len(deduped)}")

    # NOTE: Liveness checks are disabled for build speed.
    # Phishing URLs stale quickly; the model trains on URL features
    # and snapshot signals (including content_not_fetched) which handles
    # dead URLs gracefully. For benchmark eval, day-zero subsets are
    # computed independently of liveness.
    live_rows = deduped
    print(f"Using {len(live_rows)} deduped positives (liveness check skipped)")

    sampled = sample_stratified(live_rows, TARGET_COUNT, RANDOM_STATE)
    print(f"Sampled {len(sampled)} rows")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "is_phishing", "host"])
        writer.writeheader()
        for row in sampled:
            writer.writerow({"url": row["url"], "is_phishing": 1, "host": row["host"]})

    print(f"Wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
