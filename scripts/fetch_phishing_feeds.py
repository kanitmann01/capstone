"""Fetch fresh phishing URLs from multiple threat intelligence feeds.

Collects from:
  - OpenPhish (daily feed, no auth)
  - URLhaus (abuse.ch, CSV format)
  - PhishTank (if API key available)

Outputs a deduplicated CSV of phishing URLs with metadata.

Usage:
    python scripts/fetch_phishing_feeds.py

Output:
    data/processed/phishing_fresh.csv
    columns: url,source,date_added,host
"""

from __future__ import annotations

import csv
import io
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.settings import ScannerSettings  # noqa: E402


OUTPUT_PATH = Path("data/processed/phishing_fresh.csv")
TARGET_COUNT = 800  # Aim for 800 fresh phishing URLs

# Feed sources
OPENPHISH_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

HEAD_TIMEOUT = 5
MAX_WORKERS = 32


def fetch_openphish() -> list[dict[str, Any]]:
    """Fetch OpenPhish daily feed."""
    print("Fetching OpenPhish...")
    try:
        resp = requests.get(OPENPHISH_URL, timeout=30)
        resp.raise_for_status()
        urls = [
            line.strip()
            for line in resp.text.strip().split("\n")
            if line.strip().startswith("http")
        ]
        print(f"  OpenPhish: {len(urls)} URLs")
        rows = []
        for url in urls:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            rows.append(
                {
                    "url": url,
                    "source": "openphish",
                    "date_added": datetime.now(timezone.utc).isoformat(),
                    "host": host.lower(),
                }
            )
        return rows
    except Exception as exc:
        print(f"  OpenPhish error: {exc}")
        return []


def fetch_urlhaus() -> list[dict[str, Any]]:
    """Fetch URLhaus recent CSV and parse phishing/malware URLs."""
    print("Fetching URLhaus...")
    try:
        resp = requests.get(URLHAUS_URL, timeout=60)
        resp.raise_for_status()
        lines = resp.text.strip().split("\n")
        # Skip header comments (lines starting with #)
        # The header comment shows the CSV structure
        data_lines = [line for line in lines if not line.startswith("#")]
        if not data_lines:
            print("  URLhaus: no data lines")
            return []

        # Parse CSV - URLhaus format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        reader = csv.reader(data_lines)
        rows = []
        for row in reader:
            if len(row) < 9:
                continue
            url = row[2].strip()
            threat = row[5].strip().lower()
            url_status = row[3].strip().lower()
            if not url.startswith("http"):
                continue
            # Include online URLs with any threat type (phishing, malware, etc.)
            if url_status != "online":
                continue
            parsed = urlparse(url)
            host = parsed.hostname or ""
            rows.append(
                {
                    "url": url,
                    "source": "urlhaus",
                    "date_added": row[1].strip()
                    if len(row) > 1
                    else datetime.now(timezone.utc).isoformat(),
                    "host": host.lower(),
                }
            )
        print(f"  URLhaus: {len(rows)} URLs (online threats)")
        return rows
    except Exception as exc:
        print(f"  URLhaus error: {exc}")
        return []


def fetch_phishtank() -> list[dict[str, Any]]:
    """Fetch PhishTank verified phishing URLs if API key is available."""
    settings = ScannerSettings.from_env()
    app_key = settings.phishtank_app_key
    if not app_key:
        print("PhishTank: no API key configured, skipping")
        return []

    print("Fetching PhishTank...")
    url = "https://data.phishtank.com/data/online-valid.json"
    try:
        resp = requests.get(url, params={"app_key": app_key}, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        rows = []
        for entry in data:
            url = entry.get("url", "").strip()
            if not url.startswith("http"):
                continue
            parsed = urlparse(url)
            host = parsed.hostname or ""
            rows.append(
                {
                    "url": url,
                    "source": "phishtank",
                    "date_added": entry.get(
                        "submission_time", datetime.now(timezone.utc).isoformat()
                    ),
                    "host": host.lower(),
                }
            )
        print(f"  PhishTank: {len(rows)} URLs")
        return rows
    except Exception as exc:
        print(f"  PhishTank error: {exc}")
        return []


def dedupe_by_host(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep first URL per host, preferring OpenPhish > PhishTank > URLhaus."""
    source_priority = {"openphish": 0, "phishtank": 1, "urlhaus": 2}
    seen: dict[str, dict[str, Any]] = {}

    for row in rows:
        host = row["host"]
        if not host:
            continue
        if host in seen:
            current_priority = source_priority.get(seen[host]["source"], 99)
            new_priority = source_priority.get(row["source"], 99)
            if new_priority < current_priority:
                seen[host] = row
        else:
            seen[host] = row

    return list(seen.values())


def sample_stratified(rows: list[dict[str, Any]], target: int) -> list[dict[str, Any]]:
    """Sample evenly across sources to maintain diversity."""
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_source[row["source"]].append(row)

    sources = list(by_source.keys())
    if not sources:
        return []

    per_source = target // len(sources)
    result: list[dict[str, Any]] = []

    for source in sources:
        available = by_source[source]
        # Take up to per_source, or all if less available
        taken = available[:per_source]
        result.extend(taken)

    # Fill remaining slots from largest source
    remaining = target - len(result)
    if remaining > 0:
        largest = max(by_source.values(), key=len)
        # Get URLs not already taken
        taken_urls = {r["url"] for r in result}
        for row in largest:
            if row["url"] not in taken_urls and remaining > 0:
                result.append(row)
                remaining -= 1

    return result


def main() -> int:
    """Entry point: fetch, dedupe, sample, and write phishing URLs."""
    print("=== Fetching Fresh Phishing Feeds ===")

    all_rows: list[dict[str, Any]] = []
    all_rows.extend(fetch_openphish())
    all_rows.extend(fetch_urlhaus())
    all_rows.extend(fetch_phishtank())

    print(f"\nTotal raw URLs: {len(all_rows)}")

    deduped = dedupe_by_host(all_rows)
    print(f"After host dedup: {len(deduped)}")

    sampled = sample_stratified(deduped, TARGET_COUNT)
    print(f"Sampled to: {len(sampled)}")

    # Add label column
    for row in sampled:
        row["is_phishing"] = 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["url", "is_phishing", "host", "source", "date_added"]
        )
        writer.writeheader()
        writer.writerows(sampled)

    print(f"\nWrote {len(sampled)} phishing URLs to {OUTPUT_PATH}")
    by_source: dict[str, int] = {}
    for row in sampled:
        by_source[row["source"]] = by_source.get(row["source"], 0) + 1
    for source, count in sorted(by_source.items()):
        print(f"  {source}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
