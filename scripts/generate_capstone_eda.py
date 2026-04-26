from __future__ import annotations

"""
CLI script: generate an Exploratory Data Analysis (EDA) Markdown report.

Reads ``old-data/baseline.csv`` and ``old-data/baseline_scored.csv``,
computes class balance, brand signals, free-host counts, token
frequencies, and evaluation metrics, then writes a formatted Markdown
report to ``old-data/14-brand-login-eda.md``.
"""

import csv  # Standard library: CSV reading
from collections import Counter  # Standard library: frequency counting
from dataclasses import dataclass  # Standard library: immutable data class decorator
from datetime import datetime, timezone  # Standard library: UTC-aware timestamps
import re  # Standard library: regular expressions
from pathlib import Path  # Standard library: filesystem path abstraction
import sys  # Standard library: system path manipulation
from typing import Any  # Standard library: generic type hints
from urllib.parse import urlparse  # Standard library: URL parsing

# Ensure project root is on sys.path so scanner imports resolve when run standalone
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.brand_profiles import guess_host_provider  # Project-local: free-host detection
from scanner.brand_profiles import load_brand_profiles  # Project-local: JSON loader
from scanner.brand_profiles import normalize_brand_token  # Project-local: token normalisation


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OLD_DATA_DIR = PROJECT_ROOT / "old-data"
BASELINE_CSV = OLD_DATA_DIR / "baseline.csv"
SCORED_CSV = OLD_DATA_DIR / "baseline_scored.csv"
OUTPUT_MD = OLD_DATA_DIR / "14-brand-login-eda.md"

SUSPICIOUS_TOKENS = (
    "login",
    "winner",
    "prize",
    "reward",
    "bonus",
    "cash",
    "gift",
    "free",
    "offer",
    "discount",
    "promo",
    "sale",
    "special",
    "limited",
    "exclusive",
    "premium",
    "vip",
    "elite",
    "gold",
    "signin",
    "sign",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "confirm",
    "auth",
    "security",
)


@dataclass(frozen=True)
class EDAStats:
    """Aggregate statistics computed from the baseline CSV."""

    total_rows: int
    phishing_rows: int
    legitimate_rows: int
    hostname_missing: int
    url_missing: int
    token_counts: Counter[str]
    brand_counts: Counter[str]
    free_host_counts: Counter[str]
    host_suffix_counts: Counter[str]


def read_rows(path: Path) -> list[dict[str, str]]:
    """Read a CSV file into a list of string-keyed row dicts."""
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_bool(value: Any) -> bool | None:
    """Parse a flexible truthy/falsy value into a boolean or None."""
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "t", "yes", "y"}:
        return True
    if normalized in {"0", "false", "f", "no", "n"}:
        return False
    return None


def normalize_host(value: str) -> str:
    """Extract and clean a hostname from a raw URL or host string."""
    candidate = str(value or "").strip().lower()
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    host = parsed.netloc.lower() or parsed.path.lower()
    return host.split("@")[-1].split(":")[0]


def extract_path(url: str) -> str:
    """Extract the lower-case path and query from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return f"{parsed.path} {parsed.query}".lower()


def token_counts(rows: list[dict[str, str]]) -> Counter[str]:
    """Count occurrences of suspicious tokens across URL and hostname fields."""
    counts: Counter[str] = Counter()
    for row in rows:
        corpus = f"{row.get('url', '')} {row.get('hostname', '')}".lower()
        for token in SUSPICIOUS_TOKENS:
            if token in corpus:
                counts[token] += 1
    return counts


def brand_counts(rows: list[dict[str, str]]) -> Counter[str]:
    """Count how many rows mention each loaded brand profile."""
    profiles = load_brand_profiles()
    counts: Counter[str] = Counter()
    for row in rows:
        corpus = normalize_brand_token(f"{row.get('url', '')} {row.get('hostname', '')}")
        for profile in profiles:
            tokens = profile.normalized_keywords()
            if any(token and token in corpus for token in tokens):
                counts[profile.name] += 1
    return counts


def free_host_counts(rows: list[dict[str, str]]) -> Counter[str]:
    """Count rows hosted on known free-hosting providers."""
    counts: Counter[str] = Counter()
    for row in rows:
        host = normalize_host(row.get("hostname") or row.get("url") or "")
        provider = guess_host_provider(host)
        if provider:
            counts[provider] += 1
    return counts


def host_suffix_counts(rows: list[dict[str, str]]) -> Counter[str]:
    """Count occurrences of each top-level domain suffix."""
    counts: Counter[str] = Counter()
    for row in rows:
        host = normalize_host(row.get("hostname") or row.get("url") or "")
        if not host:
            continue
        parts = host.split(".")
        suffix = ".".join(parts[-2:]) if len(parts) >= 2 else host
        counts[suffix] += 1
    return counts


def summarize_baseline(rows: list[dict[str, str]]) -> EDAStats:
    """Compute aggregate EDA statistics from baseline rows."""
    total_rows = len(rows)
    phishing_rows = 0
    legitimate_rows = 0
    hostname_missing = 0
    url_missing = 0
    for row in rows:
        label = parse_bool(row.get("is_phishing"))
        if label is True:
            phishing_rows += 1
        elif label is False:
            legitimate_rows += 1
        if not str(row.get("hostname") or "").strip():
            hostname_missing += 1
        if not str(row.get("url") or "").strip():
            url_missing += 1
    return EDAStats(
        total_rows=total_rows,
        phishing_rows=phishing_rows,
        legitimate_rows=legitimate_rows,
        hostname_missing=hostname_missing,
        url_missing=url_missing,
        token_counts=token_counts(rows),
        brand_counts=brand_counts(rows),
        free_host_counts=free_host_counts(rows),
        host_suffix_counts=host_suffix_counts(rows),
    )


def count_missing(rows: list[dict[str, str]], columns: list[str]) -> dict[str, float]:
    """Calculate missing-value ratios for specified columns."""
    if not rows:
        return {column: 0.0 for column in columns}
    result: dict[str, float] = {}
    total = len(rows)
    for column in columns:
        missing = sum(1 for row in rows if not str(row.get(column) or "").strip())
        result[column] = round(missing / total, 4)
    return result


def evaluate_scored(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compute confusion matrix and metrics from scored CSV rows."""
    scored_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    tp = tn = fp = fn = 0
    for row in rows:
        actual = parse_bool(row.get("is_phishing"))
        score = row.get("risk_score")
        predicted = parse_bool(row.get("predicted_is_phishing"))
        error = str(row.get("api_error") or "").strip()
        if error:
            errors.append({"url": row.get("url", ""), "error": error})
            continue
        if actual is None or predicted is None or not str(score or "").strip():
            continue
        scored_rows.append(
            {
                "url": row.get("url", ""),
                "hostname": row.get("hostname", ""),
                "risk_score": float(score),
                "actual": actual,
                "predicted": predicted,
            }
        )
        if actual and predicted:
            tp += 1
        elif not actual and not predicted:
            tn += 1
        elif predicted and not actual:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    false_positives = sorted(
        [row for row in scored_rows if row["predicted"] and not row["actual"]],
        key=lambda item: item["risk_score"],
        reverse=True,
    )[:5]
    false_negatives = sorted(
        [row for row in scored_rows if not row["predicted"] and row["actual"]],
        key=lambda item: item["risk_score"],
        reverse=True,
    )[:5]
    return {
        "total": total,
        "scored_rows": len(scored_rows),
        "errors": errors,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def markdown_table(rows: list[tuple[str, Any]], headers: tuple[str, str] = ("Metric", "Value")) -> str:
    """Format key-value pairs as a Markdown table."""
    lines = [f"| {headers[0]} | {headers[1]} |", "|---|---|"]
    for key, value in rows:
        lines.append(f"| {key} | {value} |")
    return "\n".join(lines)


def ranked_rows(counter: Counter[str], limit: int = 8) -> list[tuple[str, int]]:
    """Return the top-N items from a Counter."""
    return counter.most_common(limit)


def format_list(items: list[str]) -> str:
    """Format a list of strings as a Markdown bullet list."""
    return "\n".join(f"- {item}" for item in items) if items else "- None"


def format_example_rows(rows: list[dict[str, Any]]) -> str:
    """Format scored example rows as Markdown bullets with URL, score, and host."""
    if not rows:
        return "- None"
    lines = []
    for row in rows:
        lines.append(
            f"- `{row.get('url', '')}` | score `{float(row.get('risk_score', 0)):.2f}` | host `{row.get('hostname', '')}`"
        )
    return "\n".join(lines)


def build_report(baseline_stats: EDAStats, scored_stats: dict[str, Any], baseline_rows: list[dict[str, str]], scored_rows: list[dict[str, str]]) -> str:
    """Assemble the complete Markdown EDA report from computed statistics."""
    missing_baseline = count_missing(baseline_rows, ["url", "is_phishing", "hostname"])
    missing_scored = count_missing(scored_rows, ["url", "is_phishing", "hostname", "risk_score", "predicted_is_phishing", "api_error"])
    brand_lines = [f"{brand} ({count})" for brand, count in ranked_rows(baseline_stats.brand_counts, 8)]
    host_lines = [f"{provider} ({count})" for provider, count in ranked_rows(baseline_stats.free_host_counts, 8)]
    token_lines = [f"{token} ({count})" for token, count in ranked_rows(baseline_stats.token_counts, 8)]
    suffix_lines = [f"{suffix} ({count})" for suffix, count in ranked_rows(baseline_stats.host_suffix_counts, 8)]

    report = f"""# Brand Login EDA Summary

Generated on `{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}` from `old-data/baseline.csv` and `old-data/baseline_scored.csv`.

## Dataset Snapshot

{markdown_table([
    ("Total rows", baseline_stats.total_rows),
    ("Phishing rows", baseline_stats.phishing_rows),
    ("Legitimate rows", baseline_stats.legitimate_rows),
    ("Phishing rate", f"{(baseline_stats.phishing_rows / baseline_stats.total_rows * 100):.1f}%" if baseline_stats.total_rows else "n/a"),
    ("Missing URL rate", f"{missing_baseline.get('url', 0.0) * 100:.1f}%"),
    ("Missing hostname rate", f"{missing_baseline.get('hostname', 0.0) * 100:.1f}%"),
])}

## Class Balance

- The dataset is intentionally close to a binary phishing-vs-legitimate setup.
- The positive class is phishing pages that impersonate login flows.
- The negative class is legitimate or non-impersonating pages.

## Brand Signals In URLs

{format_list(brand_lines)}

## Suspicious Path Tokens

{format_list(token_lines)}

## Host Pattern Signals

Free-host provider counts:

{format_list(host_lines)}

Common host suffixes:

{format_list(suffix_lines)}

## Missing Data

Baseline CSV:

{markdown_table([(key, f"{value * 100:.1f}%") for key, value in missing_baseline.items()], headers=("Column", "Missing"))}

Scored CSV:

{markdown_table([(key, f"{value * 100:.1f}%") for key, value in missing_scored.items()], headers=("Column", "Missing"))}

## Evaluation Snapshot

{markdown_table([
    ("Scored rows", scored_stats["scored_rows"]),
    ("Accuracy", f"{scored_stats['accuracy']:.4f}"),
    ("Precision", f"{scored_stats['precision']:.4f}"),
    ("Recall", f"{scored_stats['recall']:.4f}"),
    ("F1", f"{scored_stats['f1']:.4f}"),
    ("TP", scored_stats["confusion_matrix"]["tp"]),
    ("TN", scored_stats["confusion_matrix"]["tn"]),
    ("FP", scored_stats["confusion_matrix"]["fp"]),
    ("FN", scored_stats["confusion_matrix"]["fn"]),
])}

## False Positives

{format_example_rows(scored_stats["false_positives"])}

## False Negatives

{format_example_rows(scored_stats["false_negatives"])}

## Takeaways

- Brand-bearing paths and free-host infrastructure are common phishing indicators in this dataset.
- The evaluation snapshot is useful for threshold tuning and error analysis rather than as a final guarantee.
- The strongest capstone story is the combination of label collection, feature engineering, and hybrid detection.
"""
    return report


def main() -> int:
    """Entry point: read CSVs, compute stats, write Markdown report."""
    baseline_rows = read_rows(BASELINE_CSV)
    scored_rows = read_rows(SCORED_CSV)
    baseline_stats = summarize_baseline(baseline_rows)
    scored_stats = evaluate_scored(scored_rows)
    report = build_report(baseline_stats, scored_stats, baseline_rows, scored_rows)
    OUTPUT_MD.write_text(report, encoding="utf-8")
    print(f"Wrote {OUTPUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
