"""Assemble the capstone_v2 dataset from legitimate and phishing sources.

Concatenates Tranco legitimate URLs with sampled phishing positives,
performs a stratified 70/15/15 train/val/test split by label and source mix,
ensures no host leakage across splits, and emits CSVs plus a manifest.

Usage:
    python scripts/build_capstone_v2_dataset.py

Output:
    data/processed/capstone_v2.csv
    data/processed/capstone_v2_train.csv
    data/processed/capstone_v2_val.csv
    data/processed/capstone_v2_test.csv
    data/processed/capstone_v2_manifest.json
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from sklearn.model_selection import train_test_split


LEGIT_PATH = Path("data/processed/tranco_legit.csv")
PHISHING_PATH = Path("data/processed/phishing_positives_v2.csv")
OUTPUT_DIR = Path("data/processed")
RANDOM_STATE = 42


def load_rows(path: Path) -> list[dict[str, Any]]:
    """Read a CSV and return rows as dicts with consistent typing."""
    rows: list[dict[str, Any]] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            label = int(row.get("is_phishing") or 0)
            host = (row.get("host") or "").strip().lower()
            source = (row.get("source") or "unknown").strip().lower()
            rows.append(
                {"url": url, "is_phishing": label, "host": host, "source": source}
            )
    return rows


def host_conflict(
    train_rows: list[dict[str, Any]],
    val_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
) -> bool:
    """Return True if any host appears in more than one split."""
    train_hosts = {r["host"] for r in train_rows}
    val_hosts = {r["host"] for r in val_rows}
    test_hosts = {r["host"] for r in test_rows}
    return bool(
        train_hosts & val_hosts or train_hosts & test_hosts or val_hosts & test_hosts
    )


def resolve_host_conflicts(
    all_rows: list[dict[str, Any]],
    train_idx: list[int],
    val_idx: list[int],
    test_idx: list[int],
) -> tuple[list[int], list[int], list[int]]:
    """Move rows with conflicting hosts to the split where the host first appears."""
    by_index = {i: r for i, r in enumerate(all_rows)}
    host_to_split: dict[str, str] = {}
    split_map = {"train": set(train_idx), "val": set(val_idx), "test": set(test_idx)}

    for split_name, indices in split_map.items():
        for i in list(indices):
            host = by_index[i]["host"]
            if host in host_to_split:
                # Move to the existing split
                split_map[split_name].discard(i)
                split_map[host_to_split[host]].add(i)
            else:
                host_to_split[host] = split_name

    return (
        sorted(split_map["train"]),
        sorted(split_map["val"]),
        sorted(split_map["test"]),
    )


def build_manifest(
    train_rows: list[dict[str, Any]],
    val_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    all_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a manifest with counts, sources, and hashes."""

    def hash_rows(rows: list[dict[str, Any]]) -> str:
        content = "\n".join(f"{r['url']}|{r['is_phishing']}|{r['host']}" for r in rows)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "count": len(rows),
            "phishing": sum(1 for r in rows if r["is_phishing"] == 1),
            "legitimate": sum(1 for r in rows if r["is_phishing"] == 0),
            "sources": dict(Counter(r["source"] for r in rows)),
            "unique_hosts": len({r["host"] for r in rows}),
        }

    return {
        "schema_version": "capstone_v2_manifest_v1",
        "total_rows": len(all_rows),
        "train": summarize(train_rows),
        "val": summarize(val_rows),
        "test": summarize(test_rows),
        "hash_train": hash_rows(train_rows),
        "hash_val": hash_rows(val_rows),
        "hash_test": hash_rows(test_rows),
        "hash_all": hash_rows(all_rows),
        "random_state": RANDOM_STATE,
    }


def main() -> int:
    """Entry point: load, merge, split, dedupe by host across splits, write."""
    random.seed(RANDOM_STATE)

    legit_rows = load_rows(LEGIT_PATH)
    phishing_rows = load_rows(PHISHING_PATH)

    # Mark source for phishing rows if missing
    for row in phishing_rows:
        if row["source"] == "unknown":
            row["source"] = "phishing"

    # Balance classes by downsampling majority class
    random.seed(RANDOM_STATE)
    if len(legit_rows) > len(phishing_rows):
        legit_rows = random.sample(legit_rows, len(phishing_rows))
    elif len(phishing_rows) > len(legit_rows):
        phishing_rows = random.sample(phishing_rows, len(legit_rows))

    all_rows = legit_rows + phishing_rows
    print(
        f"Total rows before split: {len(all_rows)} (legit={len(legit_rows)}, phishing={len(phishing_rows)})"
    )

    if len(all_rows) < 2_200:
        print(f"WARNING: Expected >= 2,200 rows, got {len(all_rows)}")

    # Build stratification key from label + source
    stratify = [f"{r['is_phishing']}_{r['source']}" for r in all_rows]
    indices = list(range(len(all_rows)))

    # First split: train (70%) vs temp (30%)
    train_idx, temp_idx = train_test_split(
        indices,
        test_size=0.30,
        random_state=RANDOM_STATE,
        stratify=[stratify[i] for i in indices],
    )

    # Second split: val (15%) vs test (15%) from temp
    val_idx, test_idx = train_test_split(
        temp_idx,
        test_size=0.50,
        random_state=RANDOM_STATE,
        stratify=[stratify[i] for i in temp_idx],
    )

    # Resolve host conflicts across splits
    train_idx, val_idx, test_idx = resolve_host_conflicts(
        all_rows, train_idx, val_idx, test_idx
    )

    train_rows = [all_rows[i] for i in train_idx]
    val_rows = [all_rows[i] for i in val_idx]
    test_rows = [all_rows[i] for i in test_idx]

    # Verify acceptance gate
    total = len(train_rows) + len(val_rows) + len(test_rows)
    phishing_total = sum(1 for r in all_rows if r["is_phishing"] == 1)
    legit_total = sum(1 for r in all_rows if r["is_phishing"] == 0)
    balance = phishing_total / total if total else 0

    print(f"Train: {len(train_rows)}, Val: {len(val_rows)}, Test: {len(test_rows)}")
    print(f"Label balance (phishing/total): {balance:.2%}")

    assert total >= 2_200, f"Total rows {total} < 2,200"
    assert 0.45 <= balance <= 0.55, f"Label balance {balance:.2%} outside 45-55%"
    assert not host_conflict(train_rows, val_rows, test_rows), (
        "Host leakage detected across splits"
    )

    # Add split column
    for row in train_rows:
        row["split"] = "train"
    for row in val_rows:
        row["split"] = "val"
    for row in test_rows:
        row["split"] = "test"

    all_with_split = train_rows + val_rows + test_rows

    # Write CSVs
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = ["url", "is_phishing", "host", "source", "split"]

    def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    write_csv(OUTPUT_DIR / "capstone_v2.csv", all_with_split)
    write_csv(OUTPUT_DIR / "capstone_v2_train.csv", train_rows)
    write_csv(OUTPUT_DIR / "capstone_v2_val.csv", val_rows)
    write_csv(OUTPUT_DIR / "capstone_v2_test.csv", test_rows)

    # Write manifest
    manifest = build_manifest(train_rows, val_rows, test_rows, all_rows)
    with (OUTPUT_DIR / "capstone_v2_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("Dataset build complete.")
    print(f"  capstone_v2.csv: {len(all_with_split)} rows")
    print(f"  capstone_v2_train.csv: {len(train_rows)} rows")
    print(f"  capstone_v2_val.csv: {len(val_rows)} rows")
    print(f"  capstone_v2_test.csv: {len(test_rows)} rows")
    print(f"  capstone_v2_manifest.json: written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
