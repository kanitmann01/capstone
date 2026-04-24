from __future__ import annotations

"""
SQLite persistence layer for scan snapshots and dataset records.

Provides ``SnapshotRecord``—an immutable dataclass for snapshot
metadata—and ``BrandLoginDatasetStore`` which manages the SQLite
schema, deduplication, and CRUD operations.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
from datetime import datetime, timezone  # Standard library: UTC-aware timestamps
import hashlib  # Standard library: SHA-256 hashing for deduplication
import json  # Standard library: JSON serialization
import sqlite3  # Standard library: SQLite database engine
from pathlib import Path  # Standard library: filesystem path abstraction
from typing import Any  # Standard library: generic type hints


DATASET_SCHEMA_VERSION = "brand_login_dataset_v2"


@dataclass(frozen=True)
class SnapshotRecord:
    """Immutable representation of a captured page snapshot."""

    url: str
    normalized_url: str
    host: str
    captured_at_utc: str
    source_feed: str = ""
    source_label: str = ""
    source_pipeline: str = ""
    pipeline_version: str = ""
    raw_html: str = ""
    visible_text: str = ""
    page_title: str = ""
    detected_brand: str = ""
    host_provider: str = ""
    risk_score: float | None = None
    prediction: str = ""
    content_hash: str = ""
    extraction_json: str = "{}"
    label: int | None = None
    notes: str = ""

    @staticmethod
    def create(
        *,
        url: str,
        normalized_url: str,
        host: str,
        source_feed: str = "",
        source_label: str = "",
        source_pipeline: str = "",
        pipeline_version: str = "",
        raw_html: str = "",
        visible_text: str = "",
        page_title: str = "",
        detected_brand: str = "",
        host_provider: str = "",
        risk_score: float | None = None,
        prediction: str = "",
        content_hash: str = "",
        extraction: dict[str, Any] | None = None,
        label: int | None = None,
        notes: str = "",
    ) -> "SnapshotRecord":
        """Factory that computes a content hash and captures the current UTC timestamp."""
        normalized_extraction = json.dumps(extraction or {}, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        derived_content_hash = content_hash or hashlib.sha256(
            "|".join(
                [
                    normalized_url,
                    raw_html,
                    visible_text,
                    page_title,
                    detected_brand,
                    host_provider,
                    normalized_extraction,
                ]
            ).encode("utf-8")
        ).hexdigest()
        return SnapshotRecord(
            url=url,
            normalized_url=normalized_url,
            host=host,
            captured_at_utc=datetime.now(timezone.utc).isoformat(),
            source_feed=source_feed,
            source_label=source_label,
            source_pipeline=source_pipeline,
            pipeline_version=pipeline_version,
            raw_html=raw_html,
            visible_text=visible_text,
            page_title=page_title,
            detected_brand=detected_brand,
            host_provider=host_provider,
            risk_score=risk_score,
            prediction=prediction,
            content_hash=derived_content_hash,
            extraction_json=normalized_extraction,
            label=label,
            notes=notes,
        )


class BrandLoginDatasetStore:
    """SQLite-backed store for phishing scan snapshots."""

    def __init__(self, db_path: str | Path):
        """Open (or create) the SQLite database and ensure schema."""
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        """Return a connection with Row factory enabled."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        """Create tables, indexes, and migrate missing columns."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshot_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    captured_at_utc TEXT NOT NULL,
                    source_feed TEXT NOT NULL DEFAULT '',
                    source_label TEXT NOT NULL DEFAULT '',
                    source_pipeline TEXT NOT NULL DEFAULT '',
                    pipeline_version TEXT NOT NULL DEFAULT '',
                    raw_html TEXT NOT NULL DEFAULT '',
                    visible_text TEXT NOT NULL DEFAULT '',
                    page_title TEXT NOT NULL DEFAULT '',
                    detected_brand TEXT NOT NULL DEFAULT '',
                    host_provider TEXT NOT NULL DEFAULT '',
                    risk_score REAL,
                    prediction TEXT NOT NULL DEFAULT '',
                    content_hash TEXT NOT NULL DEFAULT '',
                    extraction_json TEXT NOT NULL DEFAULT '{}',
                    label INTEGER,
                    notes TEXT NOT NULL DEFAULT '',
                    schema_version TEXT NOT NULL DEFAULT 'brand_login_dataset_v2'
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_snapshot_records_normalized_url
                ON snapshot_records(normalized_url)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_snapshot_records_captured_at
                ON snapshot_records(captured_at_utc)
                """
            )
            self._ensure_columns(conn)
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_snapshot_records_content_hash
                ON snapshot_records(normalized_url, content_hash)
                """
            )
            conn.commit()

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        """Add any columns that are missing from an older schema."""
        existing = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(snapshot_records)").fetchall()
        }
        additions = {
            "source_pipeline": "TEXT NOT NULL DEFAULT ''",
            "pipeline_version": "TEXT NOT NULL DEFAULT ''",
            "risk_score": "REAL",
            "prediction": "TEXT NOT NULL DEFAULT ''",
            "content_hash": "TEXT NOT NULL DEFAULT ''",
        }
        for column_name, column_sql in additions.items():
            if column_name in existing:
                continue
            conn.execute(f"ALTER TABLE snapshot_records ADD COLUMN {column_name} {column_sql}")

    def add_snapshot(self, record: SnapshotRecord) -> int:
        """Insert a snapshot, deduplicating by (normalized_url, content_hash)."""
        with self._connect() as conn:
            existing = conn.execute(
                """
                SELECT id
                FROM snapshot_records
                WHERE normalized_url = ? AND content_hash = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (record.normalized_url, record.content_hash),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cursor = conn.execute(
                """
                INSERT INTO snapshot_records (
                    url, normalized_url, host, captured_at_utc, source_feed, source_label,
                    source_pipeline, pipeline_version, raw_html, visible_text, page_title,
                    detected_brand, host_provider, risk_score, prediction, content_hash,
                    extraction_json, label, notes, schema_version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.url,
                    record.normalized_url,
                    record.host,
                    record.captured_at_utc,
                    record.source_feed,
                    record.source_label,
                    record.source_pipeline,
                    record.pipeline_version,
                    record.raw_html,
                    record.visible_text,
                    record.page_title,
                    record.detected_brand,
                    record.host_provider,
                    record.risk_score,
                    record.prediction,
                    record.content_hash,
                    record.extraction_json,
                    record.label,
                    record.notes,
                    DATASET_SCHEMA_VERSION,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def update_label(self, snapshot_id: int, label: int, notes: str = "") -> None:
        """Update the ground-truth label for a snapshot."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE snapshot_records
                SET label = ?, notes = ?
                WHERE id = ?
                """,
                (label, notes, snapshot_id),
            )
            conn.commit()

    def iter_recent(self, limit: int = 25) -> list[dict[str, Any]]:
        """Return the most recent snapshots as a list of dicts."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM snapshot_records
                ORDER BY captured_at_utc DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        """Return aggregate statistics about the dataset."""
        with self._connect() as conn:
            counts = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_rows,
                    SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) AS phishing_rows,
                    SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END) AS legitimate_rows,
                    COUNT(DISTINCT detected_brand) AS brand_count,
                    COUNT(DISTINCT host_provider) AS host_provider_count,
                    COUNT(DISTINCT source_pipeline) AS source_pipeline_count,
                    COUNT(DISTINCT pipeline_version) AS pipeline_version_count
                FROM snapshot_records
                """
            ).fetchone()
            by_brand = conn.execute(
                """
                SELECT detected_brand, COUNT(*) AS row_count
                FROM snapshot_records
                WHERE detected_brand != ''
                GROUP BY detected_brand
                ORDER BY row_count DESC, detected_brand ASC
                LIMIT 10
                """
            ).fetchall()
            by_host_provider = conn.execute(
                """
                SELECT host_provider, COUNT(*) AS row_count
                FROM snapshot_records
                WHERE host_provider != ''
                GROUP BY host_provider
                ORDER BY row_count DESC, host_provider ASC
                LIMIT 10
                """
            ).fetchall()
            by_source_pipeline = conn.execute(
                """
                SELECT source_pipeline, COUNT(*) AS row_count
                FROM snapshot_records
                WHERE source_pipeline != ''
                GROUP BY source_pipeline
                ORDER BY row_count DESC, source_pipeline ASC
                LIMIT 10
                """
            ).fetchall()
            by_pipeline_version = conn.execute(
                """
                SELECT pipeline_version, COUNT(*) AS row_count
                FROM snapshot_records
                WHERE pipeline_version != ''
                GROUP BY pipeline_version
                ORDER BY row_count DESC, pipeline_version ASC
                LIMIT 10
                """
            ).fetchall()

        return {
            "schema_version": DATASET_SCHEMA_VERSION,
            "db_path": str(self.path),
            "total_rows": int(counts["total_rows"] or 0),
            "phishing_rows": int(counts["phishing_rows"] or 0),
            "legitimate_rows": int(counts["legitimate_rows"] or 0),
            "brand_count": int(counts["brand_count"] or 0),
            "host_provider_count": int(counts["host_provider_count"] or 0),
            "source_pipeline_count": int(counts["source_pipeline_count"] or 0),
            "pipeline_version_count": int(counts["pipeline_version_count"] or 0),
            "top_brands": [dict(row) for row in by_brand],
            "top_host_providers": [dict(row) for row in by_host_provider],
            "top_source_pipelines": [dict(row) for row in by_source_pipeline],
            "top_pipeline_versions": [dict(row) for row in by_pipeline_version],
        }
