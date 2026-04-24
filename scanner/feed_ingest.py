from __future__ import annotations

"""
Threat intelligence feed ingestion and caching.

Downloads OpenPhish, PhishTank, and VT-style snapshot feeds,
builds an in-memory index with background refresh, and persists
the index to disk for fast lookups.
"""

from dataclasses import dataclass, field  # Standard library: lightweight data structures
from datetime import datetime, timedelta, timezone  # Standard library: date/time utilities
import gzip  # Standard library: gzip decompression
import json  # Standard library: JSON serialization
from pathlib import Path  # Standard library: filesystem path abstraction
import threading  # Standard library: concurrency primitives
from typing import Any  # Standard library: generic type hints

import requests  # Third-party: HTTP client

from scanner.normalization import NormalizedTarget, normalize_feed_value  # Project-local: URL normalisation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


@dataclass
class FeedIndex:
    """In-memory index mapping URLs, hosts, and IPs to threat-intel entries."""

    urls: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    hosts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    ips: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    last_refresh_utc: str | None = None
    refresh_error: str | None = None

    def add_entry(self, kind: str, key: str, entry: dict[str, Any]) -> None:
        """Add a feed entry to the appropriate index bucket."""
        if kind == "url":
            self.urls.setdefault(key, []).append(entry)
        elif kind == "host":
            self.hosts.setdefault(key, []).append(entry)
        elif kind == "ip":
            self.ips.setdefault(key, []).append(entry)


class ThreatFeedCache:
    """Manages threat-feed refresh, indexing, and lookup with thread-safe caching."""

    def __init__(self, settings: ScannerSettings):
        """Initialise cache directory, locks, and on-disk index."""
        self.settings = settings
        self._lock = threading.Lock()
        self._index = FeedIndex()
        self._last_refresh_time: datetime | None = None
        self._refresh_in_progress = False
        self._last_refresh_attempt_utc: str | None = None
        self.cache_dir = Path(settings.feed_cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.cache_dir / "index.json"
        self._load_disk_index()

    def metadata(self) -> dict[str, Any]:
        """Return cache metadata including freshness and errors."""
        now = datetime.now(timezone.utc)
        max_age = timedelta(minutes=max(self.settings.feed_refresh_minutes, 1))
        with self._lock:
            stale = (
                self._last_refresh_time is None
                or now - self._last_refresh_time >= max_age
            )
        return {
            "last_refresh_utc": self._index.last_refresh_utc,
            "last_refresh_attempt_utc": self._last_refresh_attempt_utc,
            "refresh_error": self._index.refresh_error,
            "refresh_in_progress": self._refresh_in_progress,
            "stale_cache": stale,
            "cache_dir": str(self.cache_dir),
            "vt_pos_file": self.settings.vt_pos_file or None,
            "vt_neg_file": self.settings.vt_neg_file or None,
        }

    def refresh_if_stale(self) -> None:
        """Trigger a background refresh only if the cache is stale."""
        if self._is_stale():
            self._trigger_background_refresh()

    def refresh_now(self) -> None:
        """Synchronously rebuild the index from all configured feeds."""
        with self._lock:
            self._last_refresh_attempt_utc = datetime.now(timezone.utc).isoformat()
        self._apply_refresh(self._build_index())

    def _build_index(self) -> tuple[FeedIndex, datetime]:
        """Download and parse all feeds into a new FeedIndex."""
        new_index = FeedIndex()
        errors: list[str] = []

        if self.settings.openphish_enabled:
            try:
                self._ingest_openphish(new_index)
            except Exception as exc:
                errors.append(f"openphish: {exc}")

        if self.settings.phishtank_enabled:
            try:
                self._ingest_phishtank(new_index)
            except Exception as exc:
                errors.append(f"phishtank: {exc}")

        if self.settings.vt_enabled:
            try:
                self._ingest_vt_snapshot(
                    new_index,
                    filename=self.settings.vt_pos_file,
                    label="positive",
                    apply_threshold=True,
                )
                self._ingest_vt_snapshot(
                    new_index,
                    filename=self.settings.vt_neg_file,
                    label="negative",
                    apply_threshold=self.settings.vt_apply_min_sources_to_neg,
                )
            except Exception as exc:
                errors.append(f"vt: {exc}")

        finished_at = datetime.now(timezone.utc)
        new_index.last_refresh_utc = finished_at.isoformat()
        new_index.refresh_error = "; ".join(errors) if errors else None
        return new_index, finished_at

    def _apply_refresh(self, refresh_output: tuple[FeedIndex, datetime]) -> None:
        """Atomically swap in a newly built index."""
        new_index, finished_at = refresh_output
        with self._lock:
            self._index = new_index
            self._last_refresh_time = finished_at
            self._last_refresh_attempt_utc = finished_at.isoformat()
            self._refresh_in_progress = False
        self._save_disk_index()

    def _refresh_worker(self) -> None:
        """Background thread entry point for index rebuilding."""
        try:
            result = self._build_index()
            self._apply_refresh(result)
        except Exception as exc:
            with self._lock:
                self._refresh_in_progress = False
                self._last_refresh_attempt_utc = datetime.now(timezone.utc).isoformat()
                self._index.refresh_error = f"background_refresh_failed: {exc}"

    def _trigger_background_refresh(self) -> None:
        """Spawn a daemon thread to rebuild the index."""
        with self._lock:
            if self._refresh_in_progress:
                return
            self._refresh_in_progress = True
            self._last_refresh_attempt_utc = datetime.now(timezone.utc).isoformat()
        worker = threading.Thread(target=self._refresh_worker, daemon=True)
        worker.start()

    def _is_stale(self) -> bool:
        """Return True if the cache has exceeded its maximum age."""
        with self._lock:
            if self._last_refresh_time is None:
                return True
            max_age = timedelta(minutes=max(self.settings.feed_refresh_minutes, 1))
            return datetime.now(timezone.utc) - self._last_refresh_time >= max_age

    def lookup(self, target: NormalizedTarget) -> dict[str, Any]:
        """Query the index for a target and return match results with risk score."""
        self.refresh_if_stale()
        with self._lock:
            url_hits = self._index.urls.get(target.normalized_url, [])
            host_hits = self._index.hosts.get(target.host, [])
            ip_hits = self._index.ips.get(target.host, []) if target.is_ip else []

            all_hits = [*url_hits, *host_hits, *ip_hits]
            positives = [h for h in all_hits if h.get("label") == "positive"]
            negatives = [h for h in all_hits if h.get("label") == "negative"]

            score = 0
            if positives:
                score = 100
            elif negatives:
                score = 5

            return {
                "status": "ok",
                "match_found": bool(all_hits),
                "positive_match_count": len(positives),
                "negative_match_count": len(negatives),
                "matches": all_hits[:25],
                "risk_score": score,
                "feed_freshness": {
                    "last_refresh_utc": self._index.last_refresh_utc,
                    "refresh_error": self._index.refresh_error,
                },
            }

    def _ingest_openphish(self, index: FeedIndex) -> None:
        """Download and parse the OpenPhish public feed."""
        response = requests.get(
            self.settings.openphish_url,
            timeout=self.settings.request_timeout_seconds,
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            parsed = normalize_feed_value(line)
            if not parsed:
                continue
            kind, key = parsed
            index.add_entry(
                kind,
                key,
                {
                    "feed": "openphish",
                    "label": "positive",
                    "source_count": None,
                    "value": line.strip(),
                },
            )

    def _ingest_phishtank(self, index: FeedIndex) -> None:
        """Download and parse the PhishTank JSON feed."""
        request_url = self.settings.phishtank_data_url
        if "{app_key}" in request_url:
            if not self.settings.phishtank_app_key:
                return
            request_url = request_url.format(app_key=self.settings.phishtank_app_key)

        response = requests.get(
            request_url,
            timeout=self.settings.request_timeout_seconds,
            headers={
                "User-Agent": "CapstonePhishingDetector/1.0 (+https://cursor.local)",
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
            },
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            entries = payload.get("results") or payload.get("data") or []
        else:
            entries = payload
        if not isinstance(entries, list):
            return

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            value = str(entry.get("url") or "").strip()
            parsed = normalize_feed_value(value)
            if not parsed:
                continue
            kind, key = parsed
            index.add_entry(
                kind,
                key,
                {
                    "feed": "phishtank",
                    "label": "positive",
                    "source_count": None,
                    "value": value,
                    "phish_detail_url": entry.get("phish_detail_url") or entry.get("phish_detail_page") or "",
                    "submission_time": entry.get("submission_time") or entry.get("submitted_at") or "",
                    "verification_time": entry.get("verification_time") or entry.get("verified_at") or "",
                    "verified": entry.get("verified"),
                    "online": entry.get("online"),
                    "target": entry.get("target") or "",
                },
            )

    def _ingest_vt_snapshot(
        self,
        index: FeedIndex,
        filename: str,
        label: str,
        apply_threshold: bool,
    ) -> None:
        """Download, decompress, and parse a VT-style snapshot file."""
        if not filename:
            return
        url = f"{self.settings.vt_base_url.rstrip('/')}/{filename}"
        response = requests.get(url, timeout=self.settings.request_timeout_seconds)
        response.raise_for_status()
        content = gzip.decompress(response.content).decode("utf-8", errors="replace")

        dedupe: dict[tuple[str, str], dict[str, Any]] = {}
        for line in content.splitlines():
            parsed = self._parse_vt_line(line)
            if parsed is None:
                continue
            source_count, value = parsed
            if apply_threshold and source_count < self.settings.vt_min_sources:
                continue
            normalized = normalize_feed_value(value)
            if not normalized:
                continue
            kind, key = normalized
            dedupe_key = (kind, key)
            previous = dedupe.get(dedupe_key)
            if previous is None or source_count > previous["source_count"]:
                dedupe[dedupe_key] = {
                    "feed": "vt",
                    "label": label,
                    "source_count": source_count,
                    "value": value,
                    "snapshot": filename,
                }

        for (kind, key), entry in dedupe.items():
            index.add_entry(kind, key, entry)

    @staticmethod
    def _parse_vt_line(line: str) -> tuple[int, str] | None:
        """Parse a single VT snapshot line into (source_count, value)."""
        stripped = line.strip()
        if not stripped:
            return None
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
            return None
        count_part, value_part = parts
        try:
            source_count = int(count_part)
        except ValueError:
            return None
        value = value_part.strip()
        if not value:
            return None
        return source_count, value

    def _save_disk_index(self) -> None:
        """Persist the current index to disk as JSON."""
        payload = {
            "urls": self._index.urls,
            "hosts": self._index.hosts,
            "ips": self._index.ips,
            "last_refresh_utc": self._index.last_refresh_utc,
            "refresh_error": self._index.refresh_error,
        }
        self.index_file.write_text(json.dumps(payload), encoding="utf-8")

    def _load_disk_index(self) -> None:
        """Hydrate the index from a previously saved JSON file."""
        if not self.index_file.exists():
            return
        try:
            payload = json.loads(self.index_file.read_text(encoding="utf-8"))
        except Exception:
            return
        self._index = FeedIndex(
            urls=payload.get("urls", {}),
            hosts=payload.get("hosts", {}),
            ips=payload.get("ips", {}),
            last_refresh_utc=payload.get("last_refresh_utc"),
            refresh_error=payload.get("refresh_error"),
        )
        if self._index.last_refresh_utc:
            try:
                self._last_refresh_time = datetime.fromisoformat(self._index.last_refresh_utc)
            except ValueError:
                self._last_refresh_time = None
