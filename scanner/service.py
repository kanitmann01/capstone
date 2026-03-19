from __future__ import annotations

from typing import Any
from typing import Callable

from scanner.content import ContentScanner
from scanner.domain_age import DomainAgeScanner
from scanner.feed_ingest import ThreatFeedCache
from scanner.heuristics import URLHeuristics
from scanner.ml_features import extract_features
from scanner.ml_model import MLScanner
from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings
from scanner.ssl_check import SSLValidator
from scanner.threat_intel import ThreatIntelScanner


class ScanService:
    def __init__(self, settings: ScannerSettings, feed_cache: ThreatFeedCache):
        self.settings = settings
        self.feed_cache = feed_cache
        self.ml_scanner = MLScanner(settings)

    def scan_combined(self, raw_url: str) -> dict[str, Any]:
        return self._scan_combined(raw_url)

    def scan_combined_with_progress(
        self,
        raw_url: str,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        return self._scan_combined(raw_url, progress_callback=progress_callback)

    def _scan_combined(
        self,
        raw_url: str,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        target = normalize_input_url(raw_url)
        details = self._run_combined_checks(target, progress_callback=progress_callback)
        ml_result = self._run_ml_check(
            target,
            details,
            progress_callback=progress_callback,
        )
        details["ml"] = ml_result

        score, contributing_checks, unknown_checks = self._weighted_score(details)
        return {
            "url": target.normalized_url,
            "risk_score": round(score, 2),
            "contributing_checks": contributing_checks,
            "unknown_checks": unknown_checks,
            "feed_freshness": self.feed_cache.metadata(),
            "details": details,
        }

    def scan_heuristics(self, raw_url: str) -> dict[str, Any]:
        return URLHeuristics(normalize_input_url(raw_url)).run_checks()

    def scan_content(self, raw_url: str) -> dict[str, Any]:
        return ContentScanner(normalize_input_url(raw_url), self.settings).run_checks()

    def scan_ssl(self, raw_url: str) -> dict[str, Any]:
        return SSLValidator(normalize_input_url(raw_url), self.settings).run_checks()

    def scan_whois(self, raw_url: str) -> dict[str, Any]:
        return DomainAgeScanner(normalize_input_url(raw_url)).run_checks()

    def scan_threats(self, raw_url: str) -> dict[str, Any]:
        return ThreatIntelScanner(normalize_input_url(raw_url), self.feed_cache).run_checks()

    def scan_ml(self, raw_url: str) -> dict[str, Any]:
        target = normalize_input_url(raw_url)
        details = self._run_combined_checks(target)
        features = extract_features(target, details)
        ml_result = self.ml_scanner.scan(features)
        return {
            "url": target.normalized_url,
            "ml": ml_result,
            "features": features,
            "details": details,
            "analytics": self.ml_scanner.analytics(),
        }

    def ml_overview(self) -> dict[str, Any]:
        return self.ml_scanner.analytics()

    def refresh_feeds(self) -> dict[str, Any]:
        self.feed_cache.refresh_now()
        return {"status": "ok", "feed_freshness": self.feed_cache.metadata()}

    def _run_combined_checks(
        self,
        target,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, dict[str, Any]]:
        check_runners: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
            ("heuristics", lambda: URLHeuristics(target).run_checks()),
            ("content", lambda: ContentScanner(target, self.settings).run_checks()),
            ("ssl", lambda: SSLValidator(target, self.settings).run_checks()),
            ("domain_age", lambda: DomainAgeScanner(target).run_checks()),
            ("threat_intel", lambda: ThreatIntelScanner(target, self.feed_cache).run_checks()),
        )
        details: dict[str, dict[str, Any]] = {}

        for name, runner in check_runners:
            if progress_callback:
                progress_callback({"type": "check_started", "check": name})
            result = runner()
            details[name] = result
            if progress_callback:
                progress_callback(
                    {
                        "type": "check_completed",
                        "check": name,
                        "status": result.get("status", "ok"),
                        "risk_score": result.get("risk_score", 0),
                    }
                )
        return details

    def _run_ml_check(
        self,
        target,
        details: dict[str, dict[str, Any]],
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if progress_callback:
            progress_callback({"type": "check_started", "check": "ml"})
        features = extract_features(target, details)
        result = self.ml_scanner.scan(features)
        if progress_callback:
            progress_callback(
                {
                    "type": "check_completed",
                    "check": "ml",
                    "status": result.get("status", "unknown"),
                    "risk_score": result.get("risk_score", 0),
                }
            )
        return result

    def _weighted_score(self, details: dict[str, dict[str, Any]]) -> tuple[float, list[str], list[str]]:
        weights = {
            "heuristics": self.settings.weights_heuristics,
            "content": self.settings.weights_content,
            "ssl": self.settings.weights_ssl,
            "domain_age": self.settings.weights_domain_age,
            "threat_intel": self.settings.weights_threat_intel,
            "ml": self.settings.weights_ml,
        }

        numerator = 0.0
        denominator = 0.0
        contributing: list[str] = []
        unknown: list[str] = []

        for name, result in details.items():
            status = result.get("status", "ok")
            if status != "ok":
                unknown.append(name)
                continue
            component = float(result.get("risk_score", 0))
            weight = float(weights.get(name, 0.0))
            if weight <= 0:
                continue
            numerator += component * weight
            denominator += weight
            contributing.append(name)

        if denominator == 0:
            return 0.0, contributing, unknown
        return numerator / denominator, contributing, unknown
