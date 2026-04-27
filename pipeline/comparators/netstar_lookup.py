"""Netstar threat-intel lookup comparator lens.

Wraps ``ThreatIntelScanner`` with the feed cache only, ignoring all other
signals. Decision rule: positive feed hit ⇒ phishing, else clean.
"""

from __future__ import annotations

from scanner.feed_ingest import ThreatFeedCache
from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings
from scanner.threat_intel import ThreatIntelScanner


def score_url(url: str) -> dict:
    """Query threat-intel feeds for a URL and return a verdict dict."""
    settings = ScannerSettings.from_env()
    feed_cache = ThreatFeedCache(settings)
    target = normalize_input_url(url)
    result = ThreatIntelScanner(target, feed_cache).run_checks()
    risk_score = float(result.get("risk_score") or 0)
    return {
        "lens": "netstar_lookup",
        "risk_score": risk_score,
        "predicted_is_phishing": risk_score > 0,
        "checks": result,
    }
