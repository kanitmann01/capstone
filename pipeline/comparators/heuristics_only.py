"""Heuristics-only comparator lens.

Wraps ``URLHeuristics.run_checks()`` and returns a simple verdict dict.
Decision rule: risk_score >= 30 ⇒ phishing.
"""

from __future__ import annotations

from scanner.heuristics import URLHeuristics
from scanner.normalization import normalize_input_url


def score_url(url: str) -> dict:
    """Run heuristic checks on a URL and return a verdict dict."""
    target = normalize_input_url(url)
    checks = URLHeuristics(target).run_checks()
    risk_score = float(checks.get("risk_score") or 0)
    return {
        "lens": "heuristics_only",
        "risk_score": risk_score,
        "predicted_is_phishing": risk_score >= 30.0,
        "checks": checks,
    }
