from __future__ import annotations

"""
Rules-based scoring baseline.

Applies a deterministic rule set to a page snapshot (login forms,
password fields, free hosts, brand mismatches, suspicious phrases)
and returns a risk score and human-readable reasons.
"""

from typing import Any  # Standard library: generic type hints


def score_rules(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the rules baseline against an extracted page snapshot."""
    content = snapshot.get("content") or {}
    score = 0
    reasons: list[str] = []

    def value(name: str, default: Any = None) -> Any:
        if name in content:
            return content.get(name)
        return snapshot.get(name, default)

    if value("login_form_present"):
        score += 10
        reasons.append("login form present")
    if int(value("password_field_count") or 0) > 0:
        score += min(20, 8 + int(value("password_field_count") or 0) * 5)
        reasons.append("password field found")
    if bool(value("free_host")):
        score += 20
        reasons.append("free host detected")
    if bool(value("brand_mismatch")):
        score += 25
        reasons.append("brand mismatch")
    if bool(value("brand_path_match")):
        score += 10
        reasons.append("brand in URL path")
    if bool(value("form_action_mismatch")):
        score += 12
        reasons.append("form action mismatch")
    if len(value("suspicious_phrase_hits") or []) > 0:
        score += min(20, len(value("suspicious_phrase_hits") or []) * 5)
        reasons.append("suspicious login phrases")
    if bool(value("no_navigation_menu")):
        score += 8
        reasons.append("no navigation menu")
    if bool(value("password_on_http")):
        score += 20
        reasons.append("password field on HTTP")

    score = min(score, 100)
    return {
        "status": "ok",
        "risk_score": float(score),
        "reasons": reasons,
        "prediction": "phishing" if score >= 50 else "clean",
    }
