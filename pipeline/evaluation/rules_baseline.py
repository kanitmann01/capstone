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

    login_form_present = bool(value("login_form_present"))
    password_field_count = int(value("password_field_count") or 0)
    free_host = bool(value("free_host"))
    brand_mismatch = bool(value("brand_mismatch"))
    brand_path_match = bool(value("brand_path_match"))
    form_action_mismatch = bool(value("form_action_mismatch"))
    suspicious_phrase_hits = list(value("suspicious_phrase_hits") or [])
    no_navigation_menu = bool(value("no_navigation_menu"))
    password_on_http = bool(value("password_on_http"))
    hidden_elements = bool(value("hidden_elements"))

    if login_form_present:
        score += 2
        reasons.append("login form present")
    if password_field_count > 0:
        score += min(6, 2 + password_field_count * 2)
        reasons.append("password field found")
    if free_host:
        score += 12
        reasons.append("free host detected")
    if brand_mismatch:
        score += 10
        reasons.append("brand mismatch")
    if brand_path_match:
        score += 4
        reasons.append("brand in URL path")
    if form_action_mismatch:
        score += 6
        reasons.append("form action mismatch")
    if suspicious_phrase_hits:
        score += min(15, len(suspicious_phrase_hits) * 4)
        reasons.append("suspicious login phrases")
    if no_navigation_menu and login_form_present:
        score += 4
        reasons.append("no navigation menu")
    if password_on_http:
        score += 30
        reasons.append("password field on HTTP")
    if hidden_elements:
        score += 15
        reasons.append("hidden page elements")

    if free_host and brand_path_match:
        score += 10
        reasons.append("free host with brand in URL")
    if free_host and brand_mismatch:
        score += 15
        reasons.append("free host with brand mismatch")
    if brand_mismatch and form_action_mismatch:
        score += 8
        reasons.append("brand mismatch with external form action")
    if free_host and suspicious_phrase_hits:
        score += 6
        reasons.append("free host with suspicious copy")

    score = min(score, 100)
    return {
        "status": "ok",
        "risk_score": float(score),
        "reasons": reasons,
        "prediction": "phishing" if score >= 50 else "clean",
    }
