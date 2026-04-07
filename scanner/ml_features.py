from __future__ import annotations

from collections.abc import Iterable
from math import log2
from typing import Any

from scanner.brand_profiles import all_brand_tokens
from scanner.normalization import NormalizedTarget

FEATURE_VERSION = "ml_features_v2"
BASE_CHECK_NAMES = ("heuristics", "content", "ssl", "domain_age", "threat_intel")

SUSPICIOUS_TOKENS = (
    "login",
    "signin",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "wallet",
    "invoice",
    "confirm",
)

BRAND_TOKENS = all_brand_tokens() + ("bank", "signin", "login", "secure", "wallet", "account")

FEATURE_FIELDS = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "has_at",
    "is_ip",
    "uses_https",
    "subdomain_count",
    "path_depth",
    "query_param_count",
    "host_entropy",
    "path_entropy",
    "suspicious_token_count",
    "brand_token_count",
    "page_title_length",
    "page_heading_count",
    "form_count",
    "login_form_present",
    "password_field_count",
    "input_field_count",
    "nav_link_count",
    "image_count",
    "external_image_domain_count",
    "form_action_count",
    "free_host_flag",
    "brand_candidate_count",
    "detected_brand_present",
    "brand_mismatch_flag",
    "brand_path_match",
    "brand_mention_count",
    "suspicious_phrase_count",
    "form_action_mismatch",
    "no_navigation_menu_flag",
    "heuristics_score",
    "content_score",
    "ssl_score",
    "domain_age_score",
    "threat_intel_score",
    "unknown_check_count",
    "content_available",
    "password_on_http",
    "content_keyword_flag",
    "hidden_elements_flag",
    "ssl_valid_cert",
    "ssl_self_signed",
    "ssl_old_protocol",
    "domain_age_days",
    "domain_age_known",
    "threat_match_found",
    "threat_positive_matches",
    "threat_negative_matches",
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool_flag(value: Any) -> int:
    return 1 if bool(value) else 0


def _token_count(values: Iterable[str], text: str) -> int:
    lowered = text.lower()
    return sum(1 for token in values if token in lowered)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return round(
        -sum((count / total) * log2(count / total) for count in counts.values()),
        6,
    )


def extract_features(
    target: NormalizedTarget,
    details: dict[str, dict[str, Any]],
) -> dict[str, float]:
    normalized_url = target.normalized_url
    lowered_url = normalized_url.lower()
    content = details.get("content") or {}
    ssl = details.get("ssl") or {}
    domain_age = details.get("domain_age") or {}
    threat = details.get("threat_intel") or {}

    path_depth = len([part for part in target.path.split("/") if part])
    query_param_count = 0 if not target.query else target.query.count("&") + 1
    unknown_check_count = sum(
        1 for name in BASE_CHECK_NAMES if (details.get(name) or {}).get("status") != "ok"
    )

    protocol_version = str(ssl.get("protocol_version", "Unknown"))
    old_protocol = protocol_version in {"TLSv1", "TLSv1.1", "SSLv3"}
    special_chars = sum(1 for char in normalized_url if not char.isalnum())

    features: dict[str, float] = {
        "url_length": float(len(normalized_url)),
        "host_length": float(len(target.host)),
        "path_length": float(len(target.path or "")),
        "query_length": float(len(target.query or "")),
        "num_dots": float(target.host.count(".")),
        "num_hyphens": float(target.host.count("-")),
        "num_digits": float(sum(char.isdigit() for char in normalized_url)),
        "num_special_chars": float(special_chars),
        "has_at": float(_bool_flag("@" in normalized_url)),
        "is_ip": float(_bool_flag(target.is_ip)),
        "uses_https": float(_bool_flag(target.scheme == "https")),
        "subdomain_count": float(max(target.host.count(".") - 1, 0)),
        "path_depth": float(path_depth),
        "query_param_count": float(query_param_count),
        "host_entropy": _entropy(target.host),
        "path_entropy": _entropy(target.path or ""),
        "suspicious_token_count": float(_token_count(SUSPICIOUS_TOKENS, lowered_url)),
        "brand_token_count": float(_token_count(BRAND_TOKENS, lowered_url)),
        "page_title_length": float(len(str(content.get("page_title") or ""))),
        "page_heading_count": float(len(content.get("heading_texts") or [])),
        "form_count": float(_safe_int(content.get("form_count"))),
        "login_form_present": float(_bool_flag(content.get("login_form_present"))),
        "password_field_count": float(_safe_int(content.get("password_field_count"))),
        "input_field_count": float(_safe_int(content.get("input_field_count"))),
        "nav_link_count": float(_safe_int(content.get("nav_link_count"))),
        "image_count": float(_safe_int(content.get("image_count"))),
        "external_image_domain_count": float(_safe_int(content.get("external_image_domain_count"))),
        "form_action_count": float(_safe_int(content.get("form_action_count"))),
        "free_host_flag": float(_bool_flag(content.get("free_host"))),
        "brand_candidate_count": float(_safe_int(content.get("brand_candidate_count"))),
        "detected_brand_present": float(_bool_flag(content.get("detected_brand"))),
        "brand_mismatch_flag": float(_bool_flag(content.get("brand_mismatch"))),
        "brand_path_match": float(_bool_flag(content.get("brand_path_match"))),
        "brand_mention_count": float(_safe_int(content.get("brand_mention_count"))),
        "suspicious_phrase_count": float(len(content.get("suspicious_phrase_hits") or [])),
        "form_action_mismatch": float(_bool_flag(content.get("form_action_mismatch"))),
        "no_navigation_menu_flag": float(_bool_flag(content.get("no_navigation_menu"))),
        "heuristics_score": _safe_float((details.get("heuristics") or {}).get("risk_score")),
        "content_score": _safe_float(content.get("risk_score")),
        "ssl_score": _safe_float(ssl.get("risk_score")),
        "domain_age_score": _safe_float(domain_age.get("risk_score")),
        "threat_intel_score": _safe_float(threat.get("risk_score")),
        "unknown_check_count": float(unknown_check_count),
        "content_available": float(_bool_flag(content.get("content_fetched"))),
        "password_on_http": float(_bool_flag(content.get("password_on_http"))),
        "content_keyword_flag": float(_bool_flag(content.get("suspicious_keywords"))),
        "hidden_elements_flag": float(_bool_flag(content.get("hidden_elements"))),
        "ssl_valid_cert": float(_bool_flag(ssl.get("valid_cert"))),
        "ssl_self_signed": float(_bool_flag(ssl.get("self_signed"))),
        "ssl_old_protocol": float(_bool_flag(old_protocol)),
        "domain_age_days": float(max(_safe_int(domain_age.get("domain_age_days")), 0)),
        "domain_age_known": float(_bool_flag(domain_age.get("status") == "ok")),
        "threat_match_found": float(_bool_flag(threat.get("match_found"))),
        "threat_positive_matches": float(max(_safe_int(threat.get("positive_match_count")), 0)),
        "threat_negative_matches": float(max(_safe_int(threat.get("negative_match_count")), 0)),
    }
    return features


def vectorize_features(
    features: dict[str, Any],
    feature_names: Iterable[str] | None = None,
) -> list[float]:
    names = tuple(feature_names or FEATURE_FIELDS)
    return [_safe_float(features.get(name)) for name in names]


def build_feature_row(
    target: NormalizedTarget,
    details: dict[str, dict[str, Any]],
    *,
    label: bool | None = None,
    source: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "url": target.original,
        "normalized_url": target.normalized_url,
        "host": target.host,
        "feature_version": FEATURE_VERSION,
        "label_source": source,
    }
    if label is not None:
        row["is_phishing"] = int(bool(label))
    row.update(extract_features(target, details))
    return row
