from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from scanner.brand_profiles import BrandProfile
from scanner.brand_profiles import build_brand_lookup
from scanner.brand_profiles import host_matches_brand
from scanner.brand_profiles import load_brand_profiles
from scanner.brand_profiles import normalize_brand_token


def edit_distance(a: str, b: str, max_distance: int | None = None) -> int:
    left = normalize_brand_token(a)
    right = normalize_brand_token(b)
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, char_a in enumerate(left, start=1):
        current = [i]
        row_min = i
        for j, char_b in enumerate(right, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + cost,
                )
            )
            row_min = min(row_min, current[-1])
        previous = current
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
    return previous[-1]


def brand_tokens() -> tuple[str, ...]:
    tokens = set()
    for profile in load_brand_profiles():
        tokens.update(profile.normalized_keywords())
    return tuple(sorted(token for token in tokens if token))


def detect_brand_candidates(
    *,
    host: str,
    page_title: str = "",
    visible_text: str = "",
    headings: Iterable[str] | None = None,
    path: str = "",
    image_domains: Iterable[str] | None = None,
    form_action_domains: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    headings = list(headings or [])
    image_domains = list(image_domains or [])
    form_action_domains = list(form_action_domains or [])
    corpus = " ".join([page_title, visible_text, " ".join(headings), path, " ".join(image_domains), " ".join(form_action_domains)]).lower()
    lookup = build_brand_lookup()
    candidates: list[dict[str, Any]] = []
    for profile in load_brand_profiles():
        score = 0
        matched_fields: list[str] = []
        matched_phrases: list[str] = []
        profile_tokens = profile.normalized_keywords()
        if any(token and token in normalize_brand_token(host) for token in profile_tokens):
            score += 15
            matched_fields.append("host")
        for token in profile_tokens:
            if not token:
                continue
            if token in normalize_brand_token(page_title):
                score += 8
                matched_fields.append("title")
            if token in normalize_brand_token(visible_text):
                score += 5
                matched_fields.append("body")
            if token in normalize_brand_token(" ".join(headings)):
                score += 5
                matched_fields.append("heading")
            if token in normalize_brand_token(path):
                score += 6
                matched_fields.append("path")
            if token in normalize_brand_token(" ".join(image_domains)):
                score += 4
                matched_fields.append("image")
            if token in normalize_brand_token(" ".join(form_action_domains)):
                score += 4
                matched_fields.append("form_action")
        for phrase in (*profile.login_phrases, *profile.suspicious_phrases):
            lowered = phrase.lower()
            if lowered and lowered in corpus:
                matched_phrases.append(phrase)
                score += 4 if phrase in profile.login_phrases else 6
        official_match = host_matches_brand(host, profile)
        if official_match:
            score += 10
            matched_fields.append("official_domain")
        if score <= 0:
            continue
        candidates.append(
            {
                "brand": profile.name,
                "score": score,
                "matched_fields": sorted(set(matched_fields)),
                "matched_phrases": sorted(set(matched_phrases)),
                "official_domain_match": official_match,
            }
        )
    candidates.sort(key=lambda item: (int(item.get("score") or 0), len(item.get("matched_fields") or [])), reverse=True)
    return candidates[:5]


def summarize_brand_impersonation(
    *,
    host: str,
    path: str,
    content_result: dict[str, Any],
) -> dict[str, Any]:
    brand_candidates = list(content_result.get("brand_candidates") or [])
    detected_brand = content_result.get("detected_brand") or ""
    free_host_provider = content_result.get("host_provider") or ""
    if not free_host_provider and content_result.get("free_host"):
        free_host_provider = content_result.get("host_provider") or ""
    reasons = list(content_result.get("impersonation_reasons") or [])
    return {
        "detected_brand": detected_brand,
        "free_host_provider": free_host_provider,
        "brand_mismatch": bool(content_result.get("brand_mismatch")),
        "brand_path_match": bool(content_result.get("brand_path_match")),
        "brand_path_distance": min(
            [edit_distance(path, candidate.get("brand", ""), max_distance=2) for candidate in brand_candidates] or [99]
        ),
        "login_form_present": bool(content_result.get("login_form_present")),
        "password_field_count": int(content_result.get("password_field_count") or 0),
        "form_action_mismatch": bool(content_result.get("form_action_mismatch")),
        "suspicious_phrase_hits": list(content_result.get("suspicious_phrase_hits") or []),
        "brand_candidates": brand_candidates[:3],
        "reasons": reasons[:8],
        "target_host": host,
    }
