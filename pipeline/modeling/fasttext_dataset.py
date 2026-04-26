from __future__ import annotations

"""
FastText corpus serialization and deduplication.

Converts page snapshots into supervised FastText training lines,
removes duplicates by content hash, and writes corpus files.
"""

import html  # Standard library: HTML entity decoding
import re  # Standard library: regular expressions
from pathlib import Path  # Standard library: filesystem path abstraction
from typing import Any  # Standard library: generic type hints


LABEL_PREFIX = "__label__"
PHISHING_LABEL_VALUES = {"1", "true", "t", "yes", "y", "phishing"}
CLEAN_LABEL_VALUES = {"0", "false", "f", "no", "n", "clean", "benign", "legitimate"}


def clean_text(value: str) -> str:
    """Normalise free text for FastText tokenisation."""
    text = str(value or "")
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_token(value: Any) -> str:
    """Lower-case and replace non-alphanumeric characters with underscores."""
    text = clean_text(str(value or ""))
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def normalize_label_value(value: Any) -> str | None:
    """Map common label encodings to FastText class names."""
    if isinstance(value, bool):
        return "phishing" if value else "clean"
    text = str(value or "").strip().lower()
    if text in PHISHING_LABEL_VALUES:
        return "phishing"
    if text in CLEAN_LABEL_VALUES:
        return "clean"
    return None


def snapshot_text_key(snapshot: dict[str, Any]) -> str:
    """Generate a deduplication key from visible text, title, or URL."""
    content = snapshot.get("content") or {}
    visible_text = clean_text(snapshot.get("visible_text") or content.get("visible_text") or "")
    title = clean_text(snapshot.get("page_title") or content.get("page_title") or "")
    fallback = clean_text(snapshot.get("normalized_url") or snapshot.get("url") or "")
    return normalize_token(visible_text or title or fallback)


def corpus_dedup_key(snapshot: dict[str, Any], label: str) -> str:
    """Combine label and text key into a unique corpus identifier."""
    normalized_label = normalize_token(label) or "unknown"
    return f"{normalized_label}:{snapshot_text_key(snapshot)}"


def serialize_snapshot(snapshot: dict[str, Any]) -> str:
    """Flatten a snapshot into weighted FastText features plus bounded page text."""
    content = snapshot.get("content") or {}
    brand_summary = snapshot.get("brand_impersonation") or content.get("brand_impersonation") or {}
    brand_candidates = list(
        snapshot.get("brand_candidates")
        or content.get("brand_candidates")
        or brand_summary.get("brand_candidates")
        or []
    )
    tokens: list[str] = []

    def first_value(*names: str) -> Any:
        for name in names:
            value = snapshot.get(name)
            if value not in (None, "", [], {}):
                return value
            value = content.get(name)
            if value not in (None, "", [], {}):
                return value
            value = brand_summary.get(name)
            if value not in (None, "", [], {}):
                return value
        return None

    def add_token(token: str, weight: int = 1) -> None:
        if token:
            tokens.extend([token] * max(int(weight), 1))

    def add_bool_signal(name: str, *, token: str | None = None, weight: int = 2) -> None:
        if bool(first_value(name)):
            add_token(token or f"__signal__{name}", weight)

    def add_count_signal(name: str, *, token: str | None = None, weight: int = 2) -> int:
        try:
            count = int(first_value(name) or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            add_token(token or f"__feature__{name}", min(max(count, 1), weight))
        return count

    detected_brand = first_value("detected_brand", "matched_brand")
    brand_token = normalize_token(detected_brand)
    if brand_token:
        add_token(f"__brand__{brand_token}", 4)

    for candidate in brand_candidates[:5]:
        candidate_brand = normalize_token(candidate.get("brand") or candidate.get("matched_brand"))
        if candidate_brand and candidate_brand != brand_token:
            add_token(f"__brand__{candidate_brand}", 2)
        if candidate.get("official_domain_match"):
            add_token("__signal__official_domain_match", 3)

    host_provider = normalize_token(first_value("host_provider", "free_host_provider"))
    if host_provider:
        add_token(f"__host__{host_provider}", 3)

    host = normalize_token(first_value("host"))
    if host:
        add_token(f"__domain__{host}", 1)

    add_bool_signal("login_form_present", token="__feature__login_form_present", weight=5)
    add_count_signal("form_count", token="__feature__form_present", weight=4)
    add_count_signal("password_field_count", token="__feature__password_field", weight=5)
    add_count_signal("input_field_count", token="__feature__input_field", weight=3)

    for signal in [
        "free_host",
        "brand_mismatch",
        "brand_path_match",
        "form_action_mismatch",
        "no_navigation_menu",
        "password_on_http",
        "suspicious_keywords",
        "hidden_elements",
    ]:
        add_bool_signal(signal, weight=3)

    if first_value("content_fetched") is False:
        add_token("__signal__content_not_fetched", 3)
    if first_value("fetch_error"):
        add_token("__signal__fetch_error", 2)

    nav_links = add_count_signal("nav_link_count", token="__feature__nav_link", weight=3)
    if nav_links == 0 and first_value("nav_link_count") is not None:
        add_token("__feature__no_nav_links", 2)

    phrase_hits = [
        normalize_token(item)
        for item in (first_value("suspicious_phrase_hits") or [])
        if normalize_token(item)
    ]
    for phrase in phrase_hits[:12]:
        add_token(f"__phrase__{phrase}", 4)

    matched_phrases = []
    for candidate in brand_candidates:
        matched_phrases.extend(candidate.get("matched_phrases") or [])
    for phrase in matched_phrases[:12]:
        phrase_token = normalize_token(phrase)
        if phrase_token:
            add_token(f"__matched__{phrase_token}", 2)

    form_domains = first_value("form_action_domains") or []
    for domain in form_domains[:5]:
        domain_token = normalize_token(domain)
        if domain_token:
            add_token(f"__form_domain__{domain_token}", 2)

    title = clean_text(first_value("page_title") or "")
    visible_text = clean_text(first_value("visible_text") or "")
    headings = " ".join(
        clean_text(value)
        for value in (first_value("heading_texts") or [])
        if clean_text(value)
    )
    raw_parts = [
        _limit_words(title, 24),
        _limit_words(headings, 48),
        _limit_words(" ".join(clean_text(value) for value in matched_phrases), 36),
        _limit_words(" ".join(phrase_hits).replace("_", " "), 36),
        _limit_words(visible_text, 120),
    ]
    tokens.extend(part for part in raw_parts if part)

    if not tokens:
        fallback = clean_text(first_value("normalized_url", "url", "path") or "")
        if fallback:
            tokens.extend(["__feature__url_only_snapshot", _limit_words(fallback, 24)])
        else:
            tokens.append("__feature__empty_snapshot")

    return " ".join(tokens)


def _limit_words(text: str, max_words: int) -> str:
    """Return at most max_words whitespace-delimited words."""
    words = clean_text(text).split()
    return " ".join(words[:max_words])


def serialize_labeled_snapshot(snapshot: dict[str, Any], label: str) -> str:
    """Format a snapshot as a supervised FastText line: __label__<class> <text>."""
    normalized_label = normalize_label_value(label)
    if normalized_label is None:
        raise ValueError("label must be 'phishing' or 'clean'")
    return f"{LABEL_PREFIX}{normalized_label} {serialize_snapshot(snapshot)}"


def build_corpus_lines(rows: list[dict[str, Any]], *, dedupe_visible_text: bool = True) -> list[str]:
    """Convert labeled rows into a list of FastText corpus lines."""
    lines = []
    seen: set[str] = set()
    for row in rows:
        label = row.get("label") if "label" in row else row.get("is_phishing")
        label_text = normalize_label_value(label)
        if label_text is None:
            continue
        if dedupe_visible_text:
            dedup_key = corpus_dedup_key(row, label_text)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
        lines.append(serialize_labeled_snapshot(row, label_text))
    return lines


def write_corpus_file(lines: list[str], output_path: str | Path) -> Path:
    """Persist corpus lines to disk, creating parent directories if needed."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path
