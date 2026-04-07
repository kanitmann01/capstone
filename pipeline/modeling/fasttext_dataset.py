from __future__ import annotations

import re
from pathlib import Path
from typing import Any


LABEL_PREFIX = "__label__"


def clean_text(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_token(value: Any) -> str:
    text = clean_text(str(value or "")).lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def snapshot_text_key(snapshot: dict[str, Any]) -> str:
    content = snapshot.get("content") or {}
    visible_text = clean_text(snapshot.get("visible_text") or content.get("visible_text") or "")
    title = clean_text(snapshot.get("page_title") or content.get("page_title") or "")
    fallback = clean_text(snapshot.get("normalized_url") or snapshot.get("url") or "")
    return normalize_token(visible_text or title or fallback)


def corpus_dedup_key(snapshot: dict[str, Any], label: str) -> str:
    normalized_label = normalize_token(label) or "unknown"
    return f"{normalized_label}:{snapshot_text_key(snapshot)}"


def serialize_snapshot(snapshot: dict[str, Any]) -> str:
    content = snapshot.get("content") or {}
    brand_candidates = list(snapshot.get("brand_candidates") or content.get("brand_candidates") or [])
    title = clean_text(snapshot.get("page_title") or content.get("page_title") or "")
    visible_text = clean_text(snapshot.get("visible_text") or content.get("visible_text") or "")
    headings = " ".join(
        clean_text(value)
        for value in (snapshot.get("heading_texts") or content.get("heading_texts") or [])
        if clean_text(value)
    )
    phrase_hits = [normalize_token(item) for item in (snapshot.get("suspicious_phrase_hits") or content.get("suspicious_phrase_hits") or [])]
    matched_phrases = []
    for candidate in brand_candidates:
        matched_phrases.extend(candidate.get("matched_phrases") or [])
    body = " ".join(
        part
        for part in [
            title,
            visible_text,
            headings,
            " ".join(phrase_hits),
            " ".join(clean_text(value) for value in matched_phrases if clean_text(value)),
        ]
        if part
    )
    return clean_text(body)


def serialize_labeled_snapshot(snapshot: dict[str, Any], label: str) -> str:
    normalized_label = label.strip().lower()
    if normalized_label not in {"phishing", "clean"}:
        raise ValueError("label must be 'phishing' or 'clean'")
    return f"{LABEL_PREFIX}{normalized_label} {serialize_snapshot(snapshot)}"


def build_corpus_lines(rows: list[dict[str, Any]], *, dedupe_visible_text: bool = True) -> list[str]:
    lines = []
    seen: set[str] = set()
    for row in rows:
        label = row.get("label") or row.get("is_phishing")
        if label in {1, "1", True, "true", "True"}:
            label_text = "phishing"
        elif label in {0, "0", False, "false", "False"}:
            label_text = "clean"
        else:
            continue
        if dedupe_visible_text:
            dedup_key = corpus_dedup_key(row, label_text)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
        lines.append(serialize_labeled_snapshot(row, label_text))
    return lines


def write_corpus_file(lines: list[str], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path
