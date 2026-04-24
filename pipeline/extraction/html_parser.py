from __future__ import annotations

"""
Page snapshot extraction orchestrator.

Combines ``ContentScanner`` (HTML fetch + parse), host-feature checks,
and brand-match summarisation into a single flat snapshot dict that
feeds the rest of the pipeline.
"""

from typing import Any  # Standard library: generic type hints

from scanner.content import ContentScanner  # Project-local: HTML fetch and content analysis
from scanner.normalization import normalize_input_url  # Project-local: URL canonicalisation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration

from pipeline.extraction.brand_match import summarize_brand_impersonation  # Project-local: brand impersonation summary
from pipeline.extraction.host_features import host_provider  # Project-local: host provider resolution
from pipeline.extraction.host_features import is_free_host  # Project-local: free-host detection


def extract_page_snapshot(raw_url: str, settings: ScannerSettings) -> dict[str, Any]:
    """Fetch a page and return a comprehensive snapshot dict.

    The snapshot includes raw HTML, visible text, form statistics,
    brand candidates, host metadata, and a brand-impersonation summary.
    """
    target = normalize_input_url(raw_url)
    scanner = ContentScanner(target, settings)
    content = scanner.run_checks()
    snapshot = {
        "url": target.original,
        "normalized_url": target.normalized_url,
        "host": target.host,
        "path": target.path,
        "scheme": target.scheme,
        "content": content,
        "page_title": content.get("page_title", ""),
        "visible_text": content.get("visible_text", ""),
        "visible_text_length": int(content.get("visible_text_length") or 0),
        "form_count": int(content.get("form_count") or 0),
        "login_form_present": bool(content.get("login_form_present")),
        "password_field_count": int(content.get("password_field_count") or 0),
        "input_field_count": int(content.get("input_field_count") or 0),
        "nav_link_count": int(content.get("nav_link_count") or 0),
        "image_count": int(content.get("image_count") or 0),
        "image_domains": list(content.get("image_domains") or []),
        "form_action_domains": list(content.get("form_action_domains") or []),
        "free_host": bool(content.get("free_host")) or is_free_host(target.host),
        "host_provider": content.get("host_provider") or host_provider(target.host),
        "detected_brand": content.get("detected_brand") or "",
        "brand_candidates": list(content.get("brand_candidates") or []),
        "brand_mismatch": bool(content.get("brand_mismatch")),
        "brand_path_match": bool(content.get("brand_path_match")),
        "brand_mention_count": int(content.get("brand_mention_count") or 0),
        "suspicious_phrase_hits": list(content.get("suspicious_phrase_hits") or []),
        "suspicious_keywords": bool(content.get("suspicious_keywords")),
        "hidden_elements": bool(content.get("hidden_elements")),
        "password_on_http": bool(content.get("password_on_http")),
        "no_navigation_menu": bool(content.get("no_navigation_menu")),
        "form_action_mismatch": bool(content.get("form_action_mismatch")),
        "impersonation_reasons": list(content.get("impersonation_reasons") or []),
        "risk_score": float(content.get("risk_score") or 0),
        "brand_impersonation": summarize_brand_impersonation(
            host=target.host,
            path=target.path,
            content_result=content,
        ),
        "raw_html": scanner.html_content,
        "fetch_error": scanner.last_error,
    }
    return snapshot
