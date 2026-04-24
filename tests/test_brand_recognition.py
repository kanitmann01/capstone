from __future__ import annotations

import pytest

from app.service import AppService
from scanner.brand_recognition import DEFAULT_TARGET_BRANDS, BrandRecognitionDetector


def test_brand_inventory_has_at_least_100_brands():
    detector = BrandRecognitionDetector()

    assert len(DEFAULT_TARGET_BRANDS) >= 100
    assert len(detector.target_brands) >= 100
    assert detector.max_candidates >= 5


@pytest.mark.parametrize(
    "sample_brand",
    ["nike", "paypal", "microsoft", "spotify", "coinbase", "shopify", "netflix"],
)
def test_brand_recognition_allows_exact_safe_brand(sample_brand):
    detector = BrandRecognitionDetector()

    result = detector.analyze_url(f"https://{sample_brand}.com")

    assert result["parsed_root"] == sample_brand
    assert result["status"] == "safe"
    assert result["threat_type"] == "none"
    assert result["matched_brand"] == sample_brand
    assert result["brand_closeness"][0]["real_domain"] == f"{sample_brand}.com"
    assert result["brand_closeness"][0]["match_reason"] == "exact_root_match"
    assert result["brand_closeness_threshold"] == pytest.approx(0.70, abs=1e-6)


def test_brand_recognition_flags_typosquat():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("http://n1ke.com/login")

    assert result["parsed_root"] == "n1ke"
    assert result["status"] == "scam"
    assert result["threat_type"] == "typosquatting"
    assert result["matched_brand"] == "nike"
    assert result["risk_score"] == 95.0
    assert any(row["brand"] == "nike" for row in result["brand_closeness"])


def test_brand_recognition_flags_homograph():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("http://nιke.com/login")

    assert result["status"] == "scam"
    assert result["threat_type"] == "homograph"
    assert result["matched_brand"] == "nike"
    assert result["homograph_detected"] is True
    assert result["idna_root"].startswith("xn--")


def test_brand_recognition_flags_deceptive_subdomain():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("https://netflix.login.user123.com")

    assert result["parsed_root"] == "user123"
    assert result["parsed_subdomain"] == "netflix.login"
    assert result["status"] == "scam"
    assert result["threat_type"] == "deceptive_subdomain"
    assert result["matched_brand"] == "netflix"
    assert any(row["brand"] == "netflix" for row in result["brand_closeness"])


def test_brand_recognition_handles_invalid_url():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("")

    assert result["status"] == "unknown"
    assert result["threat_type"] == "none"
    assert result["brand_closeness"] == []
    assert result["brand_closeness_threshold"] == pytest.approx(0.70, abs=1e-6)


def test_brand_closeness_rows_respect_threshold():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("http://n1ke.com/login")

    threshold = float(result["brand_closeness_threshold"])
    matched_brand = result["matched_brand"]
    for row in result["brand_closeness"]:
        similarity = float(row["similarity_score"])
        is_match_row = row["brand"] == matched_brand
        is_preserved = row["match_reason"] in {"exact_root_match", "deceptive_subdomain_match"}
        assert similarity >= threshold or is_match_row or is_preserved


def test_brand_closeness_stays_empty_when_far_from_any_brand():
    detector = BrandRecognitionDetector()

    result = detector.analyze_url("https://totallyobscureuniquebrandxyz.com")

    assert result["status"] == "safe"
    assert result["threat_type"] == "none"
    assert result["brand_closeness"] == []


def test_app_service_includes_brand_recognition_signal(monkeypatch):
    service = AppService()

    def fake_extract_page_snapshot(raw_url, settings):
        del settings
        return {
            "url": raw_url,
            "normalized_url": raw_url,
            "host": "n1ke.com",
            "path": "/login",
            "scheme": "http",
            "content": {},
            "page_title": "",
            "visible_text": "",
            "visible_text_length": 0,
            "form_count": 0,
            "login_form_present": False,
            "password_field_count": 0,
            "input_field_count": 0,
            "nav_link_count": 0,
            "image_count": 0,
            "image_domains": [],
            "form_action_domains": [],
            "free_host": False,
            "host_provider": "",
            "detected_brand": "",
            "brand_candidates": [],
            "brand_mismatch": False,
            "brand_path_match": False,
            "brand_mention_count": 0,
            "suspicious_phrase_hits": [],
            "suspicious_keywords": False,
            "hidden_elements": False,
            "password_on_http": False,
            "no_navigation_menu": False,
            "form_action_mismatch": False,
            "impersonation_reasons": [],
            "risk_score": 0.0,
            "brand_impersonation": {
                "detected_brand": "",
                "brand_candidates": [],
                "brand_mismatch": False,
                "free_host_provider": "",
                "suspicious_phrase_hits": [],
            },
            "raw_html": "<html></html>",
            "fetch_error": None,
        }

    monkeypatch.setattr("app.service.extract_page_snapshot", fake_extract_page_snapshot)
    monkeypatch.setattr(service.detector, "predict_text", lambda text: None)
    monkeypatch.setattr(
        service,
        "_run_legacy_checks",
        lambda target, snapshot: {
            "heuristics": {"status": "ok", "risk_score": 0.0},
            "content": {"status": "ok", "content_fetched": True, "risk_score": 0.0},
            "ssl": {"status": "ok", "risk_score": 0.0},
            "domain_age": {"status": "ok", "risk_score": 0.0},
            "threat_intel": {"status": "ok", "risk_score": 0.0},
        },
    )
    monkeypatch.setattr(
        service,
        "_run_structured_ml",
        lambda target, legacy_checks: {
            "status": "unknown",
            "unknown_reason": "model_unavailable",
            "risk_score": 0.0,
            "prediction": "unknown",
        },
    )

    result = service.scan_url("http://n1ke.com/login", persist=False)

    assert result["brand_recognition"]["threat_type"] == "typosquatting"
    assert result["checks"]["brand_recognition"]["matched_brand"] == "nike"
    assert "brand_recognition" in result["contributing_checks"]
    assert result["prediction"] == "phishing"
