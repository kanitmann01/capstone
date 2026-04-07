from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.service import AppService
from pipeline.evaluation.evaluate import build_report_payload
from pipeline.evaluation.evaluate import evaluate_csv
from pipeline.modeling.fasttext_dataset import serialize_snapshot


def test_fasttext_serializer_uses_plain_text_only():
    snapshot = {
        "content": {
            "page_title": "Netflix Sign In",
            "visible_text": "Verify your account",
            "brand_candidates": [{"matched_phrases": ["sign in"]}],
            "detected_brand": "Netflix",
            "host_provider": "vercel",
            "free_host": True,
            "login_form_present": True,
            "password_field_count": 1,
            "input_field_count": 2,
            "nav_link_count": 0,
            "brand_mismatch": True,
            "brand_path_match": True,
            "form_action_mismatch": False,
            "no_navigation_menu": True,
            "suspicious_phrase_hits": ["verify your account"],
        }
    }
    text = serialize_snapshot(snapshot)
    assert "Netflix Sign In" in text
    assert "Verify your account" in text
    assert "sign in" in text.lower()
    assert "host_provider=" not in text
    assert "free_host=" not in text
    assert "verify your account" in text.lower()


def test_app_service_scan_url_uses_fasttext_and_rules(monkeypatch):
    service = AppService()

    def fake_extract_page_snapshot(raw_url, settings):
        del settings
        return {
            "url": raw_url,
            "normalized_url": raw_url,
            "host": "login.example.test",
            "path": "/login",
            "scheme": "https",
            "content": {},
            "page_title": "Example Sign In",
            "visible_text": "Please verify your account",
            "visible_text_length": 28,
            "form_count": 1,
            "login_form_present": True,
            "password_field_count": 1,
            "input_field_count": 2,
            "nav_link_count": 0,
            "image_count": 0,
            "image_domains": [],
            "form_action_domains": [],
            "free_host": True,
            "host_provider": "vercel",
            "detected_brand": "Example",
            "brand_candidates": [{"brand": "Example", "matched_phrases": ["sign in"]}],
            "brand_mismatch": True,
            "brand_path_match": True,
            "brand_mention_count": 1,
            "suspicious_phrase_hits": ["verify your account"],
            "suspicious_keywords": True,
            "hidden_elements": False,
            "password_on_http": False,
            "no_navigation_menu": True,
            "form_action_mismatch": True,
            "impersonation_reasons": ["brand mismatch"],
            "risk_score": 88.0,
            "brand_impersonation": {
                "detected_brand": "Example",
                "brand_mismatch": True,
                "free_host_provider": "vercel",
                "suspicious_phrase_hits": ["verify your account"],
            },
            "raw_html": "<html></html>",
            "fetch_error": None,
        }

    def fake_legacy_checks(target, snapshot):
        del target
        assert snapshot["normalized_url"] == "https://example.test/login"
        return {
            "heuristics": {"status": "ok", "risk_score": 25.0, "keyword_masking": True},
            "content": {
                "status": "ok",
                "risk_score": 60.0,
                "content_fetched": True,
                "brand_mismatch": True,
                "free_host": True,
            },
            "ssl": {"status": "ok", "risk_score": 10.0},
            "domain_age": {"status": "ok", "risk_score": 40.0},
            "threat_intel": {"status": "ok", "risk_score": 0.0},
        }

    def fake_structured_ml(target, legacy_checks):
        del target, legacy_checks
        return {
            "status": "unknown",
            "unknown_reason": "model_unavailable",
            "risk_score": 0.0,
            "prediction": "unknown",
        }

    @dataclass
    class FakePrediction:
        label: str = "phishing"
        probability: float = 0.93
        score: float = 93.0
        raw_label: str = "__label__phishing"
        raw_probability: float = 0.93

        def as_dict(self):
            return {
                "label": self.label,
                "probability": self.probability,
                "score": self.score,
                "raw_label": self.raw_label,
                "raw_probability": self.raw_probability,
            }

    monkeypatch.setattr("app.service.extract_page_snapshot", fake_extract_page_snapshot)
    monkeypatch.setattr(service.detector, "predict_text", lambda text: FakePrediction())
    monkeypatch.setattr(service, "_run_legacy_checks", fake_legacy_checks)
    monkeypatch.setattr(service, "_run_structured_ml", fake_structured_ml)

    result = service.scan_url("https://example.test/login", persist=False)
    assert result["override_applied"] is True
    assert result["prediction"] == "phishing"
    assert result["risk_score"] == 100.0
    assert result["hybrid_score"] == 100.0
    assert result["fasttext"]["label"] == "phishing"
    assert result["rules"]["prediction"] == "phishing"
    assert result["brand_impersonation"]["brand_mismatch"] is True
    assert result["override_reason"] == "free host with brand mismatch"


def test_app_service_overrides_official_domain(monkeypatch):
    service = AppService()

    def fake_extract_page_snapshot(raw_url, settings):
        del settings
        return {
            "url": raw_url,
            "normalized_url": raw_url,
            "host": "www.netflix.com",
            "path": "/login",
            "scheme": "https",
            "content": {},
            "page_title": "Netflix",
            "visible_text": "Ready to watch? Enter your email.",
            "visible_text_length": 32,
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
            "detected_brand": "Netflix",
            "brand_candidates": [
                {
                    "brand": "Netflix",
                    "score": 51,
                    "matched_fields": ["title", "body"],
                    "matched_phrases": ["ready to watch"],
                    "official_domain_match": True,
                }
            ],
            "brand_mismatch": False,
            "brand_path_match": True,
            "brand_mention_count": 1,
            "suspicious_phrase_hits": [],
            "suspicious_keywords": False,
            "hidden_elements": False,
            "password_on_http": False,
            "no_navigation_menu": False,
            "form_action_mismatch": False,
            "impersonation_reasons": [],
            "risk_score": 0.0,
            "brand_impersonation": {
                "detected_brand": "Netflix",
                "brand_candidates": [
                    {
                        "brand": "Netflix",
                        "official_domain_match": True,
                    }
                ],
                "brand_mismatch": False,
                "free_host_provider": "",
                "suspicious_phrase_hits": [],
            },
            "raw_html": "<html></html>",
            "fetch_error": None,
        }

    def fake_legacy_checks(target, snapshot):
        del target, snapshot
        return {
            "heuristics": {"status": "ok", "risk_score": 0.0},
            "content": {"status": "ok", "content_fetched": True, "risk_score": 0.0},
            "ssl": {"status": "ok", "risk_score": 0.0},
            "domain_age": {"status": "ok", "risk_score": 0.0},
            "threat_intel": {"status": "ok", "risk_score": 0.0},
        }

    def fake_structured_ml(target, legacy_checks):
        del target, legacy_checks
        return {
            "status": "unknown",
            "unknown_reason": "model_unavailable",
            "risk_score": 0.0,
            "prediction": "unknown",
        }

    @dataclass
    class FakePrediction:
        label: str = "phishing"
        probability: float = 0.51
        score: float = 51.15
        raw_label: str = "__label__phishing"
        raw_probability: float = 0.51

        def as_dict(self):
            return {
                "label": self.label,
                "probability": self.probability,
                "score": self.score,
                "raw_label": self.raw_label,
                "raw_probability": self.raw_probability,
            }

    monkeypatch.setattr("app.service.extract_page_snapshot", fake_extract_page_snapshot)
    monkeypatch.setattr(service.detector, "predict_text", lambda text: FakePrediction())
    monkeypatch.setattr(service, "_run_legacy_checks", fake_legacy_checks)
    monkeypatch.setattr(service, "_run_structured_ml", fake_structured_ml)

    result = service.scan_url("https://www.netflix.com/", persist=False)
    assert result["override_applied"] is True
    assert result["prediction"] == "clean"
    assert result["risk_score"] == 0.0
    assert result["hybrid_score"] == 0.0
    assert result["override_reason"] == "official domain match for Netflix"


def test_evaluation_report_includes_threshold_sweep(tmp_path):
    input_csv = tmp_path / "eval.csv"
    output_csv = tmp_path / "scored.csv"
    input_csv.write_text(
        "url,is_phishing\nhttps://phish.example,1\nhttps://clean.example,0\n",
        encoding="utf-8",
    )

    def scorer(url, progress_callback=None):
        del progress_callback
        score = 40.0 if "phish" in url else 10.0
        return {
            "url": url,
            "risk_score": score,
            "prediction": "phishing" if score >= 30.0 else "clean",
            "verdict": {"status": "ok", "label": "phishing" if score >= 30.0 else "clean", "final_score": score},
            "scores": {"final": score, "rules": score, "fasttext": score, "legacy": 0.0, "structured_ml": None},
        }

    result = evaluate_csv(input_csv=input_csv, output_csv=output_csv, scorer=scorer, threshold=30.0)
    report = build_report_payload(result)

    assert report["summary"]["total_rows"] == 2
    assert any(item["threshold"] == 30.0 for item in report["threshold_sweep"])
    assert any(item["recall"] >= 0.5 for item in report["threshold_sweep"])


def test_fasttext_corpus_export_dedupes_repeated_visible_text(monkeypatch, tmp_path):
    service = AppService()
    input_csv = tmp_path / "baseline.csv"
    input_csv.write_text("url,is_phishing\nhttps://a.example,1\nhttps://b.example,1\n", encoding="utf-8")

    snapshots = {
        "https://a.example": {
            "url": "https://a.example",
            "normalized_url": "https://a.example",
            "host": "a.example",
            "path": "/",
            "scheme": "https",
            "content": {},
            "page_title": "Brand Login",
            "visible_text": "Sign in to continue",
            "visible_text_length": 20,
            "form_count": 1,
            "login_form_present": True,
            "password_field_count": 1,
            "input_field_count": 2,
            "nav_link_count": 0,
            "image_count": 0,
            "image_domains": [],
            "form_action_domains": [],
            "free_host": False,
            "host_provider": "",
            "detected_brand": "Brand",
            "brand_candidates": [],
            "brand_mismatch": True,
            "brand_path_match": False,
            "brand_mention_count": 1,
            "suspicious_phrase_hits": ["sign in"],
            "suspicious_keywords": True,
            "hidden_elements": False,
            "password_on_http": False,
            "no_navigation_menu": True,
            "form_action_mismatch": False,
            "impersonation_reasons": [],
            "risk_score": 80.0,
            "brand_impersonation": {"detected_brand": "Brand"},
            "raw_html": "<html></html>",
            "fetch_error": None,
        },
        "https://b.example": {
            "url": "https://b.example",
            "normalized_url": "https://b.example",
            "host": "b.example",
            "path": "/",
            "scheme": "https",
            "content": {},
            "page_title": "Brand Login",
            "visible_text": "Sign in to continue",
            "visible_text_length": 20,
            "form_count": 1,
            "login_form_present": True,
            "password_field_count": 1,
            "input_field_count": 2,
            "nav_link_count": 0,
            "image_count": 0,
            "image_domains": [],
            "form_action_domains": [],
            "free_host": False,
            "host_provider": "",
            "detected_brand": "Brand",
            "brand_candidates": [],
            "brand_mismatch": True,
            "brand_path_match": False,
            "brand_mention_count": 1,
            "suspicious_phrase_hits": ["sign in"],
            "suspicious_keywords": True,
            "hidden_elements": False,
            "password_on_http": False,
            "no_navigation_menu": True,
            "form_action_mismatch": False,
            "impersonation_reasons": [],
            "risk_score": 80.0,
            "brand_impersonation": {"detected_brand": "Brand"},
            "raw_html": "<html></html>",
            "fetch_error": None,
        },
    }

    def fake_extract_page_snapshot(raw_url, settings):
        del settings
        return snapshots[raw_url]

    monkeypatch.setattr("app.service.extract_page_snapshot", fake_extract_page_snapshot)

    report = service.export_fasttext_corpus_from_csv(input_csv, tmp_path / "corpus.txt")
    corpus_text = Path(report["corpus_path"]).read_text(encoding="utf-8")

    assert report["rows"] == 2
    assert report["unique_rows"] == 1
    assert report["duplicate_rows"] == 1
    assert corpus_text.count("__label__phishing") == 1
