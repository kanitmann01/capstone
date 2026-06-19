from scanner.feed_ingest import ThreatFeedCache
from app.service import AppService
from scanner.settings import ScannerSettings


def test_service_weighted_score_excludes_unknown(tmp_path):
    settings = ScannerSettings(
        openphish_enabled=False,
        vt_enabled=False,
        feed_cache_dir=str(tmp_path),
        weights_heuristics=0.5,
        weights_content=0.5,
        weights_ssl=0.0,
        weights_domain_age=0.0,
        weights_threat_intel=0.0,
    )
    service = AppService(settings=settings, feed_cache=ThreatFeedCache(settings))
    details = {
        "heuristics": {"status": "ok", "risk_score": 100},
        "content": {"status": "unknown", "risk_score": 0},
        "ssl": {"status": "unknown", "risk_score": 0},
        "domain_age": {"status": "unknown", "risk_score": 0},
        "threat_intel": {"status": "unknown", "risk_score": 0},
    }
    score, contributing, unknown = service._weighted_score(details)
    assert score == 100
    assert contributing == ["heuristics"]
    assert "content" in unknown


def test_scan_combined_with_progress_emits_check_events(tmp_path, monkeypatch):
    settings = ScannerSettings(
        openphish_enabled=False,
        vt_enabled=False,
        feed_cache_dir=str(tmp_path),
        weights_heuristics=0.5,
        weights_content=0.5,
        weights_ssl=0.0,
        weights_domain_age=0.0,
        weights_threat_intel=0.0,
        weights_ml=0.0,
    )
    service = AppService(settings=settings, feed_cache=ThreatFeedCache(settings))
    events = []

    # Mock all scanner classes to avoid network calls
    class MockScanner:
        def __init__(self, *args, **kwargs):
            pass
        def run_checks(self):
            return {"status": "ok", "risk_score": 20}

    # Mock ContentScanner separately (different signature)
    class MockContentScanner:
        def __init__(self, *args, **kwargs):
            pass
        def run_checks(self):
            return {
                "status": "ok", "risk_score": 0,
                "detected_brand": "", "host_provider": "", "brand_mismatch": False,
                "brand_path_match": False, "login_form_present": False,
                "password_field_count": 0, "form_action_mismatch": False,
                "suspicious_phrase_hits": [], "brand_candidates": [],
                "impersonation_reasons": []
            }

    import app.service as service_module
    monkeypatch.setattr(service_module, "URLHeuristics", MockScanner)
    monkeypatch.setattr(service_module, "SSLValidator", MockScanner)
    monkeypatch.setattr(service_module, "DomainAgeScanner", MockScanner)
    monkeypatch.setattr(service_module, "ThreatIntelScanner", MockScanner)
    monkeypatch.setattr(service_module, "ContentScanner", MockContentScanner)

    # Mock extract_features
    def mock_extract_features(target, details):
        return {}
    monkeypatch.setattr(service_module, "extract_features", mock_extract_features)

    # Mock MLScanner.scan
    def mock_ml_scan(self, features):
        return {"status": "unknown", "risk_score": 0}
    monkeypatch.setattr(service.structured_ml, "scan", mock_ml_scan)

    result = service.scan_combined_with_progress("https://example.com", progress_callback=events.append)

    assert result["risk_score"] == 20
    assert events[0]["type"] == "check_started"
    assert events[0]["check"] == "heuristics"
    assert events[1]["type"] == "check_completed"
    assert events[2]["check"] == "content"
