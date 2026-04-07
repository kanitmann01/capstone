from fastapi.testclient import TestClient

import main


def test_web_view_loads():
    client = TestClient(main.app)
    response = client.get("/")
    assert response.status_code == 200
    assert "Fake Brand Login Detector" in response.text


def test_combined_endpoint_uses_service(monkeypatch):
    expected = {
        "url": "http://example.com/",
        "risk_score": 42.0,
        "hybrid_score": 42.0,
        "prediction": "phishing",
        "verdict": {"status": "ok", "label": "phishing", "final_score": 42.0},
        "scores": {"final": 42.0, "rules": 40.0, "fasttext": 44.0, "legacy": 38.0, "structured_ml": None},
        "rules": {"status": "ok", "risk_score": 40.0, "prediction": "phishing"},
        "fasttext": {"status": "ok", "label": "phishing", "score": 44.0},
        "brand_impersonation": {"detected_brand": "Example"},
        "checks": {"heuristics": {"status": "ok", "risk_score": 12.0}},
        "contributing_checks": ["heuristics", "rules", "fasttext"],
        "unknown_checks": [],
        "feed_freshness": {"last_refresh_utc": None, "refresh_error": None},
        "details": {"heuristics": {"status": "ok", "risk_score": 42}},
        "artifacts": {"persisted": True, "record_id": 1, "source": "api_scan", "pipeline_version": "unified_pipeline_v1"},
    }

    def fake_combined(url, persist=True):
        assert url == "example.com"
        assert persist is True
        return expected

    monkeypatch.setattr(main.scan_service, "scan_combined", fake_combined)
    client = TestClient(main.app)
    response = client.post("/scan/combined", json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json() == expected
