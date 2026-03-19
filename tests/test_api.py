from fastapi.testclient import TestClient

import main


def test_web_view_loads():
    client = TestClient(main.app)
    response = client.get("/")
    assert response.status_code == 200
    assert "Phishing Scanner" in response.text


def test_combined_endpoint_uses_service(monkeypatch):
    expected = {
        "url": "http://example.com/",
        "risk_score": 42.0,
        "contributing_checks": ["heuristics"],
        "unknown_checks": [],
        "feed_freshness": {"last_refresh_utc": None, "refresh_error": None},
        "details": {"heuristics": {"status": "ok", "risk_score": 42}},
    }

    def fake_combined(url):
        assert url == "example.com"
        return expected

    monkeypatch.setattr(main.scan_service, "scan_combined", fake_combined)
    client = TestClient(main.app)
    response = client.post("/scan/combined", json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json() == expected
