from scanner.feed_ingest import ThreatFeedCache
from scanner.service import ScanService
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
    service = ScanService(settings, ThreatFeedCache(settings))
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
    )
    service = ScanService(settings, ThreatFeedCache(settings))
    events = []

    def fake_run_combined_checks(target, progress_callback=None):
        del target
        if progress_callback:
            progress_callback({"type": "check_started", "check": "heuristics"})
            progress_callback(
                {"type": "check_completed", "check": "heuristics", "status": "ok", "risk_score": 20}
            )
            progress_callback({"type": "check_started", "check": "content"})
            progress_callback(
                {"type": "check_completed", "check": "content", "status": "unknown", "risk_score": 0}
            )
        return {
            "heuristics": {"status": "ok", "risk_score": 20},
            "content": {"status": "unknown", "risk_score": 0},
            "ssl": {"status": "unknown", "risk_score": 0},
            "domain_age": {"status": "unknown", "risk_score": 0},
            "threat_intel": {"status": "unknown", "risk_score": 0},
        }

    monkeypatch.setattr(service, "_run_combined_checks", fake_run_combined_checks)

    result = service.scan_combined_with_progress("https://example.com", progress_callback=events.append)

    assert result["risk_score"] == 20
    assert events[0]["type"] == "check_started"
    assert events[0]["check"] == "heuristics"
    assert events[1]["type"] == "check_completed"
    assert events[2]["check"] == "content"
