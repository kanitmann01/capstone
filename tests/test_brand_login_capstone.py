from __future__ import annotations

from scanner.dataset_store import BrandLoginDatasetStore
from scanner.dataset_store import SnapshotRecord
from scanner.normalization import normalize_input_url
from scanner.content import ContentScanner
from scanner.settings import ScannerSettings
from scanner.ml_features import extract_features


class DummyResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


def test_content_scanner_detects_brand_impersonation(monkeypatch, tmp_path):
    html = """
    <html>
      <head><title>Netflix Sign In</title></head>
      <body>
        <nav></nav>
        <h1>Sign in to Netflix</h1>
        <p>Verify your account because of unusual activity.</p>
        <form action="https://evil.example/post">
          <input type="email" />
          <input type="password" />
        </form>
        <img src="/assets/netflix-logo.png" alt="Netflix" />
      </body>
    </html>
    """

    def fake_get(url, timeout):
        del url, timeout
        return DummyResponse(html)

    monkeypatch.setattr("scanner.content.requests.get", fake_get)

    settings = ScannerSettings()
    target = normalize_input_url("https://netflix-login.vercel.app/signin")
    scanner = ContentScanner(target, settings)
    result = scanner.run_checks()
    features = extract_features(target, {"content": result})

    assert result["status"] == "ok"
    assert result["detected_brand"] == "Netflix"
    assert result["free_host"] is True
    assert result["brand_mismatch"] is True
    assert result["form_action_mismatch"] is True
    assert result["risk_score"] > 0
    assert features["brand_mismatch_flag"] == 1.0
    assert features["free_host_flag"] == 1.0
    assert features["suspicious_phrase_count"] >= 1.0


def test_brand_login_dataset_store_round_trip(tmp_path):
    store = BrandLoginDatasetStore(tmp_path / "dataset.sqlite3")
    record = SnapshotRecord.create(
        url="https://example.test/login",
        normalized_url="https://example.test/login",
        host="example.test",
        source_feed="manual",
        source_pipeline="app_service",
        pipeline_version="unified_pipeline_v1",
        raw_html="<html></html>",
        visible_text="Sign in",
        page_title="Sign In",
        detected_brand="Example",
        host_provider="vercel",
        risk_score=88.0,
        prediction="phishing",
        extraction={"status": "ok"},
        label=1,
    )
    snapshot_id = store.add_snapshot(record)
    duplicate_id = store.add_snapshot(record)
    store.update_label(snapshot_id, 0, "re-labeled as benign")

    recent = store.iter_recent(limit=5)
    summary = store.summary()

    assert recent[0]["id"] == snapshot_id
    assert recent[0]["label"] == 0
    assert duplicate_id == snapshot_id
    assert summary["total_rows"] == 1
    assert summary["legitimate_rows"] == 1
    assert summary["brand_count"] >= 1
    assert summary["source_pipeline_count"] >= 1
    assert summary["pipeline_version_count"] >= 1
