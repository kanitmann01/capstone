import gzip
import time

from scanner.feed_ingest import ThreatFeedCache
from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings


class DummyResponse:
    def __init__(self, text=None, content=None, status_code=200):
        self.text = text or ""
        self.content = content or b""
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"bad status {self.status_code}")


def test_vt_threshold_and_dedup(monkeypatch, tmp_path):
    openphish_text = "https://phish.example/login\n"
    vt_pos_lines = "\n".join(
        [
            "12 https://bad.example/login",
            "4 https://ignore.example/",
            "11 bad-host.example",
            "11 1.2.3.4",
            "14 https://bad.example/login",
        ]
    )
    vt_neg_lines = "\n".join(["20 https://bad.example/login", "3 low.example"])

    vt_pos_gz = gzip.compress(vt_pos_lines.encode("utf-8"))
    vt_neg_gz = gzip.compress(vt_neg_lines.encode("utf-8"))

    def fake_get(url, timeout):
        if "openphish" in url:
            return DummyResponse(text=openphish_text)
        if url.endswith("/pos.gz"):
            return DummyResponse(content=vt_pos_gz)
        if url.endswith("/neg.gz"):
            return DummyResponse(content=vt_neg_gz)
        raise RuntimeError(f"unexpected url {url}")

    monkeypatch.setattr("scanner.feed_ingest.requests.get", fake_get)

    settings = ScannerSettings(
        openphish_enabled=True,
        vt_enabled=True,
        vt_base_url="https://netstar.one/vt",
        vt_pos_file="pos.gz",
        vt_neg_file="neg.gz",
        vt_min_sources=10,
        feed_cache_dir=str(tmp_path),
    )
    cache = ThreatFeedCache(settings)
    cache.refresh_now()

    result = cache.lookup(normalize_input_url("https://bad.example/login"))
    assert result["match_found"] is True
    assert result["positive_match_count"] >= 1
    assert result["risk_score"] == 100

    ignored = cache.lookup(normalize_input_url("https://ignore.example/"))
    assert ignored["match_found"] is False


def test_refresh_error_metadata(monkeypatch, tmp_path):
    def always_fail(url, timeout):
        raise RuntimeError("network down")

    monkeypatch.setattr("scanner.feed_ingest.requests.get", always_fail)
    settings = ScannerSettings(
        openphish_enabled=True,
        vt_enabled=False,
        feed_cache_dir=str(tmp_path),
        feed_refresh_minutes=1,
    )
    cache = ThreatFeedCache(settings)
    cache.refresh_now()
    metadata = cache.metadata()
    assert metadata["refresh_error"] is not None
    assert "openphish" in metadata["refresh_error"]


def test_lookup_triggers_background_refresh_without_blocking(monkeypatch, tmp_path):
    openphish_text = "https://phish.example/login\n"

    def slow_get(url, timeout):
        time.sleep(0.25)
        return DummyResponse(text=openphish_text)

    monkeypatch.setattr("scanner.feed_ingest.requests.get", slow_get)
    settings = ScannerSettings(
        openphish_enabled=True,
        vt_enabled=False,
        feed_cache_dir=str(tmp_path),
        feed_refresh_minutes=1,
    )
    cache = ThreatFeedCache(settings)

    started = time.perf_counter()
    first = cache.lookup(normalize_input_url("https://phish.example/login"))
    elapsed = time.perf_counter() - started

    # First lookup should not block on network refresh.
    assert elapsed < 0.20
    assert first["match_found"] is False
    assert cache.metadata()["refresh_in_progress"] is True
