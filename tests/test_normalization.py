from scanner.normalization import normalize_feed_value, normalize_input_url


def test_normalize_input_url_adds_scheme_and_normalizes_host():
    target = normalize_input_url("Example.COM:80/path?a=2&a=1#fragment")
    assert target.host == "example.com"
    assert target.scheme == "http"
    assert target.normalized_url == "http://example.com/path?a=1&a=2"


def test_normalize_feed_value_host_and_ip():
    assert normalize_feed_value("https://Example.com/login")[0] == "url"
    assert normalize_feed_value("Example.com") == ("host", "example.com")
    assert normalize_feed_value("1.2.3.4") == ("ip", "1.2.3.4")
