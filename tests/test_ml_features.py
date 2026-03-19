from scanner.ml_features import extract_features
from scanner.normalization import normalize_input_url


def test_extract_features_uses_url_and_module_outputs():
    target = normalize_input_url("https://login-paypal.example.com/account/verify?id=123")
    details = {
        "heuristics": {"status": "ok", "risk_score": 45},
        "content": {
            "status": "ok",
            "risk_score": 60,
            "content_fetched": True,
            "password_on_http": False,
            "suspicious_keywords": True,
            "hidden_elements": False,
        },
        "ssl": {
            "status": "ok",
            "risk_score": 15,
            "valid_cert": True,
            "self_signed": False,
            "protocol_version": "TLSv1.2",
        },
        "domain_age": {"status": "ok", "risk_score": 20, "domain_age_days": 18},
        "threat_intel": {
            "status": "ok",
            "risk_score": 100,
            "match_found": True,
            "positive_match_count": 2,
            "negative_match_count": 0,
        },
    }

    features = extract_features(target, details)

    assert features["uses_https"] == 1.0
    assert features["suspicious_token_count"] >= 2.0
    assert features["brand_token_count"] >= 1.0
    assert features["heuristics_score"] == 45.0
    assert features["content_score"] == 60.0
    assert features["ssl_valid_cert"] == 1.0
    assert features["domain_age_days"] == 18.0
    assert features["threat_positive_matches"] == 2.0
    assert features["unknown_check_count"] == 0.0


def test_extract_features_counts_unknown_base_checks_only():
    target = normalize_input_url("http://10.0.0.1/login")
    details = {
        "heuristics": {"status": "ok", "risk_score": 30},
        "content": {"status": "unknown", "risk_score": 0},
        "ssl": {"status": "unknown", "risk_score": 0, "protocol_version": "Unknown"},
        "domain_age": {"status": "unknown", "risk_score": 0},
        "threat_intel": {"status": "ok", "risk_score": 0},
        "ml": {"status": "unknown", "risk_score": 0},
    }

    features = extract_features(target, details)

    assert features["is_ip"] == 1.0
    assert features["uses_https"] == 0.0
    assert features["unknown_check_count"] == 3.0
