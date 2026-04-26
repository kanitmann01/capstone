from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings
from scanner.ssl_check import SSLValidator


def test_valid_certificate_does_not_get_issuer_penalty(monkeypatch):
    target = normalize_input_url("https://example.com")
    scanner = SSLValidator(target, ScannerSettings())
    cert = {
        "connection": {"tls_version": "TLS 1.3"},
        "verification": {
            "chain_verified": True,
            "hostname_matches": True,
            "subject_equals_issuer": False,
            "self_signature_verifies": False,
            "weak_crypto": False,
            "validity_risk": False,
            "incomplete_chain": False,
        },
    }

    monkeypatch.setattr(scanner, "get_certificate_info", lambda: cert)

    result = scanner.run_checks()
    assert result["status"] == "ok"
    assert result["trusted_issuer"] is True
    assert result["risk_score"] == 0
