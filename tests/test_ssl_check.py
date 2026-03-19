from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings
from scanner.ssl_check import SSLValidator


def test_valid_certificate_does_not_get_issuer_penalty(monkeypatch):
    target = normalize_input_url("https://example.com")
    scanner = SSLValidator(target, ScannerSettings())
    cert = {
        "issuer": ((("commonName", "Some Trusted CA"),),),
        "subject": ((("commonName", "example.com"),),),
        "notAfter": "Jan 01 00:00:00 2099 GMT",
    }

    monkeypatch.setattr(scanner, "get_certificate_info", lambda: cert)
    monkeypatch.setattr(scanner, "check_validity", lambda c: True)
    monkeypatch.setattr(scanner, "check_protocol_version", lambda: "TLSv1.3")

    result = scanner.run_checks()
    assert result["status"] == "ok"
    assert result["trusted_issuer"] is True
    assert result["risk_score"] == 0
