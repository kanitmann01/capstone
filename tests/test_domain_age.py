from __future__ import annotations

from scanner.domain_age import DomainAgeScanner
from scanner.normalization import normalize_input_url


def test_domain_age_returns_unknown_when_netstar_rdap_unavailable(monkeypatch):
    scanner = DomainAgeScanner(normalize_input_url("https://example.com"))
    monkeypatch.setattr(scanner.netstar, "get_rdap", lambda host: None)

    result = scanner.run_checks()

    assert result["status"] == "unknown"
    assert result["unknown_reason"] == "rdap_unavailable"


def test_domain_age_scores_netstar_nrd_response(monkeypatch):
    scanner = DomainAgeScanner(normalize_input_url("https://new-domain.example"))
    monkeypatch.setattr(scanner.netstar, "get_rdap", lambda host: {"host": host, "nrd": True, "nameserver": []})

    result = scanner.run_checks()

    assert result["status"] == "ok"
    assert result["risk_score"] == 80


def test_domain_age_uses_full_rdap_registration_event(monkeypatch):
    scanner = DomainAgeScanner(normalize_input_url("https://old-domain.example"))
    monkeypatch.setattr(
        scanner.netstar,
        "get_rdap",
        lambda host: {
            "host": host,
            "nrd": False,
            "domain": {
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
            },
        },
    )

    result = scanner.run_checks()

    assert result["status"] == "ok"
    assert result["domain_age_days"] > 180
    assert result["registrar"] == "Example Registrar"
    assert result["risk_score"] == 0
