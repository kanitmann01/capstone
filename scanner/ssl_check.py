"""SSL/TLS certificate validation.

Uses NetSTAR TLS certificate analysis to avoid local socket handshakes while
preserving the scanner's risk result shape.
"""

from scanner.normalization import NormalizedTarget  # Project-local: canonical URL representation
from scanner.netstar_client import NetSTARClient  # Project-local: NetSTAR Worker API client
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


class SSLValidator:
    """Validates SSL certificates for HTTPS targets."""

    def __init__(self, target: NormalizedTarget, settings: ScannerSettings):
        """Initialise with target and settings."""
        self.target = target
        self.settings = settings
        self.hostname = target.host
        self.port = target.port or 443
        self.netstar = NetSTARClient(
            base_url=self.settings.netstar_base_url,
            timeout=self.settings.request_timeout_seconds,
        )

    def get_certificate_info(self):
        """Fetch certificate analysis from NetSTAR."""
        return self.netstar.get_cert(self.hostname, self.port)

    def check_validity(self, cert) -> bool:
        """Check if the certificate is currently valid."""
        verification = cert.get("verification") if isinstance(cert, dict) else {}
        return not bool((verification or {}).get("validity_risk"))

    def check_issuer(self, cert) -> bool:
        """A successful verified handshake implies trusted issuer chain."""
        verification = cert.get("verification") if isinstance(cert, dict) else {}
        return bool((verification or {}).get("chain_verified"))

    def _name_to_dict(self, name_tuple):
        return dict(item[0] for item in name_tuple)

    def check_self_signed(self, cert) -> bool:
        verification = cert.get("verification") if isinstance(cert, dict) else {}
        return bool((verification or {}).get("subject_equals_issuer")) or bool(
            (verification or {}).get("self_signature_verifies")
        )

    def check_protocol_version(self) -> str:
        """Check the SSL/TLS protocol version."""
        cert = self.get_certificate_info()
        return self._protocol_version(cert)

    def run_checks(self) -> dict:
        """Run all SSL checks and return a risk score."""
        if self.target.scheme != "https":
            return {
                "status": "unknown",
                "unknown_reason": "ssl_check_skipped_for_non_https",
                "valid_cert": False,
                "trusted_issuer": False,
                "protocol_version": "Unknown",
                "risk_score": 0,
            }

        cert = self.get_certificate_info()
        
        if not cert:
            return {
                "status": "unknown",
                "unknown_reason": "certificate_unavailable",
                "valid_cert": False,
                "trusted_issuer": False,
                "protocol_version": "Unknown",
                "risk_score": 0,
            }

        verification = cert.get("verification") or {}
        valid = self.check_validity(cert)
        trusted = self.check_issuer(cert)
        protocol = self._protocol_version(cert)
        self_signed = self.check_self_signed(cert)
        hostname_matches = bool(verification.get("hostname_matches", True))
        weak_crypto = bool(verification.get("weak_crypto"))
        incomplete_chain = bool(verification.get("incomplete_chain"))
        
        score = 0
        if not valid:
            score += 50
        if not trusted:
            score += 25
        if not hostname_matches:
            score += 50
        if self_signed:
            score += 30
        if weak_crypto:
            score += 30
        if incomplete_chain:
            score += 20
        # Check for old protocols (TLS 1.0, 1.1, SSLv3)
        if protocol in {"TLS 1.0", "TLS 1.1", "TLSv1", "TLSv1.1", "SSLv3"}:
            score += 30
            
        return {
            "status": "ok",
            "valid_cert": valid,
            "trusted_issuer": trusted,
            "self_signed": self_signed,
            "hostname_matches": hostname_matches,
            "weak_crypto": weak_crypto,
            "incomplete_chain": incomplete_chain,
            "protocol_version": protocol,
            "risk_score": min(score, 100),
        }

    def _protocol_version(self, cert) -> str:
        """Extract negotiated TLS version from a NetSTAR cert response."""
        connection = cert.get("connection") if isinstance(cert, dict) else {}
        return str((connection or {}).get("tls_version") or "Unknown")
