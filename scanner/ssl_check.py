"""SSL/TLS certificate validation.

Connects to the target host on port 443, retrieves the peer certificate,
and checks validity, self-signature, protocol version, and issuer trust.
"""

import ssl  # Standard library: TLS/SSL wrapper
import socket  # Standard library: low-level networking interface
import datetime  # Standard library: date and time utilities
from scanner.normalization import NormalizedTarget  # Project-local: canonical URL representation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


class SSLValidator:
    """Validates SSL certificates for HTTPS targets."""

    def __init__(self, target: NormalizedTarget, settings: ScannerSettings):
        """Initialise with target and settings."""
        self.target = target
        self.settings = settings
        self.hostname = target.host
        self.port = target.port or 443

    def get_certificate_info(self):
        """Fetch and parse the SSL certificate."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection(
                (self.hostname, self.port),
                timeout=self.settings.request_timeout_seconds,
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception:
            return None

    def check_validity(self, cert) -> bool:
        """Check if the certificate is currently valid."""
        if not cert:
            return False
        
        not_after_str = cert.get('notAfter')
        if not not_after_str:
            return False
            
        not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        return datetime.datetime.utcnow() < not_after

    def check_issuer(self, cert) -> bool:
        """A successful verified handshake implies trusted issuer chain."""
        if not cert:
            return False
        return True

    def _name_to_dict(self, name_tuple):
        return dict(item[0] for item in name_tuple)

    def check_self_signed(self, cert) -> bool:
        if not cert:
            return False
        issuer = self._name_to_dict(cert.get("issuer", ()))
        subject = self._name_to_dict(cert.get("subject", ()))
        return bool(issuer) and issuer == subject

    def check_protocol_version(self) -> str:
        """Check the SSL/TLS protocol version."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection(
                (self.hostname, self.port),
                timeout=self.settings.request_timeout_seconds,
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    return ssock.version()
        except Exception:
            return "Unknown"

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

        valid = self.check_validity(cert)
        trusted = self.check_issuer(cert)
        protocol = self.check_protocol_version()
        self_signed = self.check_self_signed(cert)
        
        score = 0
        if not valid:
            score += 50
        if self_signed:
            score += 30
        # Check for old protocols (TLS 1.0, 1.1, SSLv3)
        if protocol in ["TLSv1", "TLSv1.1", "SSLv3"]:
            score += 30
            
        return {
            "status": "ok",
            "valid_cert": valid,
            "trusted_issuer": trusted,
            "self_signed": self_signed,
            "protocol_version": protocol,
            "risk_score": min(score, 100),
        }
