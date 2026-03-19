import whois
import datetime
from scanner.normalization import NormalizedTarget

class DomainAgeScanner:
    def __init__(self, target: NormalizedTarget):
        self.target = target
        self.domain = target.host

    def get_whois_info(self):
        """Query WHOIS database for domain info."""
        try:
            w = whois.whois(self.domain)
            return w
        except Exception:
            return None

    def check_domain_age(self, creation_date: datetime.datetime) -> int:
        """Calculate domain age in days."""
        if not creation_date:
            return 0
            
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
        age = (datetime.datetime.utcnow() - creation_date).days
        return age

    def check_registrar(self, registrar: str) -> bool:
        """Check if registrar is known/suspicious (placeholder logic)."""
        # This is hard to generalize without a large database.
        # For now, just return True if we have registrar info.
        return bool(registrar)

    def run_checks(self) -> dict:
        if self.target.is_ip:
            return {
                "status": "unknown",
                "unknown_reason": "whois_skipped_for_ip",
                "domain_age_days": 0,
                "registrar": "Unknown",
                "risk_score": 0,
            }

        w = self.get_whois_info()
        
        if not w:
            return {
                "status": "unknown",
                "unknown_reason": "whois_unavailable",
                "domain_age_days": 0,
                "registrar": "Unknown",
                "risk_score": 0,
            }

        age_days = self.check_domain_age(w.creation_date)
        registrar = w.registrar
        
        score = 0
        # New domains (< 30 days) are high risk
        if age_days < 30:
            score += 80
        elif age_days < 180:
            score += 40
            
        return {
            "status": "ok",
            "domain_age_days": age_days,
            "registrar": str(registrar),
            "risk_score": min(score, 100),
        }
