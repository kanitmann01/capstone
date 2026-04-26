"""WHOIS-based domain age analysis.

Queries NetSTAR RDAP for domain registration freshness, then scores
risk based on domain youth (new domains are high risk).
"""

import datetime  # Standard library: date and time utilities

from scanner.netstar_client import NetSTARClient  # Project-local: NetSTAR Worker API client
from scanner.normalization import NormalizedTarget  # Project-local: canonical URL representation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


class DomainAgeScanner:
    """Analyses domain age and registrar reputation."""

    def __init__(self, target: NormalizedTarget, settings: ScannerSettings | None = None):
        """Initialise with a normalised URL target."""
        self.target = target
        self.settings = settings or ScannerSettings.from_env()
        self.domain = target.host
        self.netstar = NetSTARClient(
            base_url=self.settings.netstar_base_url,
            timeout=self.settings.request_timeout_seconds,
        )

    def get_whois_info(self) -> dict | None:
        """Query NetSTAR RDAP for domain info."""
        return self.netstar.get_rdap(self.domain)

    def check_domain_age(self, creation_date: datetime.datetime) -> int:
        """Calculate domain age in days."""
        if not creation_date:
            return 0
            
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        age = (now - creation_date).days
        return age

    def check_registrar(self, registrar: str) -> bool:
        """Check if registrar is known/suspicious (placeholder logic)."""
        # This is hard to generalize without a large database.
        # For now, just return True if we have registrar info.
        return bool(registrar)

    def run_checks(self) -> dict:
        """Run WHOIS checks and return risk score."""
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
                "unknown_reason": "rdap_unavailable",
                "domain_age_days": 0,
                "registrar": "Unknown",
                "risk_score": 0,
            }

        creation_date = self._creation_date_from_rdap(w) if isinstance(w, dict) else None
        age_days = self.check_domain_age(creation_date)
        registrar = self._registrar_from_rdap(w) if isinstance(w, dict) else "Unknown"
        
        score = 0
        # New domains (< 30 days) are high risk. If NetSTAR only returns
        # nrd=false without a creation date, treat age as unknown but low risk.
        if bool(w.get("nrd")):
            score += 80
        elif creation_date is not None and age_days < 30:
            score += 80
        elif creation_date is not None and age_days < 180:
            score += 40
            
        return {
            "status": "ok",
            "domain_age_days": age_days,
            "registrar": str(registrar),
            "risk_score": min(score, 100),
        }

    def _creation_date_from_rdap(self, payload: dict) -> datetime.datetime | None:
        """Extract a registration date from NetSTAR RDAP payload."""
        domain = payload.get("domain") if isinstance(payload.get("domain"), dict) else payload
        events = domain.get("events") if isinstance(domain, dict) else None
        if not isinstance(events, list):
            return None
        preferred_actions = {"registration", "registered"}
        fallback: datetime.datetime | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            parsed = self._parse_creation_date(event.get("eventDate"))
            if parsed is None:
                continue
            if fallback is None or parsed < fallback:
                fallback = parsed
            action = str(event.get("eventAction") or "").lower()
            if action in preferred_actions:
                return parsed
        return fallback

    def _registrar_from_rdap(self, payload: dict) -> str:
        """Extract registrar-ish display text from full RDAP payload when present."""
        domain = payload.get("domain") if isinstance(payload.get("domain"), dict) else payload
        entities = domain.get("entities") if isinstance(domain, dict) else None
        if not isinstance(entities, list):
            return "Unknown"
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = {str(role).lower() for role in entity.get("roles") or []}
            if "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray")
            name = self._name_from_vcard(vcard)
            if name:
                return name
        return "Unknown"

    def _name_from_vcard(self, vcard: object) -> str:
        """Extract fn/org from an RDAP vCard array."""
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            return ""
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if item[0] in {"fn", "org"} and item[3]:
                return str(item[3])
        return ""

    def _parse_creation_date(self, value: object) -> datetime.datetime | None:
        """Parse an isolated WHOIS creation timestamp."""
        if not value:
            return None
        if isinstance(value, datetime.datetime):
            return value
        if isinstance(value, str):
            try:
                parsed = datetime.datetime.fromisoformat(value)
            except ValueError:
                return None
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        return None
