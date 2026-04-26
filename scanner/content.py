from __future__ import annotations

"""
HTML content fetching and brand impersonation analysis.

Fetches the remote page, parses it with BeautifulSoup, and scores
risk based on login forms, password fields, brand mismatches,
suspicious phrases, hidden elements, and free-hosting indicators.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import re  # Standard library: regular expressions
from typing import Any  # Standard library: generic type hints
from urllib.parse import urlparse  # Standard library: URL parsing

import requests  # Third-party: HTTP client
from bs4 import BeautifulSoup  # Third-party: HTML parser

from scanner.brand_profiles import BrandProfile  # Project-local: brand data class
from scanner.brand_profiles import guess_host_provider  # Project-local: free-host detection
from scanner.brand_profiles import host_matches_brand  # Project-local: official domain matching
from scanner.brand_profiles import load_brand_profiles  # Project-local: JSON loader
from scanner.brand_profiles import normalize_brand_token  # Project-local: token normalisation
from scanner.normalization import NormalizedTarget  # Project-local: canonical URL representation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


FREE_HOST_SUFFIXES = (".vercel.app", ".github.io", ".netlify.app", ".glitch.me", ".onrender.com", ".pages.dev", ".web.app")
SSO_PROVIDER_BRANDS = {"apple", "google", "microsoft"}
GENERIC_SUSPICIOUS_PHRASES = (
    "verify account",
    "verify your account",
    "unusual activity",
    "security alert",
    "confirm your identity",
    "update payment",
    "password required",
    "account locked",
    "urgent action required",
    "secure your account",
)


@dataclass(frozen=True)
class BrandCandidate:
    """A single brand match candidate with score and metadata."""

    brand: str
    score: int
    matched_fields: tuple[str, ...]
    matched_phrases: tuple[str, ...]
    official_domain_match: bool

    def as_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "brand": self.brand,
            "score": self.score,
            "matched_fields": list(self.matched_fields),
            "matched_phrases": list(self.matched_phrases),
            "official_domain_match": self.official_domain_match,
        }


class ContentScanner:
    """Fetches and analyses page content for phishing signals."""

    def __init__(self, target: NormalizedTarget, settings: ScannerSettings):
        """Initialise with a normalised target and scanner settings."""
        self.target = target
        self.settings = settings
        self.html_content = ""
        self.soup: BeautifulSoup | None = None
        self.last_error = ""
        self.brand_profiles = load_brand_profiles()

    def fetch_content(self) -> bool:
        """Fetch the HTML content of the page."""
        try:
            response = requests.get(
                self.target.normalized_url,
                timeout=self.settings.request_timeout_seconds,
            )
            if response.status_code == 200:
                self.html_content = response.text
                self.soup = BeautifulSoup(self.html_content, "html.parser")
                return True
            self.last_error = f"status_code={response.status_code}"
        except Exception as exc:
            self.last_error = str(exc)
            return False
        return False

    def run_checks(self) -> dict:
        """Run all content checks and return a risk result dict."""
        fetched = self.fetch_content()
        if not fetched:
            return {
                "status": "unknown",
                "unknown_reason": "content_unavailable",
                "error": self.last_error,
                "content_fetched": False,
                "page_title": "",
                "visible_text_length": 0,
                "login_form_present": False,
                "form_count": 0,
                "password_field_count": 0,
                "input_field_count": 0,
                "nav_link_count": 0,
                "image_count": 0,
                "image_domains": [],
                "free_host": False,
                "host_provider": "",
                "brand_candidate_count": 0,
                "brand_mismatch": False,
                "brand_path_match": False,
                "suspicious_keywords": False,
                "hidden_elements": False,
                "password_on_http": False,
                "risk_score": 0,
                "impersonation_reasons": [],
                "brand_candidates": [],
            }

        assert self.soup is not None
        page_title = self._page_title()
        visible_text = self._visible_text()
        heading_texts = self._heading_texts()
        forms = self.soup.find_all("form")
        form_stats = self._form_stats(forms)
        image_domains = self._image_domains()
        form_action_domains = self._form_action_domains(forms)
        nav_link_count = self._nav_link_count()
        hidden = self._check_hidden_elements()
        brand_candidates = self._brand_candidates(
            page_title=page_title,
            visible_text=visible_text,
            heading_texts=heading_texts,
            image_domains=image_domains,
            form_action_domains=form_action_domains,
        )
        primary_candidate = self._select_primary_brand_candidate(brand_candidates)
        detected_brand = primary_candidate.brand if primary_candidate else ""
        detected_profile = self._profile_by_name(detected_brand)
        brand_mismatch = self._brand_mismatch(primary_candidate, detected_profile)
        brand_path_match = self._brand_path_match()
        suspicious_hits = self._suspicious_phrase_hits(page_title=page_title, visible_text=visible_text)
        host_provider = guess_host_provider(self.target.host) or ""
        free_host = bool(host_provider)
        login_form_present = form_stats["password_field_count"] > 0 or form_stats["form_count"] > 0
        form_action_mismatch = bool(
            form_action_domains
            and detected_profile
            and brand_mismatch
            and any(self._domain_mismatch(action_domain, detected_profile) for action_domain in form_action_domains)
        )
        no_navigation_menu = nav_link_count == 0 and login_form_present
        password_on_http = form_stats["password_field_count"] > 0 and self.target.scheme != "https"
        content_keyword_flag = bool(suspicious_hits)
        hidden_elements = hidden
        risk_score, reasons = self._impersonation_score(
            login_form_present=login_form_present,
            password_field_count=form_stats["password_field_count"],
            input_field_count=form_stats["input_field_count"],
            free_host=free_host,
            brand_mismatch=brand_mismatch,
            brand_path_match=brand_path_match,
            suspicious_hits=suspicious_hits,
            form_action_mismatch=form_action_mismatch,
            no_navigation_menu=no_navigation_menu,
            hidden_elements=hidden_elements,
            password_on_http=password_on_http,
            brand_candidates=brand_candidates,
        )

        return {
            "status": "ok",
            "content_fetched": True,
            "page_title": page_title,
            "heading_texts": heading_texts,
            "visible_text": visible_text[:2000],
            "visible_text_length": len(visible_text),
            "form_count": form_stats["form_count"],
            "login_form_present": login_form_present,
            "password_field_count": form_stats["password_field_count"],
            "input_field_count": form_stats["input_field_count"],
            "nav_link_count": nav_link_count,
            "image_count": len(image_domains),
            "image_domains": image_domains,
            "external_image_domain_count": len([domain for domain in image_domains if domain and domain != self.target.host]),
            "form_action_count": len(form_action_domains),
            "form_action_domains": form_action_domains,
            "form_action_mismatch": form_action_mismatch,
            "free_host": free_host,
            "host_provider": host_provider,
            "brand_candidate_count": len(brand_candidates),
            "detected_brand": detected_brand,
            "brand_candidates": [candidate.as_dict() for candidate in brand_candidates],
            "brand_mismatch": brand_mismatch,
            "brand_path_match": brand_path_match,
            "brand_mention_count": len(brand_candidates),
            "suspicious_phrase_hits": suspicious_hits,
            "suspicious_keywords": content_keyword_flag,
            "hidden_elements": hidden_elements,
            "password_on_http": password_on_http,
            "no_navigation_menu": no_navigation_menu,
            "impersonation_reasons": reasons,
            "risk_score": risk_score,
        }

    def _page_title(self) -> str:
        """Extract the page title from the soup."""
        if not self.soup:
            return ""
        title_tag = self.soup.find("title")
        return title_tag.get_text(" ", strip=True) if title_tag else ""

    def _visible_text(self) -> str:
        """Extract visible text from the soup, collapsing whitespace."""
        if not self.soup:
            return ""
        text = self.soup.get_text(" ", strip=True)
        return re.sub(r"\s+", " ", text).strip()

    def _heading_texts(self) -> list[str]:
        """Extract text from h1, h2, and h3 tags."""
        if not self.soup:
            return []
        headings = []
        for tag_name in ("h1", "h2", "h3"):
            for tag in self.soup.find_all(tag_name):
                value = tag.get_text(" ", strip=True)
                if value:
                    headings.append(value)
        return headings[:12]

    def _form_stats(self, forms) -> dict[str, int]:
        """Count forms, password fields, and input fields."""
        password_count = 0
        input_count = 0
        form_count = 0
        if not self.soup:
            return {"form_count": 0, "password_field_count": 0, "input_field_count": 0}
        for form in forms:
            form_count += 1
            for element in form.find_all("input"):
                input_count += 1
                input_type = str(element.get("type", "")).lower()
                if input_type == "password":
                    password_count += 1
        return {
            "form_count": form_count,
            "password_field_count": password_count,
            "input_field_count": input_count,
        }

    def _nav_link_count(self) -> int:
        """Count navigation links inside <nav> elements."""
        if not self.soup:
            return 0
        nav_links = 0
        for nav in self.soup.find_all("nav"):
            nav_links += len(nav.find_all("a"))
        return nav_links

    def _image_domains(self) -> list[str]:
        """Extract unique image source domains."""
        if not self.soup:
            return []
        domains: list[str] = []
        for image in self.soup.find_all("img"):
            src = str(image.get("src") or "").strip()
            if not src:
                continue
            parsed = urlparse(src)
            domain = parsed.netloc.lower()
            if not domain and src.startswith("/"):
                domain = self.target.host
            if domain:
                domains.append(domain)
        return sorted(set(domains))

    def _form_action_domains(self, forms) -> list[str]:
        """Extract unique form action domains."""
        domains: list[str] = []
        for form in forms:
            action = str(form.get("action") or "").strip()
            if not action:
                continue
            parsed = urlparse(action)
            domain = parsed.netloc.lower()
            if not domain and not action.startswith("javascript:"):
                domain = self.target.host
            if domain:
                domains.append(domain)
        return sorted(set(domains))

    def _check_hidden_elements(self) -> bool:
        """Detect hidden iframes or display:none elements."""
        if not self.soup:
            return False
        for iframe in self.soup.find_all("iframe"):
            width = str(iframe.get("width", "100"))
            height = str(iframe.get("height", "100"))
            style = str(iframe.get("style", "")).lower()
            if width == "0" or height == "0" or "display: none" in style or "visibility: hidden" in style:
                return True
        return False

    def _brand_candidates(
        self,
        *,
        page_title: str,
        visible_text: str,
        heading_texts: list[str],
        image_domains: list[str],
        form_action_domains: list[str],
    ) -> list[BrandCandidate]:
        """Score brand profiles against page content and return top candidates."""
        lowered_title = page_title.lower()
        lowered_text = visible_text.lower()
        lowered_headings = " ".join(heading_texts).lower()
        lowered_path = f"{self.target.path} {self.target.query}".lower()
        image_blob = " ".join(image_domains).lower()
        action_blob = " ".join(form_action_domains).lower()

        candidates: list[BrandCandidate] = []
        for profile in self.brand_profiles:
            matched_fields: list[str] = []
            matched_phrases: list[str] = []
            score = 0
            normalized_name = normalize_brand_token(profile.name)
            search_tokens = {normalized_name, *(normalize_brand_token(alias) for alias in profile.aliases)}
            keyword_hits = set()

            for token in sorted(token for token in search_tokens if token):
                if token in normalize_brand_token(self.target.host):
                    matched_fields.append("host")
                    score += 12
                if token in normalize_brand_token(lowered_path):
                    matched_fields.append("path")
                    score += 6
                if token in normalize_brand_token(lowered_title):
                    matched_fields.append("title")
                    score += 8
                if token in normalize_brand_token(lowered_headings):
                    matched_fields.append("heading")
                    score += 8
                if token in normalize_brand_token(lowered_text):
                    matched_fields.append("body")
                    score += 5
                if token in normalize_brand_token(image_blob):
                    matched_fields.append("image")
                    score += 5
                if token in normalize_brand_token(action_blob):
                    matched_fields.append("form_action")
                    score += 5
                if token:
                    keyword_hits.add(token)

            has_brand_evidence = bool(matched_fields)
            for phrase in (*profile.login_phrases, *profile.suspicious_phrases):
                lowered_phrase = phrase.lower()
                if lowered_phrase and (
                    lowered_phrase in lowered_title
                    or lowered_phrase in lowered_text
                    or lowered_phrase in lowered_headings
                    or lowered_phrase in lowered_path
                ):
                    # Generic login copy like "sign in" appears on many legitimate pages.
                    # Only attach brand phrases after a real brand token/domain matched.
                    if phrase in profile.login_phrases and not has_brand_evidence:
                        continue
                    matched_phrases.append(phrase)
                    score += 4 if phrase in profile.login_phrases else 6

            if host_matches_brand(self.target.host, profile):
                matched_fields.append("official_domain")
                score += 10
            if any(keyword and keyword in lowered_path for keyword in profile.normalized_keywords()):
                matched_fields.append("path_keyword")
                score += 5

            if score > 0:
                candidates.append(
                    BrandCandidate(
                        brand=profile.name,
                        score=score,
                        matched_fields=tuple(sorted(set(matched_fields))),
                        matched_phrases=tuple(sorted(set(matched_phrases))),
                        official_domain_match=host_matches_brand(self.target.host, profile),
                    )
                )

        candidates.sort(key=lambda candidate: (candidate.score, len(candidate.matched_fields)), reverse=True)
        return candidates[:5]

    def _select_primary_brand_candidate(self, candidates: list[BrandCandidate]) -> BrandCandidate | None:
        """Choose the impersonation target without promoting weak SSO button matches."""
        if not candidates:
            return None

        for candidate in candidates:
            if candidate.official_domain_match:
                return candidate

        host_candidates = [
            candidate
            for candidate in candidates
            if self._has_primary_brand_evidence(candidate) and not self._is_weak_sso_candidate(candidate)
        ]
        if host_candidates:
            return host_candidates[0]

        for candidate in candidates:
            if self._has_primary_brand_evidence(candidate):
                return candidate
        return None

    def _has_primary_brand_evidence(self, candidate: BrandCandidate) -> bool:
        """Return True for fields that identify the page owner or impersonation target."""
        fields = set(candidate.matched_fields)
        return bool(fields & {"host", "official_domain", "path", "path_keyword", "title", "heading", "image"})

    def _is_weak_sso_candidate(self, candidate: BrandCandidate) -> bool:
        """Return True when a common SSO provider only appears as page-body login text."""
        if normalize_brand_token(candidate.brand) not in SSO_PROVIDER_BRANDS:
            return False
        if candidate.official_domain_match:
            return False
        fields = set(candidate.matched_fields)
        strong_fields = {"host", "official_domain", "path", "path_keyword", "title", "heading"}
        return not bool(fields & strong_fields)

    def _brand_mismatch(self, candidate: BrandCandidate | None, profile: BrandProfile | None) -> bool:
        """Return whether the selected primary brand conflicts with the host."""
        if not candidate or not profile:
            return False
        if candidate.official_domain_match or host_matches_brand(self.target.host, profile):
            return False
        if self._is_weak_sso_candidate(candidate):
            return False
        return self._has_primary_brand_evidence(candidate)

    def _profile_by_name(self, name: str) -> BrandProfile | None:
        """Look up a brand profile by its exact name."""
        for profile in self.brand_profiles:
            if profile.name == name:
                return profile
        return None

    def _brand_path_match(self) -> bool:
        """Return True if any brand token appears in the URL path or query."""
        lowered_path = f"{self.target.path} {self.target.query}".lower()
        return any(token and token in lowered_path for token in self._brand_tokens())

    def _brand_tokens(self) -> tuple[str, ...]:
        """Return all normalised brand tokens from loaded profiles."""
        tokens = []
        for profile in self.brand_profiles:
            tokens.extend(profile.normalized_keywords())
        return tuple(sorted(set(tokens)))

    def _suspicious_phrase_hits(self, *, page_title: str, visible_text: str) -> list[str]:
        """Find generic and brand-specific suspicious phrases in the page text."""
        corpus = f"{page_title} {visible_text}".lower()
        hits: list[str] = []
        for phrase in GENERIC_SUSPICIOUS_PHRASES:
            if phrase in corpus:
                hits.append(phrase)
        for profile in self.brand_profiles:
            for phrase in profile.suspicious_phrases:
                lowered_phrase = phrase.lower()
                if lowered_phrase in corpus:
                    hits.append(phrase)
        return sorted(set(hits))

    def _domain_mismatch(self, domain: str, profile: BrandProfile | None) -> bool:
        """Return True if the domain does not match the brand's official domains."""
        if not profile:
            return False
        normalized_domain = str(domain or "").lower()
        if not normalized_domain:
            return False
        if self._same_site_domain(normalized_domain, self.target.host):
            return False
        if host_matches_brand(normalized_domain, profile):
            return False
        return True

    def _same_site_domain(self, action_domain: str, host: str) -> bool:
        """Return True when a form posts to the current host or same site."""
        action = action_domain.split(":", 1)[0].lower().strip(".")
        current = str(host or "").split(":", 1)[0].lower().strip(".")
        if not action or not current:
            return False
        return action == current or action.endswith(f".{current}") or current.endswith(f".{action}")

    def _impersonation_score(
        self,
        *,
        login_form_present: bool,
        password_field_count: int,
        input_field_count: int,
        free_host: bool,
        brand_mismatch: bool,
        brand_path_match: bool,
        suspicious_hits: list[str],
        form_action_mismatch: bool,
        no_navigation_menu: bool,
        hidden_elements: bool,
        password_on_http: bool,
        brand_candidates: list[BrandCandidate],
    ) -> tuple[int, list[str]]:
        """Calculate a risk score and list of reasons from content signals."""
        score = 0
        reasons: list[str] = []

        if login_form_present:
            score += 2
            reasons.append("login form detected")
        if password_field_count > 0:
            score += min(6, 2 + password_field_count * 2)
            reasons.append(f"{password_field_count} password field(s)")
        if input_field_count >= 5:
            score += 4
            reasons.append("multiple input fields")
        if free_host:
            score += 18
            reasons.append(f"free host provider: {guess_host_provider(self.target.host) or 'unknown'}")
        if brand_mismatch:
            score += 25
            reasons.append("brand text does not match host")
        if brand_path_match:
            score += 6
            reasons.append("brand keyword appears in the URL path")
        if suspicious_hits:
            score += min(15, 4 * len(suspicious_hits))
            reasons.append("suspicious login language found")
        if form_action_mismatch:
            score += 12
            reasons.append("form action points away from the brand host")
        if no_navigation_menu:
            score += 4
            reasons.append("page has a login form but no navigation")
        if hidden_elements:
            score += 15
            reasons.append("hidden page elements detected")
        if password_on_http:
            score += 30
            reasons.append("password field appears on a non-HTTPS page")
        primary_candidate = self._select_primary_brand_candidate(brand_candidates)
        if primary_candidate and not self._is_weak_sso_candidate(primary_candidate):
            score += min(8, primary_candidate.score // 3)
            if primary_candidate.matched_fields:
                reasons.append(f"brand candidate: {primary_candidate.brand}")
            if not primary_candidate.official_domain_match and brand_mismatch:
                score += 8
                reasons.append("brand candidate does not match an official domain")

        if free_host and brand_path_match:
            score += 10
            reasons.append("free host with brand in URL")
        if free_host and brand_mismatch:
            score += 15
            reasons.append("free host with brand mismatch")

        if score > 100:
            score = 100
        return score, list(dict.fromkeys(reasons))
