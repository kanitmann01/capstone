from __future__ import annotations

"""
Brand profile data structures and loading utilities.

Maintains a JSON-based inventory of known brands (names, aliases, official
domains, logo keywords, and suspicious phrases). Provides helpers to load,
tokenise, and match brands against hosts and page content.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import json  # Standard library: JSON parsing
from functools import lru_cache  # Standard library: memoisation decorator
from collections.abc import Iterable  # Standard library: abstract base classes
from pathlib import Path  # Standard library: filesystem path abstraction
import re  # Standard library: regular expressions
from typing import Any  # Standard library: generic type hints

BRAND_PROFILE_VERSION = "brand_profiles_v1"
BRAND_PROFILE_PATH = Path(__file__).with_name("brand_profiles.json")


@dataclass(frozen=True)
class BrandProfile:
    """Immutable definition of a single brand's identity and detection keywords."""

    name: str
    aliases: tuple[str, ...]
    official_domains: tuple[str, ...]
    logo_keywords: tuple[str, ...]
    login_phrases: tuple[str, ...]
    suspicious_phrases: tuple[str, ...]

    def normalized_keywords(self) -> tuple[str, ...]:
        """Return a sorted tuple of normalised tokens derived from name, aliases, and logo keywords."""
        values = {normalize_brand_token(self.name)}
        values.update(normalize_brand_token(alias) for alias in self.aliases)
        values.update(normalize_brand_token(keyword) for keyword in self.logo_keywords)
        return tuple(sorted(value for value in values if value))


def normalize_brand_token(value: str) -> str:
    """Strip non-alphanumeric characters and lower-case a brand token."""
    cleaned = re.sub(r"[^a-z0-9]+", "", str(value or "").lower())
    return cleaned.strip()


def _coerce_str_tuple(values: Any) -> tuple[str, ...]:
    """Convert an iterable of values into a tuple of non-empty strings."""
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
        return ()
    return tuple(str(item).strip() for item in values if str(item).strip())


def _default_brand_records() -> list[dict[str, Any]]:
    """Load raw brand records from the default JSON file."""
    if not BRAND_PROFILE_PATH.exists():
        return []
    try:
        payload = json.loads(BRAND_PROFILE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    brands = payload.get("brands", [])
    return [item for item in brands if isinstance(item, dict)]


@lru_cache(maxsize=1)
def load_brand_profiles(path: str | Path | None = None) -> tuple[BrandProfile, ...]:
    """Load and cache brand profiles from a JSON file on disk."""
    source_path = Path(path) if path else BRAND_PROFILE_PATH
    if source_path.exists():
        try:
            payload = json.loads(source_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {"brands": _default_brand_records()}
    else:
        payload = {"brands": _default_brand_records()}

    brands = payload.get("brands", [])
    profiles: list[BrandProfile] = []
    for item in brands:
        if not isinstance(item, dict):
            continue
        profiles.append(
            BrandProfile(
                name=str(item.get("name") or "").strip(),
                aliases=_coerce_str_tuple(item.get("aliases")),
                official_domains=_coerce_str_tuple(item.get("official_domains")),
                logo_keywords=_coerce_str_tuple(item.get("logo_keywords")),
                login_phrases=_coerce_str_tuple(item.get("login_phrases")),
                suspicious_phrases=_coerce_str_tuple(item.get("suspicious_phrases")),
            )
        )
    return tuple(profile for profile in profiles if profile.name)


def all_brand_tokens(profiles: Iterable[BrandProfile] | None = None) -> tuple[str, ...]:
    """Return every unique normalised keyword across all loaded profiles."""
    tokens: set[str] = set()
    for profile in profiles or load_brand_profiles():
        tokens.update(profile.normalized_keywords())
    return tuple(sorted(token for token in tokens if token))


def build_brand_lookup(profiles: Iterable[BrandProfile] | None = None) -> dict[str, BrandProfile]:
    """Map each normalised brand token to its parent ``BrandProfile``."""
    lookup: dict[str, BrandProfile] = {}
    for profile in profiles or load_brand_profiles():
        for token in profile.normalized_keywords():
            lookup[token] = profile
    return lookup


def host_matches_brand(host: str, profile: BrandProfile) -> bool:
    """Return True if the host matches an official domain of the profile."""
    normalized_host = str(host or "").lower()
    if not normalized_host:
        return False
    for domain in profile.official_domains:
        domain = domain.lower().strip()
        if domain and (normalized_host == domain or normalized_host.endswith(f".{domain}")):
            return True
    return False


def guess_host_provider(host: str) -> str | None:
    """Detect free-hosting providers by suffix matching."""
    normalized_host = str(host or "").lower()
    free_host_patterns = {
        "vercel": ".vercel.app",
        "github": ".github.io",
        "netlify": ".netlify.app",
        "glitch": ".glitch.me",
        "render": ".onrender.com",
        "firebase": ".web.app",
        "pages": ".pages.dev",
    }
    for provider, pattern in free_host_patterns.items():
        if normalized_host.endswith(pattern):
            return provider
    return None
