from __future__ import annotations

"""
URL parsing and canonicalisation utilities.

Provides ``NormalizedTarget``-an immutable dataclass that represents a
canonical URL with sorted query parameters, normalised host, and explicit
scheme. Also includes helpers for feed-value normalisation.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import ipaddress  # Standard library: IP address validation
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse  # Standard library: URL parsing and reconstruction


@dataclass(frozen=True)
class NormalizedTarget:
    """Immutable canonical representation of a parsed URL."""

    original: str
    normalized_url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    is_ip: bool


def is_ip_address(value: str) -> bool:
    """Return True if the supplied string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    """Lower-case and strip trailing dots from a hostname."""
    return host.strip().lower().rstrip(".")


def normalize_input_url(raw_url: str) -> NormalizedTarget:
    """Parse and canonicalise a raw URL string.

    Ensures a scheme is present, sorts query parameters alphabetically,
    strips default ports (80/443), and flags IP-based hosts.
    """
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("URL is required.")

    if "://" not in value:
        value = f"http://{value}"

    parsed = urlparse(value)
    host = normalize_host(parsed.hostname or "")
    if not host:
        raise ValueError("URL host is missing or invalid.")

    scheme = (parsed.scheme or "http").lower()
    path = parsed.path or "/"
    sorted_query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))

    port = parsed.port
    # Remove default ports for canonical comparisons.
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = host if port is None else f"{host}:{port}"
    normalized_url = urlunparse((scheme, netloc, path, "", sorted_query, ""))

    return NormalizedTarget(
        original=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=sorted_query,
        is_ip=is_ip_address(host),
    )


def normalize_feed_value(value: str) -> tuple[str, str] | None:
    """
    Normalise feed values into lookup keys.

    Returns tuple(kind, key), where kind is one of:
    - "url"
    - "host"
    - "ip"
    """
    raw = (value or "").strip()
    if not raw:
        return None

    if "://" in raw:
        target = normalize_input_url(raw)
        return ("url", target.normalized_url)

    host_candidate = normalize_host(raw)
    if is_ip_address(host_candidate):
        return ("ip", host_candidate)

    # Accept bare hostnames from feeds.
    if "." in host_candidate:
        return ("host", host_candidate)

    return None
