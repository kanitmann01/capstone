from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


@dataclass(frozen=True)
class NormalizedTarget:
    original: str
    normalized_url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    is_ip: bool


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def normalize_input_url(raw_url: str) -> NormalizedTarget:
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
    Normalize feed values into lookup keys.

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
