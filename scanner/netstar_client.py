from __future__ import annotations

"""Client helpers for the NetSTAR Worker domain intelligence API."""

from typing import Any  # Standard library: generic type hints
from urllib.parse import quote  # Standard library: safe path segments

import requests  # Third-party: HTTP client


DEFAULT_NETSTAR_BASE_URL = "https://w4.netstar.dev"


class NetSTARClient:
    """Small typed wrapper around NetSTAR single-domain endpoints."""

    def __init__(self, *, base_url: str = DEFAULT_NETSTAR_BASE_URL, timeout: int = 10):
        """Initialise with API base URL and request timeout."""
        self.base_url = str(base_url or DEFAULT_NETSTAR_BASE_URL).rstrip("/")
        self.timeout = max(int(timeout or 10), 1)

    def get_cert(self, host: str, port: int = 443) -> dict[str, Any] | None:
        """Return TLS certificate analysis from /cert/{host}."""
        host_value = f"{host}:{port}" if port and int(port) != 443 else host
        return self._get_json("cert", host_value, timeout=max(self.timeout, 20))

    def get_rdap(self, host: str) -> dict[str, Any] | None:
        """Return registration analysis from /rdap/{host}."""
        return self._get_json("rdap", host, timeout=max(self.timeout, 15))

    def _get_json(self, endpoint: str, host: str, *, timeout: int) -> dict[str, Any] | None:
        """Call a NetSTAR GET endpoint and return JSON on success."""
        cleaned_host = str(host or "").strip().strip("/")
        if not cleaned_host:
            return None
        url = f"{self.base_url}/{endpoint}/{quote(cleaned_host, safe=':')}"
        try:
            response = requests.get(url, timeout=min(timeout, 30))
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        if int(payload.get("status") or 0) > 0:
            return None
        return payload
