from __future__ import annotations

"""
Host-based feature extraction.

Provides simple predicates to detect free-hosting providers
(e.g., Vercel, GitHub Pages, Netlify) and resolve host provider names.
"""

from scanner.brand_profiles import guess_host_provider  # Project-local: free-host detection


FREE_HOST_SUFFIXES = (
    ".vercel.app",
    ".github.io",
    ".netlify.app",
    ".glitch.me",
    ".onrender.com",
    ".pages.dev",
    ".web.app",
    ".firebaseapp.com",
)


def is_free_host(host: str) -> bool:
    """Return True if the host resolves to a known free-hosting provider."""
    normalized = str(host or "").lower().strip()
    if not normalized:
        return False
    if guess_host_provider(normalized):
        return True
    return any(normalized.endswith(suffix) for suffix in FREE_HOST_SUFFIXES)


def host_provider(host: str) -> str:
    """Return the free-hosting provider name, or an empty string if none matched."""
    provider = guess_host_provider(host)
    return provider or ""
