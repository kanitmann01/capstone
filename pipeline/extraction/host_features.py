from __future__ import annotations

from scanner.brand_profiles import guess_host_provider


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
    normalized = str(host or "").lower().strip()
    if not normalized:
        return False
    if guess_host_provider(normalized):
        return True
    return any(normalized.endswith(suffix) for suffix in FREE_HOST_SUFFIXES)


def host_provider(host: str) -> str:
    provider = guess_host_provider(host)
    return provider or ""
