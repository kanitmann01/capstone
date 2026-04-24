from __future__ import annotations

"""
Re-export module for brand profile utilities.

Centralises imports from ``scanner.brand_profiles`` so downstream
pipeline modules can depend on this narrow interface rather than
reaching deep into the scanner package.
"""

from scanner.brand_profiles import BrandProfile  # Project-local: brand data class
from scanner.brand_profiles import all_brand_tokens  # Project-local: aggregate keyword list
from scanner.brand_profiles import build_brand_lookup  # Project-local: token -> profile mapping
from scanner.brand_profiles import guess_host_provider  # Project-local: free-host detection
from scanner.brand_profiles import host_matches_brand  # Project-local: official domain matching
from scanner.brand_profiles import load_brand_profiles  # Project-local: JSON loader
from scanner.brand_profiles import normalize_brand_token  # Project-local: token normalisation


__all__ = [
    "BrandProfile",
    "all_brand_tokens",
    "build_brand_lookup",
    "guess_host_provider",
    "host_matches_brand",
    "load_brand_profiles",
    "normalize_brand_token",
]
