"""Comparator lenses for the benchmark matrix.

Each module exposes a ``score_url(url: str) -> dict`` function that returns
a normalized verdict dict with at minimum:

- ``lens``: str
- ``risk_score``: float
- ``predicted_is_phishing``: bool
"""

from pipeline.comparators.heuristics_only import score_url as heuristics_only
from pipeline.comparators.netstar_lookup import score_url as netstar_lookup
from pipeline.comparators.hf_url_classifier import score_url as hf_url_classifier
from pipeline.comparators.gsb_lookup import score_url as gsb_lookup

__all__ = [
    "heuristics_only",
    "netstar_lookup",
    "hf_url_classifier",
    "gsb_lookup",
]
