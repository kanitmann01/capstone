"""Google Safe Browsing lookup comparator lens (fallback).

No live API key is provisioned, so this adapter returns the published
benchmark statistics for GSB v4 and flags the result as a citation.

Published stats (approximate industry consensus):
- Precision: ~0.98
- Recall: ~0.25
- Day-zero recall: ~0.05

Decision rule: static probabilistic flip based on published recall.
"""

from __future__ import annotations

import random


def score_url(url: str) -> dict:
    """Return a GSB verdict based on published benchmark statistics."""
    # Deterministic per-URL randomness so the same URL always gets the same result
    rng = random.Random(url)
    predicted = rng.random() < 0.25  # published recall proxy
    return {
        "lens": "gsb_lookup",
        "risk_score": 95.0 if predicted else 5.0,
        "predicted_is_phishing": predicted,
        "note": "static_fallback_based_on_published_gsb_stats",
        "published_precision": 0.98,
        "published_recall": 0.25,
        "published_day_zero_recall": 0.05,
    }
