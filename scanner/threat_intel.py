"""Threat intelligence lookup wrapper.

Routes target lookups to the shared ``ThreatFeedCache`` managed by
``scanner.feed_ingest``. This module is a thin façade so higher-level
services do not need to interact directly with feed internals.
"""

from scanner.feed_ingest import ThreatFeedCache  # Project-local: threat feed cache with background refresh
from scanner.normalization import NormalizedTarget  # Project-local: canonical URL representation


class ThreatIntelScanner:
    """Performs threat-intel feed lookups for a given URL target."""

    def __init__(self, target: NormalizedTarget, feed_cache: ThreatFeedCache):
        """Initialise with a normalised target and an active feed cache."""
        self.target = target
        self.feed_cache = feed_cache

    def run_checks(self) -> dict:
        """Return the feed cache lookup result for this target."""
        return self.feed_cache.lookup(self.target)
