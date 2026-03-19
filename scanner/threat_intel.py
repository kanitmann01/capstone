from scanner.feed_ingest import ThreatFeedCache
from scanner.normalization import NormalizedTarget

class ThreatIntelScanner:
    def __init__(self, target: NormalizedTarget, feed_cache: ThreatFeedCache):
        self.target = target
        self.feed_cache = feed_cache

    def run_checks(self) -> dict:
        return self.feed_cache.lookup(self.target)
