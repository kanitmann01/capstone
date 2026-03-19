# 06 Threat Intelligence And Caching

## Purpose

The threat-intelligence subsystem gives the scanner an evidence layer beyond
local heuristics. Instead of hardcoding malicious indicators, the project
downloads external feed data, normalizes it, and stores it in a reusable local
index for fast lookups.

## Data Sources

The project is currently designed around two source families:

- OpenPhish public feed
- VT-style gzip snapshots served from a configured base URL

The default OpenPhish URL is:

- `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`

The default VT-style base URL is:

- `https://netstar.one/vt`

## Ingestion Model

During refresh, `ThreatFeedCache` builds a new in-memory index and then swaps it
in as the active cache. This reduces the chance of partially refreshed data
being exposed to live lookups.

The feed index stores separate lookup maps for:

- normalized URLs
- hosts
- IP addresses

## VT Snapshot Parsing

The implementation expects VT-style lines shaped like:

```text
<source_count> <url_or_ip_or_host>
```

Example:

```text
12 https://bad.example/login
```

Important rules:

- positive snapshots apply `VT_MIN_SOURCES`
- negative snapshots can optionally apply the same threshold
- duplicate entries are deduplicated by key, keeping the highest source count

## Refresh Behavior

The cache supports two refresh modes:

- immediate refresh through `refresh_now()`
- non-blocking refresh through `refresh_if_stale()`

This matters because scan requests should not be forced to wait for a feed
download when stale-but-usable cached data is already present.

## Disk Persistence

The active index is saved to:

- `.cache/threat-intel/index.json`

On startup, the cache attempts to load this file so previous feed state can be
reused before the next refresh completes.

## Metadata Exposed To Clients

The service exposes feed-operational state in API responses, including:

- `last_refresh_utc`
- `last_refresh_attempt_utc`
- `refresh_error`
- `refresh_in_progress`
- `stale_cache`
- configured VT snapshot filenames

This is an important trust feature because it lets clients distinguish between:

- current feed-backed results
- stale cache usage
- refresh failures

## Lookup Semantics

Threat lookups are intentionally conservative and easy to interpret:

- positive hit: score `100`
- negative hit only: score `5`
- no hit: score `0`

Negative matches are treated as context rather than a hard allowlist. That
choice avoids the risky assumption that a negative snapshot proves safety.

## Operational Configuration

Relevant environment variables include:

- `OPENPHISH_ENABLED`
- `OPENPHISH_URL`
- `VT_ENABLED`
- `VT_BASE_URL`
- `VT_POS_FILE`
- `VT_NEG_FILE`
- `VT_MIN_SOURCES`
- `VT_APPLY_MIN_SOURCES_TO_NEG`
- `FEED_REFRESH_MINUTES`
- `THREAT_INTEL_CACHE_DIR`
- `REQUEST_TIMEOUT_SECONDS`

## Operational Risks

- feed providers may be unavailable
- configured snapshot filenames may be missing or stale
- cached data may age beyond the preferred refresh interval
- malformed feed rows may be skipped silently during normalization

## Why This Design Is Sensible

For this project size, the cache design is a good balance:

- simple enough to understand quickly
- transparent in failure cases
- fast on repeated lookups
- persistent across restarts

It avoids overengineering while still giving the scanner a meaningful external
signal source.
