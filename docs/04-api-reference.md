# 04 API Reference

## API Surface

The application exposes a small, focused HTTP API intended for direct user
scans, per-check debugging, and feed operations.

## Base URLs

- API base: `http://localhost:8000`
- Web UI: `http://localhost:8000/`
- OpenAPI docs: `http://localhost:8000/docs`

## Common Request Body

All scan endpoints accept the same JSON shape:

```json
{
  "url": "example.com/login"
}
```

The service accepts bare hosts and normalizes them into a canonical URL before
scanning.

## Endpoints

### `GET /`

Returns the web application shell rendered from `templates/index.html`.

### `POST /scan/combined`

Runs all available checks and returns:

- normalized URL
- combined weighted `risk_score`
- `contributing_checks`
- `unknown_checks`
- `feed_freshness`
- `details` for every check

This is the primary endpoint for general use.

### `POST /scan/heuristics`

Runs only URL-structure and keyword-based heuristics.

### `POST /scan/content`

Fetches page HTML and evaluates content-oriented indicators such as:

- password fields on non-HTTPS pages
- suspicious page text
- hidden iframe-like elements

### `POST /scan/ssl`

Performs certificate and protocol inspection for HTTPS targets. Non-HTTPS URLs
return an `unknown` status rather than a misleadingly safe result.

### `POST /scan/whois`

Performs WHOIS lookups and computes domain age signals. IP targets are skipped
with an `unknown` status because WHOIS domain logic does not apply.

### `POST /scan/threats`

Looks up the normalized target in the cached threat-intelligence indexes.

### `POST /feeds/refresh`

Triggers an immediate feed refresh and returns:

- `status`
- `feed_freshness`

## Error Semantics

Invalid URLs are translated into HTTP 400 responses. Operational failures
inside individual scanner modules are generally surfaced inside the module
result as `status: "unknown"` instead of failing the whole combined request.

## Response Patterns

### Combined scan example structure

```json
{
  "url": "http://example.com/login",
  "risk_score": 42.0,
  "contributing_checks": ["heuristics", "content"],
  "unknown_checks": ["ssl"],
  "feed_freshness": {
    "last_refresh_utc": "2026-01-01T00:00:00+00:00",
    "last_refresh_attempt_utc": "2026-01-01T00:00:00+00:00",
    "refresh_error": null,
    "refresh_in_progress": false,
    "stale_cache": false,
    "cache_dir": ".cache/threat-intel",
    "vt_pos_file": "pos.gz",
    "vt_neg_file": "neg.gz"
  },
  "details": {
    "heuristics": {
      "status": "ok",
      "risk_score": 30
    }
  }
}
```

### Unknown result pattern

Modules that cannot produce a trustworthy answer should return a shape similar
to this:

```json
{
  "status": "unknown",
  "unknown_reason": "content_unavailable",
  "risk_score": 0
}
```

The service then excludes that module from the combined denominator.

## Operational Guidance

- Prefer `POST /scan/combined` for normal use.
- Review `unknown_checks` before trusting a low score.
- Review `feed_freshness.stale_cache` and `feed_freshness.refresh_error` when
  threat-intelligence certainty matters.
- Use separate scan endpoints for debugging or targeted validation.
