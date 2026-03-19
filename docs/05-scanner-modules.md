# 05 Scanner Modules

## Module Overview

The scanner is composed of small, purpose-specific modules. Each one produces a
bounded set of signals and an independent `risk_score`, making the overall
system easier to reason about and maintain.

## URL Normalization

File: `scanner/normalization.py`

Normalization happens before any scan logic runs. It:

- trims input
- adds `http://` when the scheme is omitted
- validates the host
- lowercases and canonicalizes the host
- normalizes default ports
- preserves path
- sorts query parameters for stable comparisons
- detects whether the host is an IP address

This is important because feed lookups, repeated scans, and scoring all depend
on stable canonical forms rather than raw user input.

## URL Heuristics

File: `scanner/heuristics.py`

The heuristics module checks lightweight URL features:

- IP-address targets
- unusually long URLs
- suspicious characters such as `@`
- excessive dot depth
- keyword masking patterns involving words such as `login`, `verify`, or
  brand names in suspicious locations

The scoring model is additive and capped at 100. This module is fast and does
not require network access, making it a reliable baseline signal source.

## Content Analysis

File: `scanner/content.py`

The content scanner fetches the page and parses it with BeautifulSoup. It looks
for:

- password fields on non-HTTPS pages
- suspicious text such as urgent verification language
- hidden iframe-like elements

If the fetch fails or the content is unavailable, the module returns
`status: "unknown"` with an error description instead of forcing a misleading
content verdict.

## SSL/TLS Validation

File: `scanner/ssl_check.py`

The SSL module is relevant only for HTTPS targets. It checks:

- certificate availability
- certificate expiration
- self-signed certificates
- negotiated protocol version

It intentionally avoids an oversimplified issuer allowlist. A successfully
verified handshake is treated as a trusted issuer chain, which is a more
practical rule for this project's scope.

## Domain Age and WHOIS

File: `scanner/domain_age.py`

This module:

- queries WHOIS data for the domain
- extracts creation date
- computes age in days
- raises risk for very new domains

The current implementation treats domains younger than 30 days as high risk and
domains younger than 180 days as moderately elevated. WHOIS failures result in
`status: "unknown"`.

## Threat Intelligence

Files: `scanner/threat_intel.py`, `scanner/feed_ingest.py`

Threat intelligence is intentionally split:

- `scanner/threat_intel.py` is a thin adapter
- `scanner/feed_ingest.py` owns the real ingestion, persistence, and lookup work

Lookup behavior is simple and explainable:

- positive feed matches produce a risk score of 100
- negative feed matches produce informational context with a low score
- no match produces a zero threat-intel score

## Combined Scoring

File: `scanner/service.py`

Combined scoring uses environment-configured weights:

- heuristics: `0.20`
- content: `0.30`
- ssl: `0.15`
- domain age: `0.15`
- threat intel: `0.20`

Only modules with `status: "ok"` contribute to the weighted denominator.
Modules that return `unknown` are listed separately and excluded from the
average.

## Design Strengths

- per-module responses are easy to inspect
- degraded modules do not poison the score silently
- each module can be tested in isolation
- normalization is centralized instead of duplicated

## Design Limits

- heuristics are manually curated and limited in coverage
- content analysis is shallow and depends on successful HTML fetches
- SSL posture is basic and does not cover advanced certificate analysis
- WHOIS quality varies by registrar and TLD
- threat intelligence is only as current as the cached feeds and configured
  snapshots
