# Phishing Scanner Service Specification

## Project Goal
Build a practical phishing scanner web service that accepts a URL, runs multiple checks, and returns separate plus combined risk output through API and a lightweight web page.

## Functional Requirements
- Accept a URL input from API and web UI.
- Run these checks independently:
  - URL heuristics
  - page content analysis
  - SSL/TLS validation
  - domain age / WHOIS
  - threat-intel feed matching
- Provide combined weighted risk scoring.
- Expose separate and combined scan endpoints.
- Show scan results in a basic built-in web interface.

## Threat-Intel Data Sources
- OpenPhish feed:
  - `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`
- VT-style snapshot files:
  - endpoint pattern: `https://netstar.one/vt/{file}`
  - naming convention: `pos-{timestamp}.gz` and `neg-{timestamp}.gz`
  - line format: `<source_count> <url_or_ip_or_host>`
  - data is not deduplicated
  - default threshold: include entries with source count greater than 9

## Operational Requirements
- Feed data should be cached and reused across scans.
- Feed refresh should not block user scan requests.
- Expose feed freshness and refresh errors in API responses.
- Document snapshot configuration and refresh workflow.

## Quality Requirements
- Clearly mark unavailable checks as unknown.
- Avoid representing unknown/degraded checks as benign.
- Keep implementation scope realistic and maintainable.
- Include automated tests for normalization, feed ingestion, and API behavior.

## Target Stack
- Python
- FastAPI
- requests
- BeautifulSoup
- python-whois
