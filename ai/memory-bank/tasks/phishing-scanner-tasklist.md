# Phishing Scanner Development Tasks

## Specification Summary
**Original Requirements**:
- Scan phishing URLs with separate and combined checks.
- Use OpenPhish and VT-style gzip snapshots as threat-intel sources.
- Provide API endpoints and a simple web view.
- Keep feed processing cached and practical for production-like use.

**Technical Stack**: Python, FastAPI, requests, BeautifulSoup, python-whois
**Target Timeline**: 1-2 iterative hardening cycles

## Development Tasks

### [ ] Task 1: URL Normalization and Input Validation
**Description**: Normalize incoming URLs once and share normalized fields across scanners.
**Acceptance Criteria**:
- Raw input supports bare host input like `example.com`.
- Normalized output includes canonical URL, host, scheme, path, query, and IP flag.
- Invalid URL inputs return clear API errors.

**Files to Create/Edit**:
- `scanner/normalization.py`
- `main.py`

### [ ] Task 2: Feed Ingestion and Caching
**Description**: Ingest OpenPhish and VT snapshots into a shared cache with deduplication and threshold filtering.
**Acceptance Criteria**:
- OpenPhish entries are parsed and indexable.
- VT lines are parsed as `<source_count> <value>`.
- VT threshold is configurable with sensible default (>9 equivalent).
- Cache refresh metadata exposes timestamp and errors.

**Files to Create/Edit**:
- `scanner/feed_ingest.py`
- `scanner/settings.py`

### [ ] Task 3: Threat Intel Scanner Integration
**Description**: Replace stub threat-intel scanner with feed cache lookups.
**Acceptance Criteria**:
- Threat scan endpoint uses cache data, not hardcoded lists.
- Response includes match details and feed freshness information.
- Positive feed hit can drive threat score to high risk.

**Files to Create/Edit**:
- `scanner/threat_intel.py`
- `scanner/service.py`

### [ ] Task 4: Scanner Reliability Hardening
**Description**: Ensure each scanner reports clear status and unknown states.
**Acceptance Criteria**:
- Content/SSL/WHOIS failures return `status: unknown`.
- Combined scoring excludes unknown checks from weighted denominator.
- SSL scoring does not penalize valid certs only because issuer is not in a short allowlist.

**Files to Create/Edit**:
- `scanner/content.py`
- `scanner/ssl_check.py`
- `scanner/domain_age.py`
- `scanner/service.py`

### [ ] Task 5: API and Web View Consistency
**Description**: Keep API and web UI aligned with the same service output semantics.
**Acceptance Criteria**:
- Combined and separate scan endpoints remain available.
- Web page displays score, unknown checks, and feed status.
- Feed refresh endpoint is available and documented.

**Files to Create/Edit**:
- `main.py`
- `templates/index.html`
- `static/app.js`
- `static/styles.css`

### [ ] Task 6: Documentation and Runbook
**Description**: Update README for practical operation and known limits.
**Acceptance Criteria**:
- Includes environment variables and snapshot naming guidance.
- Includes feed refresh workflow and examples.
- Includes explicit disclaimer that scanner is heuristic and not guaranteed.

**Files to Create/Edit**:
- `README.md`

### [ ] Task 7: Regression and Degraded-State Tests
**Description**: Add tests for key workflows and operational edge cases.
**Acceptance Criteria**:
- Tests for URL normalization and VT line parsing.
- Tests for API combined endpoint and web page load.
- Tests for feed refresh error handling and stale-cache behavior.

**Files to Create/Edit**:
- `tests/test_normalization.py`
- `tests/test_feed_ingest.py`
- `tests/test_api.py`
- `tests/test_service.py`

## Quality Requirements
- [ ] No background shell process operators in commands.
- [ ] Keep functional scope realistic; avoid unrequested feature creep.
- [ ] API responses remain backward-compatible where possible.
- [ ] Tests pass locally before handoff.

## Technical Notes
**Special Instructions**:
- VT snapshot discovery is not guaranteed by endpoint; filenames should be configured.
- VT negative matches are informational context, not a hard allowlist.
