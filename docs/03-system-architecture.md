# 03 System Architecture

## Architecture Summary

The scanner uses a compact layered architecture:

1. HTTP entry via FastAPI.
2. Request normalization into a shared target representation.
3. Per-check scanner execution.
4. Weighted aggregation across successful checks.
5. Threat-feed metadata returned alongside results.
6. Optional web UI rendering for human users.

This architecture favors clarity over abstraction depth. The code is organized
so that each scanner module owns a narrow concern, while `ScanService` provides
the coordination point for combined scans.

## Request Flow

### Combined scan

1. A client sends `POST /scan/combined` with a URL payload.
2. `main.py` forwards the work into `scanner/service.py`.
3. `normalize_input_url()` canonicalizes the raw input.
4. The service runs the scanner modules in sequence:
   - heuristics
   - content
   - ssl
   - domain age
   - threat intelligence
5. Each module returns structured output including a `status` and `risk_score`.
6. The service excludes `unknown` modules from the weighted denominator.
7. The final response includes:
   - normalized URL
   - combined risk score
   - contributing checks
   - unknown checks
   - feed freshness metadata
   - per-check details

### Feed lookup and freshness

Threat-intelligence lookups are routed through `ThreatFeedCache`. The cache
loads persisted data from disk on startup, can refresh immediately, and can
also trigger non-blocking background refresh when data is stale.

## Main Components

### API layer

`main.py` defines the FastAPI application, mounts static assets, renders the
home page, and exposes scan plus feed-refresh endpoints. It also performs an
initial best-effort feed refresh during application lifespan startup.

### Service layer

`scanner/service.py` is the orchestration layer. It is responsible for:

- normalizing input once
- invoking scanner modules
- emitting progress events for evaluation tooling
- computing the weighted combined score
- separating contributing and unknown checks

### Scanner modules

Each module returns a self-contained dictionary rather than a custom class
hierarchy. That keeps the response shape easy to inspect and expose directly.

- `scanner/heuristics.py`: structural URL signals
- `scanner/content.py`: HTML-based page analysis
- `scanner/ssl_check.py`: certificate and protocol checks
- `scanner/domain_age.py`: WHOIS-based domain age signals
- `scanner/threat_intel.py`: feed cache lookups

### Feed subsystem

`scanner/feed_ingest.py` handles:

- downloading OpenPhish and VT-style snapshots
- threshold filtering
- deduplication
- lookup indexes by URL, host, and IP
- disk persistence
- stale-cache refresh behavior

### Settings layer

`scanner/settings.py` centralizes environment-driven configuration, including
feed behavior, timeouts, and combined-score weights.

## Data Contracts

The design leans on a few stable contracts:

- normalized targets are represented by `NormalizedTarget`
- each scan module returns `status`, signal fields, and `risk_score`
- combined scans return `details` keyed by module name
- degraded checks return `status: "unknown"` instead of pretending success

## Why Unknown States Matter

The most important architectural choice is that unavailable checks are treated
as unknown rather than low risk. This avoids a dangerous failure mode where a
network timeout, certificate issue, or WHOIS failure silently lowers the
overall score and gives false reassurance.

## Performance Characteristics

The implementation is simple and synchronous within the service layer, with
FastAPI using threadpool execution for blocking scan functions. That approach
fits the current scale and codebase size, but it implies:

- scan latency grows with the slowest external dependency
- content fetch, SSL handshake, WHOIS lookup, and feed operations all depend on
  network conditions
- concurrency is bounded by worker and threadpool resources

## Architectural Strengths

- clear separation between route handling and scan logic
- explainable per-check results
- explicit degraded-state handling
- practical feed caching
- testable modules with small responsibility boundaries

## Architectural Constraints

- sequential check execution for combined scans
- heavy reliance on external network services
- heuristic rules rather than learned or adaptive detection
- no persistence layer beyond feed cache artifacts
