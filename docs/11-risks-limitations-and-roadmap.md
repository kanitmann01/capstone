# 11 Risks Limitations And Roadmap

## Current Limitations

### Detection model limits

- the scanner is heuristic and rules-based
- it does not guarantee that a low-risk result is safe
- it does not include ML classification or dynamic content execution

### External dependency limits

- content scanning depends on successful HTTP fetches
- SSL checks depend on reachable endpoints and valid handshakes
- WHOIS quality varies by target and provider
- threat-intelligence freshness depends on feed availability and operator
  configuration

### UX limits

- raw JSON is exposed directly in the browser
- explanations are more machine-readable than human-guided
- there is limited decision support beyond the risk score and check labels

### Repository limits

- the scanner lives alongside a large ancillary content subtree
- repository scope may feel larger than the scanner codebase itself

## Key Risks

### False reassurance

The biggest product risk is that users may overtrust a low score when:

- one or more checks are unknown
- feeds are stale
- the target evades the current heuristics

### Configuration drift

Threat-intelligence quality depends on correctly maintained environment values,
especially VT snapshot filenames and refresh behavior.

### Operational variability

Because the scanner relies on live network interactions, results can vary due to
timeouts, third-party instability, or temporary failures.

## Mitigations Already Present

- explicit `unknown` check reporting
- stale-cache metadata in responses
- refresh-error metadata in responses
- combined scoring that excludes unknown modules
- baseline evaluation tooling
- tests for degraded feed behavior

## Recommended Next Improvements

### Product and detection

- add richer per-check explanations for human users
- expand heuristics with more URL deception patterns
- add redirect-chain analysis
- add page-form action inspection
- add richer threat-intel source management

### Reliability

- add more tests for normalization edge cases
- add tests for content-scanner degraded states
- add tests for WHOIS failure modes
- add structured logging around refresh lifecycle and scan timings

### Documentation and governance

- publish versioned release notes for scoring changes
- document known false-positive categories
- separate scanner and ancillary repo documentation if the workspace keeps growing

## Roadmap View

### Near term

- improve explainability
- tighten tests
- keep operational docs current

### Medium term

- improve threat-intel management
- add richer UI presentation
- add more evaluation reporting

### Long term

- consider more advanced phishing-detection signals
- separate scanner product assets from bundled ancillary content if ownership or
  scope diverges further
