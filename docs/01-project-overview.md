# 01 Project Overview

## Executive Summary

The primary application in this workspace is a FastAPI-based phishing scanner
that accepts a URL, runs multiple independent checks, and returns both
per-check details and a combined weighted risk score. It includes a lightweight
web interface, machine-readable API endpoints, cached threat-intelligence feed
lookups, and a CSV-based evaluation workflow for baseline testing.

The scanner is designed as a triage tool rather than a guaranteed detector.
That distinction is central to the project: a low score is not proof of safety,
and unavailable checks are reported as `unknown` so degraded conditions do not
silently look benign.

## Intended Users

- General employees or internal users who want a fast confidence check before
  opening a suspicious link.
- Developers maintaining the scanner API and check modules.
- Operators refreshing feeds, adjusting configuration, or running evaluations.
- Reviewers assessing the project for handoff or capstone submission.

## Core Capabilities

- URL normalization before any scan logic runs.
- Individual checks for:
  - URL heuristics
  - HTML content indicators
  - SSL/TLS certificate posture
  - WHOIS and domain age
  - Threat-intelligence feed matches
- Combined weighted scoring across successful checks only.
- Feed refresh metadata exposed in responses.
- Built-in web UI for direct scanning.
- Offline baseline evaluation using labeled CSV input.

## Project Goals

The implementation aligns with the service specification in
`ai/memory-bank/site-setup.md`:

- accept a URL from API or web UI
- perform separate and combined risk analysis
- cache threat-intelligence data instead of downloading it on every request
- preserve degraded-state visibility with explicit `unknown` responses
- keep the design realistic and maintainable

## What Success Looks Like

For a user, success means getting a quick result with enough detail to decide
whether to investigate further. For maintainers, success means the scanner is
easy to run, test, and extend without hiding operational problems such as stale
feeds, unreachable targets, or unavailable external services.

## Key Entry Points

- `main.py`: application bootstrap, routing, and web serving
- `scanner/service.py`: orchestration and combined scoring
- `scanner/feed_ingest.py`: feed download, parsing, persistence, and lookup
- `evaluate_baseline.py`: offline scoring and metrics workflow
- `templates/index.html` and `static/app.js`: browser experience

## Project Positioning

This is best understood as a practical, explainable phishing triage service
rather than a full anti-phishing platform. It emphasizes:

- transparent scoring
- bounded scope
- operational visibility
- simple deployment

It does not attempt to provide:

- browser isolation
- sandbox detonation
- ML-driven classification
- enterprise policy orchestration
- guaranteed malicious or safe verdicts
