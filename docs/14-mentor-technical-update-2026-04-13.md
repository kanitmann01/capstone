# Capstone Project: Technical Update & Feature Logic

**Project:** Containerized Phishing Scanner  
**Objective:** A triage tool for real-time phishing URL detection and evaluation.  
**Date:** 4/13/26

## Core Architecture & Request Flow

The application has recently evolved from a scanner-only prototype into a more complete hybrid detection workflow built on FastAPI. The current architecture combines deterministic security checks, page snapshot extraction, dataset persistence, and model evaluation into one explainable pipeline.

- **URL normalization logic:** Before scan logic runs, input URLs are normalized in `scanner/normalization.py` by trimming input, adding a missing scheme, lowercasing and canonicalizing hosts, normalizing default ports, preserving paths, sorting query parameters, and detecting IP-based targets.
  - **Why this matters:** Stable normalization improves consistency across repeated scans, threat-feed lookups, dataset rows, and feature extraction.
- **Hybrid request flow:** A scan request now goes through `app/service.py`, which extracts a page snapshot, scores the page with the rules baseline, runs the FastText detector, runs legacy security modules, optionally runs the structured ML feature model, and then combines available scores into one final verdict.
- **Weighted aggregation logic:** The final score is now a hybrid weighted blend:
  - `rules`: `0.35`
  - `fasttext`: `0.35`
  - `legacy`: `0.20`
  - `structured_ml`: `0.10`
- **Legacy scanner weighting:** Inside the legacy scanner bundle, the weighted average still uses environment-configured module weights:
  - `heuristics`: `0.20`
  - `content`: `0.30`
  - `ssl`: `0.15`
  - `domain_age`: `0.15`
  - `threat_intel`: `0.20`
- **Unknown-state handling:** If a check fails because of timeout, missing content, WHOIS issues, unavailable models, or network problems, that check returns `status: "unknown"` and is excluded from the weighted denominator instead of being treated as low risk.
  - **Why this matters:** This prevents broken dependencies from making a suspicious URL appear safer than it is.
- **Override logic for high-confidence cases:** Two recent logic safeguards are already in place:
  - If the page matches an official brand domain, the final score is forced to `0`.
  - If the page is on a free host and shows brand mismatch behavior, the final score is forced to `100`.

## What We Have Done Recently

Recent work has focused on making the capstone more complete, more explainable, and safer to demonstrate:

- Built a unified `AppService` flow that ties together scanning, scoring, persistence, model overview, evaluation, and training operations.
- Shifted the project toward a **FastText-first hybrid pipeline** instead of relying only on the earlier scanner modules.
- Added a **dataset-first workflow** that stores snapshots, extracted evidence, and scan outcomes in SQLite for later analysis.
- Added a dedicated **Dataset & Analysis** page and a **Results** page to make the project easier to demo and explain.
- Added a `POST /evaluate` workflow for labeled CSV input and safe scored-output download handling.
- Hardened the `/evaluate/download` route so it only serves valid CSV files from the expected ad hoc evaluation directory.
- Added a comprehensive project handbook in `docs/00-comprehensive-project-handbook.md` to improve technical handoff and mentor/reviewer visibility.
- Expanded threat-intelligence caching and metadata reporting so scans can report cache freshness and degraded feed conditions.
- Kept tests aligned with current combined scoring behavior as the hybrid weighting logic evolved.

## Detection Modules & Logic

The current system still uses modular scanners for purpose-specific evidence, but they now sit inside a broader hybrid scoring pipeline.

- **URL Heuristics** (`scanner/heuristics.py`)
  - **Features:** Checks IP-address targets, suspicious characters like `@`, excessive dot depth, long URLs, and deceptive keywords such as `login`, `verify`, or brand names in suspicious positions.
  - **Logic:** Additive, fast, and network-independent scoring capped at `100`.
- **Content Analysis** (`scanner/content.py`)
  - **Features:** Fetches HTML and parses it with BeautifulSoup to inspect forms, password fields, suspicious phrases, hidden elements, and visible page structure.
  - **Logic:** Returns explicit phishing-relevant evidence and uses `unknown` when the content fetch fails instead of silently downgrading the score.
- **SSL/TLS Validation** (`scanner/ssl_check.py`)
  - **Features:** Checks HTTPS certificate presence, expiration, self-signed state, and protocol version.
  - **Logic:** A valid verified handshake is treated as a trusted certificate path. Non-HTTPS or failed TLS checks degrade safely through `unknown`.
- **Domain Age & WHOIS** (`scanner/domain_age.py`)
  - **Features:** Queries WHOIS data and extracts domain creation date when available.
  - **Logic:** Domains younger than `30` days are treated as high risk, and domains younger than `180` days are treated as moderately risky. WHOIS failures do not become false reassurance.
- **Threat Intelligence** (`scanner/threat_intel.py`, `scanner/feed_ingest.py`)
  - **Features:** Looks up normalized URL, host, and IP values against cached external feed data.
  - **Logic:** Positive hit = `100`, negative-only hit = `5`, no hit = `0`. Negative matches are treated as context, not as a safe allowlist.
- **Rules Baseline** (`pipeline/evaluation/rules_baseline.py`)
  - **Features:** Scores page-level structural evidence such as login forms, password fields, suspicious phrases, free-host use, and brand mismatch.
  - **Logic:** Produces a transparent, explainable risk score and a list of reasons that can be shown directly in reports and the UI.
- **FastText Detector** (`pipeline/modeling/inference.py`)
  - **Features:** Uses serialized page snapshot text and tags to estimate whether a page looks like a phishing-style brand login page.
  - **Logic:** Acts as the primary text classifier in the current capstone direction. If no active model is available, the system returns `unknown` rather than failing the full scan.
- **Structured ML Features / Optional Model** (`scanner/ml_features.py`, `scanner/ml_model.py`)
  - **Features:** Converts normalized URL, page content, SSL state, threat context, and scanner outputs into numerical features for ML-based scoring.
  - **Logic:** Runs only when model artifacts are available and is safely excluded from the final weighted score when unavailable.

## Threat Intelligence & Caching Subsystem

The external threat-data layer has also been improved so it supports live demos without blocking every scan on feed refreshes.

- **Feed ingestion:** `scanner/feed_ingest.py` supports OpenPhish and VT-style snapshot ingestion.
- **Local lookup index:** Feed entries are normalized, deduplicated, and indexed by URL, host, and IP for repeated lookups.
- **Persistent caching:** The active cache is stored in `.cache/threat-intel/index.json` so the app can reuse prior feed state across restarts.
- **Asynchronous refresh behavior:** The feed cache supports immediate refreshes and stale-cache background refreshes, so a user scan does not have to wait for a full feed pull.
- **Freshness metadata returned to clients:** Scan responses now expose indicators such as `last_refresh_utc`, `refresh_error`, `refresh_in_progress`, and `stale_cache`.
  - **Why this matters:** Users and reviewers can see whether the threat-intelligence evidence is current, stale, or degraded.

## Data Science, ML Lab, & Baseline Evaluation

The project now has a stronger data-science story than it did earlier in the semester. Recent work connects live scanning to stored datasets, model training, and evaluation artifacts.

- **Baseline evaluation workflow** (`evaluate_baseline.py`, `pipeline/evaluation/evaluate.py`)
  - **Features:** Reads labeled CSV input, evaluates URLs through the live scanning stack, and writes enriched scored outputs.
  - **Logic:** Reports metrics including Accuracy, Precision, Recall, F1, confusion counts, row-level errors, false positives, and false negatives.
- **FastText training workflow**
  - **Features:** Reads labeled CSV rows, builds supervised FastText corpus lines from extracted snapshots, trains a model artifact, and stores model metadata.
  - **Logic:** Reuses the same snapshot and serialization logic used during inference to reduce training-serving drift.
- **Dataset persistence**
  - **Features:** SQLite storage captures URLs, HTML, visible text, detected brand context, labels, notes, and scan metadata.
  - **Logic:** This supports later threshold tuning, error analysis, dataset inspection, and reproducible capstone reporting.
- **Results and model overview**
  - **Features:** The `/results` page exposes current model availability, thresholds, artifact locations, and the latest evaluation report.
  - **Logic:** This makes the project easier to present as both a software system and a data-science experiment.

## Current Features Being Analyzed Per URL Request

The current request pipeline extracts and/or evaluates the following feature groups:

- **Lexical and structural URL metrics**
  - `url_length`, `host_length`, `path_length`, `query_length`
  - `num_dots`, `num_hyphens`, `num_digits`, `num_special_chars`
  - `subdomain_count`, `path_depth`, `query_param_count`
  - `has_at`, `is_ip`, `uses_https`
  - `host_entropy`, `path_entropy`
  - `suspicious_token_count`, `brand_token_count`
- **Page and form structure metrics**
  - `page_title_length`, `page_heading_count`
  - `form_count`, `login_form_present`, `password_field_count`, `input_field_count`
  - `nav_link_count`, `image_count`, `external_image_domain_count`, `form_action_count`
- **Brand impersonation and hosting signals**
  - `free_host_flag`, `brand_candidate_count`, `detected_brand_present`
  - `brand_mismatch_flag`, `brand_path_match`, `brand_mention_count`
  - `suspicious_phrase_count`, `form_action_mismatch`, `no_navigation_menu_flag`
- **Component risk scores**
  - `heuristics_score`, `content_score`, `ssl_score`, `domain_age_score`, `threat_intel_score`
  - `unknown_check_count`
- **Content and SSL indicators**
  - `content_available`, `password_on_http`, `content_keyword_flag`, `hidden_elements_flag`
  - `ssl_valid_cert`, `ssl_self_signed`, `ssl_old_protocol`
- **Threat-intel and domain context**
  - `domain_age_days`, `domain_age_known`
  - `threat_match_found`, `threat_positive_matches`, `threat_negative_matches`

## Way Forward - Goals For This Week

- Break the project into smaller student-owned modules so stakeholders can work in parallel without stepping on the same files.
- Assign one group to detection logic and scoring improvements, especially explainability and false-positive review.
- Assign one group to dataset and evaluation work, including threshold comparison, confusion-matrix reporting, and error analysis.
- Assign one group to UI and presentation polish for the Scan, Dataset, and Results pages.
- Assign one group to testing and reliability, especially degraded-network cases, normalization edge cases, and feed-refresh behavior.
- Keep the mentor update focused on measurable outputs: what is now working end to end, what is being evaluated, and which modules each student team owns next.

## To-Do List

### API To Directly Call The Service

- Add or refine an API layer that directly exposes the core `AppService` scan flow for external consumers.
- Define a stable request and response contract for direct service calls, including URL input, score output, verdict, unknown checks, and supporting evidence.
- Make sure the API returns clear error messages for invalid URLs, timeouts, unavailable models, and degraded external dependencies.
- Add endpoint-level tests for direct service invocation and response validation.
- Document how external tools or teammates can call the API locally and in deployment.

### Containerize The Project

- Add a `Dockerfile` for the FastAPI application and required runtime dependencies.
- Add a `.dockerignore` file so local caches, virtual environments, and unnecessary artifacts are not copied into the image.
- Configure the container to run the main app entrypoint consistently for demos and grading.
- Verify environment-variable support inside the container for feed settings, model paths, cache paths, and dataset storage.
- Add container run instructions so the project can be started with one reproducible command.
- If needed, add a `docker-compose.yml` or equivalent setup to simplify local development and future deployment.
