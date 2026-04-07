# Comprehensive Project Handbook

Dense, single-source reference for the Capstone phishing / fake brand-login detector: product intent, runtime architecture, scoring logic, data contracts, APIs, configuration, offline tooling, and repository boundaries. Audience: engineers, reviewers, and capstone graders who need the whole system in one pass.

## 1. Purpose and product scope

- **Primary goal**: Triage suspicious URLs that may host **fake brand login pages** before a user enters credentials. Output is **explainable** (which signals fired) and **fail-safe** (missing data reduces certainty rather than implying safety).
- **What the system does**: Fetches HTML for a URL (when reachable), extracts visible text and form/brand cues, scores the page with a **rules baseline**, a **FastText** text classifier (when a model file exists), a **weighted bundle of legacy scanners** (heuristics, content-as-module, SSL, domain age, threat intel), and an optional **structured dense ML** model (`MLScanner`) over engineered features.
- **What the system does not claim**: It is not a full browser sandbox, not a legal verdict on maliciousness, and not a replacement for enterprise phishing stacks. JS-heavy SPAs may yield incomplete HTML snapshots.

## 2. Users, trust model, and interpretation

- **End users** (per design context): Non-technical employees who paste a link and need a **fast, calm** risk cue plus **why** the score moved.
- **Operators**: Tune thresholds, refresh feeds, inspect `unknown_checks` and `feed_freshness`, export datasets, retrain FastText.
- **Trust rules**:
  - Prefer **`unknown` / missing checks** over a false “clean”.
  - **`contributing_checks`** lists human-readable reasons; **`verdict.signals`** summarizes the composite story.
  - **Overrides** (official-domain match; free host + brand mismatch) short-circuit the numeric blend for clear-cut cases.

## 3. Repository structure (two-layer model)

| Layer | Role | Key paths |
| --- | --- | --- |
| **Product runtime** | Serves scans, dataset UI, evaluation | `app/`, `pipeline/`, `scanner/`, `templates/`, `static/`, `requirements.txt` |
| **Bundled collateral** | Agents, notes, archives (not imported at scan time) | `agency-agents/`, `ai/memory-bank/`, `old-data/` |

**Runtime-critical** directories: `app/`, `pipeline/`, `scanner/`, `templates/`, `static/`. Generated state lives under **`.cache/`** (threat intel index, SQLite dataset, FastText artifacts, evaluations, optional TensorFlow ML artifacts).

## 4. Application entry points

| Entry | Module | When to use |
| --- | --- | --- |
| **Primary (documented in README)** | `uvicorn app.api:app` | Current capstone: FastText-first hybrid, dataset pages, `/train/fasttext`, `/evaluate` |
| **Legacy / alternate** | `uvicorn main:app` or `python main.py` | Older ML Lab + TensorFlow-centric flows (`main.py`); still in tree for continuity—do not assume parity with `app/api.py` without diffing routes |

This handbook treats **`app/api.py` + `app/service.py`** as the authoritative HTTP surface unless you explicitly run `main.py`.

## 5. High-level architecture

1. **Normalize** raw URL → `NormalizedTarget` (`scanner/normalization.py`).
2. **Snapshot** page via `ContentScanner` → structured `content` dict + `raw_html` / visible text (`pipeline/extraction/html_parser.py` → `extract_page_snapshot`).
3. **Rules** score snapshot (`pipeline/evaluation/rules_baseline.py` → `score_rules`): additive risk with cap 100.
4. **FastText** scores serialized page text (`pipeline/modeling/inference.py` → `FastTextDetector.predict_text` on `serialize_snapshot` output).
5. **Legacy checks** run on same target + snapshot fields: `URLHeuristics`, content dict passthrough, `SSLValidator`, `DomainAgeScanner`, `ThreatIntelScanner` + `ThreatFeedCache`.
6. **Structured ML** (`scanner/ml_features.extract_features` + `scanner/ml_model.MLScanner`) produces an additional risk score when TensorFlow model artifacts exist.
7. **Hybrid blend** in `AppService._score_components`: fixed weights over `rules`, `fasttext`, aggregated `legacy`, `structured_ml`.
8. **Verdict** in `_build_verdict`: binary `phishing` vs `clean` using `CapstoneConfig.final_score_threshold` (default **30.0** on 0–100 scale).
9. **Persistence** (optional): `BrandLoginDatasetStore` SQLite row via `SnapshotRecord.create` / `add_snapshot`.

Data contracts: snapshots are plain `dict[str, Any]`; API responses are Pydantic-shaped via `app/schemas.py` (`ScanResponse`).

## 6. Scan pipeline (step-by-step, code order)

**Function**: `AppService.scan_url` (`app/service.py`).

1. `extract_page_snapshot(raw_url, scanner_settings)` builds the **canonical snapshot** (URL fields, content module output, brand impersonation summary, raw HTML).
2. `score_rules(snapshot)` → `rules` (`risk_score` 0–100, `reasons`, `prediction` at internal 50 cutoff).
3. `FastTextDetector.predict_text(serialize_snapshot(snapshot))` → optional prediction; missing model yields `None` → API exposes `fasttext.status = unknown`.
4. `_run_legacy_checks(target, snapshot)`:
   - `heuristics`: `URLHeuristics(target).run_checks()`
   - `content`: snapshot’s `content` dict (same structure `extract_features` expects)
   - `ssl`: `SSLValidator(target, settings).run_checks()`
   - `domain_age`: `DomainAgeScanner(target).run_checks()`
   - `threat_intel`: `ThreatIntelScanner(target, feed_cache).run_checks()`
5. `_run_structured_ml`: `extract_features(target, legacy_checks)` then `MLScanner.scan(features)`; exceptions → `structured_ml` unknown.
6. `_score_components`: weighted mean over available components only (denominator excludes missing).
7. `_build_verdict`: final label from threshold vs `scores["final"]`.
8. **Overrides** (after scores):
   - **Official domain**: if any `brand_candidates` has `official_domain_match`, force `final_score = 0`, label clean.
   - **Free host + brand mismatch**: force `final_score = 100`, label phishing.
9. `_persist_scan` if `persist=True` (default on API): writes SQLite snapshot with JSON `extraction` blob (rules, scores, checks, feed metadata, overrides).

## 7. Scoring mathematics

### 7.1 Hybrid component weights (`AppService._score_components`)

| Component | Weight | Source |
| --- | ---: | --- |
| `rules` | 0.35 | `score_rules` |
| `fasttext` | 0.35 | FastText probability × 100, or omitted if model unavailable |
| `legacy` | 0.20 | Weighted mean of legacy sub-scores (see below) |
| `structured_ml` | 0.10 | `MLScanner` risk_score if status ok, else omitted |

`final = sum(w_i * s_i) / sum(w_i)` over **available** components only.

### 7.2 Legacy sub-weights (`ScannerSettings` defaults / env overrides)

| Submodule | Default weight | Env var |
| --- | ---: | --- |
| heuristics | 0.15 | `WEIGHT_HEURISTICS` |
| content | 0.35 | `WEIGHT_CONTENT` |
| ssl | 0.10 | `WEIGHT_SSL` |
| domain_age | 0.10 | `WEIGHT_DOMAIN_AGE` |
| threat_intel | 0.20 | `WEIGHT_THREAT_INTEL` |

Submodule with `status != "ok"` is excluded from numerator and denominator (same pattern as `ScanService._weighted_score` in `scanner/service.py`).

### 7.3 Rules baseline point schedule (`score_rules`)

Additive, capped at 100: login form (+10), password fields (+ up to 20), free host (+20), brand mismatch (+25), brand in path (+10), form action mismatch (+12), suspicious phrases (+ up to 20), no nav menu (+8), password on HTTP (+20). Internal `prediction` uses **≥ 50** as phishing for rules-only label.

### 7.4 Verdict threshold

- `FINAL_SCORE_THRESHOLD` (default **30.0**): `final_score >= threshold` → `verdict.label = "phishing"`, else `"clean"`.
- FastText **model** threshold (`FASTTEXT_THRESHOLD`, default 0.5 on probability) affects label inside `FastTextDetector` usage indirectly via `score = probability * 100` only if you add separate decisioning—current hybrid uses raw score contribution, not a second threshold gate.

## 8. Feature and model tracks

| Track | Artifact / location | Role |
| --- | --- | --- |
| **FastText** | `.cache/fasttext/brand-login.bin` (+ `.json` metadata) | Primary text classifier over serialized snapshot tokens |
| **Structured ML** | `.cache/ml-artifacts/active_model.keras` (+ JSON metadata) | Dense NN on `FEATURE_FIELDS` from `scanner/ml_features.py` (`FEATURE_VERSION = ml_features_v2`) |
| **Rules** | Code in `rules_baseline.py` | Interpretable baseline, always available if snapshot exists |

**Offline dataset generation**: `scripts/generate_ml_dataset.py` drives `scanner/ml_training.generate_feature_dataset`, which calls `ScanService.scan_combined_with_progress` per row—useful for building CSVs of `FEATURE_FIELDS` + labels (heavy network cost).

## 9. Page snapshot and brand impersonation

`extract_page_snapshot` merges:

- **Content module** output: forms, fields, headings, suspicious phrases, host provider string, detected brand, candidates, mismatch flags, fetch status (`content_fetched`), etc.
- **Host features**: `is_free_host`, `host_provider` heuristics (`pipeline/extraction/host_features.py`).
- **Brand impersonation summary**: `summarize_brand_impersonation` (`pipeline/extraction/brand_match.py`) for API `brand_impersonation` and UI copy.

Raw HTML is stored on the scanner instance during fetch (`scanner/content.py`); snapshot exposes `raw_html` and optional `fetch_error`.

## 10. Threat intelligence (`ThreatFeedCache`)

**Purpose**: Fast lookups of URL / host / IP against downloaded feeds; conservative scoring.

**Sources** (when enabled):

- **OpenPhish** plain-text feed (`OPENPHISH_URL`).
- **PhishTank** JSON (`PHISHTANK_DATA_URL`, optional `PHISHTANK_APP_KEY` if URL template requires it).
- **VT-style gzip snapshots** from `VT_BASE_URL` + `VT_POS_FILE` / `VT_NEG_FILE` (filenames required—no auto-discovery).

**Semantics** (`feed_ingest.lookup`): positive hit → risk 100; negative-only hit → risk 5; no hit → 0. Negatives are **context**, not allowlisting.

**Persistence**: JSON index under `THREAT_INTEL_CACHE_DIR` (`index.json`). **Refresh**: `refresh_now()` rebuilds index; `refresh_if_stale()` triggers background thread when past `FEED_REFRESH_MINUTES`.

**API exposure**: `feed_freshness` on scan responses includes `last_refresh_utc`, `refresh_error`, `stale_cache`, `refresh_in_progress`, `cache_dir`.

## 11. Dataset store (SQLite)

**Class**: `BrandLoginDatasetStore` (`scanner/dataset_store.py`). **Schema version**: `brand_login_dataset_v2`.

**`SnapshotRecord`**: captures URL, host, timestamps, raw HTML, visible text, title, detected brand, host provider, risk score, prediction, optional human `label`, `notes`, and `extraction_json` (JSON blob of rules/scores/checks/metadata).

**API**: `GET /dataset/summary`, `GET /dataset/recent?limit=`.

## 12. HTTP API (current `app/api.py`)

Base URL assumed: `http://127.0.0.1:8000`. OpenAPI: `/docs`.

| Method | Path | Body / params | Response summary |
| --- | --- | --- | --- |
| GET | `/` | — | HTML scan demo (`templates/index.html`) |
| GET | `/dataset` | — | Dataset & analysis page |
| GET | `/evaluate` | — | Alias → dataset page |
| GET | `/results` | — | Results / model overview page |
| GET | `/ml` | — | Alias → results page |
| POST | `/scan/combined` | `URLRequest`: `url`, `persist` (default true) | `ScanResponse`: hybrid score, verdict, rules, fasttext, checks, contributing/unknown, artifacts |
| GET | `/dataset/summary` | — | JSON summary from SQLite |
| GET | `/dataset/recent` | `limit` (default 25) | Recent snapshot rows |
| GET | `/models/overview` | — | FastText availability, metadata path, thresholds, structured ML analytics |
| POST | `/evaluate` | `EvaluationJobRequest`: `filename`, `csv_content`, `threshold` | Report JSON + `download_url` for scored CSV |
| GET | `/evaluate/download` | `file` query: basename only, under `evaluation_dir/ad_hoc`, `.csv` only | File download |
| POST | `/train/fasttext` | `FastTextTrainingRequest`: `filename`, `csv_content`, `activate_after_training` | Training summary + artifact paths |

**CSV expectations** for training/evaluation helpers: rows must include **`url`** and **`is_phishing`** (truthy: `1,true,yes,...`; falsy otherwise) per `AppService._read_labeled_rows`.

**Note**: Older docs listing `/scan/content`, `/feeds/refresh`, etc., describe the **legacy `main.py` / `scanner/service.py`** style API—verify before teaching or testing against `app.api:app`.

## 13. Web UI

| Template | Route | Function |
| --- | --- | --- |
| `index.html` | `/` | Single URL scan demo |
| `dataset.html` | `/dataset` | Dataset summary, recent rows, evaluation threshold display |
| `results.html` | `/results` | Model overview, latest evaluation report embed |

Static assets: `static/` (JS/CSS). Navigation context built in `app/api.py` `page_context`.

## 14. Batch evaluation and experiments

- **In-app**: `POST /evaluate` writes uploaded CSV under `.cache/evaluations/ad_hoc/`, runs `pipeline.evaluation.evaluate.evaluate_csv` with `scorer(url)=scan_url`, returns metrics payload via `build_report_payload`.
- **CLI**: `python scripts/run_experiments.py <input.csv> <output_scored.csv>` (see README) for FastText-first comparison workflows.
- **Legacy**: `evaluate_baseline.py` remains for older baseline scoring experiments (see `tests/test_evaluate_baseline.py`).

## 15. Configuration reference

### 15.1 `CapstoneConfig` (`pipeline/shared/config.py`)

| Field | Env override | Default (conceptual) |
| --- | --- | --- |
| `dataset_db_path` | `CAPSTONE_DATASET_DB` | `.cache/brand-login-dataset.sqlite3` |
| `fasttext_model_path` | `FASTTEXT_MODEL_PATH` | `.cache/fasttext/brand-login.bin` |
| `fasttext_metadata_path` | `FASTTEXT_METADATA_PATH` | `.cache/fasttext/brand-login.json` |
| `fasttext_corpus_path` | `FASTTEXT_CORPUS_PATH` | `data/processed/fasttext_corpus.txt` |
| `evaluation_dir` | `CAPSTONE_EVALUATION_DIR` | `.cache/evaluations` |
| `request_timeout_seconds` | `REQUEST_TIMEOUT_SECONDS` | 8 |
| `fasttext_dim` / `epoch` / `lr` / `word_ngrams` / `min_count` / `loss` | `FASTTEXT_*` | 100 / 25 / 0.4 / 2 / 1 / softmax |
| `fasttext_threshold` | `FASTTEXT_THRESHOLD` | 0.5 |
| `final_score_threshold` | `FINAL_SCORE_THRESHOLD` | **30.0** |

### 15.2 `ScannerSettings` (`scanner/settings.py`)

Threat feeds: `OPENPHISH_*`, `PHISHTANK_*`, `VT_*`, `FEED_REFRESH_MINUTES`, `THREAT_INTEL_CACHE_DIR`, `REQUEST_TIMEOUT_SECONDS`.

ML artifact paths: `ML_MODEL_PATH`, `ML_METADATA_PATH`, `ML_REGISTRY_PATH`, `ML_RUNS_DIR`, `ML_ENABLED`, plus many `ML_DEFAULT_*` training defaults.

Weights: `WEIGHT_HEURISTICS`, `WEIGHT_CONTENT`, `WEIGHT_SSL`, `WEIGHT_DOMAIN_AGE`, `WEIGHT_THREAT_INTEL`, `WEIGHT_ML`.

## 16. Scripts inventory (selected)

| Script | Purpose |
| --- | --- |
| `scripts/build_fasttext_corpus.py` | Build supervised corpus from labeled CSV |
| `scripts/train_fasttext_model.py` | Train FastText binary + metadata |
| `scripts/run_experiments.py` | Batch scoring / experiment harness |
| `scripts/generate_ml_dataset.py` | ML feature CSV via live `ScanService` |
| `scripts/train_ml_model.py` | TensorFlow training from labeled CSV |
| `scripts/generate_project_documentation.py` | Merge `docs/*.md` → Word `project-documentation.docx` |
| `scripts/collect_brand_snapshots.py` | Dataset collection helper |
| `scripts/evaluate_live_urls.py` | Live URL evaluation utility |

## 17. Testing

Run `pytest` from repo root. Notable suites: `tests/test_api.py` (app routes), `tests/test_feed_ingest.py`, `tests/test_ssl_check.py`, `tests/test_ml_features.py`, `tests/test_ml_training.py`, `tests/test_brand_login_capstone.py`, `tests/test_fasttext_capstone.py`.

## 18. Security, privacy, and abuse

- Scanning **arbitrary user-supplied URLs** triggers outbound HTTP/TLS/WHOIS/threat-feed traffic—operate behind appropriate policy, logging, and rate limits for production.
- Persisted SQLite rows contain **raw HTML** and may include PII from target pages—protect `.cache/` and backups accordingly.
- Threat feeds are **third-party**; integrity depends on HTTPS and operator configuration of snapshot names.
- `/evaluate/download` accepts only a safe basename (`file=`) and resolves it under `evaluation_dir/ad_hoc` to avoid path traversal.

## 19. Limitations (condensed)

- No full browser rendering; dynamic pages may be under-sampled.
- Latency dominated by slowest network dependency per scan.
- VT snapshots require explicit filenames; empty config means no VT-derived hits.
- `unknown_checks` non-empty → interpret low scores cautiously.
- Two FastAPI apps (`app.api` vs `main`) can drift; confirm entry point when debugging.

## 20. Glossary

- **Snapshot**: Dict produced by `extract_page_snapshot` representing one URL fetch + derived fields.
- **Legacy checks**: Heuristics, content-as-dict, SSL, domain age, threat intel used inside `AppService`.
- **Hybrid score**: Weighted combination of rules, FastText, legacy aggregate, structured ML.
- **Verdict**: Thresholded label (`phishing` / `clean`) plus human-readable `reason` / `signals`.
- **Structured ML**: Keras-based classifier over `scanner/ml_features.FEATURE_FIELDS`.

---

*This handbook is authored for `docs/` and is included first in `scripts/generate_project_documentation.py` when generating `docs/project-documentation.docx`.*
