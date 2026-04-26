# Brand Guard (Fake Brand Login Detector)

Dataset-first **FastAPI** app for triaging suspicious links and fake brand login pages before anyone signs in. The **web UI** is branded **Brand Guard**; the stack combines a live page snapshot, interpretable rules, FastText text scoring, host heuristics, TLS and domain-age signals, optional threat-intel context, structured ML features, and domain-only brand recognition into one **explainable composite score** and verdict.

## Key features

- **Check a link** — single-scan web UI at `/` (`POST /scan/combined` powers the form)
- **How it works** — plain-language pipeline and scoring weights at `/how-it-works`
- **Data & evaluation** — dataset summaries and tools at `/dataset` (alias `/evaluate`)
- **Model metrics** — charts and evaluation summaries at `/results` (alias `/ml`)
- **Unified chrome** — one primary nav row on every page; sidebar is brand + home link only
- **API-first** combined scan with contributing checks, unknown checks, and brand evidence
- **SQLite snapshot store** for HTML, text, labels, and experiment rows
- **FastText corpus + training scripts** for the primary model path; optional offline / improved training helpers under `scripts/`
- **Fail-safe behavior** — unavailable checks report `status: "unknown"` (never implied “safe”)
- **Archive folder** `old-data/` for legacy datasets and generated outputs

## Tech stack

- **Backend**: FastAPI + Uvicorn
- **UI**: Jinja2 templates + static assets
- **ML**: FastText + lightweight evaluation helpers

## Quickstart

### Prerequisites

- **Python 3.12+** recommended

### Setup (Windows PowerShell)

```powershell
cd D:\Capstone
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Setup (macOS/Linux)

```bash
cd /path/to/Capstone
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
```

### Run (dev)

```bash
uvicorn app.api:app --reload
```

Open:

- **Check a link**: `http://127.0.0.1:8000/`
- **How it works**: `http://127.0.0.1:8000/how-it-works`
- **Data & evaluation**: `http://127.0.0.1:8000/dataset`
- **Model metrics**: `http://127.0.0.1:8000/results`
- **OpenAPI docs**: `http://127.0.0.1:8000/docs`

### Run (no reload; recommended for stability)

```bash
python -m uvicorn app.api:app --host 127.0.0.1 --port 8000
```

## API usage

### Combined scan

```bash
curl -X POST "http://127.0.0.1:8000/scan/combined" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

### HTML pages (same app)

| Path | Purpose |
|------|---------|
| `GET /` | Scan demo (paste URL, view verdict and signals) |
| `GET /how-it-works` | Explains normalization, snapshot, parallel detectors, and score blend |
| `GET /dataset` | Dataset stats, recent rows, evaluation tools |
| `GET /results` | Model files, metric charts, latest evaluation block |

### JSON / action endpoints

- `POST /scan/combined` — run the full hybrid scan on one URL (JSON body: `{"url": "..."}`)
- `GET /dataset/summary`
- `GET /dataset/recent`
- `GET /models/overview`
- `POST /evaluate`
- `POST /train/fasttext`

## Configuration

All configuration is environment-driven. Start with **`pipeline/shared/config.py`** (paths, `FINAL_SCORE_THRESHOLD`, FastText paths) and **`scanner/settings.py`** (timeouts, feeds, scanner toggles). The live **hybrid weights** for rules, FastText, legacy bundle, structured ML, and brand recognition are defined in **`app/service.py`** (`_score_components`); tune the overall cutoff with **`FINAL_SCORE_THRESHOLD`** rather than editing code when possible.

### Threat intel feeds

- **OpenPhish public feed**
  - Default: `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`
- **VT-style gzip snapshots**
  - Base URL default: `https://netstar.one/vt`
  - You must configure snapshot filenames via env vars (`VT_POS_FILE`, `VT_NEG_FILE`)

Expected VT line format:

```text
<source_count> <url_or_ip_or_host>
```

Example:

```text
12 https://bad.example/login
```

Only entries meeting `VT_MIN_SOURCES` are used for **positive** snapshots. Negative snapshot hits are stored as **context** (not a hard allowlist).

### Environment variables

| Variable | Default | Notes |
|---|---:|---|
| `OPENPHISH_ENABLED` | `true` | Enable OpenPhish ingestion |
| `OPENPHISH_URL` | (OpenPhish public feed) | Override feed URL |
| `VT_ENABLED` | `true` | Enable VT-style snapshots |
| `VT_BASE_URL` | `https://netstar.one/vt` | Base URL (no filename discovery) |
| `VT_POS_FILE` | *(empty)* | Positive snapshot filename (required to use) |
| `VT_NEG_FILE` | *(empty)* | Negative snapshot filename (optional) |
| `VT_MIN_SOURCES` | `10` | Minimum sources to accept positive entries |
| `VT_APPLY_MIN_SOURCES_TO_NEG` | `false` | Apply min-sources filter to negative snapshot |
| `FEED_REFRESH_MINUTES` | `30` | Auto-refresh cadence (best-effort) |
| `THREAT_INTEL_CACHE_DIR` | `.cache/threat-intel` | Cache location |
| `REQUEST_TIMEOUT_SECONDS` | `8` | Upstream request timeout |
| `WEIGHT_HEURISTICS` | `0.20` | Combined score weight |
| `WEIGHT_CONTENT` | `0.30` | Combined score weight |
| `WEIGHT_SSL` | `0.15` | Combined score weight |
| `WEIGHT_DOMAIN_AGE` | `0.15` | Combined score weight |
| `WEIGHT_THREAT_INTEL` | `0.20` | Combined score weight |
| `WEIGHT_ML` | `0.10` | Legacy combined score weight |
| `FASTTEXT_MODEL_PATH` | `.cache/fasttext/brand-login.bin` | Primary model artifact |
| `FASTTEXT_METADATA_PATH` | `.cache/fasttext/brand-login.json` | Model metadata |
| `FASTTEXT_CORPUS_PATH` | `data/processed/fasttext_corpus.txt` | Supervised corpus export |
| `FASTTEXT_THRESHOLD` | `0.5` | Decision threshold |
| `FASTTEXT_DIM` | `100` | Model embedding dimension |
| `FASTTEXT_EPOCH` | `25` | Training epochs |
| `FASTTEXT_LR` | `0.4` | Training learning rate |
| `FASTTEXT_WORD_NGRAMS` | `2` | Word n-gram size |
| `FASTTEXT_MIN_COUNT` | `1` | Minimum token count |
| `FASTTEXT_LOSS` | `softmax` | FastText loss |
| `FINAL_SCORE_THRESHOLD` | `30.0` | Composite score at or above → phishing-style verdict in the UI |
| `BRAND_PROFILES_PATH` | `scanner/brand_profiles.json` | Brand inventory used by content analysis |
| `CAPSTONE_DATASET_DB` | `.cache/brand-login-dataset.sqlite3` | SQLite snapshot store for captured pages |

## FastText workflow

Build the supervised corpus:

```bash
python scripts/build_fasttext_corpus.py phishing_features_extracted_6_features.csv
```

Train the primary model:

```bash
python scripts/train_fasttext_model.py data/processed/fasttext_corpus.txt
```

Run a comparison experiment:

```bash
python scripts/run_experiments.py phishing_features_extracted_6_features.csv .cache/evaluations/phishing_features_extracted_6_features_scored.csv
```

## Baseline evaluation

Use the new experiment runner for the FastText-first capstone:

```bash
python scripts/run_experiments.py phishing_features_extracted_6_features.csv .cache/evaluations/phishing_features_extracted_6_features_scored.csv
```

## Tests

```bash
pytest
```

Quick API / page smoke:

```bash
pytest tests/test_api.py -q
```

## Project documentation (DOCX)

This repo includes a generator that writes a Word doc into `docs/`:

```bash
python scripts/generate_project_documentation.py
```

Outputs: `docs/project-documentation.docx`

## Confidence guidance

- Treat the scan result as **triage**, not a final verdict.
- Investigate results where:
  - `unknown_checks` is non-empty
  - the brand/host story does not line up
  - the HTML and visible text look inconsistent with the claimed brand
- Prioritize manual review when the page looks like a login clone.

## Data Science Story

The capstone is designed as a supervised classification project with an explainable hybrid pipeline:

- collect phishing-page snapshots from live feeds before they disappear
- store HTML, visible text, labels, and brand metadata in SQLite
- engineer page, host, form, and brand-impersonation features
- compare heuristic, ML-only, and hybrid baselines
- evaluate with precision, recall, F1, confusion matrices, and threshold sweeps
- review false positives and false negatives as part of the final analysis

The strongest story for presentation is not just "the app catches phishing." It is "the model learns which page structures, text patterns, and hosting clues distinguish fake brand login pages from legitimate ones."

## Docker (API + scripts + tests)

This repo now supports a workflow-first Docker setup so you can run the full capstone (web app, training, evaluation, and reporting) from one reproducible image.

### 1) Prepare env file

```bash
cp .env.docker.example .env.docker
```

On Windows PowerShell:

```powershell
Copy-Item .env.docker.example .env.docker
```

Update `.env.docker` if you need VT/PhishTank credentials or custom paths.

### 2) Build and run the API/UI

```bash
docker compose up --build app
```

Open:

- Web UI: `http://127.0.0.1:8000/` (and `/how-it-works`, `/dataset`, `/results`)
- Docs: `http://127.0.0.1:8000/docs`

### 3) Run script workflows in Docker

Use the `job` service to run one-off commands with the same project image:

```bash
docker compose run --rm job python scripts/build_fasttext_corpus.py phishing_features_extracted_6_features.csv
docker compose run --rm job python scripts/train_fasttext_model.py data/processed/fasttext_corpus.txt
docker compose run --rm job python scripts/run_experiments.py phishing_features_extracted_6_features.csv .cache/evaluations/scored.csv
docker compose run --rm job python scripts/generate_ml_dataset.py phishing_features_extracted_6_features.csv .cache/evaluations/ml_dataset.csv
docker compose run --rm job python scripts/train_ml_model.py phishing_features_extracted_6_features.csv
docker compose run --rm job python scripts/generate_project_documentation.py
docker compose run --rm job pytest
```

For baseline API-client evaluation (`evaluate_baseline.py`), keep `app` running and use:

```bash
docker compose run --rm job python evaluate_baseline.py phishing_features_extracted_6_features.csv .cache/evaluations/baseline_output.csv --endpoint http://app:8000/scan/combined
```

### 4) Persistent state and outputs

`compose.yaml` mounts these directories so artifacts survive container restarts:
- `.cache/` (SQLite, threat-intel cache, model artifacts, evaluation outputs)
- `data/`
- `models/`
- `docs/`
- `old-data/`
