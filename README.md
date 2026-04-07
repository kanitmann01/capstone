# Fake Brand Login Detector

Dataset-first FastAPI capstone for detecting fake brand login pages before anyone signs in. It combines HTML/text inspection, host clues, brand-mismatch signals, rules baselines, and a FastText primary model into a single explainable verdict.

## Key features

- **Single-scan web UI** at `/`
- **Dataset & analysis** page at `/dataset`
- **Results** page at `/results`
- **API-first** combined scan endpoint with brand evidence
- **SQLite snapshot store** for HTML, text, labels, and experiment rows
- **FastText corpus + training scripts** for the primary model path
- **Fails-safe** behavior: unavailable checks report `status: "unknown"` (not “safe”)
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
- **Web UI**: `http://127.0.0.1:8000/`
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

### Dataset and results endpoints

- `GET /dataset/summary`
- `GET /dataset/recent`
- `GET /models/overview`
- `POST /evaluate`
- `POST /train/fasttext`

## Configuration

All configuration is environment-driven. See `pipeline/shared/config.py` and `scanner/settings.py` for the legacy scanner compatibility layer.

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
