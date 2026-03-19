# Phishing Scanner

FastAPI web app + API for scanning suspicious links before opening them. It combines multiple signals (heuristics, content, SSL, WHOIS/domain age, threat intel, optional ML) into a **single risk score** and provides a simple **web UI** for non-technical users.

## Key features

- **Single-scan web UI** at `/`
- **API-first** scanning endpoints (combined + individual checks)
- **Threat-intel feed cache** with manual refresh endpoint
- **Batch evaluation + ML lab pages** (`/evaluate`, `/ml`) for model experimentation
- **Fails-safe** behavior: unavailable checks report `status: "unknown"` (not “safe”)

## Tech stack

- **Backend**: FastAPI + Uvicorn
- **UI**: Jinja2 templates + static assets
- **ML (optional)**: TensorFlow / scikit-learn (see `requirements.txt`)

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
uvicorn main:app --reload
```

Open:
- **Web UI**: `http://127.0.0.1:8000/`
- **OpenAPI docs**: `http://127.0.0.1:8000/docs`

### Run (no reload; recommended for stability)

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## API usage

### Combined scan

```bash
curl -X POST "http://127.0.0.1:8000/scan/combined" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

### Individual checks

- `POST /scan/heuristics`
- `POST /scan/content`
- `POST /scan/ssl`
- `POST /scan/whois`
- `POST /scan/threats`
- `POST /scan/ml`

Request body:

```json
{ "url": "example.com/login" }
```

## Configuration

All configuration is environment-driven (see `scanner/settings.py`).

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
| `WEIGHT_ML` | `0.0` | Combined score weight (set > 0 to contribute) |
| `ML_ENABLED` | `true` | Enables ML endpoints/overview |
| `ML_MODEL_PATH` | `.cache/ml-artifacts/active_model.keras` | Active model file |
| `ML_METADATA_PATH` | `.cache/ml-artifacts/active_model.json` | Model metadata |
| `ML_REGISTRY_PATH` | `.cache/ml-artifacts/model_registry.json` | Registry of trained models |
| `ML_RUNS_DIR` | `.cache/ml-jobs` | Training output directory |
| `ML_DEFAULT_MODEL_TYPE` | `tensorflow_dense` | Default training model type |
| `ML_DEFAULT_TEST_SIZE` | `0.2` | Training default |
| `ML_DEFAULT_RANDOM_STATE` | `42` | Training default |
| `ML_DEFAULT_EPOCHS` | `20` | Training default |
| `ML_DEFAULT_BATCH_SIZE` | `32` | Training default |
| `ML_DEFAULT_LEARNING_RATE` | `0.001` | Training default |
| `ML_DEFAULT_VALIDATION_SPLIT` | `0.2` | Training default |
| `ML_DEFAULT_DROPOUT_RATE` | `0.15` | Training default |
| `ML_DEFAULT_HIDDEN_UNITS` | `128,64` | Training default |
| `ML_DEFAULT_EARLY_STOPPING_PATIENCE` | `5` | Training default |
| `ML_DEFAULT_CLASSIFICATION_THRESHOLD` | `0.5` | Training default |
| `ML_DEFAULT_DEVICE` | `auto` | Training default |
| `ML_DEFAULT_ACTIVATE_AFTER_TRAINING` | `true` | Auto-activate newly trained model |

## Feed refresh workflow

1. Start the API.
2. (Optional) refresh feeds on-demand:

```bash
curl -X POST "http://127.0.0.1:8000/feeds/refresh"
```

Feed freshness metadata is included in scan responses (e.g. `last_refresh_utc`, `stale_cache`, `refresh_error`). Refresh is **non-blocking** for scan requests.

## Baseline evaluation (CSV)

Evaluate a labeled CSV against the running API:

```bash
python evaluate_baseline.py baseline.csv baseline_scored.csv
```

Expected input columns:
- `url`
- `is_phishing`

Optional args:

```bash
python evaluate_baseline.py baseline.csv baseline_scored.csv \
  --endpoint http://127.0.0.1:8000/scan/combined \
  --threshold 50 \
  --timeout 15
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

- Treat the combined score as **triage**, not a final verdict.
- Investigate results where:
  - `unknown_checks` is non-empty
  - `feed_freshness.stale_cache` is `true`
  - `feed_freshness.refresh_error` is non-empty
- Prioritize manual review when threat-intel reports positive feed matches.
