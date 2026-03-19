# 09 Development Testing And Operations

## Local Setup

Install dependencies with:

```bash
pip install -r requirements.txt
```

Run the API with:

```bash
uvicorn main:app --reload
```

Primary local endpoints:

- app root: `http://localhost:8000/`
- API docs: `http://localhost:8000/docs`

## Configuration Model

The scanner uses environment-driven configuration through
`scanner/settings.py`. The most important settings fall into three groups.

### Feed settings

- `OPENPHISH_ENABLED`
- `OPENPHISH_URL`
- `VT_ENABLED`
- `VT_BASE_URL`
- `VT_POS_FILE`
- `VT_NEG_FILE`
- `VT_MIN_SOURCES`
- `VT_APPLY_MIN_SOURCES_TO_NEG`
- `FEED_REFRESH_MINUTES`
- `THREAT_INTEL_CACHE_DIR`

### Runtime settings

- `REQUEST_TIMEOUT_SECONDS`
- `ML_ENABLED`
- `ML_MODEL_PATH`
- `ML_METADATA_PATH`
- `ML_RUNS_DIR`
- `ML_DEFAULT_CRITERION`
- `ML_DEFAULT_MAX_DEPTH`
- `ML_DEFAULT_MIN_SAMPLES_SPLIT`
- `ML_DEFAULT_MIN_SAMPLES_LEAF`
- `ML_DEFAULT_TEST_SIZE`
- `ML_DEFAULT_RANDOM_STATE`
- `ML_DEFAULT_ACTIVATE_AFTER_TRAINING`

### Combined weight settings

- `WEIGHT_HEURISTICS`
- `WEIGHT_CONTENT`
- `WEIGHT_SSL`
- `WEIGHT_DOMAIN_AGE`
- `WEIGHT_THREAT_INTEL`
- `WEIGHT_ML`

## Test Coverage

The repository includes focused tests for:

- API endpoint behavior
- page rendering
- feed thresholding and deduplication
- refresh-error metadata
- stale-cache background refresh behavior
- SSL issuer handling
- baseline evaluation parsing and metrics
- ML feature extraction
- ML model loading and fallback behavior
- ML job API lifecycle

Run the test suite with:

```bash
pytest
```

## Operational Tasks

### Refreshing feeds

Use:

```bash
curl -X POST "http://localhost:8000/feeds/refresh"
```

This is useful after changing VT snapshot filenames or when operators want to
confirm the latest feed state immediately.

### Running a combined scan

```bash
curl -X POST "http://localhost:8000/scan/combined" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

### Running baseline evaluation

```bash
python evaluate_baseline.py baseline.csv baseline_scored.csv
```

### Generating an ML feature dataset

```bash
python scripts/generate_ml_dataset.py baseline.csv .cache\ml-data\baseline_features.csv
```

### Training the baseline decision tree

```bash
python scripts/train_ml_model.py baseline.csv --output-dir .cache\ml-runs\manual_run
```

### Running an ML-only probe

```bash
curl -X POST "http://localhost:8000/scan/ml" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

## Troubleshooting Guide

### Low score but uncertain trust

Check:

- `unknown_checks`
- `feed_freshness.stale_cache`
- `feed_freshness.refresh_error`

### Threat matches not appearing

Check:

- whether feeds are enabled
- whether VT filenames are configured
- whether the cache refreshed successfully
- whether the URL normalization matches feed format expectations

### Content or SSL checks missing

Check:

- network reachability
- timeout settings
- target availability
- whether the target uses HTTP rather than HTTPS

### WHOIS results unavailable

Check:

- registrar or WHOIS service reliability
- target type, especially IP inputs

### ML model unavailable

Check:

- whether `ML_ENABLED` is on
- whether the active model artifact exists at `ML_MODEL_PATH`
- whether the metadata file exists at `ML_METADATA_PATH`
- whether training dependencies from `requirements.txt` were installed
- whether the latest ML run completed successfully

## Maintenance Priorities

- keep endpoint behavior stable
- avoid hiding degraded states
- preserve normalization consistency
- monitor third-party data-source assumptions
- document any scoring changes alongside the corresponding rationale

## Handoff Notes

This project is maintainable because its behavior is concentrated in a small
set of source files. A new maintainer should start with:

1. `README.md`
2. `main.py`
3. `scanner/service.py`
4. `scanner/feed_ingest.py`
5. `tests/`
