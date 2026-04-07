# 09 Development Testing And Operations

## Local Setup

Install dependencies with:

```bash
pip install -r requirements.txt
```

Run the API with:

```bash
uvicorn app.api:app --reload
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
- `FASTTEXT_MODEL_PATH`
- `FASTTEXT_METADATA_PATH`
- `FASTTEXT_CORPUS_PATH`
- `FASTTEXT_THRESHOLD`
- `FASTTEXT_DIM`
- `FASTTEXT_EPOCH`
- `FASTTEXT_LR`
- `FASTTEXT_WORD_NGRAMS`
- `FASTTEXT_MIN_COUNT`
- `FASTTEXT_LOSS`

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

### Running a combined scan

```bash
curl -X POST "http://localhost:8000/scan/combined" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

### Running baseline evaluation

```bash
python scripts/run_experiments.py phishing_features_extracted_6_features.csv .cache/evaluations/phishing_features_extracted_6_features_scored.csv
```

### Building a FastText corpus

```bash
python scripts/build_fasttext_corpus.py phishing_features_extracted_6_features.csv
```

### Training the FastText model

```bash
python scripts/train_fasttext_model.py data/processed/fasttext_corpus.txt
```

### Running a single FastText-backed probe

```bash
curl -X POST "http://localhost:8000/scan/combined" \
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

- whether the active FastText model artifact exists at `FASTTEXT_MODEL_PATH`
- whether the metadata file exists at `FASTTEXT_METADATA_PATH`
- whether `fasttext-wheel` was installed successfully
- whether the latest training run completed successfully

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
2. `app/api.py`
3. `app/service.py`
4. `pipeline/`
5. `tests/`
