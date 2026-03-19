# 12 ML Lab And Classifier

## Purpose

The scanner now includes a lightweight machine-learning layer that complements
the existing rules-based checks. The first model is a decision-tree baseline
chosen for three reasons:

- it trains quickly on structured phishing features
- it is easier to explain than heavier ensembles
- it creates a clear benchmark before introducing more complex models

## Runtime Design

The live scanner still starts with normalized URL handling and the existing
checks:

- heuristics
- content
- SSL
- domain age
- threat intelligence

After those checks run, the service derives tabular ML features from:

- URL lexical properties
- domain and protocol metadata
- risk scores and boolean outputs from existing scanner modules

The active model then returns an `ml` result in `details`, including:

- `status`
- `risk_score`
- `prediction`
- `probability`
- `model_version`
- `model_type`
- `feature_version`
- `top_features`

The default `WEIGHT_ML` is `0.0`, so the ML signal is visible without changing
the combined score until operators decide to enable it.

## Feature Schema

The shared feature contract lives in `scanner/ml_features.py`. The first schema
version includes:

- lexical counts such as URL length, dots, hyphens, digits, special characters,
  path depth, and query parameter count
- booleans such as `has_at`, `is_ip`, and `uses_https`
- entropy-based host and path measures
- suspicious-token and brand-token counts
- meta-features from existing checks, including per-module scores
- availability and degradation signals such as unknown-check count
- content, SSL, domain-age, and threat-intel detail flags

Training and inference both use the same ordered feature list to avoid schema
drift.

## ML Lab Page

The `ML Lab` page is available at `/ml` and is built with:

- `templates/ml.html`
- `static/ml.js`
- `static/styles.css`

The page provides:

- CSV upload for labeled data with `url` and `is_phishing`
- safe decision-tree controls such as criterion, max depth, and split/leaf
  thresholds
- a toggle to activate the finished model as the runtime artifact
- live job polling for feature extraction and training progress
- active-model analytics from runtime inference
- chart-based experiment summaries
- a single-URL ML-only probe through `POST /scan/ml`

## Training Workflow

The training pipeline is intentionally split into repeatable stages:

1. read the labeled CSV
2. run the scanner on each URL to build a feature dataset
3. save the feature dataset as a generated artifact
4. split the dataset into train and test partitions
5. fit a `DecisionTreeClassifier`
6. evaluate train and test performance
7. save the model, metadata, and report
8. optionally copy the trained run into the active runtime model paths

## Job And Artifact Model

ML runs are stored under the cache-managed runs directory configured by
`ML_RUNS_DIR`. Each run can include:

- the uploaded input CSV
- the generated feature dataset
- the trained model artifact
- model metadata
- the experiment report

The runtime model is loaded from:

- `ML_MODEL_PATH`
- `ML_METADATA_PATH`

## Visualization Model

The dashboard aims to feel similar to a TensorBoard-style experiment view, but
for tabular phishing classification rather than deep learning. Because decision
trees do not train across epochs, the dashboard emphasizes:

- train vs test metric comparison
- test-set confusion matrix
- probability distribution histograms
- top feature importance
- tree depth, leaf count, and node count
- recent run history

## Operational Caveats

- Feature extraction depends on the live scanner, so a training run can inherit
  network variability from content, SSL, WHOIS, and feed-backed checks.
- A missing or invalid active model does not break combined scans. The `ml`
  block returns `status: "unknown"` instead.
- The runtime analytics are in-memory counters for the active process. They are
  useful for the web dashboard but are not a full persistence or drift-monitoring
  solution.

## Future Extensions

Natural follow-on work includes:

- side-by-side comparison with random forest or gradient boosting
- persisted experiment registry beyond in-memory job state
- deeper per-row ML error analysis in the UI
- drift monitoring on URL distributions and module availability
- optional score integration once offline evaluation supports a nonzero
  `WEIGHT_ML`
