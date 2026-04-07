# 12 FastText Model And Results

## Purpose

The capstone now centers on a FastText-first workflow for fake brand login
detection. The model is trained from snapshot text and structured tags because
it:

- trains quickly on supervised text derived from page snapshots
- works well with mixed token + tag serialization
- keeps the final model easy to explain and reproduce

## Runtime Design

The active scan surface now combines:

- FastText prediction
- rules baseline
- brand-impersonation evidence
- hybrid comparison

The page-level explanation is intentionally lightweight so reviewers can see
why a page was flagged without opening the raw JSON.

## Feature Schema

The shared feature contract is intentionally simple and centered on these
groups:

- URL lexical properties
- host and protocol metadata
- brand candidate and path clues
- form and login structure
- suspicious visible-text phrases
- rule-score metadata used for comparison

Training and inference both use the same page snapshot and text serialization
logic to avoid drift.

## Results Page

The `Results` page is available at `/results` and is built with:

- `templates/results.html`
- `static/styles.css`

The page provides:

- a summary of the active FastText model artifact
- the current inference threshold
- artifact paths for the active model and metadata
- the latest evaluation report when one has been run from the UI

## Training Workflow

The training pipeline is intentionally split into repeatable stages:

1. read the labeled CSV
2. run the snapshot extractor on each URL
3. serialize FastText training lines
4. save the corpus as a generated artifact
5. train FastText on the supervised text
6. evaluate rules and model performance
7. save the model, metadata, and report
8. optionally copy the trained run into the active runtime model paths

## Job And Artifact Model

FastText runs are stored under cache-managed directories configured by the
capstone settings. Each run can include:

- the uploaded input CSV
- the generated corpus
- the trained model artifact
- model metadata
- the experiment report

The runtime model is loaded from:

- `FASTTEXT_MODEL_PATH`
- `FASTTEXT_METADATA_PATH`

## Visualization Model

The dashboard emphasizes:

- rules vs FastText comparison
- confusion matrix and threshold review
- false positive / false negative inspection
- recent model metadata

## Operational Caveats

- Feature extraction depends on the live snapshot fetch, so a training run can
  inherit network variability from page retrieval.
- A missing or invalid active model does not break combined scans. The FastText
  block returns `status: "unknown"` instead.
- The runtime analytics are lightweight and intended for the demo surface.

## Future Extensions

Natural follow-on work includes:

- side-by-side comparison with random forest or gradient boosting
- persisted experiment registry beyond in-memory job state
- deeper per-row model error analysis in the UI
- drift monitoring on URL distributions and model availability
