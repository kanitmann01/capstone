# 03 System Architecture

## Architecture Summary

The capstone now uses a dataset-first architecture:

1. feed collectors pull candidate phishing URLs from public sources.
2. snapshotters fetch pages immediately and persist HTML/text into SQLite.
3. extraction modules derive brand, form, host, and phrase signals.
4. FastText corpus generation serializes those signals into supervised text.
5. FastText and rules baselines are evaluated on held-out data.
6. a small FastAPI app exposes scan, dataset, and results pages.

This architecture keeps the product demo simple while making the data science
workflow explicit and reproducible.

## Request Flow

### Single scan

1. A client sends `POST /scan/combined` with a URL payload.
2. `app/service.py` normalizes and snapshots the page.
3. HTML, text, and brand cues are extracted from the snapshot.
4. A FastText model scores the page text.
5. A rules baseline scores the structured evidence.
6. The response returns the FastText score, supporting evidence, and a brand-
   impersonation summary.

### Dataset workflow

1. Feed collectors ingest candidate URLs.
2. Snapshot scripts save HTML and visible text to SQLite.
3. Feature extraction modules generate structured rows.
4. The corpus exporter writes FastText supervised examples.
5. Training and evaluation scripts compare FastText and rule baselines.

## Main Components

### App layer

`app/api.py` defines the FastAPI application and exposes the demo pages. It is
the web entrypoint for the capstone.

### Service layer

`app/service.py` coordinates scan, dataset, corpus, and training operations.
It is responsible for:

- normalizing and extracting page snapshots
- scoring pages with FastText and rules
- exporting supervised corpora
- training FastText artifacts
- returning dataset summaries and model metadata

### Pipeline modules

- `pipeline/collectors/`: feed-specific URL collection
- `pipeline/snapshots/sqlite_store.py`: snapshot persistence
- `pipeline/extraction/`: page parsing, host detection, and brand matching
- `pipeline/modeling/`: FastText corpus generation, training, and inference
- `pipeline/evaluation/`: rules baseline and comparison helpers

### Feed and brand subsystems

- `scanner/feed_ingest.py` still provides the ingestion cache used by the
  collection path.
- `scanner/brand_profiles.py` supplies the initial brand registry.
- `scanner/dataset_store.py` stores snapshot rows in SQLite.

## Data Contracts

The capstone leans on a few stable contracts:

- normalized targets are represented by `NormalizedTarget`
- snapshots contain HTML/text and brand metadata
- supervised examples follow `__label__phishing` and `__label__clean`
- degraded data is surfaced explicitly instead of being hidden

## Why Snapshotting Matters

Many phishing pages disappear quickly. The architectural choice to snapshot
pages immediately is what makes the dataset trustworthy enough for a capstone.

## Performance Characteristics

The implementation is still synchronous inside the extraction and training
steps, with FastAPI using simple request handling for the demo surface. That
fits the scale of a capstone and keeps the code easy to explain, but it implies:

- scan latency grows with the slowest external dependency
- content fetches depend on network conditions
- corpus generation and training are best run offline

## Architectural Strengths

- clear dataset-first story
- explainable per-page evidence
- explicit brand-impersonation signals
- a primary FastText model with rules as a baseline
- a simple demo app instead of a heavy experiment dashboard

## Architectural Constraints

- still dependent on live phishing feeds and snapshot availability
- FastText training is only as good as the captured labels and text quality
- some JS-rendered pages remain out of scope without a browser-rendered collector
