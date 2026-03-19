# 02 Repository Tour

## Top-Level Layout

The workspace mixes application code, generated artifacts, project notes, test
fixtures, and a large imported agent catalog. The main directories and files
are:

- `scanner/`: backend scanning modules and shared logic
- `templates/`: server-rendered HTML templates
- `static/`: frontend JavaScript and CSS
- `tests/`: automated tests for API, feed ingestion, SSL, and evaluation
- `docs/`: multi-page documentation authored for this project
- `ai/memory-bank/`: internal project notes and task tracking
- `agency-agents/`: ancillary imported agent library
- `.cache/`: threat-intelligence cache persistence
- `main.py`: FastAPI entry point
- `evaluate_baseline.py`: baseline scoring CLI
- `README.md`: operational quickstart
- `baseline.csv`: labeled evaluation input data
- `baseline_scored.csv`: enriched evaluation output artifact
- `install.sh`: root-level installer for the ancillary agent ecosystem

## Runtime-Critical Areas

Only a subset of the repository participates in scanner execution:

- `main.py`
- `scanner/`
- `templates/`
- `static/`
- `requirements.txt`

The scanner may also read and write under `.cache/` during threat-feed refresh
and lookup operations.

## Supporting Project Assets

These files help with development, review, or evaluation but are not part of
the request path for a normal scan:

- `tests/`
- `evaluate_baseline.py`
- `baseline.csv`
- `baseline_scored.csv`
- `ai/memory-bank/`
- `README.md`

## Ancillary Imported Content

The `agency-agents/` subtree is substantial and should be treated as a separate
body of content packaged inside the same workspace. It contains many markdown
agent definitions grouped by domain such as engineering, design, sales,
marketing, product, support, and testing. It includes its own `README.md`,
integration assets, and installation guidance.

This subtree does not appear in the scanner runtime path. Its presence matters
for repository comprehension and documentation scope, but not for the phishing
scanner request pipeline.

## Suggested Mental Model

Use the repository with two layers in mind:

1. The phishing scanner product.
2. The bundled AI agent content library.

That boundary helps avoid two common documentation mistakes:

- overstating the scanner's size by counting the imported agent catalog as app
  code
- understating the repository's actual contents when producing full-repo
  handoff documentation

## Important Files By Role

### Application bootstrap

- `main.py`

### Core scanning logic

- `scanner/service.py`
- `scanner/normalization.py`
- `scanner/heuristics.py`
- `scanner/content.py`
- `scanner/ssl_check.py`
- `scanner/domain_age.py`
- `scanner/threat_intel.py`
- `scanner/feed_ingest.py`
- `scanner/settings.py`

### User interface

- `templates/index.html`
- `static/app.js`
- `static/styles.css`

### Verification and evaluation

- `tests/test_api.py`
- `tests/test_feed_ingest.py`
- `tests/test_ssl_check.py`
- `tests/test_evaluate_baseline.py`
- `evaluate_baseline.py`

### Project context and notes

- `README.md`
- `CLAUDE.md`
- `.impeccable.md`
- `ai/memory-bank/site-setup.md`
- `ai/memory-bank/tasks/phishing-scanner-tasklist.md`
