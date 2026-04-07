# 08 Baseline Evaluation And Data

## Purpose

The baseline evaluation workflow provides a repeatable way to measure brand-login
detection behavior against labeled data. It is useful for:

- capstone reporting
- threshold tuning
- regression detection
- review of false positives and false negatives

## Main Script

File: `evaluate_baseline.py`

The script reads an input CSV, calls the combined scan endpoint for each row,
stores enriched output in a new CSV, and prints classification metrics.

## Expected Input

The input CSV must contain:

- `url`
- `is_phishing`

Accepted truthy and falsy labels include common values such as `1`, `0`,
`true`, `false`, `yes`, and `no`.

## Default Behavior

Defaults include:

- endpoint: `http://localhost:8000/scan/combined`
- threshold: `50.0`
- timeout: `15` seconds

Predictions are made with the rule:

- phishing if `risk_score >= threshold`

## Output

The generated CSV appends scanner-related columns such as:

- `api_scanned_url`
- `risk_score`
- `score_threshold`
- `predicted_is_phishing`
- `matched_ground_truth`
- `api_error`

The script also keeps richer in-memory row data for reporting, including:

- contributing checks
- unknown checks
- per-row details

## Reported Metrics

The CLI prints:

- total rows
- scored rows
- error rows
- true positives
- true negatives
- false positives
- false negatives
- accuracy
- precision
- recall
- F1

## Error Handling

Rows that fail due to request errors or API problems are not hidden. They are
counted as error rows and written with an `api_error` message, which is
important for honest evaluation reporting.

## Useful Extensions Already Present

The evaluation script includes support for:

- progress callbacks
- structured row evaluation objects
- report payload generation with score distributions
- check-activity summaries

That makes it a stronger foundation than a minimal one-off CSV loop.

## Relationship To The ML Workflow

The same labeled-CSV pattern now also supports the FastText workflow:

- the baseline evaluation page still measures scanner behavior through the
  combined score
- the corpus builder reuses labeled CSV input to generate FastText training
  lines from extracted snapshot text
- the combined scan exposes a `brand_impersonation` summary plus FastText and
  rules outputs, so the evaluation result can be used for both explanation and
  modeling analysis

## Data Artifacts In This Repo

- `old-data/baseline.csv`: archived input dataset
- `old-data/baseline_scored.csv`: archived enriched output artifact

Additional generated artifacts may now appear under cache-managed FastText and
evaluation directories, including:

- extracted feature corpora
- trained model artifacts
- model metadata
- experiment reports

For the capstone, the most useful evaluation artifacts are the ones that support
data science discussion:

- precision, recall, F1, and confusion matrix
- threshold comparisons
- row-level false positives and false negatives
- model feature importance
- error analysis examples grouped by brand and host provider

Because `old-data/baseline_scored.csv` is generated output, it should be treated
as a reporting artifact rather than a hand-maintained source file.

## Evaluation Caveats

- the scanner depends on live external services, so repeated runs may vary
- stale or failed feed refresh can affect threat-intelligence coverage
- threshold choice strongly shapes false-positive and false-negative balance
- heuristic systems are sensitive to dataset composition
- ML feature extraction inherits the same external variability if the dataset is
  built from live scanner outputs

## Recommended Evaluation Practice

1. start the API locally
2. refresh feeds if required
3. run the evaluator with a fixed threshold
4. inspect both summary metrics and row-level errors
5. review mismatches before adjusting scoring or rules

