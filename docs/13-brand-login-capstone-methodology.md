# Brand Login Detector Methodology

## Research Question

Can HTML structure, visible page text, hosting context, and lightweight machine-learning features detect fake brand login pages more reliably than URL heuristics alone?

## Problem Setup

- **Task:** binary classification
- **Positive class:** fake brand login page
- **Negative class:** legitimate or non-impersonating page
- **Unit of analysis:** one captured page snapshot
- **Input:** URL, HTML snapshot, page text, form structure, host metadata
- **Output:** risk score, predicted label, and explanation of why the page is suspicious

## Dataset Plan

The dataset should be built from live phishing feeds and snapshot immediately because many phishing pages disappear quickly.

Recommended sources:

- OpenPhish public feed
- PhishStats query snapshots
- optional VirusTotal-style snapshots when available

Each snapshot should store:

- original URL
- normalized URL
- capture timestamp
- raw HTML
- visible text
- page title
- detected brand candidate
- host provider
- label
- notes about extraction quality

## Feature Groups

The capstone uses several feature families:

- **URL lexical features**: length, hyphens, digits, entropy, suspicious tokens
- **Host features**: free-host provider, path brand match, brand keyword in host
- **HTML structure features**: form count, password fields, input fields, navigation density
- **Text features**: brand mentions, login phrases, suspicious phrases, title and heading signals
- **Model features**: scanner scores from heuristics, content, SSL, domain age, and threat intel

## Baseline Experiments

The project should compare at least three baselines:

1. **Rules only**: heuristic and content rules without ML
2. **ML only**: classifier on engineered features without final rule weighting
3. **Hybrid**: rules plus ML combined into the final risk score

## Evaluation Plan

Report:

- accuracy
- precision
- recall
- F1
- confusion matrix
- threshold sweep results
- false positives and false negatives

For the capstone, recall should be emphasized because missing a phishing page is more serious than a few extra alerts.

## Ablation Plan

Run feature ablations to show what matters:

- URL and host only
- HTML structure only
- text and brand features only
- full combined feature set

## Error Analysis

Document:

- legitimate login pages that were incorrectly flagged
- phishing pages that were missed
- whether misses came from weak text cues, missing logos, or unsupported rendering behavior
- whether false positives came from common words like `sign in` or `verify`

## Presentation Angle

The project is strongest when presented as a hybrid explainable AI system:

- heuristics explain the obvious cases
- ML generalizes across wording and layout variation
- the UI makes the explanation human-readable
- the dataset and evaluation show the model is grounded in evidence
