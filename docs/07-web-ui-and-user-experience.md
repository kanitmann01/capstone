# 07 Web UI And User Experience

## UI Role

The built-in web interface is a lightweight front end for mixed-skill users who
may not want to interact with the API directly. It now has four focused
pages:

- **Check link** (`/`) - Combined scan tool + dashboard with real-time stats
- **How it works** (`/how-it-works`) - Pipeline explanation and methodology
- **Data & evaluation** (`/dataset`) - Snapshot review and batch evaluation
- **Model metrics** (`/results`) - Model performance and benchmark comparison

The Paper page (`/paper`) remains accessible but is not part of the primary
navigation to keep the interface focused.

## Frontend Files

- `templates/_layout.html` - Shared layout with navigation
- `templates/index.html` - Scan demo + dashboard stats
- `templates/how-it-works.html` - Pipeline explanation (v3 methodology)
- `templates/dataset.html` - Dataset review and batch evaluation
- `templates/results.html` - Model metrics with interactive Chart.js visualizations
- `templates/paper.html` - Research paper with benchmark results
- `templates/evaluation.html` - Deprecated redirect to dataset
- `templates/ml.html` - Deprecated redirect to results
- `static/app.js` - Scan page JavaScript
- `static/styles.css` - Main stylesheet with dashboard and responsive styles
- `static/dataset.js` - Dataset page JavaScript
- `static/ml.js` - ML page JavaScript
- `static/evaluation.js` - Evaluation JavaScript

Legacy identities (`/evaluate`, `/ml`) still exist as compatibility routes and
redirect to the new capstone pages.

## Navigation Structure

```
Check link  |  How it works  |  Data & evaluation  |  Model metrics
```

Four primary tabs to minimize cognitive load. The Check link page combines
the scan tool with dashboard stats, system health, and recent activity.

## Dashboard Features (on Check link page)

The main page now surfaces:

- **Scan widget** - Paste URL and get immediate results
- **Stats row** - Total scans, threats caught, clean sites, dataset rows
- **System health** - FastText model, Structured ML, threat feed freshness
- **Benchmark snapshot** - Brand Guard F1 vs industry baselines
- **Recent activity** - Last 10 scans with color-coded verdicts

Dashboard data is cached in `.cache/dashboard_stats.json` and updated after
each persisted scan.

## Interaction Flow

1. The user enters a URL or uploads a labeled CSV depending on the page.
2. The UI disables the relevant form while the request or job starts.
3. The app posts to one of these endpoints:
   - `POST /scan/combined`
   - `POST /evaluate`
   - `POST /train/fasttext`
4. The response updates the page with either immediate scan results or summary
   outputs.
5. Status text communicates success, caution, or failure.

## UX Priorities

The design guidance in `CLAUDE.md` and `.impeccable.md` emphasizes:

- quick confidence cues
- clarity for non-technical users
- moderate motion only when it clarifies state
- trustworthy, non-alarmist presentation

That matches the current implementation well. The summary panel highlights the
FastText-led verdict while still preserving raw technical details for advanced
users.

## State Communication

The UI uses risk tiers:

- low risk
- needs review
- high risk

It also explicitly surfaces:

- unknown checks
- FastText probability
- rules baseline score
- hybrid comparison
- brand explanation

This is one of the strongest aspects of the interface because it prevents the
user from seeing only a score without its operational context.

## Accessibility And Usability Notes

Current strengths:

- simple form-based interaction
- visible status text
- compact layout with limited cognitive load
- no deep navigation required
- prefers-reduced-motion support throughout
- focus indicators on interactive elements
- dataset and results pages that summarize the current snapshot and model
  metadata
- compatibility aliases keep old `/evaluate` and `/ml` links functional during
  migration
- touch targets meet 44px minimum for interactive elements

Current gaps:

- raw JSON in the single-scan details panel is readable but not beginner-friendly
- the secondary pages intentionally stay summary-first rather than lab-heavy

## Results Page Charts

The results page uses Chart.js for interactive visualizations:

- **Model comparison** - Bar chart comparing rules, URL text, latest retrain, 5-fold
- **K-fold metrics** - Line chart showing fold-by-fold performance
- **K-fold confusion matrix** - Doughnut chart of TP/TN/FP/FN
- **Benchmark metrics** - Interactive bar chart for all 5 lenses
- **Day-zero recall** - Bar chart highlighting Brand Guard advantage
- **Bank recall** - Bar chart for bank impersonation detection
- **Capability radar** - Radar chart showing explainability features

All charts respect `prefers-reduced-motion` and use GPU-friendly animations.

## Why The Current UI Fits The Project

For a capstone-scale scanner, the UI stays appropriately lightweight. It gives
users immediate feedback, adds experiment management without introducing a
frontend build pipeline, and preserves meaningful scanner context for both
operators and reviewers. The merged dashboard approach keeps the primary
surface simple while surfacing useful operational data.
