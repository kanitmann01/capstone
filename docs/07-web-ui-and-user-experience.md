# 07 Web UI And User Experience

## UI Role

The built-in web interface is a lightweight front end for mixed-skill users who
may not want to interact with the API directly. It now has three focused
pages:

- scan demo for one URL
- dataset and analysis for snapshot review and batch evaluation
- results and model overview

## Frontend Files

- `templates/index.html`
- `templates/dataset.html`
- `templates/results.html`
- `static/app.js`
- `static/styles.css`
Legacy identities still exist as compatibility routes, but they now resolve to
the new capstone pages rather than separate product surfaces.

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
- dataset and results pages that summarize the current snapshot and model
  metadata
- compatibility aliases keep old `/evaluate` and `/ml` links functional during
  migration

Current gaps:

- raw JSON in the single-scan details panel is readable but not beginner-friendly
- the secondary pages intentionally stay summary-first rather than lab-heavy

## Results Notes

The results page adds:

- active-model metadata from the FastText detector
- artifact paths for the latest model
- a compact view of the model snapshot

## Why The Current UI Fits The Project

For a capstone-scale scanner, the UI stays appropriately lightweight. It gives
users immediate feedback, adds experiment management without introducing a
frontend build pipeline, and preserves meaningful scanner context for both
operators and reviewers.
