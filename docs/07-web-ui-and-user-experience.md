# 07 Web UI And User Experience

## UI Role

The built-in web interface is a lightweight front end for mixed-skill users who
may not want to interact with the API directly. It now has three focused pages:

- single scan for one URL
- baseline evaluation for labeled CSV testing
- ML Lab for training and inspecting the decision-tree baseline

## Frontend Files

- `templates/index.html`
- `templates/evaluation.html`
- `templates/ml.html`
- `static/app.js`
- `static/evaluation.js`
- `static/ml.js`
- `static/styles.css`

## Interaction Flow

1. The user enters a URL or uploads a labeled CSV depending on the page.
2. The UI disables the relevant form while the request or job starts.
3. The app posts to one of these endpoints:
   - `POST /scan/combined`
   - `POST /evaluate/jobs`
   - `POST /ml/jobs`
4. The response updates the page with either immediate scan results or live
   polled job progress.
5. Status text communicates success, caution, or failure.

## UX Priorities

The design guidance in `CLAUDE.md` and `.impeccable.md` emphasizes:

- quick confidence cues
- clarity for non-technical users
- moderate motion only when it clarifies state
- trustworthy, non-alarmist presentation

That matches the current implementation well. The summary panel highlights the
combined verdict while still preserving raw technical details for advanced users.

## State Communication

The UI uses risk tiers:

- low risk
- needs review
- high risk

It also explicitly surfaces:

- unknown checks
- stale feed cache
- refresh activity
- refresh errors

This is one of the strongest aspects of the interface because it prevents the
user from seeing only a score without its operational context.

## Accessibility And Usability Notes

Current strengths:

- simple form-based interaction
- visible status text
- compact layout with limited cognitive load
- no deep navigation required
- live progress for long-running evaluation and ML workflows
- one dedicated page for model inspection and experiment control

Current gaps:

- raw JSON in the single-scan details panel is readable but not beginner-friendly
- the ML Lab focuses on summary metrics rather than deep per-row drilldowns
- live progress uses polling rather than push streaming, so updates are near
  real time rather than instant

## ML Lab Notes

The ML Lab page adds:

- safe hyperparameter controls for the decision-tree baseline
- a live training-job progress panel
- active-model analytics from runtime inference
- chart-based experiment summaries for train/test metrics, probability
  distribution, and feature importance
- a single-URL probe flow through `POST /scan/ml`

## Why The Current UI Fits The Project

For a capstone-scale scanner, the UI stays appropriately lightweight. It gives
users immediate feedback, adds experiment management without introducing a
frontend build pipeline, and preserves meaningful scanner context for both
operators and reviewers.
