# Experiment Log

Use this file as the human-readable history for model training, fine-tuning, and evaluation work.

## How To Use
- Add one section per meaningful run.
- Keep the run ID consistent with `runs/metadata.json`.
- Record both the outcome and the decision you made from it.
- Point to saved checkpoints such as `best`, `last`, and milestone files.

## Run Template

### Run: `run-YYYYMMDD-HHMM-short-name`
- Date:
- Objective:
- Model:
- Dataset version:
- Code version:
- Initialization:
  - From scratch / resumed / fine-tuned from:
- Hyperparameters:
  - learning_rate:
  - batch_size:
  - epochs:
  - optimizer:
- Checkpoints:
  - best:
  - last:
  - milestones:
- Metrics:
  - train_loss:
  - val_loss:
  - accuracy:
  - precision:
  - recall:
  - f1:
  - latency_ms:
- Safety and quality checks:
  - bias/fairness notes:
  - data quality notes:
  - failure modes:
- Result summary:
- Decision:
  - promote / keep for comparison / discard / retrain
- Next step:

## Example

### Run: `run-20260316-1030-url-risk-baseline`
- Date: 2026-03-16
- Objective: Establish a baseline phishing URL classifier.
- Model: `xgboost-url-risk-v1`
- Dataset version: `dataset-2026-03-15`
- Code version: `local-working-tree`
- Initialization:
  - From scratch
- Hyperparameters:
  - learning_rate: `0.05`
  - batch_size: `n/a`
  - epochs: `n/a`
  - optimizer: `n/a`
- Checkpoints:
  - best: `artifacts/url-risk/best.json`
  - last: `artifacts/url-risk/last.json`
  - milestones: `artifacts/url-risk/milestone-100.json`
- Metrics:
  - train_loss: `n/a`
  - val_loss: `n/a`
  - accuracy: `0.91`
  - precision: `0.89`
  - recall: `0.87`
  - f1: `0.88`
  - latency_ms: `14`
- Safety and quality checks:
  - bias/fairness notes: `Demographic bias not applicable; domain-source skew still needs review.`
  - data quality notes: `High duplicate rate removed before training.`
  - failure modes: `Struggles on shortened URLs with limited lexical context.`
- Result summary: Strong baseline with low latency and balanced precision/recall.
- Decision:
  - Promote as comparison baseline, not production yet.
- Next step: Compare against content-plus-URL hybrid model.
