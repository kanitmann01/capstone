# 01 Project Overview

## Executive Summary

The primary application in this workspace is now a dataset-first FastAPI
capstone for detecting fake brand login pages. It collects phishing snapshots,
extracts HTML/text/brand signals, trains a FastText-first detector, and exposes
the resulting model through a lightweight web demo and API.

The project is designed as a supervised classification problem with explainable
signals rather than a generic scanner. That distinction is central to the
capstone: the model learns which page structures, text cues, and host patterns
most strongly indicate brand impersonation.

## Intended Users

- Reviewers evaluating the capstone as a data science / AI project.
- Developers maintaining the dataset pipeline, extraction logic, and model.
- Operators refreshing feeds, capturing snapshots, and retraining FastText.
- Demo users who want a fast confidence check before opening a suspicious link.

## Core Capabilities

- URL normalization before any extraction or scoring runs.
- Snapshot capture of phishing pages before they disappear.
- Brand-login feature extraction from HTML, visible text, and hosting context.
- FastText training and inference on a labeled supervised corpus.
- Rules baseline for interpretability and comparison.
- Dataset summary and results pages for capstone presentation.
- Offline evaluation using labeled CSV input and held-out cases.

## Project Goals

The implementation now aligns with a capstone-style supervised learning flow:

- collect and snapshot phishing pages quickly
- extract brand-specific HTML/text features
- build a FastText corpus from labeled snapshots
- compare rules and model baselines
- present results in a simple, shareable demo UI
- keep the design realistic and maintainable

## What Success Looks Like

For a user, success means getting a quick result with enough detail to decide
whether to investigate further. For maintainers, success means the scanner is
easy to run, test, and extend without hiding operational problems such as stale
feeds, unreachable targets, or unavailable external services.

## Key Entry Points

- `app/api.py`: application bootstrap, routing, and web serving
- `app/service.py`: snapshot scoring, corpus generation, and FastText inference
- `pipeline/extraction/html_parser.py`: page fetch and structured feature extraction
- `pipeline/modeling/fasttext_train.py`: FastText training and artifact writing
- `pipeline/evaluation/evaluate.py`: offline scoring and metrics workflow
- `templates/index.html` and `static/app.js`: browser experience

## Project Positioning

This is best understood as a practical, explainable brand-impersonation
detector rather than a generic phishing triage service. It emphasizes:

- transparent features
- bounded scope
- reproducible datasets
- FastText-first modeling
- simple deployment

It does not attempt to provide:

- browser isolation
- sandbox detonation
- enterprise policy orchestration
- guaranteed malicious or safe verdicts
