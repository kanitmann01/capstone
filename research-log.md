# Research Log — Brand Guard Benchmark

## 2026-04-26 — Phase 0: Bank Inventory & Dataset
**Decision**: Expand brand inventory from 10 generic brands to 110 (100 banks + existing).
**Rationale**: Plan requires bank-impersonation focus; existing brand_profiles.json insufficient.
**Action**: Generated scanner/brand_profiles_banks.json with 100 global banks. Modified loader to auto-merge. Extended DEFAULT_TARGET_BRANDS with 100+ normalized roots.
**Result**: All 19 brand_recognition tests passing, including new bank-specific cases (chase typosquat, hsbc homograph, citi deceptive subdomain, wellsfargo exact match).

## 2026-04-26 — Dataset Construction
**Decision**: Build balanced 2,200-row dataset from Tranco + historical phishing feeds.
**Rationale**: Need host-disjoint stratified splits for honest evaluation.
**Action**: Created fetch_tranco_legit.py (2,159 URLs), sample_phishing_positives.py (1,100 positives), build_capstone_v2_dataset.py (70/15/15 split).
**Result**: capstone_v2.csv with 2,200 rows (50/50 balance), host-disjoint, manifest.json created.

## 2026-04-26 — FastText Retraining
**Decision**: Skip full snapshot extraction (30+ min timeout) and build URL-only FastText corpus.
**Rationale**: Build speed priority for capstone timeline. URL-only corpus captures brand + heuristics signals.
**Action**: build_fasttext_corpus_url_only.py generated 1,540 training lines. Trained fasttext model in <1s. Activated at .cache/fasttext/brand-login.bin.
**Result**: Model active, no regression in existing tests.

## 2026-04-26 — Phase 1: Benchmark Infrastructure
**Decision**: Build 5 comparator lenses and benchmark runner.
**Rationale**: Need apples-to-apples comparison with published baselines.
**Action**: Created heuristics_only, netstar_lookup, hf_url_classifier (with caching), gsb_lookup (static fallback) comparators. run_benchmark_matrix.py scores all 5 on eval set.
**Result**: 330 URLs scored in ~2 minutes. benchmark_summary.json generated.

## 2026-04-26 — Benchmark Results
**Key finding**: Brand Guard leads on accuracy (62%), precision (96%), and day-zero recall (25%).
**Surprise**: HF BERT classifier collapsed to 50% accuracy on this distribution — trained on different data.
**Concern**: Bank-impersonation URLs in eval set only 18 samples — bank_recall confidence intervals wide.
**Mitigation**: Speaker notes explicitly call this out; suggest real-world uplift with full content fetching.

## 2026-04-26 — Phase 2: Presentation
**Decision**: Build Reveal.js HTML deck + speaker notes + QA prep.
**Rationale**: Panel presentation requirement.
**Action**: 12-slide deck with embedded plots, 60-90 word speaker notes per slide, 7 anticipated Qs with rehearsed answers. Web UI results page updated with benchmark section.
**Result**: deck.html self-contained, static assets copied for web serving.

## 2026-04-27 — AI Research Skills Installation
**Decision**: Install Orchestra Research AI Research Skills framework.
**Rationale**: User requested installation for research methodology support.
**Action**: npx install --all completed. 95 skills installed. Autoresearch skill loaded.
**Result**: Workspace initialized (research-state.yaml, research-log.md, findings.md). Ready for continuous operation.

---
**Log format**: Date — Decision title
**Decision**: What was decided
**Rationale**: Why
**Action**: What was done
**Result**: Outcome
