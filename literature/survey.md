# Literature Survey — Brand Guard Benchmark

## Key References

### Phishing Detection Surveys
1. **Gupta et al., 2023** — Comprehensive survey of phishing detection techniques (ML, heuristics, visual analysis). Identifies brand impersonation as understudied relative to generic phishing.
   - Relevance: Motivates our focus on brand-aware detection.

### Threat Intelligence Feeds
2. **OpenPhish** — Real-time phishing feed (https://openphish.com/)
   - Used as comparator in benchmark.
   - Limitation: Reactive, day-zero blind.

3. **Google Safe Browsing** — Industry blocklist with ~0.98 precision, ~0.25 recall (published stats)
   - Used as comparator (fallback due to no API key).
   - Limitation: No brand attribution, day-zero blind.

### URL-Based ML Classifiers
4. **ealvaradob/bert-finetuned-phishing** — Public HuggingFace BERT model for URL classification
   - Used as comparator.
   - Collapsed on our eval set due to distribution mismatch.
   - Limitation: Brand-blind, no explainability.

### Brand Impersonation Specific
5. **Tranco List** (Le Pochat et al.) — Research-grade top-1M domain ranking
   - Used as legitimate URL source.
   - https://tranco-list.eu/

### Related Tools
6. **VirusTotal** — Multi-engine scanner (not directly compared due to API cost)
   - Mentioned in Q&A as complementary, not competitive.

## Gap Analysis

No existing system combines:
- Brand recognition (FAISS + Bloom + Levenshtein)
- Content analysis (login form, suspicious phrases)
- Threat intel (OpenPhish, PhishTank)
- Heuristics (IP, length, suspicious chars)
- Explainability (contributing checks list)

Brand Guard fills this gap by layering all five signals into a weighted composite with per-check evidence.

---
*Survey date: 2026-04-27*
*Note: Full systematic literature search deferred to future research phase. Current survey covers directly referenced baselines and data sources.*
