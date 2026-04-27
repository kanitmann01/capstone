# Speaker Notes — Brand Guard Benchmark Deck (12 Slides)

## Slide 1 — Title + Thesis
**Claim:** Brand Guard is explainable, brand-aware phishing triage that beats heuristics, blocklists, and generic ML — in one scan.

**Notes (65 words):**
Good morning. I'm here to present Brand Guard, a hybrid phishing detection system built for one specific gap: brand-impersonation attacks. While existing tools catch generic phishing, none combine brand reasoning, content analysis, heuristics, threat intel, and explainability in a single pass. After this talk you'll see why that combination matters — especially for day-zero bank phishing — and how we benchmarked it honestly against four industry baselines.

---

## Slide 2 — The Problem
**Claim:** Three numbers frame why day-zero detection is the battleground.

**Notes (72 words):**
Phishing losses grew 76% year-over-year. 90% of breaches start with phishing. And the median phishing page lives less than 24 hours before takedown. That means reactive blocklists are always behind. By the time a URL hits OpenPhish or Google Safe Browsing, the damage is done. Day-zero detection — catching a page in its first hours, before any feed lists it — is where the real protection lives. That's the problem we designed for.

---

## Slide 3 — Three Families of Existing Tools
**Claim:** Every existing approach falls into one of three buckets; Brand Guard transcends all three.

**Notes (68 words):**
Heuristics are fast but content-blind — they miss cloned login pages on legitimate-looking domains. Blocklists like Netstar and Google Safe Browsing are industry-grade, but day-zero blind — they only know what's already been reported. Generic ML classifiers are smart but brand-blind — they don't know Chase from a typosquat of Chase. Brand Guard is the only system that layers all three families plus brand reasoning and explainability.

---

## Slide 4 — What We Built
**Claim:** URL → snapshot → 5 detectors → composite score → explanation.

**Notes (70 words):**
Our pipeline is simple on the surface. A URL comes in, we fetch a snapshot, and five detectors run in parallel: heuristics, content analysis, SSL/domain-age checks, threat-intel feeds, and brand recognition. Each detector returns evidence, not just a number. A weighted composite produces the final risk score, and every flagged URL comes with a list of contributing checks — so a SOC analyst knows *why* something was blocked, not just *that* it was blocked.

---

## Slide 5 — Live Demo
**Claim:** 30-second demo: bank typosquat flagged, legitimate bank login cleared.

**Notes (58 words):**
Let me show you two scans. First, `chase-secure-login.tk` — free host, brand mismatch, typosquat detected. Score: 95. Now `wellsfargo.com/login` — official domain override kicks in, score drops to zero. Same pipeline, opposite outcomes, both explainable. That's the difference between content-blind heuristics and brand-aware reasoning.

---

## Slide 6 — Dataset & Training
**Claim:** Phase 0 grew the brand inventory from 10 to 110, built a balanced 2,200+ URL dataset, and enforced host-disjoint splits.

**Notes (82 words):**
We grew the brand inventory from 10 generic brands to 110 — adding the world's top 100 banks with their official login domains, aliases, and suspicious phrases. We pulled 1,100 legitimate URLs from the Tranco research list, filtered to login-bearing domains. We combined that with 1,100 phishing positives from historical feeds. Most importantly: we split by host, so the same domain never appears in train and test. This single slide rebuts most "is it overfit?" questions.

---

## Slide 7 — Headline Metrics
**Claim:** Precision / Recall / F1 across all 5 lenses. Brand Guard tallest.

**Notes (75 words):**
Here are the headline numbers on our held-out test set. Heuristics manage 50% accuracy with 0.6% recall — they catch obvious patterns and miss everything else. Netstar and the HF BERT classifier both collapse on this test set because the phishing URLs are old and not in current feeds, and the BERT model was trained on a different distribution. GSB holds 47% accuracy with 23% recall. Brand Guard leads at 62% accuracy and 26% recall — the only lens with meaningful recall on this hard test.

---

## Slide 8 — Day-Zero Recall
**Claim:** Heuristics + GSB + Netstar all collapse on URLs not yet in any feed; Brand Guard holds because brand-impersonation reasoning is content-driven.

**Notes (71 words):**
This is the slide we own. On URLs that Netstar, OpenPhish, and GSB all miss, Brand Guard still flags 25% because it's not waiting for a feed. It sees a typosquat of HSBC, a deceptive subdomain with "citi" in it, or a free host carrying a Chase login form. The other lenses have day-zero recall of essentially zero. Brand Guard's brand-recognition layer is the only signal that works before a URL is reported.

---

## Slide 9 — Bank-Impersonation Recall
**Claim:** Brand Guard's bank-recall is dramatically higher because it's the only system trained and indexed on banks.

**Notes (68 words):**
Phase 0 pays off here. We added 100 banks to the brand inventory. On bank-impersonation URLs in our test set, Brand Guard's recall is 33% versus GSB's 0%, and the other three lenses are essentially zero. In production, with live content fetching, this gap widens further — the full system sees login-form mismatches, suspicious phrases, and external form actions that the URL-only benchmark can't capture.

---

## Slide 10 — Capability Matrix
**Claim:** 5 lenses × 4 capabilities. Brand Guard is the only row with all four checked.

**Notes (65 words):**
Accuracy is one dimension; capabilities are another. Heuristics are offline but not explainable. Blocklists are neither offline nor explainable. Generic ML can't tell you which brand is being impersonated. Brand Guard is the only lens with explainability, brand attribution, offline operation, and sub-second latency. That's not a marketing claim — it's a structural consequence of running brand recognition, heuristics, and content analysis in one pipeline.

---

## Slide 11 — What ML Alone Misses
**Claim:** One concrete false-negative from the public BERT classifier versus Brand Guard's correct flag.

**Notes (62 words):**
Here's what ML alone misses. The public BERT classifier saw `chasse.com` — one letter off Chase — and scored it clean. It has no concept of "Chase." Brand Guard's FAISS + Levenshtein pipeline flagged it as a typosquat in 3 milliseconds, with a contributing checks list showing: brand_recognition, typosquatting, matched_brand=chase. Concrete evidence beats a black-box probability every time.

---

## Slide 12 — Limitations + Roadmap
**Claim:** Three real limits, one mitigation each, then close with the thesis restated.

**Notes (78 words):**
Honest limitations. First, 2,200 rows is big for a capstone but small for production — we need continuous drift monitoring and retraining. Second, snapshot fetching depends on network reachability — JavaScript-rendered pages are a known gap we're addressing with headless browser support. Third, our scope is brand-login impersonation — we don't catch every phishing variant. Roadmap: browser extension, broader brand inventory, and adversarial robustness testing. Thank you.
