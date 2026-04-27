# Q&A Prep — Anticipated Panel Questions

## 1. "Why not just use VirusTotal?"
**60-second answer:**
VirusTotal is excellent for retrospective analysis, but it's expensive at scale, has no brand attribution, and is fundamentally reactive. A phishing page must be submitted and analyzed before VT knows about it — that lag is the day-zero window we target. Brand Guard runs offline, attributes the impersonated brand, and explains its verdict in milliseconds. VT complements us; it doesn't replace us.

---

## 2. "What if the page is JavaScript-rendered?"
**60-second answer:**
That's a current limitation. Our snapshot fetcher uses static HTML parsing, so React-heavy login forms may be missed. The mitigation is twofold: first, many phishing kits still use static HTML for speed. Second, our roadmap includes a headless-browser snapshot path that will render JavaScript before analysis. The URL-level heuristics and brand recognition still fire regardless of rendering.

---

## 3. "How do you avoid false positives on legit bank login pages?"
**60-second answer:**
Two layers. First, our `_official_domain_override` short-circuits the score to zero when the host matches any official domain in our brand inventory — which now includes 100 banks. Second, the composite score threshold is 30, and legitimate banks rarely trigger the content signals that push a score that high: free-host detection, brand mismatch, suspicious phrases, and form-action mismatch all require the page to look *wrong*.

---

## 4. "How big is your training set really?"
**60-second answer:**
2,200 URLs, perfectly balanced, with host-disjoint train/val/test splits. The manifest is in `data/processed/capstone_v2_manifest.json`. We pulled 1,100 legitimate URLs from the Tranco research list, filtered to login-bearing domains, and 1,100 phishing positives from historical feeds. We committed the dataset so it's pinned — no drift from URL rot between runs.

---

## 5. "Where did the bank list come from?"
**60-second answer:**
Three citeable sources: S&P Global's Top 100 Banks list, the Federal Reserve's Large Commercial Banks directory, and the European Banking Authority's directory. We selected 100 banks across five regions — 30 US, 25 European, 20 Asia-Pacific, 15 Middle East / LatAm / Other, and 10 online-first fintechs. Each entry includes official domains, login phrases, and suspicious phrases.

---

## 6. "Could an attacker evade your model?"
**60-second answer:**
Yes — adversarial robustness is an open problem for every detection system. An attacker could register a domain with no brand keywords, host on a paid server, and clone a login page without suspicious phrases. Our defense is layered: brand recognition catches typosquats, content analysis catches form mismatches, threat intel catches known infrastructure, and heuristics catch structural anomalies. Evading all four simultaneously is harder than evading any one.

---

## 7. "Why not Tranco directly as your only legit source?"
**60-second answer:**
Tranco is a research-grade top-1M list, but it includes CDNs, image hosts, and infrastructure domains that never show a login surface. Our threat model is specifically login-page impersonation, so we filtered Tranco to the union of bank domains, brand official domains, and a curated SaaS-login set. This makes the comparison fair: every legitimate URL in our set plausibly has a login form, just like the phishing positives.
