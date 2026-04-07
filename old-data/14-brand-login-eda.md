# Brand Login EDA Summary

Generated on `2026-04-07 04:47 UTC` from `old-data/baseline.csv` and `old-data/baseline_scored.csv`.

## Dataset Snapshot

| Metric | Value |
|---|---|
| Total rows | 20000 |
| Phishing rows | 10000 |
| Legitimate rows | 10000 |
| Phishing rate | 50.0% |
| Missing URL rate | 0.0% |
| Missing hostname rate | 0.0% |

## Class Balance

- The dataset is intentionally close to a binary phishing-vs-legitimate setup.
- The positive class is phishing pages that impersonate login flows.
- The negative class is legitimate or non-impersonating pages.

## Brand Signals In URLs

- Facebook (123)
- Microsoft (67)
- Google (63)
- Amazon (53)
- Apple (30)
- Adobe (10)
- PayPal (7)
- Coinbase (6)

## Suspicious Path Tokens

- login (280)
- auth (162)
- sign (125)
- update (112)
- secure (76)
- account (74)
- verify (39)
- security (34)

## Host Pattern Signals

Free-host provider counts:

- firebase (847)
- pages (150)
- vercel (97)
- github (69)
- netlify (42)

Common host suffixes:

- weebly.com (1447)
- web.app (847)
- firebaseapp.com (762)
- r2.dev (660)
- dweb.link (328)
- webcindario.com (317)
- framer.app (279)
- co.uk (240)

## Missing Data

Baseline CSV:

| Column | Missing |
|---|---|
| url | 0.0% |
| is_phishing | 0.0% |
| hostname | 0.0% |

Scored CSV:

| Column | Missing |
|---|---|
| url | 0.0% |
| is_phishing | 0.0% |
| hostname | 0.0% |
| risk_score | 1.5% |
| predicted_is_phishing | 1.5% |
| api_error | 98.5% |

## Evaluation Snapshot

| Metric | Value |
|---|---|
| Scored rows | 802 |
| Accuracy | 0.4800 |
| Precision | 0.0000 |
| Recall | 0.0000 |
| F1 | 0.0000 |
| TP | 0 |
| TN | 385 |
| FP | 0 |
| FN | 417 |

## False Positives

- None

## False Negatives

- `https://confira-desconto.vercel.app/login/index.html?placement=Facebook_Mobile_Feed&amp;amp;01ylvi4l=e5oyqauq&amp;amp;utm_source=FB&amp;amp;utm_campaign=P87C3+-+S370%257C120244592675850581&amp;amp;utm_medium=Novo+conjunto+de+an%25C3%25BAncios+de+Vendas+%25E2%2580%2594+C%25C3%25B3pia%257C120244592675870581&amp;amp;utm_content=Novo+an%25C3%25BAncio+de+Vendas%257C120244592675860581&amp;amp;utm_term=Facebook_Mobile_Feed&amp;amp;fbclid=IwdGRzaAQW8a5leHRuA2FlbQEwAGFkaWQBqzHR7f68dXNydGMGYXBwX2lkDDM1MDY4NTUzMTcyOAABHuqzs1NfK0opJWfcEURfKOHqvzfVSneRlYpKSWyeL36PVNATvYQWCE5IhNG3_aem_ERSWVGiNQBGDgmeb5BVK4g&amp;amp;utm_id=120244592675850581&amp;amp;twrclid=69aa11fd99e989d3ea07382e&amp;amp;sfnsn=wiwspwa` | score `31.43` | host `confira-desconto.vercel.app`
- `https://pub-16499d352cc14fe4b8cdf064bb205547.r2.dev/4outmanagementsecure.html` | score `28.57` | host `pub-16499d352cc14fe4b8cdf064bb205547.r2.dev`
- `https://pay.paypagementoseguroltda.site/DYp0Zx0RPArZmvX?utm_source=organic&amp;utm_campaign=&amp;utm_medium=&amp;utm_content=&amp;utm_term=` | score `25.45` | host `pay.paypagementoseguroltda.site`
- `http://allegrolokalnie.pl-oferta095152120.cfd/oferta/gitara-elektryczna-2006-ibanez-js-1000-black-pearl-made-in-japan` | score `25.45` | host `allegrolokalnie.pl-oferta095152120.cfd`
- `https://pkobp-ikplijtxjt.diue.de/R6eUMtUbOWxKYW7KltXh/ikPLIJtXjT/R6eUMtUbOWxKYW7KltXh4D9qgen/uZJs9/R6eUMtUbOWxKYW7KltXh/Zgloszenia.karty/CoeOla/pkobp.pl/R6eUMtUbOWxKYW7KltXhikPLIJtXjT` | score `24.29` | host `pkobp-ikplijtxjt.diue.de`

## Takeaways

- Brand-bearing paths and free-host infrastructure are common phishing indicators in this dataset.
- The evaluation snapshot is useful for threshold tuning and error analysis rather than as a final guarantee.
- The strongest capstone story is the combination of label collection, feature engineering, and hybrid detection.
