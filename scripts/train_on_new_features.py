from __future__ import annotations

"""
Train FastText and TensorFlow models from a combined phishing dataset.

Phishing sources (all is_phishing=1):
  * Dataset.csv          – URL only (300 rows, lexical features computed)
  * NewUrl_features.csv  – URL + pre-extracted scanner signals (300 rows)

The two files share no URLs in common, so merging gives ~533 unique
phishing examples with richer or lexical-only features depending on source.

Clean/negative examples (is_phishing=0) come from a curated list of ~150
well-known legitimate domains.  Their features are derived from URL
lexical analysis only, giving the models a realistic negative class to
learn from without requiring live scanning.

Usage
-----
    python scripts/train_on_new_features.py [--no-fasttext] [--no-ml]

Options
-------
    --no-fasttext   Skip FastText training.
    --no-ml         Skip TensorFlow/ML training.
    --dry-run       Parse and map data only; do not train.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# project root on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.modeling.fasttext_dataset import (
    LABEL_PREFIX,
    build_corpus_lines,
    write_corpus_file,
)
from pipeline.modeling.fasttext_train import (
    FastTextTrainingConfig,
    train_fasttext_model,
)
from pipeline.shared.config import CapstoneConfig
from scanner.ml_features import FEATURE_FIELDS, FEATURE_VERSION
from scanner.normalization import normalize_input_url

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATASET_CSV = PROJECT_ROOT / "Dataset.csv"
NEW_FEATURES_CSV = PROJECT_ROOT / "NewUrl_features.csv"
CORPUS_PATH = PROJECT_ROOT / "data" / "processed" / "fasttext_corpus.txt"
FASTTEXT_MODEL_PATH = PROJECT_ROOT / ".cache" / "fasttext" / "brand-login.bin"
FASTTEXT_METADATA_PATH = PROJECT_ROOT / ".cache" / "fasttext" / "brand-login.json"
ML_ARTIFACTS_DIR = PROJECT_ROOT / ".cache" / "ml-artifacts"

# ---------------------------------------------------------------------------
# Curated clean / legitimate URLs
#
# Deliberately varied across:
#   - Short root-domain URLs (google.com) AND deep-path URLs with subdomains,
#     query strings, and numeric tokens - so lexical features overlap with
#     the phishing set and the model cannot rely on url_length or path_depth
#     alone.
#   - Both http:// and https:// so uses_https is not a trivial separator.
#   - Diverse TLDs (.com, .org, .edu, .gov, .io, .co.uk, .net, etc.)
#   - Known brand names in the hostname/path that also appear in phishing
#     (e.g., paypal, amazon, microsoft) so brand_token_count overlaps.
# ---------------------------------------------------------------------------
CLEAN_URLS: list[str] = [
    # ---- Short / simple roots (https) ----
    "https://www.google.com/",
    "https://www.github.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.amazon.com/",
    "https://www.wikipedia.org/",
    "https://www.reddit.com/",
    "https://stackoverflow.com/",
    "https://www.linkedin.com/",
    "https://www.netflix.com/",
    "https://www.paypal.com/",
    "https://www.stripe.com/",
    "https://www.shopify.com/",
    "https://www.cloudflare.com/",
    "https://www.zoom.us/",
    "https://www.slack.com/",
    "https://www.notion.so/",
    "https://www.figma.com/",
    "https://www.twitch.tv/",
    "https://www.spotify.com/",

    # ---- Subdomains (legit brands with sub-domain patterns) ----
    "https://mail.google.com/mail/u/0/",
    "https://docs.google.com/document/u/0/",
    "https://drive.google.com/drive/my-drive",
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://account.microsoft.com/account/",
    "https://developer.apple.com/account/",
    "https://id.apple.com/",
    "https://secure.paypal.com/cgi-bin/webscr?cmd=_login-run",
    "https://www.paypal.com/us/signin",
    "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
    "https://www.amazon.com/ap/signin",
    "https://signin.aws.amazon.com/signin?redirect_uri=https://console.aws.amazon.com/",
    "https://www.facebook.com/login/",
    "https://m.facebook.com/login/",
    "https://www.instagram.com/accounts/login/",
    "https://twitter.com/i/flow/login",
    "https://www.linkedin.com/login",
    "https://github.com/login",
    "https://gitlab.com/users/sign_in",

    # ---- Deep paths + query params (legit complex URLs) ----
    "https://www.amazon.com/dp/B09X7CRKRZ/ref=sr_1_1?keywords=laptop&qid=1234567890&sr=8-1",
    "https://www.ebay.com/itm/123456789012?hash=item1c0a3b4c5d&_trkparms=aid%3D111001%26algo%3DREC.SEED",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.reddit.com/r/programming/comments/abc123/some_post_title/",
    "https://stackoverflow.com/questions/12345678/how-to-fix-this-python-error",
    "https://github.com/microsoft/vscode/issues/12345",
    "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise",
    "https://www.booking.com/hotel/us/marriott-downtown.html?aid=304142&checkin=2026-05-01&checkout=2026-05-07",
    "https://www.expedia.com/Flights-Search?leg1=from:LAX,to:JFK,departure:2026-05-01&passengers=adults:1",
    "https://www.walmart.com/search?q=laptop+computer&sort=best_seller&affinityOverride=default",
    "https://www.bestbuy.com/site/searchpage.jsp?st=gaming+laptop&_dyncharset=UTF-8",
    "https://support.google.com/accounts/answer/27441?hl=en",
    "https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token",
    "https://learn.microsoft.com/en-us/training/paths/sc-900-describe-security-compliance-trust/",

    # ---- http:// legitimate sites (so uses_https != 1 for all clean) ----
    "http://www.iana.org/domains/reserved",
    "http://neverssl.com/",
    "http://www.w3.org/",
    "http://info.cern.ch/",
    "http://httpbin.org/get",
    "http://checkip.amazonaws.com/",
    "http://detectportal.firefox.com/",
    "http://www.timeanddate.com/calendar/",
    "http://tools.ietf.org/html/rfc2616",
    "http://www.speedtest.net/",

    # ---- News / media (HTTPS, varying path depth) ----
    "https://www.bbc.com/news/technology",
    "https://www.bbc.com/news/technology-65403684",
    "https://www.cnn.com/2026/04/15/tech/ai-phishing/index.html",
    "https://techcrunch.com/2026/04/20/new-phishing-campaign-targets-crypto-users/",
    "https://www.theverge.com/2026/4/19/23730000/google-passkeys-security-update",
    "https://arstechnica.com/security/2026/04/phishing-attack-bypasses-mfa-using-evilginx/",
    "https://www.reuters.com/technology/cybersecurity/2026-04-18/",
    "https://www.wired.com/story/2fa-authentication-bypass-phishing/",

    # ---- Government / education ----
    "https://www.usa.gov/",
    "https://www.irs.gov/filing/",
    "https://www.ssa.gov/myaccount/",
    "https://www.cdc.gov/coronavirus/2019-ncov/index.html",
    "https://www.gov.uk/government/organisations/hm-revenue-customs",
    "https://www.canada.ca/en/revenue-agency.html",
    "https://www.mit.edu/",
    "https://www.harvard.edu/",
    "https://www.stanford.edu/",
    "https://web.stanford.edu/class/cs224n/",
    "https://ocw.mit.edu/courses/6-042j-mathematics-for-computer-science-fall-2010/",

    # ---- Banking (same brand tokens as phishing targets) ----
    "https://www.chase.com/personal/banking",
    "https://www.bankofamerica.com/online-banking/",
    "https://www.wellsfargo.com/online-banking/",
    "https://www.citibank.com/us/consumer/creditcards/",
    "https://www.hsbc.com/who-we-are/about-hsbc",
    "https://www.barclays.co.uk/personal-banking/",
    "https://www.lloydsbank.com/banking/mobile-bank-account.html",
    "https://www.americanexpress.com/en-us/account/login",

    # ---- E-commerce with complex URLs ----
    "https://www.etsy.com/listing/123456789/handmade-leather-wallet",
    "https://www.ikea.com/us/en/cat/sofas-fu003/",
    "https://www.aliexpress.com/item/1005003456789012.html",
    "https://www.target.com/p/samsung-65-class-qled-4k-tv/-/A-12345678",

    # ---- Cloud / developer (deep subdomains) ----
    "https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#Instances:",
    "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview",
    "https://console.cloud.google.com/compute/instances?project=my-project-id",
    "https://app.netlify.com/sites/my-site/settings/domain",
    "https://vercel.com/dashboard",
    "https://app.supabase.com/project/abcdefghijklmn/database/tables",

    # ---- Crypto / fintech (brand tokens shared with phishing) ----
    "https://www.coinbase.com/signin",
    "https://accounts.binance.com/en/login",
    "https://www.kraken.com/sign-in",
    "https://account.blockchain.com/en/#/login",
    "https://www.gemini.com/",

    # ---- Misc unique TLDs / patterns ----
    "https://www.mozilla.org/en-US/firefox/new/",
    "https://www.eff.org/issues/privacy",
    "https://haveibeenpwned.com/",
    "https://www.virustotal.com/gui/home/upload",
    "https://letsencrypt.org/getting-started/",
    "https://www.namecheap.com/domains/",
    "https://www.godaddy.com/domains/domain-name-search",
    "https://web.archive.org/web/20240101000000*/example.com",
    "https://archive.org/details/internetarchive",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value: object, default: int = 0) -> int:
    try:
        if value in (None, "", "FALSE", "false"):
            return default
        if str(value).upper() == "TRUE":
            return 1
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _bool_int(value: object) -> int:
    """Return 1 for truthy strings (TRUE/1/yes/…), else 0."""
    return 1 if str(value or "").strip().upper() in {"TRUE", "1", "YES", "Y", "T"} else 0


def _compute_lexical_features(url: str) -> dict[str, float]:
    """Derive URL-structure features from a raw URL string."""
    try:
        target = normalize_input_url(url)
    except Exception:
        return {field: 0.0 for field in FEATURE_FIELDS}

    from scanner.ml_features import (
        BRAND_TOKENS,
        SUSPICIOUS_TOKENS,
        _entropy,
        _token_count,
    )

    normalized = target.normalized_url
    lowered = normalized.lower()
    path_depth = len([p for p in target.path.split("/") if p])
    query_param_count = 0 if not target.query else target.query.count("&") + 1
    special_chars = sum(1 for c in normalized if not c.isalnum())

    return {
        "url_length": float(len(normalized)),
        "host_length": float(len(target.host)),
        "path_length": float(len(target.path or "")),
        "query_length": float(len(target.query or "")),
        "num_dots": float(target.host.count(".")),
        "num_hyphens": float(target.host.count("-")),
        "num_digits": float(sum(c.isdigit() for c in normalized)),
        "num_special_chars": float(special_chars),
        "has_at": float(1 if "@" in normalized else 0),
        "is_ip": float(1 if target.is_ip else 0),
        "uses_https": float(1 if target.scheme == "https" else 0),
        "subdomain_count": float(max(target.host.count(".") - 1, 0)),
        "path_depth": float(path_depth),
        "query_param_count": float(query_param_count),
        "host_entropy": _entropy(target.host),
        "path_entropy": _entropy(target.path or ""),
        "suspicious_token_count": float(_token_count(SUSPICIOUS_TOKENS, lowered)),
        "brand_token_count": float(_token_count(BRAND_TOKENS, lowered)),
    }


def _map_csv_row_to_features(row: dict[str, str], url: str) -> dict[str, float]:
    """Map a NewUrl_features.csv row to the ML FEATURE_FIELDS schema."""
    features = {field: 0.0 for field in FEATURE_FIELDS}

    # URL-derived lexical features
    features.update(_compute_lexical_features(url))

    # Direct signal column mappings
    features["form_count"] = _safe_float(row.get("signals.form_count"))
    features["password_field_count"] = _safe_float(row.get("signals.password_fields"))
    features["hidden_elements_flag"] = float(
        1 if _safe_int(row.get("signals.hidden_fields")) > 0 else 0
    )
    features["form_action_mismatch"] = float(_bool_int(row.get("signals.form_action_external")))
    features["external_image_domain_count"] = _safe_float(row.get("signals.external_links"))
    features["suspicious_phrase_count"] = _safe_float(row.get("signals.suspicious_anchors"))

    # Obfuscation / scripting signals -> content_keyword_flag
    obfuscation = _safe_float(row.get("signals.obfuscation_score"))
    eval_calls = _safe_int(row.get("signals.eval_calls"))
    base64_blobs = _safe_int(row.get("signals.base64_blobs"))
    doc_write = _safe_int(row.get("signals.document_write"))
    if obfuscation > 0 or eval_calls > 0 or base64_blobs > 0 or doc_write > 0:
        features["content_keyword_flag"] = 1.0

    # HTTP status code -> content_available
    http_code = _safe_int(row.get("code"))
    features["content_available"] = float(1 if http_code == 200 else 0)

    # Keylogger / fingerprint -> suspicious proxy
    if _bool_int(row.get("signals.keylogger_detected")):
        features["suspicious_phrase_count"] = max(features["suspicious_phrase_count"], 1.0)

    # External scripts -> external_image_domain_count supplement
    ext_scripts = _safe_int(row.get("signals.external_scripts"))
    if ext_scripts > 0 and features["external_image_domain_count"] == 0:
        features["external_image_domain_count"] = float(ext_scripts)

    # Status 1 = connection error -> set unknown_check_count
    status = _safe_int(row.get("status"))
    if status != 0:
        features["unknown_check_count"] = 1.0

    return features


def _build_fasttext_row_from_csv(row: dict[str, str], url: str, label: str) -> dict[str, object]:
    """Build a snapshot-style dict for FastText corpus serialisation."""
    host = row.get("host") or ""
    form_count = _safe_int(row.get("signals.form_count"))
    password_fields = _safe_int(row.get("signals.password_fields"))
    form_action_external = _bool_int(row.get("signals.form_action_external"))
    obfuscation = _safe_float(row.get("signals.obfuscation_score"))
    suspicious_anchors = _safe_int(row.get("signals.suspicious_anchors"))
    eval_calls = _safe_int(row.get("signals.eval_calls"))

    return {
        "url": url,
        "normalized_url": url,
        "host": host,
        "is_phishing": label,
        # Content-like fields for FastText serialisation
        "form_count": form_count,
        "password_field_count": password_fields,
        "input_field_count": password_fields,
        "login_form_present": password_fields > 0,
        "no_navigation_menu": True,
        "form_action_mismatch": bool(form_action_external),
        "suspicious_keywords": bool(obfuscation > 0 or eval_calls > 0 or suspicious_anchors > 0),
        "content_fetched": _safe_int(row.get("code")) == 200,
        "fetch_error": _safe_int(row.get("status")) != 0,
    }


def _build_fasttext_clean_row(url: str) -> dict[str, object]:
    """Build a minimal clean-label FastText snapshot dict from a URL."""
    try:
        target = normalize_input_url(url)
        host = target.host
    except Exception:
        host = url
    return {
        "url": url,
        "normalized_url": url,
        "host": host,
        "is_phishing": "0",
        "form_count": 0,
        "password_field_count": 0,
        "input_field_count": 0,
        "login_form_present": False,
        "no_navigation_menu": False,
        "form_action_mismatch": False,
        "suspicious_keywords": False,
        "content_fetched": True,
        "fetch_error": False,
    }


# ---------------------------------------------------------------------------
# Feature dataset builder
# ---------------------------------------------------------------------------

def _read_dataset_csv_urls(dataset_csv: Path) -> list[str]:
    """Read URL-only Dataset.csv and return a deduplicated list of phishing URLs."""
    urls: list[str] = []
    with dataset_csv.open("r", newline="", encoding="utf-8-sig") as src:
        reader = csv.DictReader(src)
        for row in reader:
            url = (row.get("url") or "").strip()
            if url:
                urls.append(url)
    return urls


def build_feature_dataset_csv(
    dataset_csv: Path,
    new_features_csv: Path,
    output_csv: Path,
) -> tuple[int, int, int]:
    """Build a merged FEATURE_FIELDS-format CSV from both phishing sources + clean examples.

    Priority for phishing rows:
      1. NewUrl_features.csv – uses full signal mapping (richer features)
      2. Dataset.csv         – URL-only rows, lexical features + unknown_check_count=5
    URLs present in both sources are represented only once (NewUrl takes precedence).
    Returns (new_features_count, dataset_only_count, clean_count).
    """
    fieldnames = [
        "url",
        "normalized_url",
        "host",
        "is_phishing",
        "feature_version",
        "label_source",
        *FEATURE_FIELDS,
    ]

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    # -- Collect all NewUrl_features.csv rows keyed by URL --
    new_features_rows: dict[str, dict[str, str]] = {}
    with new_features_csv.open("r", newline="", encoding="utf-8") as src:
        for row in csv.DictReader(src):
            url = (row.get("url") or "").strip()
            if url and url not in new_features_rows:
                new_features_rows[url] = row

    # -- Collect all Dataset.csv URLs --
    dataset_urls = _read_dataset_csv_urls(dataset_csv)

    seen_urls: set[str] = set()
    new_features_count = 0
    dataset_only_count = 0
    clean_count = 0

    with output_csv.open("w", newline="", encoding="utf-8") as dst:
        writer = csv.DictWriter(dst, fieldnames=fieldnames)
        writer.writeheader()

        # 1. NewUrl_features.csv rows (rich signals)
        for url, row in new_features_rows.items():
            try:
                target = normalize_input_url(url)
            except Exception:
                continue
            features = _map_csv_row_to_features(row, url)
            out_row: dict[str, object] = {
                "url": url,
                "normalized_url": target.normalized_url,
                "host": target.host,
                "is_phishing": 1,
                "feature_version": FEATURE_VERSION,
                "label_source": "NewUrl_features.csv",
            }
            out_row.update(features)
            writer.writerow(out_row)
            seen_urls.add(url)
            new_features_count += 1

        # 2. Dataset.csv URLs not already covered (lexical features only)
        for url in dataset_urls:
            if url in seen_urls:
                continue
            try:
                target = normalize_input_url(url)
            except Exception:
                continue
            features = {field: 0.0 for field in FEATURE_FIELDS}
            features.update(_compute_lexical_features(url))
            # Scanner data unavailable; leave all scanner fields at 0 so the
            # model cannot trivially infer label from "unknown_check_count".
            out_row = {
                "url": url,
                "normalized_url": target.normalized_url,
                "host": target.host,
                "is_phishing": 1,
                "feature_version": FEATURE_VERSION,
                "label_source": "Dataset.csv",
            }
            out_row.update(features)
            writer.writerow(out_row)
            seen_urls.add(url)
            dataset_only_count += 1

        # 3. Curated clean examples (lexical features only)
        for clean_url in CLEAN_URLS:
            try:
                target = normalize_input_url(clean_url)
            except Exception:
                continue
            features = {field: 0.0 for field in FEATURE_FIELDS}
            features.update(_compute_lexical_features(clean_url))
            # Clean URLs that we didn't scan: mark content_available=1
            # (they're reachable) and unknown_check_count=0 (no scanner errors).
            features["content_available"] = 1.0
            features["unknown_check_count"] = 0.0
            out_row = {
                "url": clean_url,
                "normalized_url": target.normalized_url,
                "host": target.host,
                "is_phishing": 0,
                "feature_version": FEATURE_VERSION,
                "label_source": "curated_clean",
            }
            out_row.update(features)
            writer.writerow(out_row)
            clean_count += 1

    return new_features_count, dataset_only_count, clean_count


# ---------------------------------------------------------------------------
# FastText corpus builder
# ---------------------------------------------------------------------------

def build_combined_corpus_lines(
    dataset_csv: Path,
    new_features_csv: Path,
) -> list[str]:
    """Build FastText corpus lines from both phishing sources + clean examples.

    NewUrl_features.csv rows use full signal-enriched snapshots.
    Dataset.csv-only rows use URL-text-only snapshots.
    Clean rows are minimal URL-based snapshots.
    """
    rows: list[dict[str, object]] = []
    seen_urls: set[str] = set()

    # 1. NewUrl_features.csv (rich signals)
    with new_features_csv.open("r", newline="", encoding="utf-8") as src:
        for row in csv.DictReader(src):
            url = (row.get("url") or "").strip()
            if not url or url in seen_urls:
                continue
            rows.append(_build_fasttext_row_from_csv(row, url, "phishing"))
            seen_urls.add(url)

    # 2. Dataset.csv-only URLs (lexical fallback)
    for url in _read_dataset_csv_urls(dataset_csv):
        if url in seen_urls:
            continue
        try:
            target = normalize_input_url(url)
            host = target.host
        except Exception:
            host = url
        rows.append({
            "url": url,
            "normalized_url": url,
            "host": host,
            "is_phishing": "phishing",
            "form_count": 0,
            "password_field_count": 0,
            "input_field_count": 0,
            "login_form_present": False,
            "no_navigation_menu": True,
            "form_action_mismatch": False,
            "suspicious_keywords": False,
            "content_fetched": False,
            "fetch_error": False,
        })
        seen_urls.add(url)

    # 3. Clean examples
    for clean_url in CLEAN_URLS:
        rows.append(_build_fasttext_clean_row(clean_url))

    return build_corpus_lines(rows, dedupe_visible_text=False)


# ---------------------------------------------------------------------------
# Training runners
# ---------------------------------------------------------------------------

def run_fasttext_training(
    *,
    dataset_csv: Path,
    new_features_csv: Path,
    corpus_path: Path,
    model_path: Path,
    metadata_path: Path,
    config: FastTextTrainingConfig,
    dry_run: bool = False,
) -> None:
    print("\n=== FastText Training ===")
    print(f"  Dataset.csv:         {dataset_csv}")
    print(f"  NewUrl_features.csv: {new_features_csv}")
    print(f"  Corpus output:       {corpus_path}")

    # Build corpus fresh from both sources (replaces existing corpus)
    all_lines = build_combined_corpus_lines(dataset_csv, new_features_csv)
    phishing_count = sum(1 for l in all_lines if f"{LABEL_PREFIX}phishing" in l)
    clean_count = sum(1 for l in all_lines if f"{LABEL_PREFIX}clean" in l)
    print(f"  Corpus lines: {len(all_lines)} total  ({phishing_count} phishing, {clean_count} clean)")

    if dry_run:
        print("  [dry-run] Skipping write and training.")
        return

    write_corpus_file(all_lines, corpus_path)
    print(f"  Corpus written: {corpus_path}")

    print("  Training FastText model…")
    metadata = train_fasttext_model(
        corpus_path=corpus_path,
        model_path=model_path,
        metadata_path=metadata_path,
        config=config,
    )
    print(f"  Model saved:    {metadata['model_path']}")
    print(f"  Metadata saved: {metadata_path}")
    print(f"  Version:        {metadata['model_version']}")
    label_counts = metadata.get("label_counts", {})
    print(f"  Label counts:   phishing={label_counts.get('phishing', '?')}  clean={label_counts.get('clean', '?')}")


def run_ml_training(
    *,
    dataset_csv: Path,
    new_features_csv: Path,
    artifacts_dir: Path,
    dry_run: bool = False,
) -> None:
    print("\n=== TensorFlow / ML Training ===")

    from scanner.settings import ScannerSettings
    from scanner.ml_training import (
        TensorFlowTrainingConfig,
        train_tensorflow_from_dataset,
    )

    settings = ScannerSettings()
    run_dir = artifacts_dir / f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    feature_csv = run_dir / "feature_dataset.csv"

    print(f"  Run dir:       {run_dir}")
    print(f"  Feature CSV:   {feature_csv}")

    new_count, old_count, clean_count = build_feature_dataset_csv(
        dataset_csv, new_features_csv, feature_csv
    )
    total = new_count + old_count + clean_count
    print(
        f"  Feature rows:  {new_count} (NewUrl signals) + {old_count} (Dataset.csv lexical)"
        f" + {clean_count} clean = {total} total"
    )
    print(f"  Phishing:clean ratio = {new_count + old_count}:{clean_count}")

    if dry_run:
        print("  [dry-run] Skipping model training.")
        return

    config = TensorFlowTrainingConfig(
        epochs=50,
        batch_size=32,
        learning_rate=0.001,
        hidden_units=(128, 64, 32),
        dropout_rate=0.25,
        early_stopping_patience=8,
        activate_after_training=True,
    )

    print("  Training TensorFlow model…")
    report = train_tensorflow_from_dataset(
        dataset_csv=feature_csv,
        output_dir=run_dir,
        config=config,
        settings=settings,
    )
    summary = report.get("summary", {})
    cm = report.get("confusion_matrix", {})
    print(f"  Accuracy:      {summary.get('accuracy')}")
    print(f"  Precision:     {summary.get('precision')}")
    print(f"  Recall:        {summary.get('recall')}")
    print(f"  F1:            {summary.get('f1')}")
    print(f"  ROC-AUC:       {summary.get('roc_auc')}")
    print(f"  Confusion:     TP={cm.get('tp')} FP={cm.get('fp')} FN={cm.get('fn')} TN={cm.get('tn')}")
    print(f"  Model path:    {report.get('artifacts', {}).get('active_model_path', run_dir / 'model.keras')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train FastText and TensorFlow models on NewUrl_features.csv."
    )
    parser.add_argument("--no-fasttext", action="store_true", help="Skip FastText training.")
    parser.add_argument("--no-ml", action="store_true", help="Skip TensorFlow ML training.")
    parser.add_argument("--dry-run", action="store_true", help="Parse only; do not write or train.")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    for path, name in [(NEW_FEATURES_CSV, "NewUrl_features.csv"), (DATASET_CSV, "Dataset.csv")]:
        if not path.exists():
            print(f"ERROR: {path} not found.", file=sys.stderr)
            return 1

    config = CapstoneConfig.from_env()
    ft_config = FastTextTrainingConfig(
        dim=config.fasttext_dim,
        epoch=config.fasttext_epoch,
        lr=config.fasttext_lr,
        word_ngrams=config.fasttext_word_ngrams,
        min_count=config.fasttext_min_count,
        loss=config.fasttext_loss,
        autotune=config.fasttext_autotune,
        autotune_duration=config.fasttext_autotune_duration,
        validation_ratio=config.fasttext_validation_ratio,
    )

    if not args.no_fasttext:
        run_fasttext_training(
            dataset_csv=DATASET_CSV,
            new_features_csv=NEW_FEATURES_CSV,
            corpus_path=CORPUS_PATH,
            model_path=FASTTEXT_MODEL_PATH,
            metadata_path=FASTTEXT_METADATA_PATH,
            config=ft_config,
            dry_run=args.dry_run,
        )

    if not args.no_ml:
        run_ml_training(
            dataset_csv=DATASET_CSV,
            new_features_csv=NEW_FEATURES_CSV,
            artifacts_dir=ML_ARTIFACTS_DIR,
            dry_run=args.dry_run,
        )

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
