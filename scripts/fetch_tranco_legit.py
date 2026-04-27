"""Fetch and filter the Tranco top-1M list for legitimate login-bearing domains.

Downloads the latest Tranco daily CSV, caches it under ``.cache/tranco/``,
takes the top N domains, filters to the bank/brand/SaaS-login universe,
appends representative service paths for banks, and emits a labeled CSV.

The output combines:
  1. All official domains from brand_profiles + brand_profiles_banks (with /login)
  2. All curated SaaS-login domains (with /login)
  3. Tranco-ranked domains that match the brand/bank/SaaS universe

Usage:
    python scripts/fetch_tranco_legit.py

Output:
    data/processed/tranco_legit.csv
    columns: url,is_phishing,host,source
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from pathlib import Path
from typing import Any
from urllib.request import urlopen

import tldextract

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.brand_recognition import DEFAULT_TARGET_BRANDS  # noqa: E402
from scanner.brand_profiles import (
    _load_raw_records,
    BRAND_PROFILE_PATH,
    BRAND_PROFILE_BANKS_PATH,
)  # noqa: E402


TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
CACHE_DIR = Path(".cache/tranco")
OUTPUT_PATH = Path("data/processed/tranco_legit.csv")
TOP_N = 500_000

SAAS_LOGIN_DOMAINS: set[str] = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "slack.com",
    "dropbox.com",
    "box.com",
    "drive.google.com",
    "onedrive.live.com",
    "icloud.com",
    "microsoft.com",
    "office.com",
    "zoom.us",
    "webex.com",
    "gotomeeting.com",
    "teams.microsoft.com",
    "discord.com",
    "telegram.org",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "tiktok.com",
    "youtube.com",
    "netflix.com",
    "spotify.com",
    "amazon.com",
    "ebay.com",
    "paypal.com",
    "stripe.com",
    "shopify.com",
    "wordpress.com",
    "medium.com",
    "notion.so",
    "trello.com",
    "asana.com",
    "monday.com",
    "salesforce.com",
    "hubspot.com",
    "mailchimp.com",
    "zendesk.com",
    "intercom.com",
    "freshdesk.com",
    "atlassian.com",
    "jira.com",
    "confluence.com",
    "figma.com",
    "canva.com",
    "adobe.com",
    "autodesk.com",
    "heroku.com",
    "vercel.com",
    "netlify.com",
    "firebaseapp.com",
    "cloudflare.com",
    "digitalocean.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "gcp.google.com",
    "google.com",
    "gmail.com",
    "outlook.com",
    "protonmail.com",
    "hotmail.com",
    "yahoo.com",
    "apple.com",
    "reddit.com",
    "pinterest.com",
    "quora.com",
    "tumblr.com",
    "bing.com",
    "soundcloud.com",
    "vimeo.com",
    "twitch.tv",
    "hulu.com",
    "disney.com",
    "espn.com",
    "cnn.com",
    "bbc.com",
    "nytimes.com",
    "washingtonpost.com",
    "forbes.com",
    "bloomberg.com",
    "reuters.com",
    "wsj.com",
    "ft.com",
    "economist.com",
    "nature.com",
    "science.org",
    "arxiv.org",
    "stackexchange.com",
    "stackoverflow.com",
    "wikipedia.org",
    "wikimedia.org",
    "mediawiki.org",
    "archive.org",
    "archiveofourown.org",
    "fanfiction.net",
    "goodreads.com",
    "imdb.com",
    "rottentomatoes.com",
    "metacritic.com",
    "letterboxd.com",
    "trakt.tv",
    "themoviedb.org",
    "tvdb.com",
    "anidb.net",
    "myanimelist.net",
    "kitsu.io",
    "anilist.co",
    "crunchyroll.com",
    "funimation.com",
    "hidive.com",
    "vrV.com",
    "vrv.co",
    "plex.tv",
    "emby.media",
    "jellyfin.org",
    "kodi.tv",
    "xbmc.org",
    "mpv.io",
    "vlc.org",
    "videolan.org",
    "ffmpeg.org",
    "obsproject.com",
    "streamlabs.com",
    "restream.io",
    "streamyard.com",
    "vdo.ninja",
    "obs.ninja",
}

BANK_LOGIN_PATHS: dict[str, str] = {
    "chase.com": "/login",
    "bankofamerica.com": "/login",
    "wellsfargo.com": "/login",
    "citi.com": "/login",
    "usbank.com": "/login",
    "pnc.com": "/login",
    "truist.com": "/login",
    "goldmansachs.com": "/login",
    "marcus.com": "/login",
    "capitalone.com": "/login",
    "td.com": "/login",
    "schwab.com": "/login",
    "ally.com": "/login",
    "discover.com": "/login",
    "citizensbank.com": "/login",
    "53.com": "/login",
    "key.com": "/login",
    "regions.com": "/login",
    "mtb.com": "/login",
    "huntington.com": "/login",
    "northerntrust.com": "/login",
    "bnymellon.com": "/login",
    "statestreet.com": "/login",
    "americanexpress.com": "/login",
    "usaa.com": "/login",
    "navyfederal.org": "/login",
    "sofi.com": "/login",
    "chime.com": "/login",
    "varomoney.com": "/login",
    "firstrepublic.com": "/login",
    "svb.com": "/login",
    "hsbc.com": "/login",
    "barclays.co.uk": "/login",
    "lloydsbank.com": "/login",
    "natwest.com": "/login",
    "santander.com": "/login",
    "bnpparibas.com": "/login",
    "societegenerale.com": "/login",
    "credit-agricole.fr": "/login",
    "deutsche-bank.de": "/login",
    "commerzbank.de": "/login",
    "ing.com": "/login",
    "rabobank.nl": "/login",
    "abnamro.nl": "/login",
    "ubs.com": "/login",
    "credit-suisse.com": "/login",
    "juliusbaer.com": "/login",
    "standardchartered.com": "/login",
    "unicredit.it": "/login",
    "intesasanpaolo.com": "/login",
    "nordea.com": "/login",
    "seb.se": "/login",
    "swedbank.se": "/login",
    "danskebank.dk": "/login",
    "kbc.be": "/login",
    "erstebank.com": "/login",
    "icbc.com.cn": "/login",
    "ccb.com": "/login",
    "abchina.com": "/login",
    "boc.cn": "/login",
    "bankcomm.com": "/login",
    "cmbchina.com": "/login",
    "mufg.jp": "/login",
    "mizuhobank.com": "/login",
    "smbc.co.jp": "/login",
    "nomura.com": "/login",
    "dbs.com.sg": "/login",
    "ocbc.com": "/login",
    "uob.com.sg": "/login",
    "maybank2u.com.my": "/login",
    "cimbclicks.com.my": "/login",
    "hdfcbank.com": "/login",
    "icicibank.com": "/login",
    "onlinesbi.sbi": "/login",
    "axisbank.com": "/login",
    "kotak.com": "/login",
    "emiratesnbd.com": "/login",
    "adcb.com": "/login",
    "qnb.com": "/login",
    "alahlionline.com": "/login",
    "itau.com.br": "/login",
    "bradesco.com.br": "/login",
    "bb.com.br": "/login",
    "bbva.com": "/login",
    "scotiabank.com": "/login",
    "rbcroyalbank.com": "/login",
    "tdcanadatrust.com": "/login",
    "westpac.com.au": "/login",
    "anz.com": "/login",
    "commbank.com.au": "/login",
    "nab.com.au": "/login",
    "revolut.com": "/login",
    "wise.com": "/login",
    "n26.com": "/login",
    "monzo.com": "/login",
    "starlingbank.com": "/login",
    "nubank.com.br": "/login",
    "mercury.com": "/login",
    "brex.com": "/login",
    "cash.app": "/login",
    "klarna.com": "/login",
}


def download_tranco_zip() -> bytes:
    """Download the Tranco top-1M CSV zip and return raw bytes."""
    print(f"Downloading {TRANCO_URL} ...")
    with urlopen(TRANCO_URL, timeout=60) as response:
        return response.read()


def get_cached_or_download() -> bytes:
    """Return cached zip bytes or download and cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / "top-1m.csv.zip"
    if cache_path.exists():
        print(f"Using cached {cache_path}")
        return cache_path.read_bytes()
    data = download_tranco_zip()
    cache_path.write_bytes(data)
    print(f"Cached to {cache_path}")
    return data


def load_top_n_domains(zip_bytes: bytes, n: int) -> list[str]:
    """Extract the top N domains from the Tranco zip."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        csv_name = next(name for name in zf.namelist() if name.endswith(".csv"))
        with zf.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            domains: list[str] = []
            for _, domain in reader:
                domains.append(domain.strip().lower())
                if len(domains) >= n:
                    break
    return domains


def load_brand_and_bank_domains() -> set[str]:
    """Load official domains from both brand profile files."""
    domains: set[str] = set()
    for path in (BRAND_PROFILE_PATH, BRAND_PROFILE_BANKS_PATH):
        for record in _load_raw_records(path):
            for domain in record.get("official_domains", []):
                domain = domain.strip().lower()
                if domain:
                    domains.add(domain)
    return domains


def classify_domain(
    domain: str, brand_domains: set[str], target_brands: set[str]
) -> str | None:
    """Classify a domain into bank/brand/saas/tranco or None if rejected."""
    # Direct match in brand/bank official domains
    if domain in brand_domains:
        # Heuristic: classify as bank if it contains typical bank keywords
        bank_keywords = {
            "bank",
            "chase",
            "wells",
            "citi",
            "hsbc",
            "barclays",
            "lloyds",
            "santander",
            "deutsche",
            "bnp",
            "ing",
            "dbs",
            "hdfc",
            "icici",
            "sbi",
            "axis",
            "kotak",
            "rbc",
            "td",
            "anz",
            "commbank",
            "nab",
            "westpac",
            "scotiabank",
            "itau",
            "bradesco",
            "bbva",
            "mufg",
            "mizuho",
            "smbc",
            "nomura",
            "ocbc",
            "uob",
            "maybank",
            "cimb",
            "emirates",
            "adcb",
            "qnb",
            "revolut",
            "n26",
            "monzo",
            "starling",
            "nubank",
            "chime",
            "sofi",
            "varo",
            "mercury",
            "brex",
            "klarna",
            "wise",
        }
        if any(kw in domain for kw in bank_keywords):
            return "bank"
        return "brand"

    # Subdomain match for brand/bank domains
    for official in brand_domains:
        if domain == official or domain.endswith(f".{official}"):
            if any(
                kw in official
                for kw in {
                    "bank",
                    "chase",
                    "wells",
                    "citi",
                    "hsbc",
                    "barclays",
                    "lloyds",
                    "santander",
                    "deutsche",
                    "bnp",
                    "ing",
                    "dbs",
                    "hdfc",
                    "icici",
                    "sbi",
                    "axis",
                    "kotak",
                    "rbc",
                    "td",
                    "anz",
                    "commbank",
                    "nab",
                    "westpac",
                    "scotiabank",
                    "itau",
                    "bradesco",
                    "bbva",
                    "mufg",
                    "mizuho",
                    "smbc",
                    "nomura",
                    "ocbc",
                    "uob",
                    "maybank",
                    "cimb",
                    "emirates",
                    "adcb",
                    "qnb",
                    "revolut",
                    "n26",
                    "monzo",
                    "starling",
                    "nubank",
                    "chime",
                    "sofi",
                    "varo",
                    "mercury",
                    "brex",
                    "klarna",
                    "wise",
                }
            ):
                return "bank"
            return "brand"

    # SaaS-login match
    for saas in SAAS_LOGIN_DOMAINS:
        if domain == saas or domain.endswith(f".{saas}"):
            return "saas"

    # Root-domain match against target brands (catches brand domains not in official_domains)
    ext = tldextract.extract(domain)
    root = ext.domain.lower()
    if root in target_brands and len(root) >= 3:
        if any(
            kw in root
            for kw in {
                "bank",
                "chase",
                "wells",
                "citi",
                "hsbc",
                "barclays",
                "lloyds",
                "santander",
                "deutsche",
                "bnp",
                "ing",
                "dbs",
                "hdfc",
                "icici",
                "sbi",
                "axis",
                "kotak",
                "rbc",
                "td",
                "anz",
                "commbank",
                "nab",
                "westpac",
                "scotiabank",
                "itau",
                "bradesco",
                "bbva",
                "mufg",
                "mizuho",
                "smbc",
                "nomura",
                "ocbc",
                "uob",
                "maybank",
                "cimb",
                "emirates",
                "adcb",
                "qnb",
                "revolut",
                "n26",
                "monzo",
                "starling",
                "nubank",
                "chime",
                "sofi",
                "varo",
                "mercury",
                "brex",
                "klarna",
                "wise",
            }
        ):
            return "bank"
        return "brand"

    return None


def build_url(domain: str, source: str) -> str:
    """Build a representative URL, appending a login path for banks."""
    if source == "bank" and domain in BANK_LOGIN_PATHS:
        return f"https://{domain}{BANK_LOGIN_PATHS[domain]}"
    return f"https://{domain}/login"


def main() -> int:
    """Entry point: download, filter, and write the legitimate URL CSV."""
    zip_bytes = get_cached_or_download()
    domains = load_top_n_domains(zip_bytes, TOP_N)
    brand_domains = load_brand_and_bank_domains()
    target_brands = set(DEFAULT_TARGET_BRANDS)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. Direct official domains (guaranteed legitimate, even if not in Tranco)
    for domain in sorted(brand_domains):
        if domain in seen:
            continue
        seen.add(domain)
        source = classify_domain(domain, brand_domains, target_brands)
        if source is None:
            source = "brand"
        rows.append(
            {
                "url": build_url(domain, source),
                "is_phishing": 0,
                "host": domain,
                "source": source,
            }
        )

    # 2. SaaS-login domains (guaranteed legitimate)
    for domain in sorted(SAAS_LOGIN_DOMAINS):
        if domain in seen:
            continue
        seen.add(domain)
        rows.append(
            {
                "url": f"https://{domain}/login",
                "is_phishing": 0,
                "host": domain,
                "source": "saas",
            }
        )

    # 3. Tranco-ranked domains that match our universe
    tranco_matches = 0
    for domain in domains:
        if domain in seen:
            continue
        source = classify_domain(domain, brand_domains, target_brands)
        if source is None:
            continue
        seen.add(domain)
        rows.append(
            {
                "url": build_url(domain, source),
                "is_phishing": 0,
                "host": domain,
                "source": source,
            }
        )
        tranco_matches += 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "is_phishing", "host", "source"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} legitimate URLs to {OUTPUT_PATH}")
    print(f"  Direct official domains: {len(brand_domains)}")
    print(f"  SaaS domains: {len(SAAS_LOGIN_DOMAINS)}")
    print(f"  Tranco matches: {tranco_matches}")
    by_source: dict[str, int] = {}
    for row in rows:
        by_source[row["source"]] = by_source.get(row["source"], 0) + 1
    for source, count in sorted(by_source.items()):
        print(f"  {source}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
