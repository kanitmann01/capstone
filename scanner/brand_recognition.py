from __future__ import annotations

"""
High-throughput phishing and brand-recognition detector.

The detector is intentionally host-first: exact safe brand roots short-circuit
through a Bloom filter before the code performs vector search or edit-distance
work. Non-exact roots are compared against a curated target brand inventory of
100+ well-known global brands using character 3-gram TF-IDF, FAISS
nearest-neighbor search, and Levenshtein distance.
"""

from dataclasses import dataclass
import json
from typing import Any

import encodings.idna  # noqa: F401 - imported explicitly to document the stdlib IDNA codec dependency.
import faiss
import numpy as np
from Levenshtein import distance as levenshtein_distance
from pybloom_live import BloomFilter
from sklearn.feature_extraction.text import TfidfVectorizer
import tldextract


DEFAULT_TARGET_BRANDS: tuple[str, ...] = (
    # Consumer tech and OS vendors
    "apple", "microsoft", "google", "amazon", "meta", "facebook", "instagram",
    "whatsapp", "tiktok", "twitter", "linkedin", "youtube", "snapchat", "reddit",
    "pinterest", "github", "gitlab", "dropbox", "slack", "zoom", "salesforce",
    "oracle", "intel", "nvidia", "samsung", "sony", "dell", "lenovo", "huawei",
    "xiaomi",
    # Retail and e-commerce
    "ebay", "walmart", "target", "costco", "alibaba", "aliexpress", "shopify",
    "etsy", "bestbuy", "homedepot", "ikea", "nordstrom",
    # Streaming and media
    "netflix", "hulu", "disney", "spotify", "soundcloud", "twitch", "vimeo",
    # Finance and payments
    "paypal", "venmo", "stripe", "chase", "wellsfargo", "citibank", "capitalone",
    "americanexpress", "visa", "mastercard", "discover", "hsbc", "barclays",
    "usbank", "coinbase", "binance", "robinhood", "kraken",
    # Cloud and infrastructure
    "aws", "azure", "cloudflare", "digitalocean", "heroku", "vercel", "netlify",
    "akamai",
    # Shipping and logistics
    "fedex", "ups", "usps", "dhl",
    # Airlines
    "delta", "united", "lufthansa", "emirates",
    # Travel and mobility
    "booking", "airbnb", "expedia", "tripadvisor", "uber", "lyft",
    # Gaming
    "steam", "playstation", "xbox", "nintendo", "epicgames", "roblox",
    "minecraft", "nike",
    # Food and QSR
    "starbucks", "mcdonalds",
    # Search and web services
    "yahoo", "bing", "tumblr", "quora", "medium", "wordpress",
    # Productivity and creative
    "notion", "trello", "asana", "jira", "figma", "canva", "adobe", "autodesk",
    # Communications
    "skype", "telegram", "discord", "signal", "webex",
    # Automotive
    "tesla", "toyota", "honda", "ford", "bmw",
    # Asian internet giants
    "wechat", "tencent", "baidu", "naver", "line", "paytm", "flipkart",
    # Webmail and identity providers
    "gmail", "outlook", "icloud", "protonmail", "hotmail",
)


@dataclass(frozen=True)
class ParsedDomain:
    """Normalized domain pieces used by the brand-recognition pipeline."""

    subdomain: str
    root_domain: str
    tld: str
    idna_root: str
    is_homograph: bool


class BrandRecognitionDetector:
    """Detect brand typosquatting, homographs, and deceptive subdomains."""

    def __init__(
        self,
        target_brands: tuple[str, ...] | list[str] | None = None,
        *,
        false_positive_rate: float = 0.001,
        max_candidates: int = 10,
        min_similarity: float = 0.70,
    ) -> None:
        """Initialize the Bloom filter, TF-IDF vectorizer, and FAISS index once."""
        self.target_brands = self._normalize_brands(tuple(target_brands or DEFAULT_TARGET_BRANDS))
        self.max_candidates = max(1, min(int(max_candidates), len(self.target_brands)))
        self.min_similarity = max(0.0, min(1.0, float(min_similarity)))
        self.brand_set = frozenset(self.target_brands)
        self.safe_brand_filter = BloomFilter(capacity=max(len(self.target_brands), 1), error_rate=false_positive_rate)
        for brand in self.target_brands:
            self.safe_brand_filter.add(brand)
        self.tld_extract = tldextract.TLDExtract(suffix_list_urls=())
        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 3), lowercase=True, norm="l2")
        self._brand_matrix = self._fit_brand_vectors()
        self.index = self._build_faiss_index(self._brand_matrix)

    def analyze_url(self, url: str) -> dict[str, Any]:
        """Run the full brand-recognition pipeline for a raw URL."""
        try:
            parsed = self.preprocess_url(url)
        except Exception as exc:
            return self._error_payload(url, exc)

        payload = self._base_payload(url, parsed)
        root_domain = parsed.root_domain
        if not root_domain:
            payload.update(
                {
                    "status": "unknown",
                    "threat_type": "none",
                    "confidence_score": 0.0,
                    "unknown_reason": "missing_root_domain",
                }
            )
            return payload

        if root_domain in self.safe_brand_filter and root_domain in self.brand_set:
            payload.update(
                {
                    "status": "safe",
                    "threat_type": "none",
                    "matched_brand": root_domain,
                    "confidence_score": 0.99,
                    "brand_closeness": [self._closeness_row(root_domain, 1.0, 0, "exact_root_match")],
                }
            )
            return payload

        candidates = self._nearest_brand_candidates(root_domain)
        closeness_rows = [
            self._closeness_row(candidate["brand"], candidate["faiss_score"], candidate["distance"], "nearest_brand")
            for candidate in candidates
        ]

        closest = min(candidates, key=lambda item: item["distance"], default=None)
        matched_brand: str = ""
        threat_verdict: dict[str, Any] | None = None
        if parsed.is_homograph and closest and 0 <= int(closest["distance"]) <= 3:
            matched_brand = closest["brand"]
            threat_verdict = {
                "status": "scam",
                "threat_type": "homograph",
                "matched_brand": matched_brand,
                "confidence_score": self._confidence_from_distance(int(closest["distance"]), homograph=True),
                "risk_score": 98.0,
            }
        else:
            typo_match = next((candidate for candidate in candidates if 1 <= int(candidate["distance"]) <= 3), None)
            if typo_match:
                matched_brand = typo_match["brand"]
                threat_verdict = {
                    "status": "scam",
                    "threat_type": "typosquatting",
                    "matched_brand": matched_brand,
                    "confidence_score": self._confidence_from_distance(int(typo_match["distance"])),
                    "risk_score": 95.0,
                }
            else:
                deceptive_brand = self._brand_in_subdomain(parsed.subdomain)
                if deceptive_brand:
                    matched_brand = deceptive_brand
                    if not any(row["brand"] == deceptive_brand for row in closeness_rows):
                        closeness_rows.append(
                            self._closeness_row(deceptive_brand, 0.0, len(root_domain), "deceptive_subdomain_match")
                        )
                    threat_verdict = {
                        "status": "scam",
                        "threat_type": "deceptive_subdomain",
                        "matched_brand": matched_brand,
                        "confidence_score": 0.88,
                        "risk_score": 88.0,
                    }

        payload["brand_closeness"] = self._filter_closeness_rows(closeness_rows, matched_brand)
        if threat_verdict is not None:
            payload.update(threat_verdict)
            return payload

        payload.update({"status": "safe", "threat_type": "none", "confidence_score": 0.25})
        return payload

    def preprocess_url(self, raw_url: str) -> ParsedDomain:
        """Extract subdomain, root domain, TLD, and IDNA homograph metadata."""
        value = (raw_url or "").strip()
        if not value:
            raise ValueError("URL is required.")
        parse_target = value if "://" in value else f"http://{value}"
        extracted = self.tld_extract(parse_target)
        root_domain = str(extracted.domain or "").strip().lower()
        subdomain = str(extracted.subdomain or "").strip().lower()
        suffix = str(extracted.suffix or "").strip().lower()
        if not root_domain:
            raise ValueError("URL root domain is missing or invalid.")
        idna_root = root_domain.encode("idna").decode("ascii")
        is_homograph = idna_root != root_domain or idna_root.startswith("xn--")
        return ParsedDomain(
            subdomain=subdomain,
            root_domain=root_domain,
            tld=suffix,
            idna_root=idna_root,
            is_homograph=is_homograph,
        )

    def _nearest_brand_candidates(self, root_domain: str) -> list[dict[str, Any]]:
        """Use TF-IDF and FAISS to retrieve candidate brands before edit distance.

        FAISS handles the common "search-space reduction" case in O(log N), but
        short typosquats can share zero character 3-grams with their target
        brand (e.g. "n1ke" vs "nike"), so we complement the ANN result with a
        bounded full scan that only considers brands close in length. The union
        is deduplicated and returned sorted by edit distance.
        """
        try:
            query = self.vectorizer.transform([root_domain]).astype(np.float32).toarray()
            faiss.normalize_L2(query)
            scores, indices = self.index.search(query, self.max_candidates)
        except Exception as exc:
            raise RuntimeError("FAISS brand lookup failed.") from exc

        candidates: dict[str, dict[str, Any]] = {}
        for raw_score, raw_index in zip(scores[0], indices[0], strict=False):
            if raw_index < 0:
                continue
            brand = self.target_brands[int(raw_index)]
            candidates[brand] = {
                "brand": brand,
                "faiss_score": float(max(raw_score, 0.0)),
                "distance": int(levenshtein_distance(root_domain, brand)),
            }

        has_close_match = any(int(row["distance"]) <= 3 for row in candidates.values())
        if not has_close_match:
            for brand in self.target_brands:
                if brand in candidates:
                    continue
                if abs(len(brand) - len(root_domain)) > 3:
                    continue
                dist = int(levenshtein_distance(root_domain, brand))
                if dist <= 3:
                    candidates[brand] = {
                        "brand": brand,
                        "faiss_score": 0.0,
                        "distance": dist,
                    }

        sorted_candidates = sorted(
            candidates.values(),
            key=lambda item: (int(item["distance"]), -float(item["faiss_score"]), item["brand"]),
        )
        return sorted_candidates[: self.max_candidates]

    def _fit_brand_vectors(self) -> np.ndarray:
        """Fit character 3-gram TF-IDF vectors for the target brand roots."""
        matrix = self.vectorizer.fit_transform(self.target_brands).astype(np.float32).toarray()
        faiss.normalize_L2(matrix)
        return np.ascontiguousarray(matrix, dtype=np.float32)

    def _build_faiss_index(self, matrix: np.ndarray) -> faiss.IndexFlatIP:
        """Build an in-memory FAISS index for cosine-similar brand retrieval."""
        index = faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        return index

    def _brand_in_subdomain(self, subdomain: str) -> str:
        """Return the first exact target brand found inside the isolated subdomain."""
        normalized = subdomain.replace("-", "").replace("_", "").replace(".", "")
        for brand in self.target_brands:
            if brand in normalized:
                return brand
        return ""

    def _filter_closeness_rows(
        self, rows: list[dict[str, Any]], matched_brand: str
    ) -> list[dict[str, Any]]:
        """Apply the similarity threshold while always keeping match/exact rows."""
        if not rows:
            return []
        preserved_reasons = {"exact_root_match", "deceptive_subdomain_match"}
        filtered: list[dict[str, Any]] = []
        for row in rows:
            similarity = float(row.get("similarity_score", 0.0))
            is_match = bool(matched_brand) and row.get("brand") == matched_brand
            is_preserved = row.get("match_reason") in preserved_reasons
            if similarity >= self.min_similarity or is_match or is_preserved:
                filtered.append(row)
        filtered.sort(key=lambda item: float(item.get("similarity_score", 0.0)), reverse=True)
        return filtered

    def _base_payload(self, url: str, parsed: ParsedDomain) -> dict[str, Any]:
        """Create the common JSON-serializable response shape."""
        return {
            "url_analyzed": url,
            "parsed_root": parsed.root_domain,
            "parsed_subdomain": parsed.subdomain,
            "parsed_tld": parsed.tld,
            "idna_root": parsed.idna_root,
            "homograph_detected": parsed.is_homograph,
            "status": "safe",
            "threat_type": "none",
            "matched_brand": "",
            "confidence_score": 0.0,
            "risk_score": 0.0,
            "brand_closeness": [],
            "brand_closeness_threshold": round(self.min_similarity, 4),
            "brand_inventory_size": len(self.target_brands),
        }

    def _error_payload(self, url: str, exc: Exception) -> dict[str, Any]:
        """Return a bounded error payload when parsing or analysis fails."""
        return {
            "url_analyzed": url,
            "parsed_root": "",
            "parsed_subdomain": "",
            "parsed_tld": "",
            "idna_root": "",
            "homograph_detected": False,
            "status": "unknown",
            "threat_type": "none",
            "matched_brand": "",
            "confidence_score": 0.0,
            "risk_score": 0.0,
            "brand_closeness": [],
            "brand_closeness_threshold": round(self.min_similarity, 4),
            "brand_inventory_size": len(self.target_brands),
            "unknown_reason": str(exc),
        }

    def _closeness_row(self, brand: str, faiss_score: float, distance: int, reason: str) -> dict[str, Any]:
        """Build one visualization row comparing the analyzed root with a real brand."""
        similarity_score = max(0.0, min(1.0, 1.0 - (float(distance) / max(len(brand), 1))))
        return {
            "brand": brand,
            "real_domain": f"{brand}.com",
            "levenshtein_distance": int(distance),
            "faiss_score": round(float(faiss_score), 4),
            "similarity_score": round(similarity_score, 4),
            "match_reason": reason,
        }

    def _confidence_from_distance(self, distance: int, *, homograph: bool = False) -> float:
        """Convert edit distance into a bounded confidence score."""
        base = {0: 0.98, 1: 0.95, 2: 0.9, 3: 0.82}.get(distance, 0.65)
        if homograph:
            base = min(base + 0.03, 0.99)
        return round(base, 2)

    def _normalize_brands(self, brands: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize configured brand roots while preserving first-seen order."""
        seen: set[str] = set()
        normalized: list[str] = []
        for brand in brands:
            value = "".join(char for char in str(brand or "").lower() if char.isalnum())
            if len(value) < 3 or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        if not normalized:
            raise ValueError("At least one target brand is required.")
        return tuple(normalized)


if __name__ == "__main__":
    detector = BrandRecognitionDetector()
    examples = [
        "https://nike.com",
        "http://n1ke.com/login",
        "http://nιke.com/login",
        "https://netflix.login.user123.com",
    ]
    for example_url in examples:
        print(json.dumps(detector.analyze_url(example_url), indent=2, ensure_ascii=True))
