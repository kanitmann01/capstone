"""HuggingFace BERT URL classifier comparator lens.

Lazy-loads ``ealvaradob/bert-finetuned-phishing`` via the transformers
pipeline, caches the model under ``.cache/hf-models/``, and runs CPU-only
inference. Decision rule: model probability >= 0.5 ⇒ phishing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

HF_MODEL_ID = "ealvaradob/bert-finetuned-phishing"
CACHE_DIR = Path(".cache/hf-models")

_pipeline: Any = None


def _get_pipeline():
    """Lazy-load the HuggingFace text-classification pipeline."""
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    try:
        from transformers import pipeline
    except ImportError as exc:
        raise RuntimeError(
            "transformers library is required for hf_url_classifier"
        ) from exc
    os.environ.setdefault("HF_HOME", str(CACHE_DIR.resolve()))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _pipeline = pipeline(
        "text-classification",
        model=HF_MODEL_ID,
        tokenizer=HF_MODEL_ID,
        device=-1,  # CPU
        truncation=True,
        max_length=512,
    )
    return _pipeline


def score_url(url: str) -> dict:
    """Classify a URL with the public BERT model and return a verdict dict."""
    pipe = _get_pipeline()
    result = pipe(url)[0]
    label = result.get("label", "").lower()
    score = float(result.get("score", 0.0))
    # Some versions return LABEL_0/LABEL_1; treat high confidence as phishing
    is_phishing = "phish" in label or label.endswith("1")
    return {
        "lens": "hf_url_classifier",
        "risk_score": round(score * 100, 2),
        "predicted_is_phishing": is_phishing and score >= 0.5,
        "raw_label": label,
        "raw_score": round(score, 4),
    }
