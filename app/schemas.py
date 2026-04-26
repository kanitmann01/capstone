from __future__ import annotations

"""
Pydantic request and response models for API validation and serialization.

Defines the structured payloads used by the FastAPI endpoints in ``app.api``.
Requests enforce required fields (e.g., ``url``) while responses describe the
rich output of a hybrid phishing scan.
"""

from typing import Any  # Standard library: generic type hints

from pydantic import BaseModel  # Third-party: declarative data validation and settings management
from pydantic import Field  # Third-party: model field metadata and defaults


class URLRequest(BaseModel):
    """Inbound payload for a single URL scan request."""

    url: str = Field(..., max_length=8192, description="Raw or pasted URL to analyze")
    persist: bool = True


class ScanResponse(BaseModel):
    """Outbound payload representing the full result of a hybrid phishing scan."""

    url: str
    risk_score: float
    hybrid_score: float
    prediction: str
    verdict: dict[str, Any]
    scores: dict[str, Any]
    rules: dict[str, Any]
    fasttext: dict[str, Any]
    brand_impersonation: dict[str, Any]
    details: dict[str, Any]
    checks: dict[str, Any] = Field(default_factory=dict)
    contributing_checks: list[str] = Field(default_factory=list)
    unknown_checks: list[str] = Field(default_factory=list)
    feed_freshness: dict[str, Any] = Field(default_factory=dict)
    artifacts: dict[str, Any] = Field(default_factory=dict)


class EvaluationJobRequest(BaseModel):
    """Inbound payload for an ad-hoc evaluation job against a labeled CSV."""

    filename: str
    csv_content: str
    threshold: float = 30.0


class FastTextTrainingRequest(BaseModel):
    """Inbound payload for a FastText supervised training run from a labeled CSV."""

    filename: str
    csv_content: str
    activate_after_training: bool = True
