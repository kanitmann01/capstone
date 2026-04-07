from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic import Field


class URLRequest(BaseModel):
    url: str
    persist: bool = True


class ScanResponse(BaseModel):
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
    filename: str
    csv_content: str
    threshold: float = 30.0


class FastTextTrainingRequest(BaseModel):
    filename: str
    csv_content: str
    activate_after_training: bool = True
