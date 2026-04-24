from __future__ import annotations

"""
FastText model inference and prediction.

Loads a trained ``.bin`` model on demand, patches numpy compatibility,
and returns structured prediction objects with label, probability, and score.
"""

from dataclasses import dataclass  # Standard library: lightweight data structures
from pathlib import Path  # Standard library: filesystem path abstraction
from typing import Any  # Standard library: generic type hints

import numpy as np  # Third-party: numerical arrays

from pipeline.modeling.fasttext_dataset import serialize_snapshot  # Project-local: snapshot -> text
from pipeline.modeling.fasttext_train import load_fasttext_model  # Project-local: model loader


@dataclass
class FastTextPrediction:
    """Structured result from a FastText inference call."""

    label: str
    probability: float
    score: float
    raw_label: str
    raw_probability: float

    def as_dict(self) -> dict[str, Any]:
        """Serialize the prediction to a plain dict."""
        return {
            "label": self.label,
            "probability": self.probability,
            "score": self.score,
            "raw_label": self.raw_label,
            "raw_probability": self.raw_probability,
        }


class FastTextDetector:
    """Lazy-loading wrapper around a FastText supervised model."""

    def __init__(self, model_path: str | Path, threshold: float = 0.5):
        """Initialise with model path and decision threshold."""
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._model = None

    def _ensure_model(self):
        """Load the model if it has not yet been loaded."""
        if self._model is not None:
            return self._model
        if not self.model_path.exists():
            return None
        self._patch_fasttext_numpy_compat()
        self._model = load_fasttext_model(self.model_path)
        return self._model

    def _patch_fasttext_numpy_compat(self) -> None:
        """Monkey-patch fasttext's internal numpy array constructor for compatibility."""
        try:
            import fasttext.FastText as fasttext_fasttext  # type: ignore
        except Exception:
            return

        def _array_compat(obj, dtype=None, copy=None, order=None, subok=False, ndmin=0):
            del copy, subok, ndmin
            return np.asarray(obj, dtype=dtype, order=order)

        if getattr(fasttext_fasttext.np.array, "__name__", "") != "_array_compat":
            fasttext_fasttext.np.array = _array_compat  # type: ignore[attr-defined]

    def available(self) -> bool:
        """Return True if the model file exists and is loadable."""
        return self._ensure_model() is not None

    def predict_text(self, text: str) -> FastTextPrediction | None:
        """Run inference on a raw text string."""
        model = self._ensure_model()
        if model is None:
            return None
        labels, probabilities = model.predict(text, k=1)
        raw_label = labels[0] if labels else "__label__clean"
        raw_probability = float(probabilities[0]) if probabilities else 0.0
        if raw_label.startswith("__label__"):
            label = raw_label.replace("__label__", "", 1)
        else:
            label = raw_label
        probability = raw_probability
        score = probability * 100.0
        return FastTextPrediction(
            label=label,
            probability=probability,
            score=score,
            raw_label=raw_label,
            raw_probability=raw_probability,
        )

    def predict_snapshot(self, snapshot: dict[str, Any]) -> FastTextPrediction | None:
        """Serialise a snapshot and run inference on it."""
        text = serialize_snapshot(snapshot)
        return self.predict_text(text)
