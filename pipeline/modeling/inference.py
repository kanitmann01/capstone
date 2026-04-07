from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from pipeline.modeling.fasttext_dataset import serialize_snapshot
from pipeline.modeling.fasttext_train import load_fasttext_model


@dataclass
class FastTextPrediction:
    label: str
    probability: float
    score: float
    raw_label: str
    raw_probability: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "probability": self.probability,
            "score": self.score,
            "raw_label": self.raw_label,
            "raw_probability": self.raw_probability,
        }


class FastTextDetector:
    def __init__(self, model_path: str | Path, threshold: float = 0.5):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._model = None

    def _ensure_model(self):
        if self._model is not None:
            return self._model
        if not self.model_path.exists():
            return None
        self._patch_fasttext_numpy_compat()
        self._model = load_fasttext_model(self.model_path)
        return self._model

    def _patch_fasttext_numpy_compat(self) -> None:
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
        return self._ensure_model() is not None

    def predict_text(self, text: str) -> FastTextPrediction | None:
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
        text = serialize_snapshot(snapshot)
        return self.predict_text(text)
