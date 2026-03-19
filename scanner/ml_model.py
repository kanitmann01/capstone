from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any

try:
    import joblib
except ImportError:  # pragma: no cover - handled at runtime.
    joblib = None

try:
    import numpy as np
except ImportError:  # pragma: no cover - handled at runtime.
    np = None

try:
    import tensorflow as tf  # pyright: ignore[reportMissingImports]
except ImportError:  # pragma: no cover - handled at runtime.
    tf = None

from scanner.ml_features import FEATURE_FIELDS
from scanner.ml_features import FEATURE_VERSION
from scanner.ml_features import vectorize_features
from scanner.settings import ScannerSettings


class MLScanner:
    def __init__(self, settings: ScannerSettings):
        self.settings = settings
        self._lock = threading.Lock()
        self._model: Any | None = None
        self._metadata: dict[str, Any] = {}
        self._artifact_signature: tuple[float | None, float | None] | None = None
        self._analytics = {
            "predictions_total": 0,
            "unknown_total": 0,
            "phishing_total": 0,
            "benign_total": 0,
            "probability_sum": 0.0,
            "last_prediction_utc": None,
        }

    def refresh(self) -> None:
        with self._lock:
            self._artifact_signature = None
            self._model = None
            self._metadata = {}

    def analytics(self) -> dict[str, Any]:
        self._ensure_loaded()
        with self._lock:
            predictions_total = int(self._analytics["predictions_total"])
            avg_probability = (
                float(self._analytics["probability_sum"]) / predictions_total
                if predictions_total
                else 0.0
            )
            return {
                "enabled": self.settings.ml_enabled,
                "available": self._model is not None,
                "model_version": self._metadata.get("model_version"),
                "model_type": self._metadata.get("model_type"),
                "feature_version": self._metadata.get("feature_version", FEATURE_VERSION),
                "trained_at": self._metadata.get("trained_at"),
                "model_path": self.settings.ml_model_path,
                "metadata_path": self.settings.ml_metadata_path,
                "predictions_total": predictions_total,
                "unknown_total": int(self._analytics["unknown_total"]),
                "phishing_total": int(self._analytics["phishing_total"]),
                "benign_total": int(self._analytics["benign_total"]),
                "average_probability": round(avg_probability, 4),
                "last_prediction_utc": self._analytics["last_prediction_utc"],
                "top_features": self._top_features(limit=5),
            }

    def scan(self, features: dict[str, Any]) -> dict[str, Any]:
        if not self.settings.ml_enabled:
            return {
                "status": "unknown",
                "unknown_reason": "ml_disabled",
                "risk_score": 0,
                "prediction": "unknown",
                "probability": 0.0,
                "model_version": None,
                "feature_version": FEATURE_VERSION,
                "top_features": [],
            }

        self._ensure_loaded()
        if self._model is None:
            self._record_unknown()
            return {
                "status": "unknown",
                "unknown_reason": "model_unavailable",
                "risk_score": 0,
                "prediction": "unknown",
                "probability": 0.0,
                "model_version": self._metadata.get("model_version"),
                "feature_version": self._metadata.get("feature_version", FEATURE_VERSION),
                "top_features": [],
            }

        try:
            feature_names = self._feature_names()
            vector = [vectorize_features(features, feature_names)]
            if hasattr(self._model, "predict_proba"):
                probability = float(self._model.predict_proba(vector)[0][1])
            elif tf is not None and isinstance(self._model, tf.keras.Model):
                if np is None:
                    raise RuntimeError("numpy_not_installed")
                prediction = self._model.predict(np.asarray(vector, dtype="float32"), verbose=0)
                probability = _extract_probability(prediction)
            else:
                prediction = self._model.predict(vector)[0]
                probability = float(prediction)
            threshold = float(self._metadata.get("classification_threshold", 0.5) or 0.5)
            prediction_label = "phishing" if probability >= threshold else "benign"
            self._record_prediction(probability)
            return {
                "status": "ok",
                "risk_score": round(probability * 100, 2),
                "prediction": prediction_label,
                "probability": round(probability, 6),
                "model_version": self._metadata.get("model_version"),
                "model_type": self._metadata.get("model_type", "tensorflow_dense"),
                "feature_version": self._metadata.get("feature_version", FEATURE_VERSION),
                "top_features": self._top_features(limit=5),
            }
        except Exception as exc:  # pragma: no cover - defensive runtime path.
            self._record_unknown()
            return {
                "status": "unknown",
                "unknown_reason": "inference_failed",
                "error": str(exc),
                "risk_score": 0,
                "prediction": "unknown",
                "probability": 0.0,
                "model_version": self._metadata.get("model_version"),
                "feature_version": self._metadata.get("feature_version", FEATURE_VERSION),
                "top_features": [],
            }

    def _feature_names(self) -> tuple[str, ...]:
        feature_names = self._metadata.get("feature_names")
        if isinstance(feature_names, list) and feature_names:
            return tuple(str(value) for value in feature_names)
        return FEATURE_FIELDS

    def _artifact_state(self) -> tuple[float | None, float | None]:
        model_mtime = None
        metadata_mtime = None
        model_path = Path(self.settings.ml_model_path)
        metadata_path = Path(self.settings.ml_metadata_path)
        if model_path.exists():
            model_mtime = model_path.stat().st_mtime
        if metadata_path.exists():
            metadata_mtime = metadata_path.stat().st_mtime
        return model_mtime, metadata_mtime

    def _ensure_loaded(self) -> None:
        signature = self._artifact_state()
        with self._lock:
            if signature == self._artifact_signature:
                return
            self._artifact_signature = signature
            self._model = None
            self._metadata = {}

            model_path = Path(self.settings.ml_model_path)
            metadata_path = Path(self.settings.ml_metadata_path)
            if metadata_path.exists():
                try:
                    self._metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                except Exception:
                    self._metadata = {"load_error": "invalid_metadata"}
            if not model_path.exists():
                return
            try:
                if model_path.suffix.lower() == ".joblib":
                    if joblib is None:
                        self._metadata["load_error"] = "joblib_not_installed"
                        self._model = None
                        return
                    self._model = joblib.load(model_path)
                else:
                    if tf is None:
                        self._metadata["load_error"] = "tensorflow_not_installed"
                        self._model = None
                        return
                    self._model = tf.keras.models.load_model(model_path, compile=False)
            except Exception as exc:
                self._metadata["load_error"] = str(exc)
                self._model = None

    def _record_prediction(self, probability: float) -> None:
        with self._lock:
            self._analytics["predictions_total"] += 1
            self._analytics["probability_sum"] += probability
            if probability >= 0.5:
                self._analytics["phishing_total"] += 1
            else:
                self._analytics["benign_total"] += 1
            self._analytics["last_prediction_utc"] = datetime.now(timezone.utc).isoformat()

    def _record_unknown(self) -> None:
        with self._lock:
            self._analytics["unknown_total"] += 1
            self._analytics["last_prediction_utc"] = datetime.now(timezone.utc).isoformat()

    def _top_features(self, limit: int = 5) -> list[dict[str, Any]]:
        metadata_features = self._metadata.get("feature_importance")
        if isinstance(metadata_features, list) and metadata_features:
            return [
                {
                    "feature": str(item.get("feature") or ""),
                    "importance": round(float(item.get("importance") or 0.0), 6),
                }
                for item in metadata_features[:limit]
                if item.get("feature")
            ]
        if self._model is None or not hasattr(self._model, "feature_importances_"):
            return []
        feature_names = self._feature_names()
        importances = list(getattr(self._model, "feature_importances_", []))
        if not importances:
            return []
        ranked = sorted(
            zip(feature_names, importances, strict=False),
            key=lambda item: item[1],
            reverse=True,
        )
        top = [
            {"feature": feature, "importance": round(float(importance), 6)}
            for feature, importance in ranked
            if float(importance) > 0
        ]
        return top[:limit]


def _extract_probability(prediction: Any) -> float:
    if np is not None:
        values = np.asarray(prediction).reshape(-1)
        if values.size == 1:
            return float(values[0])
        if values.size >= 2:
            return float(values[-1])
    if isinstance(prediction, (list, tuple)) and prediction:
        first = prediction[0]
        if isinstance(first, (list, tuple)) and first:
            return float(first[-1])
        return float(first)
    return float(prediction)
