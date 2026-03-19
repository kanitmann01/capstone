import json

import pytest

from scanner.ml_features import FEATURE_FIELDS
from scanner.ml_model import MLScanner
from scanner.settings import ScannerSettings

joblib = pytest.importorskip("joblib")


class DummyModel:
    feature_importances_ = [0.4, 0.6] + [0.0] * (len(FEATURE_FIELDS) - 2)

    def predict_proba(self, rows):
        del rows
        return [[0.15, 0.85]]


def test_ml_scanner_returns_prediction_with_top_features(tmp_path):
    model_path = tmp_path / "model.joblib"
    metadata_path = tmp_path / "model.json"
    joblib.dump(DummyModel(), model_path)
    metadata_path.write_text(
        json.dumps(
            {
                "model_version": "decision_tree_test",
                "model_type": "decision_tree",
                "feature_version": "ml_features_v1",
                "feature_names": list(FEATURE_FIELDS),
            }
        ),
        encoding="utf-8",
    )

    settings = ScannerSettings(
        ml_enabled=True,
        ml_model_path=str(model_path),
        ml_metadata_path=str(metadata_path),
    )
    scanner = MLScanner(settings)

    result = scanner.scan({field: 0 for field in FEATURE_FIELDS})

    assert result["status"] == "ok"
    assert result["prediction"] == "phishing"
    assert result["risk_score"] == 85.0
    assert result["top_features"][0]["feature"] == FEATURE_FIELDS[1]
    assert scanner.analytics()["available"] is True


def test_ml_scanner_returns_unknown_when_model_missing(tmp_path):
    settings = ScannerSettings(
        ml_enabled=True,
        ml_model_path=str(tmp_path / "missing.joblib"),
        ml_metadata_path=str(tmp_path / "missing.json"),
    )
    scanner = MLScanner(settings)

    result = scanner.scan({field: 0 for field in FEATURE_FIELDS})

    assert result["status"] == "unknown"
    assert result["unknown_reason"] == "model_unavailable"
