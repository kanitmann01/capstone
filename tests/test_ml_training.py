import csv
from pathlib import Path

import pytest

from scanner.ml_features import FEATURE_FIELDS
from scanner.ml_training import sanitize_training_config
from scanner.ml_training import train_tensorflow_from_dataset
from scanner.settings import ScannerSettings

tf = pytest.importorskip("tensorflow")


def test_sanitize_training_config_accepts_valid_inputs():
    settings = ScannerSettings()
    config = sanitize_training_config(
        {
            "test_size": 0.25,
            "random_state": 99,
            "epochs": 12,
            "batch_size": 16,
            "learning_rate": 0.002,
            "validation_split": 0.2,
            "dropout_rate": 0.1,
            "hidden_units": [64, 32],
            "early_stopping_patience": 3,
            "classification_threshold": 0.6,
            "device": "cpu",
            "activate_after_training": False,
        },
        settings,
    )

    assert config.test_size == 0.25
    assert config.random_state == 99
    assert config.epochs == 12
    assert config.batch_size == 16
    assert config.learning_rate == 0.002
    assert config.validation_split == 0.2
    assert config.dropout_rate == 0.1
    assert config.hidden_units == (64, 32)
    assert config.early_stopping_patience == 3
    assert config.classification_threshold == 0.6
    assert config.device == "cpu"
    assert config.activate_after_training is False


def test_sanitize_training_config_rejects_invalid_ranges():
    settings = ScannerSettings()

    with pytest.raises(ValueError, match="epochs"):
        sanitize_training_config({"epochs": 0}, settings)

    with pytest.raises(ValueError, match="test_size"):
        sanitize_training_config({"test_size": 0.9}, settings)

    with pytest.raises(ValueError, match="device"):
        sanitize_training_config({"device": "tpu"}, settings)


def test_train_tensorflow_report_includes_history_and_tensorboard(tmp_path):
    dataset_path = tmp_path / "feature_dataset.csv"
    output_dir = tmp_path / "run"
    settings = ScannerSettings()
    config = sanitize_training_config(
        {
            "epochs": 2,
            "batch_size": 4,
            "validation_split": 0.25,
            "device": "cpu",
            "hidden_units": [16, 8],
        },
        settings,
    )

    rows = []
    for index in range(12):
        label = 1 if index % 2 else 0
        row = {
            "url": f"https://example{index}.test/login",
            "normalized_url": f"https://example{index}.test/login",
            "host": f"example{index}.test",
            "is_phishing": label,
            "feature_version": "ml_features_v1",
            "label_source": "test",
        }
        for feature_index, feature in enumerate(FEATURE_FIELDS):
            row[feature] = round((index + 1) * (feature_index + 1) * (1.7 if label else 0.6), 4)
        rows.append(row)

    with dataset_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "url",
                "normalized_url",
                "host",
                "is_phishing",
                "feature_version",
                "label_source",
                *FEATURE_FIELDS,
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    report = train_tensorflow_from_dataset(
        dataset_csv=dataset_path,
        output_dir=output_dir,
        config=config,
        settings=settings,
    )

    assert report["summary"]["model_type"] == "tensorflow_dense"
    assert report["training_history"]["epoch"]
    assert report["splits"]["validation"]["accuracy"] >= 0
    assert report["model_summary"]["resolved_device"] == "/CPU:0"
    assert report["feature_importance"]
    assert "hardest_mistakes" in report["error_analysis"]
    assert Path(report["artifacts"]["history_path"]).exists()
    assert Path(report["artifacts"]["tensorboard_log_dir"]).name == "tensorboard"
    assert "launch_commands" in report["tensorboard"]
