from __future__ import annotations

"""
TensorFlow and decision tree model training utilities.

Handles feature dataset generation from labeled CSVs, TensorFlow dense
classifier training with early stopping, model registry management,
and artifact activation. Also includes permutation feature importance,
threshold analysis, and TensorBoard logging helpers.
"""

import csv  # Standard library: CSV reading and writing
from dataclasses import asdict  # Standard library: dataclass -> dict
from dataclasses import dataclass  # Standard library: immutable data class decorator
from datetime import datetime, timezone  # Standard library: UTC-aware timestamps
import json  # Standard library: JSON serialization
from pathlib import Path  # Standard library: filesystem path abstraction
import shutil  # Standard library: file copy operations
import time  # Standard library: timestamps for TensorBoard
from typing import Any  # Standard library: generic type hints

from scanner.ml_features import FEATURE_FIELDS  # Project-local: ordered feature names
from scanner.ml_features import FEATURE_VERSION  # Project-local: feature schema version
from scanner.ml_features import build_feature_row  # Project-local: row assembly for CSV export
from scanner.ml_features import extract_features  # Project-local: structured feature engineering
from scanner.normalization import normalize_input_url  # Project-local: URL canonicalisation
from scanner.settings import ScannerSettings  # Project-local: scanner configuration

TRUTHY_VALUES = {"1", "true", "t", "yes", "y"}
FALSY_VALUES = {"0", "false", "f", "no", "n"}
MODEL_REGISTRY_VERSION = "ml_model_registry_v1"


@dataclass(frozen=True)
class TensorFlowTrainingConfig:
    """Immutable hyperparameters for TensorFlow dense classifier training."""

    model_type: str = "tensorflow_dense"
    test_size: float = 0.2
    random_state: int = 42
    epochs: int = 20
    batch_size: int = 32
    learning_rate: float = 0.001
    validation_split: float = 0.2
    dropout_rate: float = 0.15
    hidden_units: tuple[int, ...] = (128, 64)
    early_stopping_patience: int = 5
    classification_threshold: float = 0.5
    device: str = "auto"
    activate_after_training: bool = True


@dataclass(frozen=True)
class FeatureDatasetSummary:
    """Result of generating a feature dataset from a labeled CSV."""

    input_rows: int
    usable_rows: int
    skipped_rows: int
    positive_rows: int
    negative_rows: int
    output_csv: str
    errors: list[dict[str, Any]]


def utc_now_iso() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _registry_payload(path: Path) -> dict[str, Any]:
    """Load or initialise the model registry JSON payload."""
    if not path.exists():
        return {
            "registry_version": MODEL_REGISTRY_VERSION,
            "updated_at": None,
            "models": [],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "registry_version": MODEL_REGISTRY_VERSION,
            "updated_at": None,
            "models": [],
        }

    models = payload.get("models")
    if not isinstance(models, list):
        models = []
    return {
        "registry_version": payload.get("registry_version", MODEL_REGISTRY_VERSION),
        "updated_at": payload.get("updated_at"),
        "models": models,
    }


def load_model_registry(settings: ScannerSettings) -> list[dict[str, Any]]:
    """Return a chronologically sorted list of registry entries."""
    payload = _registry_payload(Path(settings.ml_registry_path))
    models = [entry for entry in payload.get("models", []) if isinstance(entry, dict)]
    return sorted(
        models,
        key=lambda item: str(item.get("completed_at") or item.get("trained_at") or item.get("created_at") or ""),
        reverse=True,
    )


def append_model_registry_entry(
    *,
    settings: ScannerSettings,
    run_dir: str | Path,
    input_filename: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Append a training run to the model registry."""
    registry_path = Path(settings.ml_registry_path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _registry_payload(registry_path)
    run_path = Path(run_dir)
    summary = dict(report.get("summary") or {})

    entry = {
        "job_id": run_path.name,
        "status": "completed",
        "input_filename": input_filename,
        "created_at": summary.get("created_at"),
        "completed_at": summary.get("completed_at") or summary.get("trained_at"),
        "trained_at": summary.get("trained_at"),
        "model_version": summary.get("model_version"),
        "model_type": summary.get("model_type"),
        "feature_version": summary.get("feature_version"),
        "activated": bool(summary.get("activated")),
        "accuracy": summary.get("accuracy"),
        "precision": summary.get("precision"),
        "recall": summary.get("recall"),
        "f1": summary.get("f1"),
        "roc_auc": summary.get("roc_auc"),
        "input_rows": summary.get("input_rows"),
        "usable_rows": summary.get("usable_rows"),
        "skipped_rows": summary.get("skipped_rows"),
        "train_rows": summary.get("train_rows"),
        "test_rows": summary.get("test_rows"),
        "positive_rows": summary.get("positive_rows"),
        "negative_rows": summary.get("negative_rows"),
        "model_summary": report.get("model_summary") or report.get("tree_summary") or {},
        "hyperparameters": report.get("hyperparameters") or {},
        "feature_importance": list(report.get("feature_importance") or [])[:15],
        "artifacts": dict(report.get("artifacts") or {}),
    }

    models = [item for item in payload["models"] if isinstance(item, dict) and item.get("job_id") != entry["job_id"]]
    models.append(entry)
    payload["models"] = sorted(
        models,
        key=lambda item: str(item.get("completed_at") or item.get("trained_at") or item.get("created_at") or ""),
        reverse=True,
    )
    payload["updated_at"] = utc_now_iso()
    registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return entry


def parse_label(value: Any) -> bool:
    """Parse a flexible truthy/falsy value into a boolean."""
    normalized = str(value).strip().lower()
    if normalized in TRUTHY_VALUES:
        return True
    if normalized in FALSY_VALUES:
        return False
    raise ValueError(
        f"Unsupported is_phishing value {value!r}. Expected one of {sorted(TRUTHY_VALUES | FALSY_VALUES)}"
    )


def sanitize_training_config(raw: dict[str, Any] | None, settings: ScannerSettings) -> TensorFlowTrainingConfig:
    """Validate raw training config and return a typed TensorFlowTrainingConfig."""
    payload = dict(raw or {})
    test_size = float(payload.get("test_size", settings.ml_default_test_size))
    if test_size <= 0.05 or test_size >= 0.45:
        raise ValueError("test_size must be between 0.05 and 0.45")

    random_state = int(payload.get("random_state", settings.ml_default_random_state))
    epochs = int(payload.get("epochs", settings.ml_default_epochs))
    if epochs < 1 or epochs > 500:
        raise ValueError("epochs must be between 1 and 500")

    batch_size = int(payload.get("batch_size", settings.ml_default_batch_size))
    if batch_size < 1 or batch_size > 4096:
        raise ValueError("batch_size must be between 1 and 4096")

    learning_rate = float(payload.get("learning_rate", settings.ml_default_learning_rate))
    if learning_rate <= 0 or learning_rate > 1:
        raise ValueError("learning_rate must be greater than 0 and at most 1")

    validation_split = float(payload.get("validation_split", settings.ml_default_validation_split))
    if validation_split < 0.05 or validation_split >= 0.5:
        raise ValueError("validation_split must be between 0.05 and 0.5")

    dropout_rate = float(payload.get("dropout_rate", settings.ml_default_dropout_rate))
    if dropout_rate < 0 or dropout_rate >= 0.9:
        raise ValueError("dropout_rate must be between 0 and 0.9")

    early_stopping_patience = int(
        payload.get("early_stopping_patience", settings.ml_default_early_stopping_patience)
    )
    if early_stopping_patience < 0 or early_stopping_patience > 50:
        raise ValueError("early_stopping_patience must be between 0 and 50")

    classification_threshold = float(
        payload.get("classification_threshold", settings.ml_default_classification_threshold)
    )
    if classification_threshold <= 0 or classification_threshold >= 1:
        raise ValueError("classification_threshold must be between 0 and 1")

    hidden_units = _parse_hidden_units(
        payload.get("hidden_units", settings.ml_default_hidden_units),
    )
    if not hidden_units:
        raise ValueError("hidden_units must contain at least one layer size")

    device = str(payload.get("device", settings.ml_default_device)).strip().lower() or "auto"
    if device != "auto" and device != "cpu" and not device.startswith("gpu:"):
        raise ValueError("device must be one of: auto, cpu, gpu:0, gpu:1, ...")

    activate_after_training = bool(
        payload.get("activate_after_training", settings.ml_default_activate_after_training)
    )

    return TensorFlowTrainingConfig(
        test_size=test_size,
        random_state=random_state,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        validation_split=validation_split,
        dropout_rate=dropout_rate,
        hidden_units=hidden_units,
        early_stopping_patience=early_stopping_patience,
        classification_threshold=classification_threshold,
        device=device,
        activate_after_training=activate_after_training,
    )


def _parse_hidden_units(raw: Any) -> tuple[int, ...]:
    """Parse hidden layer sizes from a list, tuple, or comma-separated string."""
    values: list[int] = []
    if isinstance(raw, (list, tuple)):
        candidates = list(raw)
    else:
        candidates = [segment.strip() for segment in str(raw or "").split(",")]

    for candidate in candidates:
        if candidate in {"", None}:
            continue
        units = int(candidate)
        if units < 1 or units > 4096:
            raise ValueError("hidden_units values must be between 1 and 4096")
        values.append(units)
    return tuple(values)


def describe_tensorflow_runtime() -> dict[str, Any]:
    """Return metadata about the TensorFlow installation and available devices."""
    try:
        import tensorflow as tf  # pyright: ignore[reportMissingImports]
    except Exception as exc:  # pragma: no cover - depends on environment.
        return {
            "available": False,
            "version": None,
            "error": str(exc),
            "devices": _runtime_device_options([]),
            "gpus": [],
            "warnings": ["TensorFlow is not currently installed or failed to import."],
        }

    gpus = tf.config.list_physical_devices("GPU")
    gpu_items = []
    for index, gpu in enumerate(gpus):
        label = getattr(gpu, "name", f"GPU {index}")
        device_id = f"gpu:{index}"
        gpu_items.append({"id": device_id, "label": label})
    warnings: list[str] = []
    if not gpus:
        warnings.append(
            "No TensorFlow GPU device was detected. Manual GPU selectors are still shown, but this host may train on CPU."
        )
    return {
        "available": True,
        "version": getattr(tf, "__version__", None),
        "error": None,
        "devices": _runtime_device_options(gpu_items),
        "gpus": gpu_items,
        "warnings": warnings,
    }


def _runtime_device_options(gpu_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a list of device options for UI display."""
    devices = [
        {"id": "auto", "label": "Auto select", "type": "auto"},
        {"id": "cpu", "label": "CPU", "type": "cpu"},
    ]
    if gpu_items:
        for item in gpu_items:
            devices.append({"id": item["id"], "label": item["label"], "type": "gpu"})
        return devices
    for index in range(4):
        devices.append({"id": f"gpu:{index}", "label": f"GPU {index} (manual)", "type": "gpu"})
    return devices


def generate_feature_dataset(
    *,
    input_csv: str | Path,
    output_csv: str | Path,
    scan_service,
    label_source: str = "",
    progress_callback=None,
) -> FeatureDatasetSummary:
    """Read a labeled CSV, run the scanner, and write a feature dataset CSV."""
    input_path = Path(input_csv)
    output_path = Path(output_csv)

    with input_path.open("r", newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("Input CSV is missing a header row")
        required_columns = {"url", "is_phishing"}
        missing = required_columns.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"Input CSV missing required columns: {', '.join(sorted(missing))}")
        rows = list(reader)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "url",
        "normalized_url",
        "host",
        "is_phishing",
        "feature_version",
        "label_source",
        *FEATURE_FIELDS,
    ]

    errors: list[dict[str, Any]] = []
    usable_rows = 0
    skipped_rows = 0
    positive_rows = 0
    negative_rows = 0

    if progress_callback:
        progress_callback(
            {
                "type": "job_started",
                "total_rows": len(rows),
                "processed_rows": 0,
                "usable_rows": 0,
                "skipped_rows": 0,
                "message": "Preparing ML feature extraction...",
                "phase": "prepare_dataset",
                "progress_percent": 0.0,
            }
        )
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "extract_features",
                "message": "Extracting scanner and lexical features from labeled URLs...",
                "progress_percent": 2.0,
            }
        )

    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()

        for index, row in enumerate(rows, start=1):
            url = (row.get("url") or "").strip()
            if progress_callback:
                progress_callback(
                    {
                        "type": "row_started",
                        "row_index": index,
                        "url": url,
                    }
                )
            try:
                if not url:
                    raise ValueError("Missing URL value")
                label = parse_label(row.get("is_phishing"))
                payload = scan_service.scan_combined_with_progress(
                    url,
                    progress_callback=progress_callback,
                )
                target = normalize_input_url(url)
                feature_row = build_feature_row(
                    target,
                    payload.get("details") or {},
                    label=label,
                    source=label_source,
                )
                writer.writerow(feature_row)
                usable_rows += 1
                if label:
                    positive_rows += 1
                else:
                    negative_rows += 1
            except Exception as exc:
                skipped_rows += 1
                errors.append({"index": index, "url": url, "error": str(exc)})
            if progress_callback:
                progress_callback(
                    {
                        "type": "row_completed",
                        "row_index": index,
                        "url": url,
                        "processed_rows": index,
                        "usable_rows": usable_rows,
                        "skipped_rows": skipped_rows,
                        "progress_percent": round((index / max(len(rows), 1)) * 70, 1),
                    }
                )

    return FeatureDatasetSummary(
        input_rows=len(rows),
        usable_rows=usable_rows,
        skipped_rows=skipped_rows,
        positive_rows=positive_rows,
        negative_rows=negative_rows,
        output_csv=str(output_path),
        errors=errors[:20],
    )


def train_tensorflow_from_dataset(
    *,
    dataset_csv: str | Path,
    output_dir: str | Path,
    config: TensorFlowTrainingConfig,
    settings: ScannerSettings,
    progress_callback=None,
) -> dict[str, Any]:
    """Train a TensorFlow dense classifier on a feature dataset."""
    try:
        import numpy as np
        import pandas as pd
        import tensorflow as tf  # pyright: ignore[reportMissingImports]
        from sklearn.metrics import accuracy_score
        from sklearn.metrics import confusion_matrix
        from sklearn.metrics import f1_score
        from sklearn.metrics import precision_score
        from sklearn.metrics import recall_score
        from sklearn.metrics import roc_auc_score
        from sklearn.model_selection import train_test_split
    except ImportError as exc:  # pragma: no cover - depends on environment.
        raise RuntimeError(
            "Training dependencies are missing. Install tensorflow, pandas, scikit-learn, and numpy."
        ) from exc

    dataset_path = Path(dataset_csv)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "load_dataset",
                "message": "Loading feature dataset...",
                "progress_percent": 74.0,
            }
        )

    df = pd.read_csv(dataset_path)
    required_columns = {"is_phishing", *FEATURE_FIELDS}
    missing_columns = required_columns.difference(df.columns)
    if missing_columns:
        raise ValueError(f"Dataset missing required feature columns: {', '.join(sorted(missing_columns))}")

    usable_df = df.dropna(subset=["is_phishing"]).copy()
    if usable_df.empty:
        raise ValueError("Feature dataset contains no usable labeled rows")

    X = usable_df[list(FEATURE_FIELDS)].fillna(0.0).astype("float32")
    y = usable_df["is_phishing"].astype(int)
    row_meta = usable_df[[column for column in ("url", "normalized_url", "host") if column in usable_df.columns]].fillna("")
    if len(set(y.tolist())) < 2:
        raise ValueError("Training requires both phishing and legitimate labels")
    stratify = y if len(set(y.tolist())) > 1 else None

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "split_dataset",
                "message": "Creating train and test splits...",
                "progress_percent": 78.0,
            }
        )

    X_train_df, X_test_df, y_train_series, y_test_series, meta_train, meta_test = train_test_split(
        X,
        y,
        row_meta,
        test_size=config.test_size,
        random_state=config.random_state,
        stratify=stratify,
    )
    X_train_full = X_train_df.to_numpy(dtype="float32")
    X_test = X_test_df.to_numpy(dtype="float32")
    y_train_full = y_train_series.to_numpy(dtype="float32")
    y_test = y_test_series.to_numpy(dtype="int32")

    val_stratify = y_train_series if len(set(y_train_series.tolist())) > 1 else None
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=config.validation_split,
        random_state=config.random_state,
        stratify=val_stratify,
    )

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "train_model",
                "message": "Training the TensorFlow baseline...",
                "progress_percent": 84.0,
            }
        )

    tf.random.set_seed(config.random_state)
    np.random.seed(config.random_state)

    normalization = tf.keras.layers.Normalization(name="feature_normalization")
    normalization.adapt(X_train)

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(len(FEATURE_FIELDS),), name="features"),
            normalization,
            *[
                layer
                for units in config.hidden_units
                for layer in (
                    tf.keras.layers.Dense(units, activation="relu"),
                    tf.keras.layers.Dropout(config.dropout_rate) if config.dropout_rate > 0 else None,
                )
                if layer is not None
            ],
            tf.keras.layers.Dense(1, activation="sigmoid", name="phishing_probability"),
        ],
        name="phishing_dense_classifier",
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=config.learning_rate),
        loss="binary_crossentropy",
        metrics=[
            tf.keras.metrics.BinaryAccuracy(name="accuracy"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
            tf.keras.metrics.AUC(name="auc"),
        ],
    )

    tensorboard_log_dir = output_path / "tensorboard"
    callbacks: list[Any] = [
        tf.keras.callbacks.TensorBoard(
            log_dir=str(tensorboard_log_dir),
            histogram_freq=0,
            write_graph=True,
            update_freq="epoch",
        ),
    ]
    if config.early_stopping_patience > 0:
        callbacks.append(
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=config.early_stopping_patience,
                restore_best_weights=True,
            )
        )
    if progress_callback:
        class TrainingProgressCallback(tf.keras.callbacks.Callback):
            def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
                progress = 84.0 + (((epoch + 1) / max(config.epochs, 1)) * 6.0)
                metrics = dict(logs or {})
                progress_callback(
                    {
                        "type": "stage_changed",
                        "phase": "train_model",
                        "message": f"Epoch {epoch + 1} of {config.epochs} completed.",
                        "progress_percent": round(progress, 1),
                        "epoch": epoch + 1,
                        "total_epochs": config.epochs,
                        "epoch_metrics": {
                            key: round(float(value), 4)
                            for key, value in metrics.items()
                            if isinstance(value, (int, float))
                        },
                    }
                )

        callbacks.append(
            TrainingProgressCallback()
        )

    device_name = _resolve_tf_device(config.device)
    with tf.device(device_name):
        history = model.fit(
            X_train,
            y_train,
            validation_data=(X_val, y_val),
            epochs=config.epochs,
            batch_size=config.batch_size,
            verbose=0,
            callbacks=callbacks,
        )

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "evaluate_model",
                "message": "Evaluating train and test performance...",
                "progress_percent": 90.0,
            }
        )

    train_probs = model.predict(X_train_full, verbose=0).reshape(-1)
    val_probs = model.predict(X_val, verbose=0).reshape(-1)
    test_probs = model.predict(X_test, verbose=0).reshape(-1)
    train_preds = (train_probs >= config.classification_threshold).astype(int)
    val_preds = (val_probs >= config.classification_threshold).astype(int)
    test_preds = (test_probs >= config.classification_threshold).astype(int)

    train_metrics = _metrics_for_split(
        y_true=y_train_full.astype(int).tolist(),
        y_pred=train_preds.tolist(),
        probabilities=train_probs.tolist(),
        accuracy_score=accuracy_score,
        precision_score=precision_score,
        recall_score=recall_score,
        f1_score=f1_score,
        roc_auc_score=roc_auc_score,
    )
    val_metrics = _metrics_for_split(
        y_true=y_val.astype(int).tolist(),
        y_pred=val_preds.tolist(),
        probabilities=val_probs.tolist(),
        accuracy_score=accuracy_score,
        precision_score=precision_score,
        recall_score=recall_score,
        f1_score=f1_score,
        roc_auc_score=roc_auc_score,
    )
    test_metrics = _metrics_for_split(
        y_true=y_test.tolist(),
        y_pred=test_preds.tolist(),
        probabilities=test_probs.tolist(),
        accuracy_score=accuracy_score,
        precision_score=precision_score,
        recall_score=recall_score,
        f1_score=f1_score,
        roc_auc_score=roc_auc_score,
    )

    tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
    feature_importance = _permutation_feature_importance(
        X_test=X_test,
        y_test=y_test.tolist(),
        probabilities=test_probs.tolist(),
        model=model,
        roc_auc_score=roc_auc_score,
        random_state=config.random_state,
    )
    history_payload = _training_history_payload(history.history)
    error_analysis = _prediction_error_examples(
        row_meta=meta_test,
        y_true=y_test.tolist(),
        y_pred=test_preds.tolist(),
        probabilities=test_probs.tolist(),
    )
    model_summary = {
        "layers": len(config.hidden_units) + 2,
        "hidden_units": list(config.hidden_units),
        "epochs_trained": len(history.history.get("loss", [])),
        "best_epoch": _best_epoch(history.history),
        "total_params": int(model.count_params()),
        "device": config.device,
        "resolved_device": device_name,
    }

    model_version = datetime.now(timezone.utc).strftime("tensorflow_dense_%Y%m%d_%H%M%S")
    metadata = {
        "model_version": model_version,
        "model_type": config.model_type,
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_FIELDS),
        "trained_at": utc_now_iso(),
        "dataset_csv": str(dataset_path),
        "model_hyperparameters": asdict(config),
        "classification_threshold": config.classification_threshold,
        "model_summary": model_summary,
        "train_metrics": train_metrics,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "feature_importance": feature_importance[:12],
        "training_history": history_payload,
    }

    model_path = output_path / "model.keras"
    metadata_path = output_path / "model_metadata.json"
    report_path = output_path / "report.json"
    history_path = output_path / "training_history.json"

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "save_artifacts",
                "message": "Saving trained model artifacts...",
                "progress_percent": 96.0,
            }
        )

    model.save(model_path)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    history_path.write_text(json.dumps(history_payload, indent=2), encoding="utf-8")

    report = {
        "summary": {
            "model_type": config.model_type,
            "model_version": model_version,
            "feature_version": FEATURE_VERSION,
            "trained_at": metadata["trained_at"],
            "accuracy": test_metrics["accuracy"],
            "precision": test_metrics["precision"],
            "recall": test_metrics["recall"],
            "f1": test_metrics["f1"],
            "roc_auc": test_metrics["roc_auc"],
            "train_rows": len(X_train_full),
            "validation_rows": len(X_val),
            "test_rows": len(X_test),
            "usable_rows": len(usable_df),
            "positive_rows": int(y.sum()),
            "negative_rows": int((1 - y).sum()),
        },
        "hyperparameters": asdict(config),
        "dataset": {
            "dataset_csv": str(dataset_path),
            "total_rows": len(df),
            "usable_rows": len(usable_df),
            "train_rows": len(X_train_full),
            "validation_rows": len(X_val),
            "test_rows": len(X_test),
            "positive_rows": int(y.sum()),
            "negative_rows": int((1 - y).sum()),
        },
        "splits": {
            "train": train_metrics,
            "validation": val_metrics,
            "test": test_metrics,
        },
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "feature_importance": feature_importance[:15],
        "model_summary": model_summary,
        "probability_distribution": _probability_distribution(
            probabilities=test_probs.tolist(),
            labels=y_test.tolist(),
        ),
        "training_history": history_payload,
        "error_analysis": error_analysis,
        "tensorboard": {
            "enabled": True,
            "log_dir": str(tensorboard_log_dir),
            "compare_root": str(output_path.parent),
            "launch_commands": {
                "single_run": f'tensorboard --logdir "{tensorboard_log_dir}"',
                "compare_runs": f'tensorboard --logdir "{output_path.parent}"',
            },
        },
        "artifacts": {
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "report_path": str(report_path),
            "history_path": str(history_path),
            "tensorboard_log_dir": str(tensorboard_log_dir),
        },
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if config.activate_after_training:
        activate_model_artifacts(
            run_dir=output_path,
            settings=settings,
            model_filename=model_path.name,
            metadata_filename=metadata_path.name,
        )
        report["artifacts"]["active_model_path"] = settings.ml_model_path
        report["artifacts"]["active_metadata_path"] = settings.ml_metadata_path

    if progress_callback:
        progress_callback(
            {
                "type": "stage_changed",
                "phase": "completed",
                "message": "ML training completed.",
                "progress_percent": 100.0,
            }
        )

    return report


def train_decision_tree_from_dataset(
    *,
    dataset_csv: str | Path,
    output_dir: str | Path,
    config: TensorFlowTrainingConfig,
    settings: ScannerSettings,
    progress_callback=None,
) -> dict[str, Any]:
    """Alias for train_tensorflow_from_dataset (legacy compatibility)."""
    return train_tensorflow_from_dataset(
        dataset_csv=dataset_csv,
        output_dir=output_dir,
        config=config,
        settings=settings,
        progress_callback=progress_callback,
    )


def activate_model_artifacts(
    *,
    run_dir: str | Path,
    settings: ScannerSettings,
    model_filename: str = "model.keras",
    metadata_filename: str = "model_metadata.json",
) -> None:
    """Copy the latest run artifacts into the active model slots."""
    run_path = Path(run_dir)
    active_model_path = Path(settings.ml_model_path)
    active_metadata_path = Path(settings.ml_metadata_path)
    active_model_path.parent.mkdir(parents=True, exist_ok=True)
    active_metadata_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(run_path / model_filename, active_model_path)
    shutil.copyfile(run_path / metadata_filename, active_metadata_path)


def train_from_labeled_csv(
    *,
    input_csv: str | Path,
    run_dir: str | Path,
    scan_service,
    settings: ScannerSettings,
    config: TensorFlowTrainingConfig,
    input_filename: str | None = None,
    label_source: str = "",
    progress_callback=None,
) -> dict[str, Any]:
    """End-to-end pipeline: feature extraction -> dataset -> training -> registry entry."""
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    input_path = Path(input_csv)
    feature_dataset_path = run_path / "feature_dataset.csv"
    dataset_summary = generate_feature_dataset(
        input_csv=input_path,
        output_csv=feature_dataset_path,
        scan_service=scan_service,
        label_source=label_source,
        progress_callback=progress_callback,
    )
    if dataset_summary.usable_rows < 2:
        raise ValueError("Not enough usable rows were extracted to train a model")

    report = train_tensorflow_from_dataset(
        dataset_csv=feature_dataset_path,
        output_dir=run_path,
        config=config,
        settings=settings,
        progress_callback=progress_callback,
    )
    report["dataset"]["input_rows"] = dataset_summary.input_rows
    report["dataset"]["usable_rows"] = dataset_summary.usable_rows
    report["dataset"]["skipped_rows"] = dataset_summary.skipped_rows
    report["dataset"]["label_source"] = label_source
    report["dataset"]["errors"] = dataset_summary.errors
    report["artifacts"]["feature_dataset_path"] = dataset_summary.output_csv
    report["summary"]["input_rows"] = dataset_summary.input_rows
    report["summary"]["skipped_rows"] = dataset_summary.skipped_rows
    report["summary"]["activated"] = bool(config.activate_after_training)
    report["summary"]["created_at"] = utc_now_iso()
    report["summary"]["completed_at"] = utc_now_iso()
    original_input_filename = input_filename or input_path.name
    report["summary"]["input_filename"] = original_input_filename
    report_path = Path(report["artifacts"]["report_path"])
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    append_model_registry_entry(
        settings=settings,
        run_dir=run_path,
        input_filename=original_input_filename,
        report=report,
    )
    return report


def _resolve_tf_device(device: str) -> str:
    """Map a device selector (auto, cpu, gpu:N) to a TensorFlow device string."""
    import tensorflow as tf  # pyright: ignore[reportMissingImports]

    selected = str(device or "auto").strip().lower()
    gpus = tf.config.list_physical_devices("GPU")
    if selected == "auto":
        return "/GPU:0" if gpus else "/CPU:0"
    if selected == "cpu":
        return "/CPU:0"
    if selected.startswith("gpu:"):
        try:
            index = int(selected.split(":", 1)[1])
        except ValueError as exc:
            raise ValueError(f"Invalid GPU selector {device!r}.") from exc
        if index < 0:
            raise ValueError(f"Selected GPU {device!r} is not available.")
        if index >= len(gpus):
            return "/CPU:0"
        return f"/GPU:{index}"
    raise ValueError(f"Unsupported TensorFlow device selection: {device}")


def _training_history_payload(history: dict[str, list[Any]]) -> dict[str, list[float]]:
    """Normalise Keras history into a serialisable payload."""
    payload: dict[str, list[float]] = {"epoch": []}
    max_length = 0
    for values in history.values():
        max_length = max(max_length, len(values))
    payload["epoch"] = list(range(1, max_length + 1))
    for key, values in history.items():
        payload[key] = [round(float(value), 6) for value in values]
    return payload


def _best_epoch(history: dict[str, list[Any]]) -> int | None:
    """Find the epoch with the lowest validation loss."""
    val_loss = history.get("val_loss") or []
    if not val_loss:
        return None
    best_index = min(range(len(val_loss)), key=lambda index: float(val_loss[index]))
    return best_index + 1


def _permutation_feature_importance(
    *,
    X_test,
    y_test: list[int],
    probabilities: list[float],
    model,
    roc_auc_score,
    random_state: int,
) -> list[dict[str, Any]]:
    """Compute permutation-based feature importance on the test set."""
    if len(set(y_test)) < 2 or len(probabilities) != len(y_test):
        return []
    import numpy as np

    baseline = float(roc_auc_score(y_test, probabilities))
    rng = np.random.default_rng(random_state)
    results: list[dict[str, Any]] = []
    for index, feature in enumerate(FEATURE_FIELDS):
        permuted = np.array(X_test, copy=True)
        permuted[:, index] = rng.permutation(permuted[:, index])
        permuted_probs = model.predict(permuted, verbose=0).reshape(-1)
        score = float(roc_auc_score(y_test, permuted_probs.tolist()))
        importance = max(0.0, baseline - score)
        results.append({"feature": feature, "importance": round(importance, 6)})
    return sorted(results, key=lambda item: item["importance"], reverse=True)


def _metrics_for_split(
    *,
    y_true: list[int],
    y_pred: list[int],
    probabilities: list[float],
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
) -> dict[str, Any]:
    """Compute accuracy, precision, recall, F1, and ROC-AUC for a data split."""
    roc_auc = 0.0
    if len(set(y_true)) > 1:
        roc_auc = float(roc_auc_score(y_true, probabilities))
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(roc_auc, 4),
    }


def _probability_distribution(*, probabilities: list[float], labels: list[int]) -> list[dict[str, Any]]:
    """Bin predicted probabilities into 10-decile histograms."""
    bins = [
        {
            "label": f"{start}-{start + 9}" if start < 90 else "90-100",
            "range_start": start,
            "range_end": 100 if start == 90 else start + 9,
            "phishing": 0,
            "legitimate": 0,
        }
        for start in range(0, 100, 10)
    ]
    for probability, label in zip(probabilities, labels, strict=False):
        percent = max(0.0, min(float(probability) * 100.0, 100.0))
        index = min(int(percent // 10), len(bins) - 1)
        if int(label) == 1:
            bins[index]["phishing"] += 1
        else:
            bins[index]["legitimate"] += 1
    return bins


def _roc_curve_points(*, y_true: list[int], probabilities: list[float], roc_curve) -> dict[str, Any]:
    """Generate ROC curve points and compute AUC via trapezoidal integration."""
    if len(set(y_true)) < 2:
        return {"points": [], "auc": 0.0}
    false_positive_rate, true_positive_rate, thresholds = roc_curve(y_true, probabilities)
    points = []
    for fpr, tpr, threshold in zip(false_positive_rate, true_positive_rate, thresholds, strict=False):
        points.append(
            {
                "false_positive_rate": round(float(fpr), 4),
                "true_positive_rate": round(float(tpr), 4),
                "threshold": None if threshold == float("inf") else round(float(threshold), 4),
            }
        )
    area = 0.0
    if len(points) >= 2:
        area = sum(
            (points[index]["false_positive_rate"] - points[index - 1]["false_positive_rate"])
            * (points[index]["true_positive_rate"] + points[index - 1]["true_positive_rate"])
            / 2
            for index in range(1, len(points))
        )
    return {"points": points, "auc": round(float(area), 4)}


def _precision_recall_curve_points(
    *,
    y_true: list[int],
    probabilities: list[float],
    precision_recall_curve,
    auc,
) -> dict[str, Any]:
    """Generate precision-recall curve points and compute PR-AUC."""
    precision, recall, thresholds = precision_recall_curve(y_true, probabilities)
    points = []
    for index, (precision_value, recall_value) in enumerate(zip(precision, recall, strict=False)):
        threshold = thresholds[index] if index < len(thresholds) else None
        points.append(
            {
                "precision": round(float(precision_value), 4),
                "recall": round(float(recall_value), 4),
                "threshold": None if threshold is None else round(float(threshold), 4),
            }
        )
    pr_auc = float(auc(recall, precision)) if len(points) >= 2 else 0.0
    return {"points": points, "auc": round(pr_auc, 4)}


def _threshold_analysis(
    *,
    y_true: list[int],
    probabilities: list[float],
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
) -> list[dict[str, Any]]:
    """Evaluate metrics across a grid of decision thresholds."""
    analysis: list[dict[str, Any]] = []
    for threshold_percent in range(5, 100, 5):
        threshold = threshold_percent / 100
        predictions = [1 if probability >= threshold else 0 for probability in probabilities]
        tn, fp, fn, tp = _confusion_counts(y_true=y_true, y_pred=predictions)
        predicted_positive_rate = (sum(predictions) / len(predictions)) if predictions else 0.0
        specificity = (tn / max(tn + fp, 1)) if y_true else 0.0
        analysis.append(
            {
                "threshold": round(threshold, 2),
                "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
                "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 4),
                "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 4),
                "f1": round(float(f1_score(y_true, predictions, zero_division=0)), 4),
                "specificity": round(float(specificity), 4),
                "predicted_positive_rate": round(float(predicted_positive_rate), 4),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            }
        )
    return analysis


def _calibration_curve(
    *,
    y_true: list[int],
    probabilities: list[float],
    brier_score_loss,
) -> dict[str, Any]:
    """Compute calibration bins and Brier score."""
    bins = [
        {
            "label": f"{start}-{start + 10}%",
            "range_start": round(start / 100, 2),
            "range_end": round((start + 10) / 100, 2),
            "count": 0,
            "sum_probability": 0.0,
            "positive_count": 0,
        }
        for start in range(0, 100, 10)
    ]
    for probability, label in zip(probabilities, y_true, strict=False):
        bounded = max(0.0, min(float(probability), 0.999999))
        index = min(int(bounded * 10), len(bins) - 1)
        bins[index]["count"] += 1
        bins[index]["sum_probability"] += bounded
        bins[index]["positive_count"] += int(label)

    output_bins = []
    for item in bins:
        count = item["count"]
        output_bins.append(
            {
                "label": item["label"],
                "range_start": item["range_start"],
                "range_end": item["range_end"],
                "count": count,
                "avg_confidence": round(item["sum_probability"] / count, 4) if count else None,
                "actual_positive_rate": round(item["positive_count"] / count, 4) if count else None,
            }
        )

    brier = float(brier_score_loss(y_true, probabilities)) if probabilities else 0.0
    return {
        "brier_score": round(brier, 4),
        "bins": output_bins,
    }


def _feature_importance_cumulative(feature_importance: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank features by importance and add cumulative coverage."""
    if not feature_importance:
        return []
    total_importance = sum(float(item.get("importance") or 0.0) for item in feature_importance)
    if total_importance <= 0:
        return []
    cumulative = 0.0
    points = []
    for rank, item in enumerate(feature_importance[:15], start=1):
        importance = float(item.get("importance") or 0.0)
        cumulative += importance
        points.append(
            {
                "rank": rank,
                "feature": str(item.get("feature") or ""),
                "importance": round(importance, 6),
                "cumulative_importance": round(cumulative / total_importance, 4),
            }
        )
    return points


def _prediction_error_examples(
    *,
    row_meta,
    y_true: list[int],
    y_pred: list[int],
    probabilities: list[float],
) -> dict[str, Any]:
    """Collect and rank false positives and false negatives by confidence."""
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for index, (actual, predicted, probability) in enumerate(zip(y_true, y_pred, probabilities, strict=False)):
        if int(actual) == int(predicted):
            continue
        row = row_meta.iloc[index].to_dict() if hasattr(row_meta, "iloc") else {}
        predicted_phishing_probability = float(probability)
        confidence = predicted_phishing_probability if int(predicted) == 1 else 1.0 - predicted_phishing_probability
        item = {
            "url": str(row.get("url") or ""),
            "normalized_url": str(row.get("normalized_url") or ""),
            "host": str(row.get("host") or ""),
            "actual_label": "phishing" if int(actual) == 1 else "legitimate",
            "predicted_label": "phishing" if int(predicted) == 1 else "legitimate",
            "probability": round(predicted_phishing_probability, 4),
            "confidence": round(confidence, 4),
        }
        if int(predicted) == 1:
            false_positives.append(item)
        else:
            false_negatives.append(item)
    false_positives.sort(key=lambda item: item["confidence"], reverse=True)
    false_negatives.sort(key=lambda item: item["confidence"], reverse=True)
    hardest = sorted(false_positives + false_negatives, key=lambda item: item["confidence"], reverse=True)[:10]
    return {
        "false_positives": false_positives[:6],
        "false_negatives": false_negatives[:6],
        "hardest_mistakes": hardest,
    }


def _confusion_counts(*, y_true: list[int], y_pred: list[int]) -> tuple[int, int, int, int]:
    """Manually compute TP, TN, FP, FN."""
    tn = fp = fn = tp = 0
    for actual, predicted in zip(y_true, y_pred, strict=False):
        if int(actual) == 1 and int(predicted) == 1:
            tp += 1
        elif int(actual) == 1 and int(predicted) == 0:
            fn += 1
        elif int(actual) == 0 and int(predicted) == 1:
            fp += 1
        else:
            tn += 1
    return tn, fp, fn, tp


def _write_tensorboard_logs(
    *,
    log_dir: Path,
    compare_root: Path,
    model_version: str,
    train_metrics: dict[str, Any],
    test_metrics: dict[str, Any],
    tree_summary: dict[str, Any],
    threshold_analysis: list[dict[str, Any]],
    calibration_curve: list[dict[str, Any]],
    roc_curve_points: list[dict[str, Any]],
    precision_recall_points: list[dict[str, Any]],
) -> dict[str, Any]:
    """Write scalar summaries to TensorBoard event files."""
    try:
        from tensorboard.compat.proto import event_pb2  # pyright: ignore[reportMissingImports]
        from tensorboard.compat.proto import summary_pb2  # pyright: ignore[reportMissingImports]
        from tensorboard.summary.writer.event_file_writer import EventFileWriter  # pyright: ignore[reportMissingImports]
    except Exception as exc:  # pragma: no cover - optional dependency.
        return {
            "enabled": False,
            "log_dir": str(log_dir),
            "compare_root": str(compare_root),
            "run_name": model_version,
            "error": str(exc),
            "launch_commands": {
                "single_run": f'tensorboard --logdir "{log_dir}"',
                "compare_runs": f'tensorboard --logdir "{compare_root}"',
            },
        }

    log_dir.mkdir(parents=True, exist_ok=True)
    writer = EventFileWriter(str(log_dir))
    scalar_tags: list[str] = []

    def write_scalar(tag: str, value: Any, step: int = 0) -> None:
        if value is None:
            return
        scalar_tags.append(tag)
        writer.add_event(
            event_pb2.Event(
                wall_time=time.time(),
                step=int(step),
                summary=summary_pb2.Summary(
                    value=[summary_pb2.Summary.Value(tag=tag, simple_value=float(value))]
                ),
            )
        )

    for split_name, metrics in (("train", train_metrics), ("test", test_metrics)):
        for metric_name, value in metrics.items():
            write_scalar(f"{split_name}/{metric_name}", value)

    for key, value in tree_summary.items():
        write_scalar(f"tree/{key}", value)

    for point in threshold_analysis:
        step = int(round(float(point["threshold"]) * 100))
        for metric_name in ("accuracy", "precision", "recall", "f1", "specificity", "predicted_positive_rate"):
            write_scalar(f"threshold/{metric_name}", point[metric_name], step)

    for index, point in enumerate(roc_curve_points):
        write_scalar("curves/roc_false_positive_rate", point["false_positive_rate"], index)
        write_scalar("curves/roc_true_positive_rate", point["true_positive_rate"], index)

    for index, point in enumerate(precision_recall_points):
        write_scalar("curves/pr_precision", point["precision"], index)
        write_scalar("curves/pr_recall", point["recall"], index)

    for index, point in enumerate(calibration_curve):
        if point["avg_confidence"] is None or point["actual_positive_rate"] is None:
            continue
        write_scalar("calibration/avg_confidence", point["avg_confidence"], index)
        write_scalar("calibration/actual_positive_rate", point["actual_positive_rate"], index)

    writer.flush()
    writer.close()

    return {
        "enabled": True,
        "log_dir": str(log_dir),
        "compare_root": str(compare_root),
        "run_name": model_version,
        "scalar_tags": sorted(set(scalar_tags)),
        "launch_commands": {
            "single_run": f'tensorboard --logdir "{log_dir}"',
            "compare_runs": f'tensorboard --logdir "{compare_root}"',
        },
    }
