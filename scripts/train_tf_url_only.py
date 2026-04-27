"""Fast URL-only TensorFlow training for benchmark competitiveness.

Trains a dense classifier using URL heuristics + brand recognition features
without slow page snapshot extraction.

Usage:
    python scripts/train_tf_url_only.py data/processed/capstone_v3_train.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import numpy as np


def extract_url_features(url: str) -> dict[str, float]:
    """Extract lightweight features from a URL."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scanner.brand_recognition import BrandRecognitionDetector
    from scanner.heuristics import URLHeuristics
    from scanner.normalization import normalize_input_url

    target = normalize_input_url(url)
    heuristics = URLHeuristics(target).run_checks()
    detector = BrandRecognitionDetector()
    brand = detector.analyze_url(url)

    url_lower = url.lower()
    host = target.host.lower()
    path = target.path.lower()

    # Count special chars
    special_chars = sum(
        1
        for c in url
        if not c.isalnum() and c not in (":", "/", ".", "-", "_", "?", "=", "&")
    )

    # Brand features
    brand_score = float(brand.get("risk_score", 0))
    is_scam = 1.0 if brand.get("status") == "scam" else 0.0
    matched_brand = brand.get("matched_brand", "")

    features = {
        # URL structure
        "url_length": float(len(url)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "num_dots": float(host.count(".")),
        "num_hyphens": float(host.count("-")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "num_special": float(special_chars),
        "has_at": 1.0 if "@" in url else 0.0,
        "is_ip": 1.0 if target.is_ip else 0.0,
        "uses_https": 1.0 if target.scheme == "https" else 0.0,
        "subdomain_depth": float(max(host.count(".") - 1, 0)),
        "path_depth": float(len([p for p in path.split("/") if p])),
        "has_query": 1.0 if target.query else 0.0,
        # Heuristic scores
        "heur_score": float(heuristics.get("risk_score", 0)),
        "heur_ip": 1.0 if heuristics.get("is_ip_address") else 0.0,
        "heur_long": 1.0 if heuristics.get("excessive_length") else 0.0,
        "heur_suspicious": 1.0 if heuristics.get("suspicious_chars") else 0.0,
        "heur_keyword_mask": 1.0 if heuristics.get("keyword_masking") else 0.0,
        # Brand features
        "brand_score": brand_score,
        "brand_is_scam": is_scam,
        "brand_matched": 1.0 if matched_brand else 0.0,
        "brand_typosquat": 1.0 if brand.get("threat_type") == "typosquatting" else 0.0,
        "brand_homograph": 1.0 if brand.get("threat_type") == "homograph" else 0.0,
        "brand_deceptive": 1.0
        if brand.get("threat_type") == "deceptive_subdomain"
        else 0.0,
        # Content hints (URL-based)
        "has_login": 1.0
        if any(k in path for k in ("login", "signin", "auth", "verify", "secure"))
        else 0.0,
        "has_bank": 1.0
        if any(
            k in url_lower for k in ("bank", "chase", "wells", "citi", "paypal", "amex")
        )
        else 0.0,
        "suspicious_tld": 1.0
        if host.endswith((".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"))
        else 0.0,
    }

    return features


def load_dataset(csv_path: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Load CSV and extract features."""
    rows: list[dict[str, Any]] = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"Extracting features for {len(rows)} URLs...")
    features_list = []
    labels = []

    for i, row in enumerate(rows):
        url = row["url"].strip()
        label = int(row["is_phishing"])
        feats = extract_url_features(url)
        features_list.append(feats)
        labels.append(label)
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(rows)} done")

    # Convert to matrix
    feature_names = list(features_list[0].keys())
    X = np.array(
        [[f[name] for name in feature_names] for f in features_list], dtype=np.float32
    )
    y = np.array(labels, dtype=np.float32)

    return X, y, feature_names


def train_model(
    X: np.ndarray, y: np.ndarray, feature_names: list[str], args: argparse.Namespace
) -> dict[str, Any]:
    """Train a TensorFlow dense classifier."""
    import tensorflow as tf
    from sklearn.model_selection import train_test_split

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Normalize features
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Build model
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(
                args.hidden_units[0], activation="relu", input_shape=(X_train.shape[1],)
            ),
            tf.keras.layers.Dropout(args.dropout_rate),
            tf.keras.layers.Dense(args.hidden_units[1], activation="relu"),
            tf.keras.layers.Dropout(args.dropout_rate),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=args.learning_rate),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.Precision(), tf.keras.metrics.Recall()],
    )

    # Callbacks
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=args.early_stopping_patience,
            restore_best_weights=True,
        ),
    ]

    # Train
    print(f"\nTraining model on {len(X_train)} samples...")
    history = model.fit(
        X_train,
        y_train,
        epochs=args.epochs,
        batch_size=args.batch_size,
        validation_split=0.2,
        callbacks=callbacks,
        verbose=1,
    )

    # Evaluate
    print("\nEvaluating on test set...")
    test_loss, test_acc, test_prec, test_recall = model.evaluate(
        X_test, y_test, verbose=0
    )

    # Predictions for F1
    y_pred = (model.predict(X_test, verbose=0) > 0.5).astype(int).flatten()
    from sklearn.metrics import f1_score, confusion_matrix

    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\nTest Accuracy: {test_acc:.4f}")
    print(f"Test Precision: {test_prec:.4f}")
    print(f"Test Recall: {test_recall:.4f}")
    print(f"Test F1: {f1:.4f}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, FN={fn}, TN={tn}")

    # Save model
    run_dir = Path(args.output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    model_path = run_dir / "model.keras"
    model.save(model_path)

    # Save metadata
    from datetime import datetime

    metadata = {
        "model_version": f"tf_url_only_v3_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "accuracy": float(test_acc),
        "precision": float(test_prec),
        "recall": float(test_recall),
        "f1": float(f1),
        "confusion_matrix": {
            "tp": int(tp),
            "fp": int(fp),
            "fn": int(fn),
            "tn": int(tn),
        },
        "feature_names": feature_names,
        "hyperparameters": {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "dropout_rate": args.dropout_rate,
            "hidden_units": args.hidden_units,
        },
        "history": {k: [float(v) for v in vals] for k, vals in history.history.items()},
    }

    metadata_path = run_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"\nModel saved to {model_path}")
    print(f"Metadata saved to {metadata_path}")

    return metadata


def main() -> int:
    from datetime import datetime

    parser = argparse.ArgumentParser(description="Fast URL-only TF training.")
    parser.add_argument("input_csv", help="Input CSV with url and is_phishing columns.")
    parser.add_argument(
        "--output-dir",
        default=".cache/ml-artifacts/run_v3_capstone",
        help="Output directory.",
    )
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--dropout-rate", type=float, default=0.3)
    parser.add_argument(
        "--hidden-units", default="128,64", help="Comma-separated layer sizes."
    )
    parser.add_argument("--early-stopping-patience", type=int, default=15)
    args = parser.parse_args()

    args.hidden_units = [int(x.strip()) for x in args.hidden_units.split(",")]

    print("=== URL-Only TensorFlow Training ===\n")
    X, y, feature_names = load_dataset(args.input_csv)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Label distribution: {np.bincount(y.astype(int))}")

    metadata = train_model(X, y, feature_names, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
