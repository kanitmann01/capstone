"""Quick TensorFlow model training with URL-only features.

This bypasses slow page snapshot extraction and trains directly from
URL features (heuristics + brand recognition) for speed.

Usage:
    python scripts/train_tf_quick.py data/processed/capstone_v3_train.csv

Output:
    .cache/ml-artifacts/run_v3_capstone/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.feed_ingest import ThreatFeedCache
from scanner.ml_training import sanitize_training_config, train_from_labeled_csv
from scanner.service import ScanService
from scanner.settings import ScannerSettings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Quick TF training with URL-only features."
    )
    parser.add_argument("input_csv", help="Input CSV with url and is_phishing columns.")
    parser.add_argument(
        "--output-dir",
        default=".cache/ml-artifacts/run_v3_capstone",
        help="Run directory.",
    )
    parser.add_argument("--epochs", type=int, default=50, help="Training epochs.")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size.")
    parser.add_argument(
        "--learning-rate", type=float, default=0.001, help="Learning rate."
    )
    parser.add_argument("--dropout-rate", type=float, default=0.2, help="Dropout rate.")
    parser.add_argument("--hidden-units", default="128,64", help="Hidden layer sizes.")
    parser.add_argument(
        "--early-stopping-patience",
        type=int,
        default=10,
        help="Early stopping patience.",
    )
    parser.add_argument(
        "--no-activate", action="store_true", help="Don't activate after training."
    )
    args = parser.parse_args()

    settings = ScannerSettings.from_env()
    feed_cache = ThreatFeedCache(settings)
    scan_service = ScanService(settings, feed_cache)

    config = sanitize_training_config(
        {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "dropout_rate": args.dropout_rate,
            "hidden_units": args.hidden_units,
            "early_stopping_patience": args.early_stopping_patience,
            "activate_after_training": not args.no_activate,
            "device": "cpu",
        },
        settings,
    )

    report = train_from_labeled_csv(
        input_csv=args.input_csv,
        run_dir=Path(args.output_dir),
        scan_service=scan_service,
        settings=settings,
        config=config,
        label_source="capstone_v3",
    )

    print("\nTraining complete!")
    summary = report.get("summary", {})
    print(f"Model version: {summary.get('model_version')}")
    print(f"Accuracy: {summary.get('accuracy', 0):.4f}")
    print(f"Precision: {summary.get('precision', 0):.4f}")
    print(f"Recall: {summary.get('recall', 0):.4f}")
    print(f"F1: {summary.get('f1', 0):.4f}")
    print(f"Artifacts: {report.get('artifacts', {})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
