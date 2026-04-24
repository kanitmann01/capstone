from __future__ import annotations

"""
CLI script: train the TensorFlow phishing classifier from labeled URLs.

Orchestrates feature extraction, dataset generation, model training,
and optional artifact activation. Hyperparameters can be overridden
via CLI flags; defaults come from ``ScannerSettings``.
"""

import argparse  # Standard library: command-line argument parsing
from pathlib import Path  # Standard library: filesystem path abstraction

from scanner.feed_ingest import ThreatFeedCache  # Project-local: threat-intel cache
from scanner.ml_training import sanitize_training_config  # Project-local: config validator
from scanner.ml_training import train_from_labeled_csv  # Project-local: end-to-end training pipeline
from scanner.service import ScanService  # Project-local: combined scanner service
from scanner.settings import ScannerSettings  # Project-local: scanner configuration


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser with extensive training hyperparameter overrides."""
    parser = argparse.ArgumentParser(
        description="Train the TensorFlow phishing classifier from labeled URLs.",
    )
    parser.add_argument("input_csv", help="Input CSV with url and is_phishing columns.")
    parser.add_argument(
        "--output-dir",
        default="models/manual_run",
        help="Directory to write feature dataset, model artifact, metadata, and report.",
    )
    parser.add_argument("--test-size", type=float, default=None)
    parser.add_argument("--random-state", type=int, default=None)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--learning-rate", type=float, default=None)
    parser.add_argument("--validation-split", type=float, default=None)
    parser.add_argument("--dropout-rate", type=float, default=None)
    parser.add_argument("--hidden-units", default=None, help="Comma-separated dense layer sizes, e.g. 128,64")
    parser.add_argument("--early-stopping-patience", type=int, default=None)
    parser.add_argument("--classification-threshold", type=float, default=None)
    parser.add_argument("--device", default=None, help="auto, cpu, gpu:0, gpu:1, ...")
    parser.add_argument(
        "--no-activate",
        action="store_true",
        help="Do not copy the trained run into the active runtime model paths.",
    )
    parser.add_argument("--label-source", default="manual")
    return parser


def main() -> int:
    """Entry point: parse args, sanitise config, train model, print summary."""
    args = build_parser().parse_args()
    settings = ScannerSettings.from_env()
    feed_cache = ThreatFeedCache(settings)
    scan_service = ScanService(settings, feed_cache)
    raw_config = {
        "test_size": args.test_size,
        "random_state": args.random_state,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "validation_split": args.validation_split,
        "dropout_rate": args.dropout_rate,
        "hidden_units": args.hidden_units,
        "early_stopping_patience": args.early_stopping_patience,
        "classification_threshold": args.classification_threshold,
        "device": args.device,
    }
    config = sanitize_training_config(
        {
            key: value
            for key, value in raw_config.items()
            if value is not None
        }
        | {"activate_after_training": not args.no_activate},
        settings,
    )
    report = train_from_labeled_csv(
        input_csv=args.input_csv,
        run_dir=Path(args.output_dir),
        scan_service=scan_service,
        settings=settings,
        config=config,
        label_source=args.label_source,
    )
    print("Model training complete")
    print(f"model_version: {report['summary']['model_version']}")
    print(f"accuracy: {report['summary']['accuracy']}")
    print(f"precision: {report['summary']['precision']}")
    print(f"recall: {report['summary']['recall']}")
    print(f"f1: {report['summary']['f1']}")
    print(f"feature_dataset_path: {report['artifacts']['feature_dataset_path']}")
    print(f"model_path: {report['artifacts']['model_path']}")
    print(f"report_path: {report['artifacts']['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
