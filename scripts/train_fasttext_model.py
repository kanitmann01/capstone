from __future__ import annotations

"""
CLI script: train the FastText brand-login detector from a supervised corpus.

Reads a corpus in FastText format, builds a training config from
environment variables via ``CapstoneConfig``, and persists the model
binary plus metadata sidecar.
"""

import argparse  # Standard library: command-line argument parsing
from pathlib import Path  # Standard library: filesystem path abstraction

from pipeline.modeling.fasttext_train import default_training_config  # Project-local: config factory
from pipeline.modeling.fasttext_train import train_fasttext_model  # Project-local: FastText trainer
from pipeline.shared.config import CapstoneConfig  # Project-local: global capstone configuration


def build_parser() -> argparse.ArgumentParser:
    """Configure the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Train the FastText brand-login detector.")
    parser.add_argument("corpus_path", help="Training corpus in FastText supervised format.")
    parser.add_argument(
        "--model-path",
        default=None,
        help="Where to save the trained model. Defaults to the configured FastText model path.",
    )
    parser.add_argument(
        "--metadata-path",
        default=None,
        help="Where to save the model metadata. Defaults to the configured metadata path.",
    )
    return parser


def main() -> int:
    """Entry point: parse args, train model, print summary."""
    args = build_parser().parse_args()
    config = CapstoneConfig.from_env()
    train_config = default_training_config(config)
    model_path = Path(args.model_path or config.fasttext_model_path)
    metadata_path = Path(args.metadata_path or config.fasttext_metadata_path)
    metadata = train_fasttext_model(
        corpus_path=args.corpus_path,
        model_path=model_path,
        metadata_path=metadata_path,
        config=train_config,
    )
    print("FastText model trained")
    print(f"model_version: {metadata['model_version']}")
    print(f"model_path: {metadata['model_path']}")
    print(f"metadata_path: {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
