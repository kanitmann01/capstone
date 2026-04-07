from __future__ import annotations

import argparse
from pathlib import Path

from pipeline.modeling.fasttext_train import FastTextTrainingConfig
from pipeline.modeling.fasttext_train import train_fasttext_model
from pipeline.shared.config import CapstoneConfig


def build_parser() -> argparse.ArgumentParser:
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
    args = build_parser().parse_args()
    config = CapstoneConfig.from_env()
    train_config = FastTextTrainingConfig(
        dim=config.fasttext_dim,
        epoch=config.fasttext_epoch,
        lr=config.fasttext_lr,
        word_ngrams=config.fasttext_word_ngrams,
        min_count=config.fasttext_min_count,
        loss=config.fasttext_loss,
    )
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
