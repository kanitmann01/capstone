from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from pipeline.shared.config import CapstoneConfig


@dataclass(frozen=True)
class FastTextTrainingConfig:
    dim: int = 100
    epoch: int = 25
    lr: float = 0.4
    word_ngrams: int = 2
    min_count: int = 1
    loss: str = "softmax"


def train_fasttext_model(
    *,
    corpus_path: str | Path,
    model_path: str | Path,
    metadata_path: str | Path,
    config: FastTextTrainingConfig,
) -> dict[str, Any]:
    try:
        import fasttext  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency failure is environment-specific.
        raise RuntimeError("fasttext-wheel is required to train the capstone model") from exc

    corpus = Path(corpus_path)
    model_file = Path(model_path)
    metadata_file = Path(metadata_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)
    metadata_file.parent.mkdir(parents=True, exist_ok=True)

    model = fasttext.train_supervised(
        input=str(corpus),
        dim=config.dim,
        epoch=config.epoch,
        lr=config.lr,
        wordNgrams=config.word_ngrams,
        minCount=config.min_count,
        loss=config.loss,
    )
    model.save_model(str(model_file))

    metadata = {
        "model_version": f"fasttext_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "model_type": "fasttext",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "corpus_path": str(corpus),
        "model_path": str(model_file),
        "feature_version": "fasttext_brand_login_v1",
        "hyperparameters": asdict(config),
    }
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def load_fasttext_model(model_path: str | Path):
    try:
        import fasttext  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency failure is environment-specific.
        raise RuntimeError("fasttext-wheel is required to load the capstone model") from exc
    return fasttext.load_model(str(model_path))


def default_training_config(config: CapstoneConfig) -> FastTextTrainingConfig:
    return FastTextTrainingConfig(
        dim=config.fasttext_dim,
        epoch=config.fasttext_epoch,
        lr=config.fasttext_lr,
        word_ngrams=config.fasttext_word_ngrams,
        min_count=config.fasttext_min_count,
        loss=config.fasttext_loss,
    )
