from __future__ import annotations

"""
FastText supervised model training.

Wraps ``fasttext.train_supervised`` with a typed configuration dataclass
and writes model binaries plus JSON metadata sidecars.
"""

from dataclasses import asdict  # Standard library: dataclass -> dict
from dataclasses import dataclass  # Standard library: immutable data class decorator
from datetime import datetime, timezone  # Standard library: UTC-aware timestamps
import json  # Standard library: JSON serialization
from pathlib import Path  # Standard library: filesystem path abstraction
import tempfile  # Standard library: temporary validation corpus
from typing import Any  # Standard library: generic type hints

from pipeline.modeling.fasttext_dataset import LABEL_PREFIX  # Project-local: FastText supervised label prefix
from pipeline.shared.config import CapstoneConfig  # Project-local: global capstone configuration


@dataclass(frozen=True)
class FastTextTrainingConfig:
    """Immutable hyperparameters for FastText supervised training."""

    dim: int = 100
    epoch: int = 50
    lr: float = 0.2
    word_ngrams: int = 3
    min_count: int = 1
    loss: str = "softmax"
    autotune: bool = False
    autotune_duration: int = 60
    validation_ratio: float = 0.2


def train_fasttext_model(
    *,
    corpus_path: str | Path,
    model_path: str | Path,
    metadata_path: str | Path,
    config: FastTextTrainingConfig,
) -> dict[str, Any]:
    """Train a FastText classifier and persist model + metadata."""
    corpus = Path(corpus_path)
    model_file = Path(model_path)
    metadata_file = Path(metadata_path)
    label_counts = _validate_training_corpus(corpus)

    try:
        import fasttext  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency failure is environment-specific.
        raise RuntimeError("fasttext-wheel is required to train the capstone model") from exc

    model_file.parent.mkdir(parents=True, exist_ok=True)
    metadata_file.parent.mkdir(parents=True, exist_ok=True)

    train_input = corpus
    validation_counts: dict[str, int] = {}
    autotune_enabled = False
    train_kwargs: dict[str, Any] = {
        "input": str(train_input),
        "dim": config.dim,
        "epoch": config.epoch,
        "lr": config.lr,
        "wordNgrams": config.word_ngrams,
        "minCount": config.min_count,
        "loss": config.loss,
    }

    with tempfile.TemporaryDirectory(prefix="capstone_fasttext_") as temp_dir:
        if config.autotune:
            split = _build_autotune_split(corpus, Path(temp_dir), config.validation_ratio)
            if split is not None:
                train_input, validation_file, validation_counts = split
                train_kwargs = {
                    "input": str(train_input),
                    "autotuneValidationFile": str(validation_file),
                    "autotuneDuration": max(int(config.autotune_duration), 1),
                }
                autotune_enabled = True

        model = fasttext.train_supervised(**train_kwargs)
    model.save_model(str(model_file))

    selected_hyperparameters = _model_hyperparameters(model)
    metadata = {
        "model_version": f"fasttext_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "model_type": "fasttext",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "corpus_path": str(corpus),
        "training_input_path": str(train_input if autotune_enabled else corpus),
        "model_path": str(model_file),
        "feature_version": "fasttext_brand_login_v2",
        "hyperparameters": selected_hyperparameters or asdict(config),
        "base_hyperparameters": asdict(config),
        "autotune": {
            "enabled": autotune_enabled,
            "requested": bool(config.autotune),
            "duration_seconds": int(config.autotune_duration),
            "validation_ratio": float(config.validation_ratio),
            "validation_counts": validation_counts,
        },
        "label_counts": label_counts,
    }
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def _validate_training_corpus(corpus: Path) -> dict[str, int]:
    """Ensure the corpus exists and contains both supervised classes."""
    if not corpus.exists():
        raise FileNotFoundError(f"FastText corpus does not exist: {corpus}")

    label_counts = {"phishing": 0, "clean": 0}
    with corpus.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            label = stripped.split(maxsplit=1)[0]
            if label.startswith(LABEL_PREFIX):
                label_name = label.replace(LABEL_PREFIX, "", 1)
                if label_name in label_counts:
                    label_counts[label_name] += 1

    if sum(label_counts.values()) == 0:
        raise ValueError("FastText corpus must contain at least one labeled training row")
    if any(count == 0 for count in label_counts.values()):
        raise ValueError("FastText corpus must contain both phishing and clean labels")
    return label_counts


def _build_autotune_split(corpus: Path, temp_dir: Path, validation_ratio: float) -> tuple[Path, Path, dict[str, int]] | None:
    """Create deterministic train/validation files when both classes can be split."""
    rows_by_label: dict[str, list[str]] = {"phishing": [], "clean": []}
    with corpus.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            label = stripped.split(maxsplit=1)[0].replace(LABEL_PREFIX, "", 1)
            if label in rows_by_label:
                rows_by_label[label].append(stripped)

    if any(len(rows) < 2 for rows in rows_by_label.values()):
        return None

    ratio = min(max(float(validation_ratio), 0.05), 0.5)
    train_lines: list[str] = []
    validation_lines: list[str] = []
    validation_counts: dict[str, int] = {}
    for label, rows in rows_by_label.items():
        validation_count = min(max(int(round(len(rows) * ratio)), 1), len(rows) - 1)
        validation_counts[label] = validation_count
        validation_lines.extend(rows[:validation_count])
        train_lines.extend(rows[validation_count:])

    train_file = temp_dir / "fasttext_train.txt"
    validation_file = temp_dir / "fasttext_validation.txt"
    train_file.write_text("\n".join(train_lines) + "\n", encoding="utf-8")
    validation_file.write_text("\n".join(validation_lines) + "\n", encoding="utf-8")
    return train_file, validation_file, validation_counts


def _model_hyperparameters(model: Any) -> dict[str, Any]:
    """Extract trained FastText args when the Python binding exposes them."""
    try:
        args = model.f.getArgs()
    except Exception:
        return {}
    return {
        "dim": getattr(args, "dim", None),
        "epoch": getattr(args, "epoch", None),
        "lr": getattr(args, "lr", None),
        "word_ngrams": getattr(args, "wordNgrams", None),
        "min_count": getattr(args, "minCount", None),
        "loss": str(getattr(args, "loss", "")),
    }


def load_fasttext_model(model_path: str | Path):
    """Load a previously trained FastText model from disk."""
    try:
        import fasttext  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency failure is environment-specific.
        raise RuntimeError("fasttext-wheel is required to load the capstone model") from exc
    return fasttext.load_model(str(model_path))


def default_training_config(config: CapstoneConfig) -> FastTextTrainingConfig:
    """Map CapstoneConfig values into a FastTextTrainingConfig instance."""
    return FastTextTrainingConfig(
        dim=config.fasttext_dim,
        epoch=config.fasttext_epoch,
        lr=config.fasttext_lr,
        word_ngrams=config.fasttext_word_ngrams,
        min_count=config.fasttext_min_count,
        loss=config.fasttext_loss,
        autotune=config.fasttext_autotune,
        autotune_duration=config.fasttext_autotune_duration,
        validation_ratio=config.fasttext_validation_ratio,
    )
