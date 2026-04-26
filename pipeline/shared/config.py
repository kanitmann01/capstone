from __future__ import annotations

"""
Capstone-wide configuration and paths.

``CapstoneConfig`` is a frozen dataclass that centralises all file-system
roots, model paths, thresholds, and FastText hyperparameters. It is
constructed from environment variables with sensible defaults.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import os  # Standard library: environment variable access
from pathlib import Path  # Standard library: filesystem path abstraction


@dataclass(frozen=True)
class CapstoneConfig:
    """Immutable container for global capstone settings."""

    project_root: Path
    data_root: Path
    brand_profiles_path: Path
    dataset_db_path: Path
    fasttext_model_path: Path
    fasttext_metadata_path: Path
    fasttext_corpus_path: Path
    evaluation_dir: Path
    request_timeout_seconds: int = 8
    fasttext_dim: int = 100
    fasttext_epoch: int = 50
    fasttext_lr: float = 0.2
    fasttext_word_ngrams: int = 3
    fasttext_min_count: int = 1
    fasttext_loss: str = "softmax"
    fasttext_autotune: bool = False
    fasttext_autotune_duration: int = 60
    fasttext_validation_ratio: float = 0.2
    fasttext_threshold: float = 0.5
    final_score_threshold: float = 30.0

    @staticmethod
    def from_env() -> "CapstoneConfig":
        """Build a CapstoneConfig from environment variables and defaults."""
        project_root = Path(__file__).resolve().parents[2]
        data_root = Path(os.getenv("CAPSTONE_DATA_ROOT", str(project_root / "data")))
        brand_profiles_path = Path(
            os.getenv("BRAND_PROFILES_PATH", str(project_root / "scanner" / "brand_profiles.json"))
        )
        dataset_db_path = Path(
            os.getenv("CAPSTONE_DATASET_DB", str(project_root / ".cache" / "brand-login-dataset.sqlite3"))
        )
        fasttext_model_path = Path(
            os.getenv("FASTTEXT_MODEL_PATH", str(project_root / ".cache" / "fasttext" / "brand-login.bin"))
        )
        fasttext_metadata_path = Path(
            os.getenv("FASTTEXT_METADATA_PATH", str(project_root / ".cache" / "fasttext" / "brand-login.json"))
        )
        fasttext_corpus_path = Path(
            os.getenv("FASTTEXT_CORPUS_PATH", str(data_root / "processed" / "fasttext_corpus.txt"))
        )
        evaluation_dir = Path(
            os.getenv("CAPSTONE_EVALUATION_DIR", str(project_root / ".cache" / "evaluations"))
        )
        return CapstoneConfig(
            project_root=project_root,
            data_root=data_root,
            brand_profiles_path=brand_profiles_path,
            dataset_db_path=dataset_db_path,
            fasttext_model_path=fasttext_model_path,
            fasttext_metadata_path=fasttext_metadata_path,
            fasttext_corpus_path=fasttext_corpus_path,
            evaluation_dir=evaluation_dir,
            request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 8),
            fasttext_dim=_int_env("FASTTEXT_DIM", 100),
            fasttext_epoch=_int_env("FASTTEXT_EPOCH", 50),
            fasttext_lr=_float_env("FASTTEXT_LR", 0.2),
            fasttext_word_ngrams=_int_env("FASTTEXT_WORD_NGRAMS", 3),
            fasttext_min_count=_int_env("FASTTEXT_MIN_COUNT", 1),
            fasttext_loss=os.getenv("FASTTEXT_LOSS", "softmax"),
            fasttext_autotune=_bool_env("FASTTEXT_AUTOTUNE", False),
            fasttext_autotune_duration=_int_env("FASTTEXT_AUTOTUNE_DURATION", 60),
            fasttext_validation_ratio=_float_env("FASTTEXT_VALIDATION_RATIO", 0.2),
            fasttext_threshold=_float_env("FASTTEXT_THRESHOLD", 0.5),
            final_score_threshold=_float_env("FINAL_SCORE_THRESHOLD", 30.0),
        )


def _int_env(name: str, default: int) -> int:
    """Safely parse an integer environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    """Safely parse a float environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    """Safely parse a boolean environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
