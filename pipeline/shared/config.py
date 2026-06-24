from __future__ import annotations

"""
Capstone-wide configuration and paths.

``AppConfig`` is the unified frozen dataclass that centralises all application
configuration including file-system roots, model paths, thresholds, FastText
hyperparameters, scanner settings, and external service URLs.

``CapstoneConfig`` is a frozen dataclass that centralises all file-system
roots, model paths, thresholds, and FastText hyperparameters. It is
constructed from environment variables with sensible defaults.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import os  # Standard library: environment variable access
from pathlib import Path  # Standard library: filesystem path abstraction
from typing import TYPE_CHECKING  # Standard library: type checking guard

if TYPE_CHECKING:
    from scanner.settings import ScannerSettings


@dataclass(frozen=True)
class CapstoneConfig:
    """Immutable container for global capstone settings.

    DEPRECATED: Use AppConfig instead. This class is maintained for backward compatibility.
    """

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
        """Build a CapstoneConfig from environment variables and defaults.

        Now delegates to AppConfig for unified configuration.
        """
        app_config = AppConfig.from_env()
        capstone_config, _ = app_config_to_legacy(app_config)
        return capstone_config


@dataclass(frozen=True)
class AppConfig:
    """Unified configuration for the entire capstone application.

    Combines all settings from both CapstoneConfig and ScannerSettings
    into a single, centralised configuration source.
    """

    # CapstoneConfig fields
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

    # ScannerSettings fields
    openphish_enabled: bool = True
    openphish_url: str = (
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )
    phishtank_enabled: bool = True
    phishtank_data_url: str = "https://data.dev.phishtank.com/data/online-valid.json"
    phishtank_app_key: str = ""
    netstar_base_url: str = "https://w4.netstar.dev"
    vt_enabled: bool = True
    vt_base_url: str = "https://netstar.one/vt"
    vt_pos_file: str = ""
    vt_neg_file: str = ""
    vt_min_sources: int = 10
    vt_apply_min_sources_to_neg: bool = False
    feed_refresh_minutes: int = 30
    feed_cache_dir: str = ".cache/threat-intel"
    weights_heuristics: float = 0.15
    weights_content: float = 0.35
    weights_ssl: float = 0.10
    weights_domain_age: float = 0.10
    weights_threat_intel: float = 0.20
    weights_ml: float = 0.10
    ml_enabled: bool = True
    ml_model_path: str = ".cache/ml-artifacts/active_model.keras"
    ml_metadata_path: str = ".cache/ml-artifacts/active_model.json"
    ml_registry_path: str = ".cache/ml-artifacts/model_registry.json"
    ml_runs_dir: str = ".cache/ml-jobs"
    brand_dataset_db_path: str = ".cache/brand-login-dataset.sqlite3"
    ml_default_model_type: str = "tensorflow_dense"
    ml_default_test_size: float = 0.2
    ml_default_random_state: int = 42
    ml_default_epochs: int = 20
    ml_default_batch_size: int = 32
    ml_default_learning_rate: float = 0.001
    ml_default_validation_split: float = 0.2
    ml_default_dropout_rate: float = 0.15
    ml_default_hidden_units: str = "128,64"
    ml_default_early_stopping_patience: int = 5
    ml_default_classification_threshold: float = 0.5
    ml_default_device: str = "auto"
    ml_default_activate_after_training: bool = True

    @staticmethod
    def from_env() -> "AppConfig":
        """Build AppConfig from environment variables and defaults."""
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

        return AppConfig(
            # CapstoneConfig fields
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

            # ScannerSettings fields
            openphish_enabled=_bool_env("OPENPHISH_ENABLED", True),
            openphish_url=os.getenv(
                "OPENPHISH_URL",
                "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            ),
            phishtank_enabled=_bool_env("PHISHTANK_ENABLED", True),
            phishtank_data_url=os.getenv(
                "PHISHTANK_DATA_URL", "https://data.dev.phishtank.com/data/online-valid.json"
            ),
            phishtank_app_key=os.getenv("PHISHTANK_APP_KEY", ""),
            netstar_base_url=os.getenv("NETSTAR_BASE_URL", "https://w4.netstar.dev"),
            vt_enabled=_bool_env("VT_ENABLED", True),
            vt_base_url=os.getenv("VT_BASE_URL", "https://netstar.one/vt"),
            vt_pos_file=os.getenv("VT_POS_FILE", ""),
            vt_neg_file=os.getenv("VT_NEG_FILE", ""),
            vt_min_sources=_int_env("VT_MIN_SOURCES", 10),
            vt_apply_min_sources_to_neg=_bool_env("VT_APPLY_MIN_SOURCES_TO_NEG", False),
            feed_refresh_minutes=_int_env("FEED_REFRESH_MINUTES", 30),
            feed_cache_dir=os.getenv("THREAT_INTEL_CACHE_DIR", ".cache/threat-intel"),
            weights_heuristics=_float_env("WEIGHT_HEURISTICS", 0.15),
            weights_content=_float_env("WEIGHT_CONTENT", 0.35),
            weights_ssl=_float_env("WEIGHT_SSL", 0.10),
            weights_domain_age=_float_env("WEIGHT_DOMAIN_AGE", 0.10),
            weights_threat_intel=_float_env("WEIGHT_THREAT_INTEL", 0.20),
            weights_ml=_float_env("WEIGHT_ML", 0.10),
            ml_enabled=_bool_env("ML_ENABLED", True),
            ml_model_path=os.getenv("ML_MODEL_PATH", ".cache/ml-artifacts/active_model.keras"),
            ml_metadata_path=os.getenv("ML_METADATA_PATH", ".cache/ml-artifacts/active_model.json"),
            ml_registry_path=os.getenv("ML_REGISTRY_PATH", ".cache/ml-artifacts/model_registry.json"),
            ml_runs_dir=os.getenv("ML_RUNS_DIR", ".cache/ml-jobs"),
            brand_dataset_db_path=os.getenv("CAPSTONE_DATASET_DB", ".cache/brand-login-dataset.sqlite3"),
            ml_default_model_type=os.getenv("ML_DEFAULT_MODEL_TYPE", "tensorflow_dense"),
            ml_default_test_size=_float_env("ML_DEFAULT_TEST_SIZE", 0.2),
            ml_default_random_state=_int_env("ML_DEFAULT_RANDOM_STATE", 42),
            ml_default_epochs=_int_env("ML_DEFAULT_EPOCHS", 20),
            ml_default_batch_size=_int_env("ML_DEFAULT_BATCH_SIZE", 32),
            ml_default_learning_rate=_float_env("ML_DEFAULT_LEARNING_RATE", 0.001),
            ml_default_validation_split=_float_env("ML_DEFAULT_VALIDATION_SPLIT", 0.2),
            ml_default_dropout_rate=_float_env("ML_DEFAULT_DROPOUT_RATE", 0.15),
            ml_default_hidden_units=os.getenv("ML_DEFAULT_HIDDEN_UNITS", "128,64"),
            ml_default_early_stopping_patience=_int_env(
                "ML_DEFAULT_EARLY_STOPPING_PATIENCE", 5
            ),
            ml_default_classification_threshold=_float_env(
                "ML_DEFAULT_CLASSIFICATION_THRESHOLD", 0.5
            ),
            ml_default_device=os.getenv("ML_DEFAULT_DEVICE", "auto"),
            ml_default_activate_after_training=_bool_env(
                "ML_DEFAULT_ACTIVATE_AFTER_TRAINING", True
            ),
        )


def app_config_to_legacy(config: AppConfig) -> tuple[CapstoneConfig, "ScannerSettings"]:
    """Convert unified AppConfig to legacy CapstoneConfig and ScannerSettings.

    This allows existing code to continue working with the legacy config objects
    while the unified AppConfig is the source of truth.
    """
    from scanner.settings import ScannerSettings

    capstone_config = CapstoneConfig(
        project_root=config.project_root,
        data_root=config.data_root,
        brand_profiles_path=config.brand_profiles_path,
        dataset_db_path=config.dataset_db_path,
        fasttext_model_path=config.fasttext_model_path,
        fasttext_metadata_path=config.fasttext_metadata_path,
        fasttext_corpus_path=config.fasttext_corpus_path,
        evaluation_dir=config.evaluation_dir,
        request_timeout_seconds=config.request_timeout_seconds,
        fasttext_dim=config.fasttext_dim,
        fasttext_epoch=config.fasttext_epoch,
        fasttext_lr=config.fasttext_lr,
        fasttext_word_ngrams=config.fasttext_word_ngrams,
        fasttext_min_count=config.fasttext_min_count,
        fasttext_loss=config.fasttext_loss,
        fasttext_autotune=config.fasttext_autotune,
        fasttext_autotune_duration=config.fasttext_autotune_duration,
        fasttext_validation_ratio=config.fasttext_validation_ratio,
        fasttext_threshold=config.fasttext_threshold,
        final_score_threshold=config.final_score_threshold,
    )

    scanner_settings = ScannerSettings(
        openphish_enabled=config.openphish_enabled,
        openphish_url=config.openphish_url,
        phishtank_enabled=config.phishtank_enabled,
        phishtank_data_url=config.phishtank_data_url,
        phishtank_app_key=config.phishtank_app_key,
        netstar_base_url=config.netstar_base_url,
        vt_enabled=config.vt_enabled,
        vt_base_url=config.vt_base_url,
        vt_pos_file=config.vt_pos_file,
        vt_neg_file=config.vt_neg_file,
        vt_min_sources=config.vt_min_sources,
        vt_apply_min_sources_to_neg=config.vt_apply_min_sources_to_neg,
        feed_refresh_minutes=config.feed_refresh_minutes,
        feed_cache_dir=config.feed_cache_dir,
        request_timeout_seconds=config.request_timeout_seconds,
        weights_heuristics=config.weights_heuristics,
        weights_content=config.weights_content,
        weights_ssl=config.weights_ssl,
        weights_domain_age=config.weights_domain_age,
        weights_threat_intel=config.weights_threat_intel,
        weights_ml=config.weights_ml,
        ml_enabled=config.ml_enabled,
        ml_model_path=config.ml_model_path,
        ml_metadata_path=config.ml_metadata_path,
        ml_registry_path=config.ml_registry_path,
        ml_runs_dir=config.ml_runs_dir,
        brand_profiles_path=config.brand_profiles_path,
        brand_dataset_db_path=config.brand_dataset_db_path,
        ml_default_model_type=config.ml_default_model_type,
        ml_default_test_size=config.ml_default_test_size,
        ml_default_random_state=config.ml_default_random_state,
        ml_default_epochs=config.ml_default_epochs,
        ml_default_batch_size=config.ml_default_batch_size,
        ml_default_learning_rate=config.ml_default_learning_rate,
        ml_default_validation_split=config.ml_default_validation_split,
        ml_default_dropout_rate=config.ml_default_dropout_rate,
        ml_default_hidden_units=config.ml_default_hidden_units,
        ml_default_early_stopping_patience=config.ml_default_early_stopping_patience,
        ml_default_classification_threshold=config.ml_default_classification_threshold,
        ml_default_device=config.ml_default_device,
        ml_default_activate_after_training=config.ml_default_activate_after_training,
    )

    return capstone_config, scanner_settings


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
