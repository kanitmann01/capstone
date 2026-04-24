from __future__ import annotations

"""
Environment-driven configuration for scanner modules.

``ScannerSettings`` encapsulates all runtime tunables: threat-feed URLs,
API keys, cache directories, request timeouts, per-check score weights,
and TensorFlow training defaults. Values are read from environment
variables with sensible defaults.
"""

from dataclasses import dataclass  # Standard library: immutable data class decorator
import os  # Standard library: environment variable access


@dataclass(frozen=True)
class ScannerSettings:
    """Immutable container for scanner configuration."""

    openphish_enabled: bool = True
    openphish_url: str = (
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )
    phishtank_enabled: bool = True
    phishtank_data_url: str = "https://data.dev.phishtank.com/data/online-valid.json"
    phishtank_app_key: str = ""
    vt_enabled: bool = True
    vt_base_url: str = "https://netstar.one/vt"
    vt_pos_file: str = ""
    vt_neg_file: str = ""
    vt_min_sources: int = 10
    vt_apply_min_sources_to_neg: bool = False
    feed_refresh_minutes: int = 30
    feed_cache_dir: str = ".cache/threat-intel"
    request_timeout_seconds: int = 8
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
    brand_profiles_path: str = "scanner/brand_profiles.json"
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
    def from_env() -> "ScannerSettings":
        """Load settings from environment variables, falling back to defaults."""
        return ScannerSettings(
            openphish_enabled=_bool_env("OPENPHISH_ENABLED", True),
            openphish_url=os.getenv(
                "OPENPHISH_URL",
                "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            ),
            phishtank_enabled=_bool_env("PHISHTANK_ENABLED", True),
            phishtank_data_url=os.getenv(
                "PHISHTANK_DATA_URL",
                "https://data.dev.phishtank.com/data/online-valid.json",
            ),
            phishtank_app_key=os.getenv("PHISHTANK_APP_KEY", ""),
            vt_enabled=_bool_env("VT_ENABLED", True),
            vt_base_url=os.getenv("VT_BASE_URL", "https://netstar.one/vt"),
            vt_pos_file=os.getenv("VT_POS_FILE", ""),
            vt_neg_file=os.getenv("VT_NEG_FILE", ""),
            vt_min_sources=_int_env("VT_MIN_SOURCES", 10),
            vt_apply_min_sources_to_neg=_bool_env("VT_APPLY_MIN_SOURCES_TO_NEG", False),
            feed_refresh_minutes=_int_env("FEED_REFRESH_MINUTES", 30),
            feed_cache_dir=os.getenv("THREAT_INTEL_CACHE_DIR", ".cache/threat-intel"),
            request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 8),
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
            brand_profiles_path=os.getenv("BRAND_PROFILES_PATH", "scanner/brand_profiles.json"),
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
            ml_default_early_stopping_patience=_int_env("ML_DEFAULT_EARLY_STOPPING_PATIENCE", 5),
            ml_default_classification_threshold=_float_env("ML_DEFAULT_CLASSIFICATION_THRESHOLD", 0.5),
            ml_default_device=os.getenv("ML_DEFAULT_DEVICE", "auto"),
            ml_default_activate_after_training=_bool_env("ML_DEFAULT_ACTIVATE_AFTER_TRAINING", True),
        )


def _bool_env(name: str, default: bool) -> bool:
    """Parse a boolean environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    """Parse an integer environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    """Parse a float environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default
