from __future__ import annotations

"""
Small TensorFlow import helpers.

TensorFlow prints native Windows CPU/GPU diagnostics during import. The scanner
uses TensorFlow lazily, so keep those diagnostics out of normal app terminals.
"""

from contextlib import redirect_stderr  # Standard library: suppress import-time diagnostics
import io  # Standard library: in-memory text stream
import logging  # Standard library: logger controls
import os  # Standard library: environment controls
from typing import Any  # Standard library: generic type hints


def configure_tensorflow_runtime() -> None:
    """Set TensorFlow runtime defaults before importing it."""
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
    logging.getLogger("tensorflow").setLevel(logging.ERROR)


def import_tensorflow_quietly() -> Any:
    """Import TensorFlow while suppressing expected CPU-only startup chatter."""
    configure_tensorflow_runtime()
    with redirect_stderr(io.StringIO()):
        import tensorflow as tf_module  # pyright: ignore[reportMissingImports]
    tf_module.get_logger().setLevel("ERROR")
    return tf_module
