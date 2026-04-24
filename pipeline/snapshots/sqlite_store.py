from __future__ import annotations

"""
Re-export module for SQLite dataset storage.

Provides a convenience façade so pipeline modules can import
``SnapshotRecord`` and ``BrandLoginDatasetStore`` from a dedicated
snapshots namespace rather than from the scanner package directly.
"""

from scanner.dataset_store import BrandLoginDatasetStore  # Project-local: SQLite CRUD operations
from scanner.dataset_store import SnapshotRecord  # Project-local: immutable snapshot dataclass


__all__ = ["BrandLoginDatasetStore", "SnapshotRecord"]
