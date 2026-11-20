"""
Exact in-memory LRU deduplicator for H-SOC streaming ingestion.

Ensures zero silent drops (no Bloom filter false positives).
Backed by DB unique constraint on EventORM.raw_hash.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any


class LRUDeduplicator:
    """Thread-safe exact in-memory LRU set for deduplication."""

    def __init__(self, max_size: int = 100000) -> None:
        self.max_size = max_size
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self._duplicate_count: int = 0
        self._checked_count: int = 0

    def is_duplicate(self, raw_hash: str, timestamp: float = 0.0) -> bool:
        """
        Check if raw_hash was already seen.
        If seen, moves entry to MRU position and returns True.
        If not seen, inserts entry (evicting LRU if full) and returns False.
        """
        with self._lock:
            self._checked_count += 1
            if raw_hash in self._cache:
                self._cache.move_to_end(raw_hash)
                self._duplicate_count += 1
                return True

            self._cache[raw_hash] = timestamp
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)  # Evict oldest (LRU)
            return False

    def clear(self) -> None:
        """Clear the deduplication cache."""
        with self._lock:
            self._cache.clear()
            self._duplicate_count = 0
            self._checked_count = 0

    def get_stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "checked_total": self._checked_count,
                "duplicates_total": self._duplicate_count,
            }


# Global singleton instance
_global_dedup: LRUDeduplicator | None = None


def get_deduplicator() -> LRUDeduplicator:
    """Return the global LRUDeduplicator singleton."""
    global _global_dedup
    if _global_dedup is None:
        _global_dedup = LRUDeduplicator()
    return _global_dedup
