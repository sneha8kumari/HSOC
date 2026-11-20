"""
Sliding window state manager for rule evaluation.

Maintains per-entity circular buffers keyed by (src_ip, user, dst_host).
Windows are pruned lazily when events are added.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from hsoc.schema import Event


class WindowManager:
    """
    Keeps per-entity sliding windows of events.

    Usage::

        wm = WindowManager()
        wm.add(event)
        window = wm.get_window("src_ip", "192.168.1.5", window_seconds=60)
    """

    def __init__(self) -> None:
        # Map: entity_type -> entity_value -> list of Events sorted by ts
        self._buffers: dict[str, dict[str, list[Event]]] = {
            "src_ip": defaultdict(list),
            "user": defaultdict(list),
            "dst_host": defaultdict(list),
        }

    def add(self, event: Event) -> None:
        """Add an event to its relevant entity windows."""
        if event.src_ip:
            self._buffers["src_ip"][event.src_ip].append(event)
        if event.user:
            self._buffers["user"][event.user].append(event)

        host_target = event.host or event.dst_ip
        if host_target:
            self._buffers["dst_host"][host_target].append(event)

    def get_window(
        self,
        entity_type: str,
        entity_value: str,
        window_seconds: int,
        as_of: datetime | None = None,
    ) -> list[Event]:
        """
        Return all events for an entity within the window.

        Args:
            entity_type: One of src_ip, user, dst_host.
            entity_value: The specific entity value to look up.
            window_seconds: Window duration in seconds.
            as_of: Reference time (defaults to newest event time or now).

        Returns:
            List of events within the window, newest first.
        """
        if entity_type not in self._buffers:
            return []

        events = self._buffers[entity_type].get(entity_value, [])
        if not events:
            return []

        ref_time = as_of or events[-1].ts
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        cutoff = ref_time - timedelta(seconds=window_seconds)

        # Filter events in window [cutoff, ref_time]
        in_window = [e for e in events if cutoff <= (e.ts.replace(tzinfo=timezone.utc) if e.ts.tzinfo is None else e.ts) <= ref_time]
        # Return newest first
        return sorted(in_window, key=lambda x: x.ts, reverse=True)

    def get_all_entities(self, entity_type: str) -> list[str]:
        """Return list of all registered entity keys for an entity type."""
        return list(self._buffers.get(entity_type, {}).keys())
