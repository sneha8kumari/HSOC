from __future__ import annotations
import uuid
"""
Asynchronous File Tailer for H-SOC.

Tails local log files in real-time with:
  - Persistent byte offset storage (resume across restarts)
  - Log rotation and truncation detection
  - Exact in-memory LRU deduplication
  - Zero-silent-drop quarantine and Event Bus publication
"""

from datetime import datetime, timezone

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from hsoc.config import get_settings
from hsoc.db import EventORM, QuarantineORM, SessionLocal
from hsoc.ingest.collector import compute_raw_hash
from hsoc.ingest.dedup import get_deduplicator
from hsoc.ingest.enrich import enrich
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.parsers import PARSER_REGISTRY
from hsoc.schema import Event, QuarantineRecord
from hsoc.streaming.bus import StreamMessage, get_event_bus

logger = logging.getLogger(__name__)


class AsyncFileTailer:
    """Tails one or more files asynchronously and ingests appended lines."""

    def __init__(
        self,
        targets: list[dict[str, Any]] | None = None,
        offset_store_path: str = "data/tailer_offsets.json",
        poll_interval_seconds: float = 0.5,
    ) -> None:
        self.targets = targets or []
        self.offset_store_path = Path(offset_store_path)
        self.poll_interval = poll_interval_seconds
        self.offsets: dict[str, int] = {}
        self.is_running: bool = False
        self._tail_tasks: list[asyncio.Task] = []
        self.events_read: int = 0
        self._load_offsets()

    def _load_offsets(self) -> None:
        """Load stored byte offsets from disk."""
        if self.offset_store_path.exists():
            try:
                with open(self.offset_store_path, "r", encoding="utf-8") as f:
                    self.offsets = json.load(f)
            except Exception as exc:
                logger.warning("Could not read offset store (%s): %s", self.offset_store_path, exc)
                self.offsets = {}

    def _save_offsets(self) -> None:
        """Persist current byte offsets to disk."""
        try:
            self.offset_store_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.offset_store_path, "w", encoding="utf-8") as f:
                json.dump(self.offsets, f, indent=2)
        except Exception as exc:
            logger.error("Failed to write offset store (%s): %s", self.offset_store_path, exc)

    async def ingest_line(self, line: str, source_type: str, host: str = "localhost") -> dict[str, Any]:
        """Ingest a single line read by the tailer."""
        raw_line = line.strip()
        if not raw_line:
            return {"status": "ignored"}

        raw_hash = compute_raw_hash(raw_line)
        dedup = get_deduplicator()
        if dedup.is_duplicate(raw_hash):
            return {"status": "duplicate", "raw_hash": raw_hash}

        parser_fn = PARSER_REGISTRY.get(source_type)
        db = SessionLocal()
        try:
            if not parser_fn:
                q = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type=source_type,
                    raw=raw_line,
                    reason=f"Unknown source_type '{source_type}'",
                    parser="tailer",
                )
                db.add(q)
                db.commit()
                return {"status": "quarantined", "reason": q.reason}

            try:
                parsed_dict = parser_fn(raw_line)
                if not parsed_dict.get("host") and host:
                    parsed_dict["host"] = host
                item = map_to_event(parsed_dict, source_type)
            except Exception as exc:
                q = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type=source_type,
                    raw=raw_line,
                    reason=f"Parser exception: {str(exc)}",
                    parser=source_type,
                )
                db.add(q)
                db.commit()
                return {"status": "quarantined", "reason": q.reason}

            if isinstance(item, QuarantineRecord):
                q = QuarantineORM(
                    record_id=item.record_id,
                    ts=item.ts or datetime.now(timezone.utc),
                    source_type=item.source_type,
                    raw=item.raw,
                    reason=item.reason,
                    parser=item.parser,
                )
                db.add(q)
                db.commit()
                return {"status": "quarantined", "reason": item.reason}

            enriched = enrich(item)
            source_type_val = enriched.source_type.value if hasattr(enriched.source_type, "value") else str(enriched.source_type)
            event_orm = EventORM(
                event_id=enriched.event_id,
                ts=enriched.ts,
                source_type=source_type_val,
                host=enriched.host,
                src_ip=enriched.src_ip,
                dst_ip=enriched.dst_ip,
                dst_port=enriched.dst_port,
                user=enriched.user,
                action=enriched.action,
                outcome=enriched.outcome.value if hasattr(enriched.outcome, "value") else str(enriched.outcome),
                asset_criticality=enriched.asset.criticality if enriched.asset else None,
                asset_role=enriched.asset.role if enriched.asset else None,
                asset_owner=enriched.asset.owner if enriched.asset else None,
                user_privileged=enriched.user_ctx.privileged if enriched.user_ctx else False,
                features=enriched.features,
                label=enriched.label,
                raw=enriched.raw or raw_line,
                repeat_count=enriched.repeat_count,
                raw_hash=raw_hash,
            )
            db.add(event_orm)
            db.commit()

            bus = get_event_bus()
            msg = StreamMessage(
                topic="events",
                event_type="event_ingested",
                payload={"event": enriched.model_dump(), "source": "tailer"},
            )
            await bus.publish("events", msg)
            self.events_read += 1
            return {"status": "accepted", "event_id": enriched.event_id}

        except Exception as exc:
            db.rollback()
            logger.error("Error in tailer line ingestion: %s", exc)
            return {"status": "error", "reason": str(exc)}
        finally:
            db.close()

    async def _tail_file(self, target: dict[str, Any]) -> None:
        """Coroutine tailing a single target file."""
        file_path = Path(target.get("path", ""))
        source_type = target.get("source_type", "linux_auth")
        host = target.get("host", "localhost")

        while self.is_running:
            if not file_path.exists():
                await asyncio.sleep(self.poll_interval)
                continue

            str_path = str(file_path.resolve())
            current_offset = self.offsets.get(str_path, 0)
            file_size = file_path.stat().st_size

            # Handle log truncation or rotation
            if file_size < current_offset:
                logger.info("File truncation detected on %s. Resetting offset to 0.", str_path)
                current_offset = 0

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(current_offset)
                    lines = f.readlines()
                    new_offset = f.tell()

                for line in lines:
                    if not self.is_running:
                        break
                    await self.ingest_line(line, source_type=source_type, host=host)

                if new_offset != current_offset:
                    self.offsets[str_path] = new_offset
                    self._save_offsets()

            except Exception as exc:
                logger.error("Error reading file %s: %s", str_path, exc)

            await asyncio.sleep(self.poll_interval)

    def start(self) -> None:
        """Start async tailing workers."""
        if self.is_running:
            return
        self.is_running = True
        for target in self.targets:
            task = asyncio.create_task(self._tail_file(target))
            self._tail_tasks.append(task)
        logger.info("AsyncFileTailer started with %d targets.", len(self.targets))

    def stop(self) -> None:
        """Stop tailing workers and persist offsets."""
        self.is_running = False
        for task in self._tail_tasks:
            task.cancel()
        self._tail_tasks.clear()
        self._save_offsets()
        logger.info("AsyncFileTailer stopped.")

    def get_stats(self) -> dict[str, Any]:
        """Return tailer statistics."""
        return {
            "is_running": self.is_running,
            "target_count": len(self.targets),
            "events_read": self.events_read,
            "offsets": self.offsets,
        }
