"""
Windows Telemetry Ingestion & Health Router for H-SOC.

Endpoints:
  GET  /api/v1/telemetry/windows/status   Health, buffer depth, and event counters
  POST /api/v1/telemetry/windows/collect  Trigger an immediate local Windows log/network collection
  POST /api/v1/telemetry/windows/ingest   Ingest Windows security/system/network logs
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from hsoc.config import get_settings
from hsoc.db import EventORM, QuarantineORM, SessionLocal
from hsoc.ingest.collector import compute_raw_hash
from hsoc.ingest.dedup import get_deduplicator
from hsoc.ingest.enrich import enrich
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.parsers.win_security import parse as parse_win_security
from hsoc.ingest.windows_collector import get_windows_collector
from hsoc.schema import Event, QuarantineRecord, SourceType
from hsoc.streaming.bus import StreamMessage, get_event_bus

logger = logging.getLogger(__name__)

router = APIRouter()


class WindowsCollectRequest(BaseModel):
    max_events: int = Field(default=20, ge=1, le=200)
    include_network: bool = Field(default=True)


@router.get("/status", tags=["windows_telemetry"])
def get_windows_status() -> dict[str, Any]:
    """Return health, buffer status, and event counters for Windows telemetry."""
    collector = get_windows_collector()
    return collector.get_status()


@router.post("/collect", tags=["windows_telemetry"])
async def trigger_local_windows_collection(
    req: WindowsCollectRequest = WindowsCollectRequest(),
) -> dict[str, Any]:
    """
    Execute an on-demand snapshot of the host Windows laptop telemetry.
    Collects real Windows Event Logs and active TCP network connection metadata,
    normalizes them into the shared schema, and injects them into the live pipeline.
    """
    collector = get_windows_collector()
    log_records = collector.collect_event_logs(max_records=req.max_events)
    net_records = []
    if req.include_network:
        net_records = collector.collect_network_connections(max_connections=req.max_events)

    all_raw = log_records + net_records
    if not all_raw:
        return {
            "status": "idle",
            "message": "No new Windows events or external network connections detected during snapshot window.",
            "collected": 0,
            "accepted": 0,
        }

    dedup = get_deduplicator()
    bus = get_event_bus()
    db = SessionLocal()

    accepted = 0
    duplicates = 0
    quarantined = 0

    try:
        for item in all_raw:
            raw_str = item.get("raw") or json.dumps(item)
            raw_hash = compute_raw_hash(raw_str)

            if dedup.is_duplicate(raw_hash):
                duplicates += 1
                continue

            try:
                parsed = parse_win_security(raw_str)
                mapped = map_to_event(parsed, parser="win_security")
            except Exception as exc:
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type="win_security",
                    raw=raw_str,
                    reason=f"Windows parse error: {str(exc)}",
                    parser="windows_collector",
                )
                db.add(q_orm)
                continue

            if isinstance(mapped, QuarantineRecord):
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=mapped.record_id,
                    ts=mapped.ts or datetime.now(timezone.utc),
                    source_type=mapped.source_type,
                    raw=mapped.raw,
                    reason=mapped.reason,
                    parser="windows_collector",
                )
                db.add(q_orm)
                continue

            enriched = enrich(mapped)
            # Mark strictly as live telemetry (NOT simulated)
            enriched.is_simulated = False

            src_type_str = enriched.source_type.value if hasattr(enriched.source_type, "value") else str(enriched.source_type)
            event_orm = EventORM(
                event_id=enriched.event_id,
                ts=enriched.ts,
                source_type=src_type_str,
                host=enriched.host or collector.hostname,
                src_ip=enriched.src_ip,
                dst_ip=enriched.dst_ip,
                dst_port=enriched.dst_port,
                user=enriched.user,
                action=enriched.action,
                outcome=enriched.outcome.value if hasattr(enriched.outcome, "value") else str(enriched.outcome),
                asset_criticality=enriched.asset.criticality if enriched.asset else 1,
                asset_role=enriched.asset.role if enriched.asset else "workstation",
                asset_owner=enriched.asset.owner if enriched.asset else "analyst",
                user_privileged=enriched.user_ctx.privileged if enriched.user_ctx else False,
                features=enriched.features,
                label=enriched.label,
                raw=enriched.raw or raw_str,
                repeat_count=enriched.repeat_count,
                raw_hash=raw_hash,
                is_simulated=False,
            )
            db.add(event_orm)
            accepted += 1

            # Broadcast live event to EventBus
            msg = StreamMessage(
                topic="events",
                event_type="event_ingested",
                payload={"event": enriched.model_dump(mode="json"), "source": "windows_host", "is_simulated": False},
            )
            await bus.publish("events", msg)

        db.commit()
        collector.total_forwarded += accepted
        return {
            "status": "success",
            "host": collector.hostname,
            "collected": len(all_raw),
            "events_logged": len(log_records),
            "network_connections": len(net_records),
            "accepted": accepted,
            "duplicates": duplicates,
            "quarantined": quarantined,
        }
    except Exception as exc:
        db.rollback()
        logger.error("Error in Windows local telemetry collection: %s", exc)
        raise HTTPException(status_code=500, detail=f"Collection failure: {str(exc)}")
    finally:
        db.close()


@router.post("/ingest", tags=["windows_telemetry"])
async def ingest_windows_telemetry(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
) -> dict[str, Any]:
    """
    Ingest remote Windows events pushed by the PowerShell agent or Winlogbeat.
    """
    body_bytes = await request.body()
    if len(body_bytes) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Windows telemetry payload exceeds 2 MB limit.",
        )

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(exc)}")

    items = data if isinstance(data, list) else [data]
    dedup = get_deduplicator()
    bus = get_event_bus()
    db = SessionLocal()

    accepted = 0
    duplicates = 0
    quarantined = 0

    try:
        for item in items:
            raw_str = item.get("raw") or json.dumps(item)
            raw_hash = compute_raw_hash(raw_str)

            if dedup.is_duplicate(raw_hash):
                duplicates += 1
                continue

            try:
                parsed = parse_win_security(raw_str)
                mapped = map_to_event(parsed, parser="win_security")
            except Exception as exc:
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type="win_security",
                    raw=raw_str,
                    reason=f"Windows parse error: {str(exc)}",
                    parser="windows_agent",
                )
                db.add(q_orm)
                continue

            if isinstance(mapped, QuarantineRecord):
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=mapped.record_id,
                    ts=mapped.ts or datetime.now(timezone.utc),
                    source_type=mapped.source_type,
                    raw=mapped.raw,
                    reason=mapped.reason,
                    parser="windows_agent",
                )
                db.add(q_orm)
                continue

            enriched = enrich(mapped)
            enriched.is_simulated = False

            src_type_str = enriched.source_type.value if hasattr(enriched.source_type, "value") else str(enriched.source_type)
            event_orm = EventORM(
                event_id=enriched.event_id,
                ts=enriched.ts,
                source_type=src_type_str,
                host=enriched.host,
                src_ip=enriched.src_ip,
                dst_ip=enriched.dst_ip,
                dst_port=enriched.dst_port,
                user=enriched.user,
                action=enriched.action,
                outcome=enriched.outcome.value if hasattr(enriched.outcome, "value") else str(enriched.outcome),
                asset_criticality=enriched.asset.criticality if enriched.asset else 1,
                asset_role=enriched.asset.role if enriched.asset else "workstation",
                asset_owner=enriched.asset.owner if enriched.asset else "analyst",
                user_privileged=enriched.user_ctx.privileged if enriched.user_ctx else False,
                features=enriched.features,
                label=enriched.label,
                raw=enriched.raw or raw_str,
                repeat_count=enriched.repeat_count,
                raw_hash=raw_hash,
                is_simulated=False,
            )
            db.add(event_orm)
            accepted += 1

            # Publish to EventBus
            msg = StreamMessage(
                topic="events",
                event_type="event_ingested",
                payload={"event": enriched.model_dump(mode="json"), "source": "windows_agent", "is_simulated": False},
            )
            await bus.publish("events", msg)

        db.commit()
        return {
            "status": "success",
            "received": len(items),
            "accepted": accepted,
            "duplicates": duplicates,
            "quarantined": quarantined,
        }
    except Exception as exc:
        db.rollback()
        logger.error("Error in Windows agent telemetry ingestion: %s", exc)
        raise HTTPException(status_code=500, detail=f"Ingestion error: {str(exc)}")
    finally:
        db.close()
