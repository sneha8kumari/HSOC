from __future__ import annotations
import uuid
"""
REST Webhook Ingestion Router for H-SOC Live Telemetry.

Accepts single events or micro-batches:
  POST /api/v1/telemetry/ingest
  GET  /api/v1/telemetry/stats

Enforces API-key auth, payload boundaries, LRU deduplication,
quarantine on malformed input, and Event Bus publication.
"""

from datetime import datetime, timezone

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

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

router = APIRouter()


class TelemetryItem(BaseModel):
    """Single telemetry payload entry."""
    source_type: str = "linux_auth"
    raw: str = Field(..., description="Raw log line or JSON string")
    host: str | None = None
    extra: dict[str, Any] | None = None


class IngestBatchRequest(BaseModel):
    """Batch of telemetry items."""
    events: list[TelemetryItem]


@router.post("/ingest", tags=["telemetry_ingest"])
async def ingest_telemetry(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
) -> dict[str, Any]:
    """
    Ingest a single telemetry event or micro-batch.
    Returns per-record accepted, duplicate, and quarantined status.
    """
    cfg = get_settings().streaming.get("webhook", {})
    
    # 1. API Key Auth Check if configured
    if cfg.get("api_key_required", False):
        configured_key = cfg.get("api_key", "")
        token = x_api_key
        if not token and authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
        if not token or token != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key for telemetry ingestion.",
            )

    # 2. Payload size guard
    max_bytes = int(cfg.get("max_payload_bytes", 1048576))  # 1 MB default
    body_bytes = await request.body()
    if len(body_bytes) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds limit of {max_bytes} bytes.",
        )

    # 3. Parse JSON body flexibly (single object, list of objects, or wrapped in 'events')
    try:
        data = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {str(exc)}")

    raw_items: list[dict[str, Any]] = []
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        if "events" in data and isinstance(data["events"], list):
            raw_items = data["events"]
        else:
            raw_items = [data]
    else:
        raise HTTPException(status_code=400, detail="Expected JSON object or array of objects.")

    max_batch = int(cfg.get("max_batch_size", 500))
    if len(raw_items) > max_batch:
        raise HTTPException(
            status_code=400,
            detail=f"Batch size {len(raw_items)} exceeds configured limit {max_batch}.",
        )

    dedup = get_deduplicator()
    bus = get_event_bus()

    accepted = 0
    duplicates = 0
    quarantined = 0
    details: list[dict[str, Any]] = []

    db = SessionLocal()
    try:
        for idx, item in enumerate(raw_items):
            # Extract fields
            if isinstance(item, str):
                raw_line = item.strip()
                source_type = "linux_auth"
                host_val = None
            elif isinstance(item, dict):
                raw_line = str(item.get("raw") or item).strip()
                source_type = str(item.get("source_type", "linux_auth"))
                host_val = item.get("host")
            else:
                quarantined += 1
                details.append({"index": idx, "status": "quarantined", "reason": "Non-object entry"})
                continue

            if not raw_line:
                details.append({"index": idx, "status": "ignored", "reason": "Empty payload"})
                continue

            raw_hash = compute_raw_hash(raw_line)
            if dedup.is_duplicate(raw_hash):
                duplicates += 1
                details.append({"index": idx, "status": "duplicate", "raw_hash": raw_hash})
                continue

            parser_fn = PARSER_REGISTRY.get(source_type)
            if not parser_fn:
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type=source_type,
                    raw=raw_line,
                    reason=f"No parser registered for source_type '{source_type}'",
                    parser="webhook",
                )
                db.add(q_orm)
                db.commit()
                details.append({"index": idx, "status": "quarantined", "reason": q_orm.reason})
                continue

            try:
                parsed_dict = parser_fn(raw_line)
                if host_val and not parsed_dict.get("host"):
                    parsed_dict["host"] = host_val
                mapped = map_to_event(parsed_dict, source_type)
            except Exception as exc:
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type=source_type,
                    raw=raw_line,
                    reason=f"Parser exception: {str(exc)}",
                    parser=source_type,
                )
                db.add(q_orm)
                db.commit()
                details.append({"index": idx, "status": "quarantined", "reason": q_orm.reason})
                continue

            if isinstance(mapped, QuarantineRecord):
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=mapped.record_id,
                    ts=mapped.ts or datetime.now(timezone.utc),
                    source_type=mapped.source_type,
                    raw=mapped.raw,
                    reason=mapped.reason,
                    parser=mapped.parser,
                )
                db.add(q_orm)
                db.commit()
                details.append({"index": idx, "status": "quarantined", "reason": mapped.reason})
                continue

            # Valid Event: Enrich and persist
            enriched = enrich(mapped)
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

            # Publish to Event Bus
            msg = StreamMessage(
                topic="events",
                event_type="event_ingested",
                payload={"event": enriched.model_dump(), "source": "webhook"},
            )
            await bus.publish("events", msg)

            accepted += 1
            details.append({"index": idx, "status": "accepted", "event_id": enriched.event_id, "raw_hash": raw_hash})

        return {
            "status": "success",
            "received": len(raw_items),
            "accepted": accepted,
            "duplicates": duplicates,
            "quarantined": quarantined,
            "details": details,
        }

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.error("Error in webhook telemetry ingestion: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ingestion failure: {str(exc)}")
    finally:
        db.close()


@router.get("/stats", tags=["telemetry_ingest"])
def get_ingest_stats() -> dict[str, Any]:
    """Return live ingestion statistics, LRU deduplication stats, and Event Bus queue depths."""
    dedup = get_deduplicator()
    bus = get_event_bus()
    return {
        "deduplicator": dedup.get_stats(),
        "bus": bus.get_metrics(),
    }
