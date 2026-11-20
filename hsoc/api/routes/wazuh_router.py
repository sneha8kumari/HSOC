"""
Wazuh Ingestion & Health Status API Router for H-SOC.

Endpoints:
  GET  /api/v1/telemetry/wazuh/status   Check Wazuh connection and polling health
  POST /api/v1/telemetry/wazuh/test     Test live connection to Wazuh Manager
  POST /api/v1/telemetry/wazuh/poll     Trigger manual poll of Wazuh alerts
  POST /api/v1/telemetry/wazuh/webhook  Webhook ingestion for Wazuh alert payloads
"""

from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
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
from hsoc.ingest.parsers.wazuh_json import parse as parse_wazuh_json
from hsoc.ingest.wazuh_client import get_wazuh_client
from hsoc.schema import Event, QuarantineRecord, SourceType
from hsoc.streaming.bus import StreamMessage, get_event_bus

logger = logging.getLogger(__name__)

router = APIRouter()


class WazuhPollRequest(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    time_window: str = Field(default="15m")
    min_level: int = Field(default=3, ge=1, le=15)


@router.get("/status", tags=["wazuh"])
def get_wazuh_status() -> dict[str, Any]:
    """Return health, configuration, and connectivity status for Wazuh."""
    client = get_wazuh_client()
    health = client.test_connection()
    return {
        "status": health.get("status", "DISCONNECTED"),
        "connected": health.get("connected", False),
        "configured": health.get("configured", False),
        "base_url": client.base_url if client._is_configured() else None,
        "verify_ssl": client.verify_ssl,
        "last_sync_time": client.last_sync_time.isoformat() if client.last_sync_time else None,
        "last_error": client.last_poll_error,
        "total_polled_alerts": client.total_polled_alerts,
        "message": health.get("message", ""),
    }


@router.post("/test", tags=["wazuh"])
def test_wazuh_connection() -> dict[str, Any]:
    """Actively test connection and authentication against the configured Wazuh manager."""
    client = get_wazuh_client()
    return client.test_connection()


@router.post("/poll", tags=["wazuh"])
async def trigger_wazuh_poll(req: WazuhPollRequest = WazuhPollRequest()) -> dict[str, Any]:
    """Manually trigger alert polling from Wazuh API and ingest into pipeline."""
    client = get_wazuh_client()
    if not client._is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Wazuh is not configured. Set WAZUH_URL, WAZUH_USER, and WAZUH_PASSWORD in environment.",
        )

    try:
        events = client.poll_and_normalize(limit=req.limit)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed communicating with Wazuh API: {str(exc)}",
        )

    dedup = get_deduplicator()
    bus = get_event_bus()
    db = SessionLocal()

    accepted = 0
    duplicates = 0

    try:
        for ev in events:
            raw_hash = compute_raw_hash(ev.raw or ev.event_id)
            if dedup.is_duplicate(raw_hash):
                duplicates += 1
                continue

            event_orm = EventORM(
                event_id=ev.event_id,
                ts=ev.ts,
                source_type=ev.source_type.value,
                host=ev.host,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                dst_port=ev.dst_port,
                user=ev.user,
                action=ev.action,
                outcome=ev.outcome.value,
                asset_criticality=ev.asset.criticality,
                asset_role=ev.asset.role,
                asset_owner=ev.asset.owner,
                user_privileged=ev.user_ctx.privileged,
                features=ev.features,
                label=ev.label,
                raw=ev.raw,
                repeat_count=ev.repeat_count,
                raw_hash=raw_hash,
                is_simulated=False,
            )
            db.add(event_orm)
            accepted += 1

            # Publish live event to bus
            msg = StreamMessage(
                topic="events",
                event_type="event_ingested",
                payload={"event": ev.model_dump(mode="json"), "source": "wazuh_api", "is_simulated": False},
            )
            await bus.publish("events", msg)

        db.commit()
        return {
            "status": "success",
            "polled": len(events),
            "accepted": accepted,
            "duplicates": duplicates,
        }
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database persistence failure: {str(exc)}")
    finally:
        db.close()


@router.post("/webhook", tags=["wazuh"])
async def wazuh_webhook(
    request: Request,
    x_wazuh_secret: str | None = Header(None, alias="X-Wazuh-Secret"),
    authorization: str | None = Header(None, alias="Authorization"),
) -> dict[str, Any]:
    """
    Webhook receiver for Wazuh alert forwarding.
    Validates token if WAZUH_WEBHOOK_SECRET is configured.
    Normalizes alerts, deduplicates, persists, and publishes to EventBus.
    """
    expected_secret = os.getenv("WAZUH_WEBHOOK_SECRET", "")
    if expected_secret:
        token = x_wazuh_secret
        if not token and authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
        if not token or not hmac.compare_digest(token, expected_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Wazuh webhook secret token.",
            )

    # Size limit guard (2MB max)
    body_bytes = await request.body()
    if len(body_bytes) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Wazuh webhook payload exceeds 2 MB limit.",
        )

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(exc)}")

    items = data if isinstance(data, list) else [data]
    dedup = get_deduplicator()
    bus = get_event_bus()
    db = SessionLocal()

    accepted = 0
    duplicates = 0
    quarantined = 0

    try:
        for idx, item in enumerate(items):
            line_str = json.dumps(item) if isinstance(item, dict) else str(item).strip()
            raw_hash = compute_raw_hash(line_str)

            if dedup.is_duplicate(raw_hash):
                duplicates += 1
                continue

            try:
                parsed = parse_wazuh_json(line_str)
                mapped = map_to_event(parsed, parser="wazuh_json")
            except Exception as exc:
                quarantined += 1
                q_orm = QuarantineORM(
                    record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                    ts=datetime.now(timezone.utc),
                    source_type="wazuh",
                    raw=line_str,
                    reason=f"Wazuh webhook parse exception: {str(exc)}",
                    parser="wazuh_webhook",
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
                    parser="wazuh_webhook",
                )
                db.add(q_orm)
                continue

            enriched = enrich(mapped)
            enriched.is_simulated = False

            event_orm = EventORM(
                event_id=enriched.event_id,
                ts=enriched.ts,
                source_type="wazuh",
                host=enriched.host,
                src_ip=enriched.src_ip,
                dst_ip=enriched.dst_ip,
                dst_port=enriched.dst_port,
                user=enriched.user,
                action=enriched.action,
                outcome=enriched.outcome.value if hasattr(enriched.outcome, "value") else str(enriched.outcome),
                asset_criticality=enriched.asset.criticality if enriched.asset else 1,
                asset_role=enriched.asset.role if enriched.asset else "unknown",
                asset_owner=enriched.asset.owner if enriched.asset else "unknown",
                user_privileged=enriched.user_ctx.privileged if enriched.user_ctx else False,
                features=enriched.features,
                label=enriched.label,
                raw=enriched.raw or line_str,
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
                payload={"event": enriched.model_dump(mode="json"), "source": "wazuh_webhook", "is_simulated": False},
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
        logger.error("Error processing Wazuh webhook: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Webhook ingestion error: {str(exc)}")
    finally:
        db.close()
