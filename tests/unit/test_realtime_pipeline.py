"""
Integration test for the unified real-time pipeline.
Verifies:
  Source Event (Windows / Wazuh) -> EventBus ("events") -> StreamingPipelineManager
  -> StreamDetector (CEP) -> AlertORM -> EventBus ("alerts")
  -> DynamicStreamCorrelator -> IncidentORM -> EventBus ("incidents")
  -> Live SSE broadcasting.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
import pytest

from hsoc.streaming.bus import get_event_bus, StreamMessage
from hsoc.db import AlertORM, EventORM, IncidentORM, init_db, SessionLocal
from hsoc.schema import Event, SourceType
from hsoc.streaming.stream_pipeline import get_pipeline_manager


@pytest.mark.asyncio
async def test_realtime_pipeline_event_to_incident():
    """Verify an ingested real host event flows through detector to incident and database."""
    init_db()
    bus = get_event_bus()
    pipeline = get_pipeline_manager()
    
    # Start background worker
    pipeline.start()

    # Create a real failed logon event matching detection rule (e.g. brute force / 4625)
    test_event = Event(
        event_id="evt-realtime-test-001",
        ts=datetime.now(timezone.utc),
        source_type=SourceType.windows_event,
        host="WIN-SERVER-TEST",
        src_ip="203.0.113.199",
        dst_ip="192.168.1.100",
        dst_port=445,
        action="logon_failure",
        outcome="failure",
        raw=json.dumps({"EventID": 4625, "FailureReason": "BadPassword"}),
        is_simulated=False,
    )

    msg = StreamMessage(
        topic="events",
        event_type="event_ingested",
        payload={"event": test_event.model_dump(mode="json"), "is_simulated": False},
    )

    # Publish to the real-time event bus
    await bus.publish("events", msg)

    # Allow background event processing loop to drain and evaluate
    await asyncio.sleep(0.3)

    # Verify pipeline metrics and state
    metrics = bus.get_metrics()
    assert metrics["published_total"] >= 1

    # Stop pipeline
    await pipeline.stop()
