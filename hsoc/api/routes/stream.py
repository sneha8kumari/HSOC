"""
Real-time streaming REST and SSE router for H-SOC.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hsoc.simulate.stream_engine import engine
from hsoc.streaming.bus import get_event_bus
from hsoc.streaming.stream_pipeline import get_pipeline_manager

logger = logging.getLogger(__name__)
router = APIRouter()


class SpeedRequest(BaseModel):
    speed: int


class InjectRequest(BaseModel):
    scenario_id: str | None = None


@router.get("/status", tags=["stream"])
def get_stream_status() -> dict[str, Any]:
    """Return real-time stream engine and pipeline status."""
    bus = get_event_bus()
    engine_status = engine.get_status()
    engine_status["bus_metrics"] = bus.get_metrics()
    return engine_status


@router.post("/start", tags=["stream"])
async def start_stream() -> dict[str, Any]:
    """Start or resume real-time data streaming."""
    engine.set_running(True)
    engine.start_background_task()
    return {"status": "started", "engine": engine.get_status()}


@router.post("/pause", tags=["stream"])
async def pause_stream() -> dict[str, Any]:
    """Pause real-time data streaming."""
    engine.set_running(False)
    return {"status": "paused", "engine": engine.get_status()}


@router.post("/speed", tags=["stream"])
async def set_stream_speed(req: SpeedRequest) -> dict[str, Any]:
    """Adjust real-time stream playback speed multiplier (1x, 5x, 10x)."""
    engine.set_speed(req.speed)
    return {"status": "speed_updated", "speed": engine.speed}


@router.post("/inject", tags=["stream"])
async def inject_attack_event(req: InjectRequest) -> dict[str, Any]:
    """Manually trigger immediate injection of an attack scenario stage."""
    res = await engine.inject_step(req.scenario_id)
    return {"status": "injected", "engine": res}


async def _unified_stream_generator() -> AsyncGenerator[str, None]:
    """
    Multiplexes real-time telemetry from EventBus with simulation events,
    emitting standards-compliant SSE chunks with 15s heartbeats.
    """
    bus = get_event_bus()
    sim_subscriber = engine.subscribe()
    last_heartbeat = time.time()

    # Initial connection notice
    init_payload = {
        "event_type": "stream_connected",
        "timestamp": time.time(),
        "status": "LIVE",
    }
    yield f"event: connect\ndata: {json.dumps(init_payload)}\n\n"

    while True:
        try:
            # 1. Drain any pending real events from bus
            real_msg = await bus.consume("events", timeout=0.1)
            if real_msg:
                out = {
                    "event_type": real_msg.event_type,
                    "payload": real_msg.payload,
                    "is_simulated": bool(real_msg.payload.get("is_simulated", False)),
                    "timestamp": time.time(),
                }
                yield f"event: event_ingested\ndata: {json.dumps(out)}\n\n"

            # 2. Drain any pending real alerts from bus
            alert_msg = await bus.consume("alerts", timeout=0.05)
            if alert_msg:
                out = {
                    "event_type": alert_msg.event_type,
                    "payload": alert_msg.payload,
                    "is_simulated": bool(alert_msg.payload.get("is_simulated", False)),
                    "timestamp": time.time(),
                }
                yield f"event: alert_created\ndata: {json.dumps(out)}\n\n"

            # 3. Drain any pending real incidents from bus
            inc_msg = await bus.consume("incidents", timeout=0.05)
            if inc_msg:
                out = {
                    "event_type": inc_msg.event_type,
                    "payload": inc_msg.payload,
                    "is_simulated": bool(inc_msg.payload.get("is_simulated", False)),
                    "timestamp": time.time(),
                }
                yield f"event: incident_updated\ndata: {json.dumps(out)}\n\n"

            # 4. Check simulation engine if running
            if engine.is_running:
                try:
                    sim_chunk = await asyncio.wait_for(sim_subscriber.__anext__(), timeout=0.2)
                    if sim_chunk:
                        yield sim_chunk
                except (asyncio.TimeoutError, StopAsyncIteration):
                    pass

            # 5. Heartbeat every 15 seconds
            now = time.time()
            if now - last_heartbeat > 15.0:
                yield ": heartbeat\n\n"
                last_heartbeat = now

            await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.debug("Error in unified live SSE stream: %s", exc)
            yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"
            await asyncio.sleep(1.0)


@router.get("/live", tags=["stream"])
async def live_event_stream() -> StreamingResponse:
    """
    Server-Sent Events (SSE) streaming live Windows/Wazuh events, detection alerts,
    and correlated incident updates directly to the dashboard.
    """
    pipeline_mgr = get_pipeline_manager()
    pipeline_mgr.start()

    return StreamingResponse(
        _unified_stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
