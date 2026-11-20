"""
FastAPI application factory.

Endpoints (implemented in M6):
  POST /events          Ingest a single event
  POST /events/batch    Ingest a batch of events
  GET  /alerts          List alerts (filters: severity, domain, status)
  GET  /incidents       List incidents (filters: severity, domain, status)
  GET  /incidents/{id}  Get a single incident with full detail
  POST /incidents/{id}/analyze  Trigger GenAI report generation
  POST /knowledge/search  Search the knowledge index
  POST /feedback        Submit analyst feedback
  GET  /metrics         Pipeline and model performance metrics
  GET  /health          Health check

Auth: Bearer token when API_TOKEN is set in .env.
CORS: Allowed for the dashboard origin.
Docs: OpenAPI at /docs, ReDoc at /redoc.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hsoc.db import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize database and real-time streaming pipeline."""
    init_db()
    from hsoc.streaming.stream_pipeline import get_pipeline_manager
    pipeline_mgr = get_pipeline_manager()
    pipeline_mgr.start()
    logger.info("H-SOC API started. DB initialised and Real-Time Pipeline launched.")
    yield
    await pipeline_mgr.stop()
    logger.info("H-SOC API stopped. Real-Time Pipeline shut down cleanly.")


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application."""
    application = FastAPI(
        title="H-SOC API",
        description="Hybrid Security Operations Center — REST API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS — allow the dashboard dev server
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health endpoint — always registered so the app is immediately runnable
    @application.get("/health", tags=["meta"])
    async def health() -> dict[str, Any]:
        """Return API health status."""
        from hsoc.streaming.bus import get_event_bus
        return {
            "status": "ok",
            "version": "0.1.0",
            "bus": get_event_bus().get_metrics(),
        }

    # Register routers
    from hsoc.api.routes import (
        copilot,
        feedback,
        incidents,
        ingest,
        knowledge,
        models,
        soar,
        stream,
        wazuh_router,
        windows_router,
    )
    application.include_router(feedback.router, prefix="/feedback", tags=["feedback"])
    application.include_router(incidents.router, prefix="/incidents", tags=["incidents", "traces"])
    application.include_router(copilot.router, prefix="/incidents", tags=["copilot"])
    application.include_router(knowledge.router, prefix="/knowledge", tags=["knowledge"])
    application.include_router(models.router, prefix="/models/markov", tags=["models"])
    application.include_router(stream.router, prefix="/stream", tags=["stream"])
    application.include_router(ingest.router, prefix="/api/v1/telemetry", tags=["telemetry_ingest"])
    application.include_router(wazuh_router.router, prefix="/api/v1/telemetry/wazuh", tags=["wazuh"])
    application.include_router(windows_router.router, prefix="/api/v1/telemetry/windows", tags=["windows_telemetry"])
    application.include_router(soar.router, prefix="/api/v1/soar", tags=["soar"])
    application.include_router(soar.router, prefix="/soar", tags=["soar"])

    @application.get("/api/v1/telemetry/health", tags=["telemetry_health"])
    async def telemetry_health() -> dict[str, Any]:
        """Consolidated health report across all telemetry collectors and event bus."""
        from hsoc.ingest.wazuh_client import get_wazuh_client
        from hsoc.ingest.windows_collector import get_windows_collector
        from hsoc.streaming.bus import get_event_bus
        from hsoc.ingest.dedup import get_deduplicator

        wazuh_health = get_wazuh_client().test_connection()
        win_status = get_windows_collector().get_status()
        bus_metrics = get_event_bus().get_metrics()
        dedup_stats = get_deduplicator().get_stats()

        provider_name = os.getenv("LLM_PROVIDER", "ollama")
        ai_health: dict[str, Any] = {"provider": provider_name, "status": "READY"}
        if provider_name == "ollama":
            from hsoc.genai.providers.ollama import OllamaProvider
            ai_health = OllamaProvider().check_health()
        elif provider_name == "hosted":
            has_key = bool(os.getenv("HOSTED_LLM_API_KEY"))
            ai_health = {
                "provider": "hosted",
                "status": "CONFIGURED" if has_key else "NO_API_KEY",
                "model": os.getenv("HOSTED_LLM_MODEL", "gpt-4o-mini"),
            }

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "wazuh": wazuh_health,
            "windows": win_status,
            "event_bus": bus_metrics,
            "deduplicator": dedup_stats,
            "ai_provider": ai_health,
        }

    @application.get("/models/markov/status", tags=["models"])
    async def markov_status() -> dict[str, Any]:
        """Return active Markov model version, KL divergence, and drift notice."""
        predictor = feedback.get_active_predictor()
        registry = feedback.get_model_registry()
        is_drifted, kl_val, notice = predictor.check_drift()
        return {
            "current_version": registry.get_current_version(),
            "kl_divergence": kl_val,
            "model_drift_detected": is_drifted,
            "notice": notice,
        }

    # Mount compiled dashboard UI if dist directory exists
    dist_dir = Path(__file__).parent.parent.parent / "dashboard" / "dist"
    if dist_dir.exists():
        from fastapi.staticfiles import StaticFiles
        application.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="static_dashboard")

    return application


app = create_app()
