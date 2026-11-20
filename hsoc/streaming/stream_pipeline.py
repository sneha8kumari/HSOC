"""
Unified Streaming Event & Dynamic Correlation Pipeline for H-SOC.

Connects:
  Event Ingestion (Windows, Wazuh, Syslog, Webhook)
    │
    ▼
  EventBus ("events") ───────────► SSE Broadcaster (/stream/live)
    │
    ▼
  StreamDetector (Rules R-01..R-10 + ML Anomaly)
    │
    ▼
  EventBus ("alerts") ───────────► SSE Broadcaster (/stream/live)
    │
    ▼
  Dynamic Real-Time Correlator
    │
    ▼
  IncidentORM Update & Persistence
    │
    ▼
  EventBus ("incidents") ────────► SSE Broadcaster (/stream/live)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any
import uuid

from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import AlertORM, EventORM, IncidentORM, SessionLocal
from hsoc.detect.stream_detector import get_stream_detector
from hsoc.investigate.chain import build_chain
from hsoc.investigate.domain import classify_domain
from hsoc.investigate.predictor import MarkovPredictor
from hsoc.investigate.severity import compute_severity
from hsoc.schema import Alert, Domain, Event, Incident, IncidentStatus, Severity
from hsoc.streaming.bus import EventBus, StreamMessage, get_event_bus

logger = logging.getLogger(__name__)


class DynamicStreamCorrelator:
    """
    Incremental real-time correlator.
    Associates incoming streaming alerts with open incidents using entity tokens
    and time window proximity, without waiting for batch runs.
    """

    def __init__(self) -> None:
        self.predictor = MarkovPredictor()

    def process_alert(self, alert: Alert, is_simulated: bool = False) -> Incident:
        """
        Associate an alert with an active incident or create a new incident.
        Updates incident timeline, tactics, risk score, and Markov predictions.
        """
        settings = get_settings()
        window_min = int(settings.correlation.get("window_minutes", 30))
        ignore_entities = set(settings.correlation.get("ignore_entities", ["127.0.0.1", "::1"]))
        cutoff_time = alert.ts - timedelta(minutes=window_min)

        # Build candidate pivot keys
        alert_keys = set()
        if alert.src_ip and alert.src_ip not in ignore_entities:
            alert_keys.add(f"ip:{alert.src_ip}")
        if alert.user and alert.user not in ignore_entities:
            alert_keys.add(f"user:{alert.user}")
        if alert.dst_host and alert.dst_host not in ignore_entities:
            alert_keys.add(f"host:{alert.dst_host}")

        db: Session = SessionLocal()
        try:
            # Query recent open incidents
            recent_incidents = (
                db.query(IncidentORM)
                .filter(IncidentORM.status != "closed")
                .filter(IncidentORM.updated_at >= cutoff_time)
                .order_by(IncidentORM.updated_at.desc())
                .all()
            )

            matched_orm: IncidentORM | None = None
            for inc in recent_incidents:
                inc_keys = set(inc.entity_keys or [])
                if alert_keys.intersection(inc_keys):
                    matched_orm = inc
                    break

            if matched_orm:
                # Update existing incident
                existing_alerts: list[Alert] = []
                if matched_orm.alert_ids:
                    orm_alerts = db.query(AlertORM).filter(AlertORM.alert_id.in_(matched_orm.alert_ids)).all()
                    for oa in orm_alerts:
                        existing_alerts.append(
                            Alert(
                                alert_id=oa.alert_id,
                                ts=oa.ts,
                                rule_ids=oa.rule_ids or [],
                                model_id=oa.model_id,
                                ml_score=oa.ml_score,
                                conf=oa.conf,
                                technique=oa.technique,
                                tactic=oa.tactic,
                                domain=Domain(oa.domain) if oa.domain in Domain.__members__ else Domain.unknown,
                                src_ip=oa.src_ip,
                                dst_host=oa.dst_host,
                                user=oa.user,
                                evidence_event_ids=oa.evidence_event_ids or [],
                                description=oa.description or "",
                            )
                        )
                existing_alerts.append(alert)

                combined_keys = list(set((matched_orm.entity_keys or []) + list(alert_keys)))
                inc_obj = Incident(
                    incident_id=matched_orm.incident_id,
                    created_at=matched_orm.created_at,
                    updated_at=alert.ts,
                    status=IncidentStatus(matched_orm.status) if matched_orm.status in IncidentStatus.__members__ else IncidentStatus.open,
                    alert_ids=[a.alert_id for a in existing_alerts],
                    entity_keys=combined_keys,
                    is_simulated=is_simulated,
                )

                # Re-enrich chain, domain, severity, and Markov predictions
                inc_obj = build_chain(inc_obj, existing_alerts)
                inc_obj = classify_domain(inc_obj, existing_alerts)
                inc_obj = compute_severity(inc_obj, existing_alerts)

                last_tactic = inc_obj.tactics[-1] if inc_obj.tactics else "reconnaissance"
                inc_obj.predicted_next = self.predictor.predict(last_tactic, top_n=3)

                # Update ORM record
                matched_orm.updated_at = alert.ts
                matched_orm.alert_ids = inc_obj.alert_ids
                matched_orm.entity_keys = inc_obj.entity_keys
                matched_orm.timeline = [t.model_dump(mode="json") for t in inc_obj.timeline]
                matched_orm.techniques = inc_obj.techniques
                matched_orm.tactics = inc_obj.tactics
                matched_orm.domain = inc_obj.domain.value
                matched_orm.secondary_domains = [d.value for d in inc_obj.secondary_domains]
                matched_orm.severity = inc_obj.severity.value
                matched_orm.risk_score = inc_obj.risk_score
                matched_orm.risk_rationale = inc_obj.risk_rationale
                matched_orm.out_of_order_stage = inc_obj.out_of_order_stage
                matched_orm.predicted_next = [p.model_dump(mode="json") for p in inc_obj.predicted_next]
                matched_orm.is_simulated = is_simulated
                db.commit()

                # Update alert foreign key
                db.query(AlertORM).filter(AlertORM.alert_id == alert.alert_id).update({"incident_id": inc_obj.incident_id})
                db.commit()
                return inc_obj

            else:
                # Create brand new Incident
                inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
                alert.incident_id = inc_id

                inc_obj = Incident(
                    incident_id=inc_id,
                    created_at=alert.ts,
                    updated_at=alert.ts,
                    status=IncidentStatus.open,
                    alert_ids=[alert.alert_id],
                    entity_keys=list(alert_keys),
                    is_simulated=is_simulated,
                )
                inc_obj = build_chain(inc_obj, [alert])
                inc_obj = classify_domain(inc_obj, [alert])
                inc_obj = compute_severity(inc_obj, [alert])
                last_tactic = inc_obj.tactics[-1] if inc_obj.tactics else "reconnaissance"
                inc_obj.predicted_next = self.predictor.predict(last_tactic, top_n=3)

                new_orm = IncidentORM(
                    incident_id=inc_obj.incident_id,
                    created_at=inc_obj.created_at,
                    updated_at=inc_obj.updated_at,
                    status=inc_obj.status.value,
                    alert_ids=inc_obj.alert_ids,
                    entity_keys=inc_obj.entity_keys,
                    timeline=[t.model_dump(mode="json") for t in inc_obj.timeline],
                    techniques=inc_obj.techniques,
                    tactics=inc_obj.tactics,
                    domain=inc_obj.domain.value,
                    secondary_domains=[d.value for d in inc_obj.secondary_domains],
                    severity=inc_obj.severity.value,
                    risk_score=inc_obj.risk_score,
                    risk_rationale=inc_obj.risk_rationale,
                    out_of_order_stage=inc_obj.out_of_order_stage,
                    predicted_next=[p.model_dump(mode="json") for p in inc_obj.predicted_next],
                    report_id=None,
                    is_simulated=is_simulated,
                )
                db.add(new_orm)
                db.commit()

                # Link alert to incident
                db.query(AlertORM).filter(AlertORM.alert_id == alert.alert_id).update({"incident_id": inc_id})
                db.commit()
                return inc_obj

        except Exception as exc:
            db.rollback()
            logger.error("Dynamic correlation error: %s", exc, exc_info=True)
            raise
        finally:
            db.close()


class StreamingPipelineManager:
    """
    Manages long-running asynchronous worker tasks consuming from EventBus.
    """

    def __init__(self) -> None:
        self.detector = get_stream_detector()
        self.correlator = DynamicStreamCorrelator()
        self.bus = get_event_bus()
        self._running = False
        self._consumer_task: asyncio.Task | None = None

    def start(self) -> None:
        """Start the background stream consumers."""
        if self._running:
            return
        self._running = True
        self._consumer_task = asyncio.create_task(self._pipeline_worker())
        logger.info("Real-time Streaming Pipeline started (EventBus -> CEP Detector -> Dynamic Correlator)")

    async def stop(self) -> None:
        """Stop the background workers cleanly."""
        self._running = False
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        logger.info("Real-time Streaming Pipeline stopped.")

    async def _pipeline_worker(self) -> None:
        """Continuously consume events from the event bus and forward alerts."""
        while self._running:
            try:
                async for msg in self.bus.subscribe("events"):
                    if not self._running:
                        break

                    if msg.event_type == "event_ingested":
                        ev_dict = msg.payload.get("event", {})
                        is_sim = bool(msg.payload.get("is_simulated", False))

                        try:
                            event = Event(**ev_dict)
                        except Exception as e:
                            logger.warning("Could not construct Event from payload: %s", e)
                            continue

                        # Process in CEP detector
                        alerts = self.detector.process_event(event)

                        for alert in alerts:
                            alert.is_simulated = is_sim
                            # Persist alert
                            self.detector.persist_alerts([alert])

                            # Publish alert to bus
                            alert_msg = StreamMessage(
                                topic="alerts",
                                event_type="alert_created",
                                payload={"alert": alert.model_dump(mode="json"), "is_simulated": is_sim},
                            )
                            await self.bus.publish("alerts", alert_msg)

                            # Correlate alert into incident
                            try:
                                incident = self.correlator.process_alert(alert, is_simulated=is_sim)
                                # Publish incident to bus
                                inc_msg = StreamMessage(
                                    topic="incidents",
                                    event_type="incident_updated",
                                    payload={"incident": incident.model_dump(mode="json"), "is_simulated": is_sim},
                                )
                                await self.bus.publish("incidents", inc_msg)
                            except Exception as c_err:
                                logger.error("Correlation processing error: %s", c_err)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in streaming pipeline worker: %s", exc)
                await asyncio.sleep(0.5)


# Global singleton pipeline manager
_pipeline_manager: StreamingPipelineManager | None = None


def get_pipeline_manager() -> StreamingPipelineManager:
    """Return the global pipeline manager singleton."""
    global _pipeline_manager
    if _pipeline_manager is None:
        _pipeline_manager = StreamingPipelineManager()
    return _pipeline_manager
