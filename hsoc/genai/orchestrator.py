"""
GenAI orchestrator: Wires the multi-agent state machine into the report pipeline.

Flow:
  1. Spawns MultiAgentOrchestrator with shared IncidentContext.
  2. Runs state transitions: Triage -> Investigate -> Forecast -> Remediate -> Critic.
  3. Bounded retries and deterministic fallback on verification failure.
  4. Persists agent execution traces and the validated Report to SQLite database.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import ReportORM, SessionLocal, init_db
from hsoc.genai.agents.orchestrator import MultiAgentOrchestrator
from hsoc.schema import Incident, Report

logger = logging.getLogger(__name__)


def generate_report(incident: Incident, db: Session | None = None) -> Report:
    """
    Generate an incident report for the given incident using the multi-agent orchestrator.

    Args:
        incident: A fully correlated, scored incident.
        db: Optional existing SQLAlchemy session.

    Returns:
        A validated Report object with execution traces saved in the database.
    """
    init_db()
    t0 = time.perf_counter()

    orchestrator = MultiAgentOrchestrator()
    report = orchestrator.run(incident, db=db)
    report.latency_seconds = round(time.perf_counter() - t0, 4)

    # Persist report to database
    report_dict = report.model_dump(mode="json")
    orm = ReportORM(
        report_id=report.report_id,
        incident_id=report.incident_id,
        generated_at=report.generated_at,
        generated_by=report.generated_by,
        model_name=report.model_name,
        prompt_version=report.prompt_version,
        latency_seconds=report.latency_seconds,
        retries=report.retries,
        valid=report.valid,
        severity=report.severity.value,
        summary=report.summary,
        evidence=report.evidence,
        attack_mapping=[m.model_dump(mode="json") for m in report.attack_mapping],
        domain=report.domain.value,
        predicted_next=[p.model_dump(mode="json") for p in report.predicted_next],
        remediation=[r.model_dump(mode="json") for r in report.remediation],
        uncertainty=report.uncertainty,
        chunk_ids_used=report.chunk_ids_used,
        full_json=report_dict,
    )

    if db is not None:
        db.add(orm)
    else:
        local_db = SessionLocal()
        try:
            local_db.add(orm)
            local_db.commit()
        finally:
            local_db.close()

    return report
