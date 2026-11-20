"""
Deterministic Multi-Agent Orchestrator (Finite State Machine).

Coordinates the five specialized agents:
  1. TriageAgent
  2. InvestigatorAgent
  3. ForecasterAgent
  4. RemediationAgent
  5. CriticAgent

Transitions:
  INIT -> TRIAGE -> INVESTIGATE -> FORECAST -> REMEDIATE -> CRITIC
  If Critic FAILS and retries < max_retries:
    RETRY -> REMEDIATE -> CRITIC
  If Critic fails after max_retries:
    FALLBACK -> deterministic template fallback

Logs every execution step as an immutable trace in the database.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import AgentTraceORM, SessionLocal, init_db
from hsoc.genai.agents.context import IncidentContext
from hsoc.genai.agents.critic_agent import CriticAgent
from hsoc.genai.agents.forecaster_agent import ForecasterAgent
from hsoc.genai.agents.investigator_agent import InvestigatorAgent
from hsoc.genai.agents.remediation_agent import RemediationAgent
from hsoc.genai.agents.triage_agent import TriageAgent
from hsoc.genai.fallback import build_fallback_report
from hsoc.schema import Incident, Report

logger = logging.getLogger(__name__)


class OrchestratorState(str, Enum):
    INIT = "INIT"
    TRIAGE = "TRIAGE"
    INVESTIGATE = "INVESTIGATE"
    FORECAST = "FORECAST"
    REMEDIATE = "REMEDIATE"
    CRITIC = "CRITIC"
    RETRY = "RETRY"
    FINALIZE = "FINALIZE"
    FALLBACK = "FALLBACK"


class MultiAgentOrchestrator:
    """
    State-machine orchestrator ensuring linear, deterministic execution
    with bounded retry guardrails and DB audit tracing.
    """

    def __init__(self) -> None:
        self.triage_agent = TriageAgent()
        self.investigator_agent = InvestigatorAgent()
        self.forecaster_agent = ForecasterAgent()
        self.remediation_agent = RemediationAgent()
        self.critic_agent = CriticAgent()

    def run(self, incident: Incident, db: Session | None = None) -> Report:
        """
        Execute the deterministic multi-agent state machine on an incident.

        Args:
            incident: The correlated, scored Incident.
            db: Optional existing database session.

        Returns:
            A schema-validated Report with execution traces persisted to DB.
        """
        init_db()
        context = IncidentContext(incident)
        max_retries = int(get_settings().genai.get("max_retries", 2))

        context.current_state = OrchestratorState.INIT.value
        logger.info("Starting Multi-Agent Orchestrator for incident %s", incident.incident_id)

        # State 1: TRIAGE
        context.current_state = OrchestratorState.TRIAGE.value
        self.triage_agent.execute(context)

        # State 2: INVESTIGATE
        context.current_state = OrchestratorState.INVESTIGATE.value
        self.investigator_agent.execute(context)

        # State 3: FORECAST
        context.current_state = OrchestratorState.FORECAST.value
        self.forecaster_agent.execute(context)

        # State 4: REMEDIATE
        context.current_state = OrchestratorState.REMEDIATE.value
        self.remediation_agent.execute(context)

        # State 5: CRITIC with bounded retry loop
        context.current_state = OrchestratorState.CRITIC.value
        passed, errors = self.critic_agent.execute(context)

        retries = 0
        while not passed and retries < max_retries:
            retries += 1
            context.critic_review["retries"] = retries
            context.current_state = OrchestratorState.RETRY.value
            logger.warning("Critic validation failed (attempt %d/%d). Retrying remediation...", retries, max_retries)

            context.current_state = OrchestratorState.REMEDIATE.value
            self.remediation_agent.execute(context)

            context.current_state = OrchestratorState.CRITIC.value
            passed, errors = self.critic_agent.execute(context)

        # If still failing after bounded retries, activate deterministic fallback
        if not passed:
            context.current_state = OrchestratorState.FALLBACK.value
            logger.warning("Critic verification failed after %d retries. Triggering deterministic fallback.", retries)
            fallback_report = build_fallback_report(incident)
            fallback_report.retries = retries
            context.final_report = fallback_report

            context.add_trace(
                agent_name="Orchestrator",
                state="FALLBACK",
                inputs={"errors": errors, "retries": retries},
                tool_calls=[],
                output_message="Deterministic template fallback activated due to unresolvable validation errors.",
                latency_ms=1.0,
                tokens=10,
            )
        else:
            context.current_state = OrchestratorState.FINALIZE.value

        final_report = context.final_report or build_fallback_report(incident)
        final_report.retries = retries

        # Persist traces to DB
        self._persist_traces(context.traces, db=db)

        return final_report

    def _persist_traces(self, traces: list[Any], db: Session | None = None) -> None:
        """Persist execution traces to agent_traces table."""
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True

        try:
            for t in traces:
                orm_trace = AgentTraceORM(
                    trace_id=t.trace_id,
                    incident_id=t.incident_id,
                    step_index=t.step_index,
                    agent_name=t.agent_name,
                    state=t.state,
                    inputs=t.inputs,
                    tool_calls=t.tool_calls,
                    output_message=t.output_message,
                    latency_ms=t.latency_ms,
                    tokens=t.tokens,
                    created_at=t.created_at,
                )
                db.add(orm_trace)
            db.commit()
            logger.info("Persisted %d agent trace records to database", len(traces))
        except Exception as exc:
            db.rollback()
            logger.error("Failed to persist agent traces: %s", exc)
        finally:
            if should_close:
                db.close()
