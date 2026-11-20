"""
Shared blackboard context and typed message schemas for the H-SOC multi-agent system.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from hsoc.schema import AgentTrace, Incident, Report


class AgentMessage(BaseModel):
    """Typed message exchanged between agents in the state machine."""

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: str
    recipient: str
    message_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentContext:
    """
    Shared memory blackboard accessed and mutated by agents according to state transitions.
    """

    def __init__(self, incident: Incident) -> None:
        self.incident = incident
        self.incident_id = incident.incident_id
        self.created_at = datetime.now(timezone.utc)

        # Stage artifacts
        self.triage_data: dict[str, Any] = {}
        self.evidence_pack: dict[str, Any] = {
            "events": [],
            "graph_neighbors": [],
            "assets": {},
            "users": {},
            "sanitized_evidence_lines": [],
        }
        self.forecast_data: dict[str, Any] = {
            "predictions": [],
            "narration": "",
            "out_of_order": False,
        }
        self.remediation_proposals: list[dict[str, Any]] = []
        self.retrieved_chunk_ids: set[str] = set()
        self.critic_review: dict[str, Any] = {
            "passed": False,
            "errors": [],
            "retries": 0,
            "hallucinations_detected": [],
            "corrections_made": [],
        }
        self.traces: list[AgentTrace] = []
        self.messages: list[AgentMessage] = []
        self.final_report: Report | None = None
        self.current_state: str = "INIT"

    def add_trace(
        self,
        agent_name: str,
        state: str,
        inputs: dict[str, Any],
        tool_calls: list[dict[str, Any]],
        output_message: str,
        latency_ms: float,
        tokens: int = 0,
    ) -> AgentTrace:
        """Record and return an execution trace step."""
        trace = AgentTrace(
            incident_id=self.incident_id,
            step_index=len(self.traces) + 1,
            agent_name=agent_name,
            state=state,
            inputs=inputs,
            tool_calls=tool_calls,
            output_message=output_message,
            latency_ms=round(latency_ms, 2),
            tokens=tokens,
        )
        self.traces.append(trace)
        return trace

    def send_message(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        payload: dict[str, Any],
    ) -> AgentMessage:
        """Append a typed message to the shared context history."""
        msg = AgentMessage(
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
        )
        self.messages.append(msg)
        return msg
