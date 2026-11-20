"""
TriageAgent: Classifies incident severity and de-duplicates alert noise.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from hsoc.genai.agents.context import IncidentContext
from hsoc.schema import Severity

logger = logging.getLogger(__name__)


class TriageAgent:
    """Classifies the incident, consolidates alerts, and filters duplicate noise."""

    def __init__(self, name: str = "TriageAgent") -> None:
        self.name = name

    def execute(self, context: IncidentContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        incident = context.incident

        # 1. Deduplicate alerts by technique and target entity
        unique_alerts = []
        seen_signatures = set()
        for t in incident.timeline:
            sig = f"{t.technique}|{t.tactic}|{t.description}"
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_alerts.append(t)

        noise_ratio = round(1.0 - (len(unique_alerts) / max(len(incident.timeline), 1)), 2)

        # 2. Triage classification
        classification = {
            "incident_id": incident.incident_id,
            "domain": incident.domain.value,
            "assessed_severity": incident.severity.value,
            "risk_score": incident.risk_score,
            "total_alerts": len(incident.timeline),
            "deduplicated_alerts": len(unique_alerts),
            "noise_filtered_pct": noise_ratio * 100,
            "primary_entities": incident.entity_keys,
            "primary_techniques": incident.techniques,
            "primary_tactics": incident.tactics,
        }

        context.triage_data = classification
        latency_ms = (time.perf_counter() - t0) * 1000

        # Output message
        msg_text = (
            f"Triage completed: Domain={classification['domain']}, "
            f"Severity={classification['assessed_severity'].upper()}, "
            f"Filtered {classification['total_alerts'] - classification['deduplicated_alerts']} noise alerts."
        )

        context.add_trace(
            agent_name=self.name,
            state="TRIAGE",
            inputs={"incident_id": incident.incident_id, "alerts_count": len(incident.timeline)},
            tool_calls=[],
            output_message=msg_text,
            latency_ms=latency_ms,
            tokens=45,
        )

        context.send_message(
            sender=self.name,
            recipient="InvestigatorAgent",
            message_type="TRIAGE_RESULT",
            payload=classification,
        )

        return classification
