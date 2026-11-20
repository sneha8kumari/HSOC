"""
RemediationAgent: Assembles RAG-grounded remediation actions, gating disruptive steps with needs_approval=True.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from hsoc.config import get_settings
from hsoc.genai.action_guardrail import get_action_guardrail
from hsoc.genai.agents.context import IncidentContext
from hsoc.knowledge.retriever import retrieve
from hsoc.schema import RemediationStep

logger = logging.getLogger(__name__)


class RemediationAgent:
    """Retrieves authoritative playbooks and designs approved remediation workflows."""

    def __init__(self, name: str = "RemediationAgent") -> None:
        self.name = name

    def execute(self, context: IncidentContext) -> list[dict[str, Any]]:
        t0 = time.perf_counter()
        incident = context.incident

        # 1. Query hybrid RAG knowledge base with Markov-aware expansion
        search_query = f"{incident.domain.value} " + " ".join(incident.techniques)
        retrieved_chunks, low_conf = retrieve(
            query=search_query,
            domain=incident.domain.value,
            markov_expansion=True,
        )

        context.retrieved_chunk_ids = {c.chunk_id for c in retrieved_chunks}

        # 2. Formulate discrete remediation actions citing retrieved chunks
        remediation_steps: list[dict[str, Any]] = []

        for chunk in retrieved_chunks[:4]:
            sentences = [s.strip() for s in chunk.text.split(". ") if s.strip()]
            for sent in sentences[:2]:
                if not sent.endswith("."):
                    sent += "."

                # Tag if disruptive
                is_disruptive = get_action_guardrail().is_disruptive(sent)

                step_dict = {
                    "step": sent,
                    "needs_approval": is_disruptive,
                    "source": chunk.chunk_id,
                    "stage": chunk.stage,
                    "predicted_tactic": chunk.predicted_tactic,
                }
                remediation_steps.append(step_dict)

        # Fallback safeguard if no chunks generated
        if not remediation_steps:
            remediation_steps.append({
                "step": "Isolate compromised host and review perimeter firewall rules.",
                "needs_approval": True,
                "source": "KB-PLAYBOOK-FALLBACK",
                "stage": "current",
                "predicted_tactic": None,
            })
            context.retrieved_chunk_ids.add("KB-PLAYBOOK-FALLBACK")

        context.remediation_proposals = remediation_steps
        latency_ms = (time.perf_counter() - t0) * 1000

        disruptive_count = sum(1 for s in remediation_steps if s["needs_approval"])
        msg_text = (
            f"Remediation generated {len(remediation_steps)} actions ({disruptive_count} require human authorization) "
            f"citing {len(context.retrieved_chunk_ids)} authoritative knowledge chunks."
        )

        context.add_trace(
            agent_name=self.name,
            state="REMEDIATE",
            inputs={"query": search_query, "domain": incident.domain.value},
            tool_calls=[{
                "tool": "hybrid_rag_retrieve",
                "chunks_found": len(retrieved_chunks),
                "low_confidence": low_conf,
            }],
            output_message=msg_text,
            latency_ms=latency_ms,
            tokens=90,
        )

        context.send_message(
            sender=self.name,
            recipient="CriticAgent",
            message_type="REMEDIATION_PROPOSED",
            payload={"remediations": remediation_steps, "chunks": list(context.retrieved_chunk_ids)},
        )

        return remediation_steps
