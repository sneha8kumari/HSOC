"""
Unit and acceptance tests for multi-agent deterministic orchestrator,
tool allow-listing, hallucination detection by CriticAgent, and the trace viewer API.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from hsoc.api.main import app
from hsoc.db import AgentTraceORM, SessionLocal, init_db
from hsoc.genai.agents.context import IncidentContext
from hsoc.genai.agents.critic_agent import CriticAgent
from hsoc.genai.agents.forecaster_agent import ForecasterAgent
from hsoc.genai.agents.investigator_agent import InvestigatorAgent
from hsoc.genai.agents.orchestrator import MultiAgentOrchestrator
from hsoc.genai.agents.remediation_agent import RemediationAgent
from hsoc.genai.agents.tools import ToolDispatcher
from hsoc.genai.agents.triage_agent import TriageAgent
from hsoc.schema import Domain, Incident, IncidentStatus, PredictedTactic, Severity, TimelineItem


@pytest.fixture
def sample_incident() -> Incident:
    return Incident(
        incident_id="inc-agent-test-01",
        created_at=datetime.now(timezone.utc),
        status=IncidentStatus.open,
        entity_keys=["ip:192.168.56.100", "host:db-srv-01", "user:alice"],
        techniques=["T1046"],
        tactics=["reconnaissance"],
        domain=Domain.reconnaissance,
        severity=Severity.high,
        risk_score=75,
        timeline=[
            TimelineItem(
                alert_id="al-recon-01",
                ts=datetime.now(timezone.utc),
                technique="T1046",
                tactic="reconnaissance",
                description="SYN port scan sweep detected on 192.168.56.100",
            ),
            TimelineItem(
                alert_id="al-recon-02",
                ts=datetime.now(timezone.utc),
                technique="T1046",
                tactic="reconnaissance",
                description="SYN port scan sweep detected on 192.168.56.100",  # Duplicate alert
            ),
        ],
        predicted_next=[PredictedTactic(tactic="initial_access", probability=0.72)],
    )


def test_tool_allowlisting_and_execution(sample_incident):
    # Allow-listed tool calls must succeed
    asset = ToolDispatcher.call("lookup_asset", host_or_ip="db-srv-01")
    assert "criticality" in asset

    user = ToolDispatcher.call("lookup_user", username="alice")
    assert "privileged" in user

    traj = ToolDispatcher.call("predict_markov_trajectory", current_tactic="reconnaissance", top_n=2)
    assert len(traj.get("predictions", [])) > 0

    # Non-allow-listed tool must be blocked
    with pytest.raises(PermissionError):
        ToolDispatcher.call("execute_shell_command", cmd="rm -rf /")


def test_multi_agent_state_machine_execution(sample_incident):
    init_db()
    orchestrator = MultiAgentOrchestrator()
    report = orchestrator.run(sample_incident)

    assert report.incident_id == "inc-agent-test-01"
    assert report.valid is True
    assert len(report.remediation) > 0
    assert len(report.attack_mapping) > 0

    # Verify disruptive remediation gating
    for rem in report.remediation:
        if any(v in rem.step.lower() for v in ["block", "disable", "isolate", "kill"]):
            assert rem.needs_approval is True

    # Verify traces recorded in database
    db = SessionLocal()
    try:
        traces = (
            db.query(AgentTraceORM)
            .filter(AgentTraceORM.incident_id == sample_incident.incident_id)
            .order_by(AgentTraceORM.step_index.asc())
            .all()
        )
        assert len(traces) >= 5
        agent_names = [t.agent_name for t in traces]
        assert "TriageAgent" in agent_names
        assert "InvestigatorAgent" in agent_names
        assert "ForecasterAgent" in agent_names
        assert "RemediationAgent" in agent_names
        assert "CriticAgent" in agent_names

        for t in traces:
            assert t.latency_ms >= 0.0
            assert t.state in ["TRIAGE", "INVESTIGATE", "FORECAST", "REMEDIATE", "CRITIC", "FALLBACK"]
    finally:
        db.close()


def test_critic_catches_and_drops_hallucinated_technique():
    """
    Acceptance Test:
    Inject a hallucinated ATT&CK ID (e.g. 'T9999.999' and 'T9999') into the context.
    The CriticAgent must detect the hallucination, record the violation,
    and drop/correct it so the final report contains only valid techniques.
    """
    critic = CriticAgent()

    # Create incident with hallucinated technique
    bad_incident = Incident(
        incident_id="inc-hallucination-test-01",
        created_at=datetime.now(timezone.utc),
        status=IncidentStatus.open,
        entity_keys=["ip:10.0.0.5"],
        techniques=["T9999.999", "T1046"],  # T9999.999 is completely fabricated
        tactics=["reconnaissance"],
        domain=Domain.reconnaissance,
        severity=Severity.medium,
        risk_score=50,
        timeline=[],
        predicted_next=[],
    )

    context = IncidentContext(bad_incident)
    context.retrieved_chunk_ids = {"KB-MITRE-T1046"}
    context.remediation_proposals = [
        {"step": "Configure stateful firewall rules.", "needs_approval": True, "source": "KB-MITRE-T1046"}
    ]

    # Execute Critic review
    passed, errors = critic.execute(context)

    # Acceptance verification:
    # 1. Hallucination was caught
    assert len(context.critic_review["hallucinations_detected"]) > 0
    assert "T9999.999" in context.critic_review["hallucinations_detected"]

    # 2. Hallucination was dropped/corrected
    final_techniques = [m.technique_id for m in context.final_report.attack_mapping]
    assert "T9999.999" not in final_techniques
    assert "T1046" in final_techniques

    # 3. Report remains schema-valid
    assert context.final_report.valid is True


def test_trace_viewer_api_endpoint(sample_incident):
    init_db()
    client = TestClient(app)

    # Run orchestrator to seed traces
    orchestrator = MultiAgentOrchestrator()
    orchestrator.run(sample_incident)

    # Call trace viewer endpoint
    response = client.get(f"/incidents/{sample_incident.incident_id}/traces")
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == sample_incident.incident_id
    assert data["total_steps"] >= 5
    assert data["total_latency_ms"] >= 0.0
    assert len(data["traces"]) >= 5

    # Check structure of trace steps
    first_trace = data["traces"][0]
    assert "trace_id" in first_trace
    assert "step_index" in first_trace
    assert "agent_name" in first_trace
    assert "state" in first_trace
    assert "inputs" in first_trace
    assert "tool_calls" in first_trace
    assert "output_message" in first_trace
    assert "latency_ms" in first_trace
