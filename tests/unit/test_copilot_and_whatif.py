"""
Unit tests for Copilot Chat (SSE streaming + citation validation), What-If Engine, Counterfactuals, and Export Formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from hsoc.api.main import create_app
from hsoc.db import AlertORM, Base, EventORM, IncidentORM, ReportORM, get_db
from hsoc.genai.copilot import CopilotEngine, get_copilot_engine
from hsoc.schema import Domain, Severity


@pytest.fixture
def test_db_session() -> Session:
    """Provide an isolated in-memory database with populated test incident data."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    now = datetime.now(timezone.utc)
    inc_id = "INC-COPILOT-01"
    alt_id = "ALT-COPILOT-01"
    evt_id = "EVT-COPILOT-01"

    # Populate Event
    event = EventORM(
        event_id=evt_id,
        ts=now,
        source_type="linux_auth",
        action="authentication",
        outcome="failure",
        src_ip="192.168.1.55",
        host="auth-srv-02",
        user="root",
        raw="Failed password for root from 192.168.1.55 port 22 ssh2",
        raw_hash="hash0123456789abcdef",
    )
    session.add(event)

    # Populate Alert
    alert = AlertORM(
        alert_id=alt_id,
        ts=now,
        rule_ids=["R-02"],
        model_id=None,
        ml_score=None,
        conf=0.92,
        technique="T1110.001",
        tactic="credential_access",
        domain="authentication",
        src_ip="192.168.1.55",
        dst_host="auth-srv-02",
        user="root",
        evidence_event_ids=[evt_id],
        description="SSH Brute Force detected on auth-srv-02",
        incident_id=inc_id,
    )
    session.add(alert)

    # Populate Incident
    incident = IncidentORM(
        incident_id=inc_id,
        created_at=now,
        updated_at=now,
        status="open",
        alert_ids=[alt_id],
        entity_keys=["auth-srv-02", "192.168.1.55"],
        timeline=[{"alert_id": alt_id, "ts": now.isoformat(), "technique": "T1110.001"}],
        techniques=["T1110.001", "T1078"],
        tactics=["credential_access", "privilege_escalation"],
        domain="authentication",
        secondary_domains=["authorization"],
        severity="high",
        risk_score=78,
        risk_rationale="High volume credential stuffing against critical authentication server.",
        out_of_order_stage=False,
        predicted_next=[{"tactic": "privilege_escalation", "probability": 0.42}],
        report_id="REP-COPILOT-01",
    )
    session.add(incident)

    # Populate Report
    report = ReportORM(
        report_id="REP-COPILOT-01",
        incident_id=inc_id,
        generated_at=now,
        generated_by="llm",
        model_name="gpt-4o-mini",
        prompt_version="1.0.0",
        latency_seconds=1.2,
        retries=0,
        valid=True,
        severity="high",
        summary="Attacker conducted automated SSH brute-force against auth-srv-02.",
        evidence=["Failed password for root from 192.168.1.55"],
        attack_mapping=[{"technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "credential_access"}],
        domain="authentication",
        predicted_next=[{"tactic": "privilege_escalation", "probability": 0.42}],
        remediation=[
            {
                "step": "Isolate compromised host auth-srv-02 at edge firewall.",
                "needs_approval": True,
                "source": "KB-PLAYBOOK-FIREWALL",
            },
            {
                "step": "Revoke active session tokens and force password reset for user root.",
                "needs_approval": True,
                "source": "KB-PLAYBOOK-IAM",
            },
            {
                "step": "Log attacker IP to threat intelligence feed.",
                "needs_approval": False,
                "source": "KB-PLAYBOOK-SIEM",
            },
        ],
        uncertainty="None",
        chunk_ids_used=["KB-PLAYBOOK-FIREWALL", "KB-PLAYBOOK-IAM", "KB-PLAYBOOK-SIEM"],
        full_json={},
    )
    session.add(report)
    session.commit()

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(test_db_session: Session) -> TestClient:
    """Create FastAPI test client overriding get_db dependency."""
    app = create_app()

    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    # Set zero stream delay for fast tests
    get_copilot_engine().stream_delay = 0.0
    return TestClient(app)


# ── 1. Scripted 10-Question Copilot Acceptance Test Suite ───────────────────

SCRIPTED_COPILOT_QUESTIONS = [
    {
        "id": "Q1",
        "question": "Why is this incident classified as High severity?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["high", "formula", "risk = round(20", "tactic weight"],
    },
    {
        "id": "Q2",
        "question": "What happens if the attacker gets sudo?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["privilege_escalation", "markov", "risk", "containment"],
    },
    {
        "id": "Q3",
        "question": "Show evidence for step 1 of remediation.",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["step 1", "isolate", "KB-PLAYBOOK-FIREWALL", "needs_approval=True"],
    },
    {
        "id": "Q4",
        "question": "Show evidence for step 2 of remediation.",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["step 2", "revoke", "KB-PLAYBOOK-IAM", "needs_approval=True"],
    },
    {
        "id": "Q5",
        "question": "What entities and hostnames are compromised in this incident?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["auth-srv-02", "192.168.1.55"],
    },
    {
        "id": "Q6",
        "question": "What alerts are associated with this incident?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["ALT-COPILOT-01", "T1110.001"],
    },
    {
        "id": "Q7",
        "question": "What techniques did the attacker use?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["T1110.001", "credential_access"],
    },
    {
        "id": "Q8",
        "question": "What are the recommended containment steps?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["isolate", "KB-PLAYBOOK-FIREWALL", "approval"],
    },
    {
        "id": "Q9",
        "question": "What evidence supports the brute force alert?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["ALT-COPILOT-01", "EVT-COPILOT-01"],
    },
    {
        "id": "Q10",
        "question": "What happens if the attacker pivots to lateral movement?",
        "expected_alert_id": "ALT-COPILOT-01",
        "expected_keywords": ["lateral_movement", "markov", "risk"],
    },
]


def test_scripted_10_copilot_questions_and_citations(test_db_session: Session):
    """
    Acceptance Test: 10 scripted copilot questions must return accurate answers
    and strictly cite expected alert/event IDs.
    """
    engine = get_copilot_engine()
    incident_id = "INC-COPILOT-01"

    for script in SCRIPTED_COPILOT_QUESTIONS:
        ans = engine.answer_question(query=script["question"], incident_id=incident_id, db=test_db_session)

        # 1. Answer must be non-empty string
        assert len(ans.answer) > 20, f"Failed on {script['id']}: Answer too short"

        # 2. Answer must cite expected alert ID
        assert script["expected_alert_id"] in ans.cited_alert_ids or script["expected_alert_id"] in ans.answer, (
            f"Failed on {script['id']}: Expected alert citation {script['expected_alert_id']} not found in {ans.answer}"
        )

        # 3. Expected domain keywords must be present
        for kw in script["expected_keywords"]:
            assert kw.lower() in ans.answer.lower(), (
                f"Failed on {script['id']}: Expected keyword '{kw}' not in answer: {ans.answer}"
            )


# ── 2. Streaming SSE Endpoint Test ──────────────────────────────────────────

def test_copilot_chat_streaming_sse(client: TestClient):
    """Verify that the copilot chat endpoint streams tokens in text/event-stream format."""
    incident_id = "INC-COPILOT-01"

    response = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"query": "Why High severity?", "stream": True},
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")

    # Parse SSE stream
    stream_lines = response.text.strip().split("\n\n")
    tokens = []
    received_citations = []
    has_done = False

    for chunk in stream_lines:
        if chunk == "data: [DONE]":
            has_done = True
            continue
        if chunk.startswith("data: "):
            payload = json.loads(chunk[6:])
            tokens.append(payload.get("token", ""))
            if payload.get("citations"):
                received_citations.extend(payload["citations"])

    assert has_done is True
    full_reassembled = "".join(tokens)
    assert "ALT-COPILOT-01" in full_reassembled
    assert len(received_citations) > 0
    assert "ALT-COPILOT-01" in received_citations


def test_copilot_chat_non_streaming_json(client: TestClient):
    """Verify non-streaming JSON option for copilot chat."""
    incident_id = "INC-COPILOT-01"
    response = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"query": "What entities are compromised?", "stream": False},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == incident_id
    assert "ALT-COPILOT-01" in data["cited_alert_ids"]
    assert "auth-srv-02" in data["answer"]


# ── Frontend-Backend Schema Contract Test ────────────────────────────────────

def test_copilot_chat_contract_schema_compatibility(client: TestClient):
    """
    Contract test ensuring frontend payload and backend schema cannot drift:
    1. Supports 'query' (backend original canonical key).
    2. Supports 'question' (frontend UI key).
    3. Supports both 'query' and 'question' combined.
    4. Handles empty payload without 422 Unprocessable Content.
    5. Returns valid answer for 'hello'.
    """
    incident_id = "INC-COPILOT-01"

    # Test 1: Frontend payload with 'question' only
    res_question = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"question": "hello", "stream": False},
    )
    assert res_question.status_code == 200, f"Expected 200 with 'question' field, got {res_question.status_code}"
    assert len(res_question.json()["answer"]) > 0

    # Test 2: Canonical payload with 'query' only
    res_query = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"query": "hello", "stream": False},
    )
    assert res_query.status_code == 200, f"Expected 200 with 'query' field, got {res_query.status_code}"

    # Test 3: Frontend live payload with both 'query', 'question', and 'stream'
    res_combined = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"query": "hello", "question": "hello", "stream": False},
    )
    assert res_combined.status_code == 200
    assert "INC-COPILOT-01" in res_combined.json()["answer"]

    # Test 4: Default fallback on empty payload (no 422)
    res_empty = client.post(
        f"/incidents/{incident_id}/copilot/chat",
        json={"stream": False},
    )
    assert res_empty.status_code == 200, f"Expected 200 on default payload, got {res_empty.status_code}"


# ── 3. What-If Engine Tests ──────────────────────────────────────────────────

def test_what_if_engine_endpoint(client: TestClient):
    """Verify what-if engine recalculates Markov trajectory, risk score, and containment playbooks."""
    incident_id = "INC-COPILOT-01"

    response = client.post(
        f"/incidents/{incident_id}/copilot/what-if",
        json={"forced_state": "attacker obtains domain admin credentials and sudo privileges"},
    )

    assert response.status_code == 200
    res = response.json()

    assert res["incident_id"] == incident_id
    assert res["normalized_tactic"] == "privilege_escalation"
    assert res["baseline_risk_score"] == 78
    assert res["projected_risk_score"] >= 78
    assert len(res["reforecasted_predictions"]) > 0
    assert len(res["playbook_chunk_ids"]) > 0
    assert "privilege_escalation" in res["narrative"]


# ── 4. Counterfactual Explanation Tests ──────────────────────────────────────

def test_counterfactual_explanation_endpoint(client: TestClient):
    """Verify deterministic calculation of asset criticality sensitivity."""
    incident_id = "INC-COPILOT-01"

    response = client.get(f"/incidents/{incident_id}/copilot/counterfactual")
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == incident_id
    assert data["current_severity"] == "high"
    assert data["target_lower_severity"] == "medium"
    assert data["asset_criticality_threshold"] <= 3
    assert "Severity would drop from HIGH to MEDIUM" in data["verbalized_explanation"]
    assert "ALT-COPILOT-01" in data["verbalized_explanation"]


# ── 5. Auto-Generated Export Formats Tests ───────────────────────────────────

def test_export_executive_summary(client: TestClient):
    """Verify executive summary format export."""
    response = client.get("/incidents/INC-COPILOT-01/copilot/export/executive_summary")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "executive_summary"
    assert "# Executive Incident Summary" in data["content"]
    assert "INC-COPILOT-01" in data["content"]
    assert "Business Impact & Exposure" in data["content"]


def test_export_technical_report(client: TestClient):
    """Verify technical forensic report export."""
    response = client.get("/incidents/INC-COPILOT-01/copilot/export/technical_report")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "technical_report"
    assert "# H-SOC Technical Investigation Report" in data["content"]
    assert "Telemetry Timeline & Correlated Alerts" in data["content"]
    assert "ALT-COPILOT-01" in data["content"]


def test_export_jira_ticket(client: TestClient):
    """Verify Jira ticket markup export."""
    response = client.get("/incidents/INC-COPILOT-01/copilot/export/jira")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "jira"
    assert "h1. [SEC-INC-COPI]" in data["content"]
    assert "*Project*: Security Operations (SEC)" in data["content"]
    assert "* [ ] Isolate compromised host" in data["content"]


def test_export_servicenow_record(client: TestClient):
    """Verify ServiceNow record format export."""
    response = client.get("/incidents/INC-COPILOT-01/copilot/export/servicenow")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "servicenow"
    assert "SERVICENOW SECURITY INCIDENT RECORD (SIR)" in data["content"]
    assert "Configuration Item (CI): auth-srv-02" in data["content"]


def test_export_invalid_format_raises_400(client: TestClient):
    """Verify invalid format raises 400 Bad Request."""
    response = client.get("/incidents/INC-COPILOT-01/copilot/export/invalid_format_xyz")
    assert response.status_code == 400
