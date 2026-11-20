"""
Unit tests for the React/Vite dashboard backend APIs:
  - Incidents list and detail
  - Interactive attack graph nodes and edges
  - Scenario replay telemetry data (10x speed)
  - Markov panel (13x13 transition matrix, credible intervals, Viterbi path, absorption gauge)
  - Knowledge chunk retrieval for citations
  - Static dashboard HTML serving
"""

from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest

from hsoc.api.main import create_app
from hsoc.db import AlertORM, EventORM, IncidentORM, ReportORM, SessionLocal, init_db


@pytest.fixture(scope="module")
def api_client():
    init_db()
    db = SessionLocal()
    try:
        # Seed test incident, alert, event, and report
        now = datetime.now(timezone.utc)
        test_inc = IncidentORM(
            incident_id="INC-UI-TEST-01",
            created_at=now,
            updated_at=now,
            status="open",
            alert_ids=["ALT-UI-01", "ALT-UI-02"],
            entity_keys=["ip:203.0.113.11", "host:db-srv-01", "user:admin"],
            timeline=[
                {"alert_id": "ALT-UI-01", "ts": now.isoformat(), "tactic": "privilege_escalation", "technique": "T1548.003"},
                {"alert_id": "ALT-UI-02", "ts": now.isoformat(), "tactic": "initial_access", "technique": "T1078"},
            ],
            techniques=["T1548.003", "T1078"],
            tactics=["privilege_escalation", "initial_access"],
            domain="authorization",
            secondary_domains=["authentication"],
            severity="high",
            risk_score=78,
            risk_rationale="Privilege escalation followed by initial access",
            out_of_order_stage=True,
            report_id="REP-UI-TEST-01",
        )

        test_alt1 = AlertORM(
            alert_id="ALT-UI-01",
            ts=now,
            rule_ids=["R-07"],
            conf=0.9,
            technique="T1548.003",
            tactic="privilege_escalation",
            domain="authorization",
            src_ip="203.0.113.11",
            dst_host="db-srv-01",
            user="admin",
            evidence_event_ids=["EVT-UI-01"],
            description="Unauthorized sudo shell",
            incident_id="INC-UI-TEST-01",
        )

        test_alt2 = AlertORM(
            alert_id="ALT-UI-02",
            ts=now,
            rule_ids=["R-03"],
            conf=0.85,
            technique="T1078",
            tactic="initial_access",
            domain="authentication",
            src_ip="203.0.113.11",
            dst_host="db-srv-01",
            user="admin",
            evidence_event_ids=["EVT-UI-02"],
            description="Valid admin login",
            incident_id="INC-UI-TEST-01",
        )

        test_evt1 = EventORM(
            event_id="EVT-UI-01",
            ts=now,
            source_type="linux_auth",
            raw="2026-10-26T00:00:00Z db-srv-01 sudo: admin : COMMAND=/bin/bash",
            src_ip="203.0.113.11",
            host="db-srv-01",
            user="admin",
            action="sudo",
            outcome="success",
            raw_hash="hash_ui_evt_01",
        )

        test_rep = ReportORM(
            report_id="REP-UI-TEST-01",
            incident_id="INC-UI-TEST-01",
            generated_at=now,
            generated_by="multi_agent",
            model_name="deterministic_critic",
            prompt_version="1.0",
            latency_seconds=1.2,
            retries=0,
            valid=True,
            severity="high",
            summary="Attacker performed [ALT-UI-01] unauthorized sudo abuse on db-srv-01.",
            evidence=["Observed [ALT-UI-01] on db-srv-01", "Raw log [EVT-UI-01]"],
            attack_mapping=[{"technique_id": "T1548.003", "technique_name": "Sudo Abuse", "tactic": "privilege_escalation"}],
            domain="authorization",
            predicted_next=[{"tactic": "defense_evasion", "probability": 0.45}],
            remediation=[{"step": "Isolate host and revoke sudo privileges", "needs_approval": True, "source": "KB-MITRE-71f422897c56"}],
            uncertainty="Low",
            chunk_ids_used=["KB-MITRE-71f422897c56"],
            full_json={
                "report_id": "REP-UI-TEST-01",
                "summary": "Attacker performed [ALT-UI-01] unauthorized sudo abuse.",
                "evidence": ["Observed [ALT-UI-01] on db-srv-01"],
                "attack_mapping": [{"technique_id": "T1548.003", "tactic": "privilege_escalation"}],
                "predicted_next": [{"tactic": "defense_evasion", "probability": 0.45}],
                "remediation": [{"step": "Isolate host", "needs_approval": True, "source": "KB-MITRE-71f422897c56"}],
                "chunk_ids_used": ["KB-MITRE-71f422897c56"],
            },
        )

        db.add_all([test_inc, test_alt1, test_alt2, test_evt1, test_rep])
        db.commit()
    finally:
        db.close()

    app = create_app()
    return TestClient(app)


def test_list_incidents_endpoint(api_client):
    res = api_client.get("/incidents")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1

    inc = next((i for i in data if i["incident_id"] == "INC-UI-TEST-01"), None)
    assert inc is not None
    assert inc["severity"] == "high"
    assert inc["risk_score"] == 78
    assert inc["out_of_order_stage"] is True


def test_get_incident_detail_endpoint(api_client):
    res = api_client.get("/incidents/INC-UI-TEST-01")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == "INC-UI-TEST-01"
    assert "alerts" in data
    assert len(data["alerts"]) >= 2
    assert "report" in data
    assert data["report"]["report_id"] == "REP-UI-TEST-01"


def test_attack_graph_endpoint(api_client):
    res = api_client.get("/incidents/INC-UI-TEST-01/graph")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data

    nodes = data["nodes"]
    node_types = {n["type"] for n in nodes}
    assert "incident" in node_types
    assert "alert" in node_types
    assert "entity_host" in node_types or "entity_ip" in node_types

    edges = data["edges"]
    assert len(edges) >= 2


def test_replay_telemetry_endpoint(api_client):
    res = api_client.get("/incidents/INC-UI-TEST-01/replay")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == "INC-UI-TEST-01"
    assert "steps" in data
    assert data["recommended_speed"] == 10


def test_markov_panel_endpoint(api_client):
    res = api_client.get("/models/markov/panel?current_tactic=privilege_escalation")
    assert res.status_code == 200
    data = res.json()

    assert "matrix" in data
    assert len(data["matrix"]) == 13  # 13x13 matrix
    assert "tactics" in data
    assert "next_step_predictions" in data
    assert len(data["next_step_predictions"]) > 0

    # Verify credible intervals are present and properly bounded
    for pred in data["next_step_predictions"]:
        assert "ci_lower" in pred
        assert "ci_upper" in pred
        assert pred["ci_lower"] <= pred["ci_upper"]

    assert "absorption_risk" in data
    assert 0.0 <= data["absorption_risk"] <= 1.0

    assert "viterbi_path" in data
    assert len(data["viterbi_path"]) >= 1


def test_knowledge_chunk_lookup_endpoint(api_client):
    res = api_client.get("/knowledge/chunks/KB-MITRE-71f422897c56")
    assert res.status_code == 200
    data = res.json()
    assert data["chunk_id"] == "KB-MITRE-71f422897c56"
    assert "title" in data
    assert "text" in data
    assert "source" in data


def test_static_dashboard_html_serving(api_client):
    res = api_client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "H-SOC" in res.text
