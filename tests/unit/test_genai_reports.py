"""
Unit tests for GenAI report validation, citation verification, and fallback generation.
"""

from datetime import datetime, timezone

from hsoc.genai.fallback import build_fallback_report
from hsoc.genai.validator import validate
from hsoc.schema import Domain, Incident, IncidentStatus, PredictedTactic, Severity, TimelineItem


def test_validator_citation_check_and_disruptive_verbs():
    retrieved_chunks = {"KB-RECON-T1046", "KB-AUTH-T1110"}

    # Test report citing unauthorized chunk
    bad_report = {
        "incident_id": "123e4567-e89b-12d3-a456-426614174000",
        "severity": "high",
        "summary": "Test incident summary text.",
        "evidence": ["Evidence log line 1"],
        "attack_mapping": [{"technique_id": "T1046", "technique_name": "Port Scan", "tactic": "reconnaissance"}],
        "domain": "reconnaissance",
        "predicted_next": [{"tactic": "initial_access", "probability": 0.8}],
        "remediation": [{"step": "Block IP address at gateway.", "needs_approval": False, "source": "UNAUTHORIZED-CHUNK-999"}],
        "uncertainty": "None",
    }
    valid, errors = validate(bad_report, retrieved_chunks)
    assert not valid
    assert any("unauthorized chunk" in e for e in errors)
    # Disruptive verb "block" should be forced to needs_approval=True
    assert bad_report["remediation"][0]["needs_approval"] is True


def test_fallback_report_structure_and_validity():
    incident = Incident(
        incident_id="test-inc-01",
        created_at=datetime.now(timezone.utc),
        status=IncidentStatus.open,
        entity_keys=["ip:203.0.113.10", "host:db-srv-01"],
        techniques=["T1046"],
        tactics=["reconnaissance"],
        domain=Domain.reconnaissance,
        severity=Severity.critical,
        risk_score=85,
        timeline=[
            TimelineItem(
                alert_id="al-01",
                ts=datetime.now(timezone.utc),
                technique="T1046",
                tactic="reconnaissance",
                description="Port scan on 192.168.56.20",
            )
        ],
        predicted_next=[PredictedTactic(tactic="initial_access", probability=0.65)],
    )

    report = build_fallback_report(incident)
    assert report.incident_id == "test-inc-01"
    assert report.generated_by == "template"
    assert report.valid is True
    assert len(report.remediation) > 0
    assert len(report.evidence) > 0

    # Ensure all citations point to returned chunk IDs
    for step in report.remediation:
        assert step.source in report.chunk_ids_used
