with open('tests/unit/test_soar_actions.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_test = """

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
"""

if 'def test_approved_step_target_matches_audited_target' not in content:
    with open('tests/unit/test_soar_actions.py', 'w', encoding='utf-8') as f:
        f.write(content + new_test)
    print('Added test_approved_step_target_matches_audited_target')
else:
    print('Test already present')
