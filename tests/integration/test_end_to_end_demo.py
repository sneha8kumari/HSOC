"""
Integration test for the full end-to-end demo flow:
simulate scenario (S1..S5) -> ingest -> detect -> correlate -> report.
"""

from hsoc.db import AlertORM, EventORM, IncidentORM, ReportORM, SessionLocal, init_db
from hsoc.detect import fusion
from hsoc.ingest import collector
from hsoc.investigate import correlate
from hsoc.simulate import benign_generator, scenario_generator


def test_end_to_end_demo_flow(tmp_path):
    init_db()
    db_clean = SessionLocal()
    try:
        db_clean.query(ReportORM).delete()
        db_clean.query(IncidentORM).delete()
        db_clean.query(AlertORM).delete()
        db_clean.query(EventORM).delete()
        db_clean.commit()
    finally:
        db_clean.close()

    # 1. Simulate scenarios S1..S5
    scenario_generator.generate(
        seed=42,
        scenarios=["S1", "S2", "S3", "S4", "S5"],
        out_dir="data/processed/synthetic",
    )
    benign_generator.generate_benign(seed=1337, count=30, out_dir="data/processed/synthetic")

    # 2. Ingest
    ingest_res = collector.run(mode="demo")
    assert len(ingest_res["runs"]) > 0

    # 3. Detect
    alerts = fusion.run_demo()
    assert len(alerts) >= 5

    # 4. Correlate & Report
    incidents = correlate.run_demo(generate_reports=True)
    assert len(incidents) == 5

    # 5. Verify database integrity
    db = SessionLocal()
    try:
        total_incidents = db.query(IncidentORM).count()
        total_reports = db.query(ReportORM).count()
        assert total_incidents == 5
        assert total_reports == 5

        reports = db.query(ReportORM).all()
        for r in reports:
            assert r.valid is True
            assert r.severity in ("low", "medium", "high", "critical")
            assert len(r.evidence) > 0
            assert len(r.remediation) > 0
            # Every cited source chunk must exist in chunk_ids_used
            for step in r.remediation:
                assert step["source"] in r.chunk_ids_used
    finally:
        db.close()
