"""
Integration tests for the synthetic attack simulation and ingestion pipeline.
"""

from pathlib import Path

from hsoc.db import EventORM, SessionLocal, init_db
from hsoc.ingest import collector
from hsoc.simulate import benign_generator, scenario_generator


def test_end_to_end_simulation_and_ingestion(tmp_path):
    # Setup test directory
    test_out = tmp_path / "synthetic"
    test_out.mkdir()

    # 1. Generate attack scenarios
    scenario_generator.generate(seed=42, scenarios=["S1", "S2", "S4"], out_dir=str(test_out))

    assert (test_out / "auth.log").exists()
    assert (test_out / "apache_access.log").exists()
    assert (test_out / "flows.csv").exists()
    assert (test_out / "truth.jsonl").exists()

    truth_lines = (test_out / "truth.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(truth_lines) >= 3

    # 2. Append benign background traffic
    benign_generator.generate_benign(seed=1337, count=30, out_dir=str(test_out))

    # 3. Test collector batch processing
    init_db()
    db = SessionLocal()
    try:
        # Process auth.log
        auth_lines = (test_out / "auth.log").read_text(encoding="utf-8").strip().splitlines()
        res_auth = collector.process_lines(auth_lines, "linux_auth", db, batch_size=50)
        assert res_auth["ingested_events"] > 0
        assert res_auth["quarantined_records"] == 0
        assert res_auth["throughput_events_per_sec"] > 100

        # Process apache_access.log
        apache_lines = (test_out / "apache_access.log").read_text(encoding="utf-8").strip().splitlines()
        res_apache = collector.process_lines(apache_lines, "apache", db, batch_size=50)
        assert res_apache["ingested_events"] > 0
        assert res_apache["throughput_events_per_sec"] > 100

        # Process flows.csv
        flow_lines = (test_out / "flows.csv").read_text(encoding="utf-8").strip().splitlines()
        res_flow = collector.process_lines(flow_lines, "flow", db, batch_size=50)
        assert res_flow["ingested_events"] > 0
        assert res_flow["throughput_events_per_sec"] > 100

        # 4. Verify database persistence and enrichment
        total_in_db = db.query(EventORM).count()
        assert total_in_db >= (res_auth["ingested_events"] + res_apache["ingested_events"] + res_flow["ingested_events"])

        # Check an enriched event from db-srv-01
        db_event = db.query(EventORM).filter(EventORM.dst_ip == "192.168.56.20").first()
        if db_event:
            assert db_event.asset_criticality == 5
            assert db_event.asset_role == "database"

    finally:
        db.close()
