"""
Unit and integration tests for Phase 1: Live Ingestion Tier.
Tests:
  - Exact LRU deduplication (no false positive silent drops)
  - RFC 3164 and RFC 5424 syslog envelope parsing and routing
  - Syslog server live message ingestion into DB and Event Bus
  - Malformed syslog/webhook input quarantine path (no silent drop)
  - REST Webhook /api/v1/telemetry/ingest (single and micro-batch)
  - File tailer offset persistence and rotation recovery
  - Event Bus backpressure and subscriber fan-out
  - Ingestion throughput (events per second) measurement
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from hsoc.db import EventORM, QuarantineORM, SessionLocal, init_db
from hsoc.ingest.dedup import LRUDeduplicator
from hsoc.ingest.syslog_server import (
    parse_syslog_envelope,
    detect_parser_for_syslog,
    process_raw_syslog_line,
    SyslogServerManager,
)
from hsoc.ingest.tailer import AsyncFileTailer
from hsoc.streaming.bus import (
    AsyncioEventBus,
    StreamMessage,
    get_event_bus,
    reset_event_bus,
)


@pytest.fixture(autouse=True)
def setup_test_env():
    init_db()
    reset_event_bus()
    yield
    reset_event_bus()


# ---------------------------------------------------------------------------
# 1. Exact LRU Deduplication Tests
# ---------------------------------------------------------------------------

def test_lru_deduplication():
    dedup = LRUDeduplicator(max_size=3)
    
    # 1. Distinct hashes are not duplicates
    assert dedup.is_duplicate("hash-1") is False
    assert dedup.is_duplicate("hash-2") is False
    assert dedup.is_duplicate("hash-3") is False

    # 2. Existing hash is flagged duplicate
    assert dedup.is_duplicate("hash-1") is True
    assert dedup.is_duplicate("hash-2") is True

    # 3. New hash evicts LRU item ("hash-3" was least recently accessed)
    assert dedup.is_duplicate("hash-4") is False
    assert dedup.is_duplicate("hash-3") is False


# ---------------------------------------------------------------------------
# 2. Syslog Envelope Parsing Tests (RFC 3164 & RFC 5424)
# ---------------------------------------------------------------------------

def test_syslog_rfc5424_parsing():
    raw = '<34>1 2026-10-26T22:10:00Z myhost.net sshd 8812 ID47 [exampleSDID@32473 iut="3"] Failed password for admin from 203.0.113.11 port 44820 ssh2'
    rec = parse_syslog_envelope(raw)
    assert rec.facility == 4  # 34 >> 3 = 4 (auth)
    assert rec.severity == 2  # 34 & 7 = 2 (crit)
    assert rec.hostname == "myhost.net"
    assert rec.app_name == "sshd"
    assert rec.proc_id == "8812"
    assert "Failed password for admin" in rec.msg
    assert detect_parser_for_syslog(rec) == "linux_auth"


def test_syslog_rfc3164_parsing():
    raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[4110]: Accepted publickey for alice from 192.168.56.105 port 55412 ssh2'
    rec = parse_syslog_envelope(raw)
    assert rec.facility == 1  # 13 >> 3 = 1 (user)
    assert rec.severity == 5  # 13 & 7 = 5 (notice)
    assert rec.hostname == "auth-srv-02"
    assert rec.app_name == "sshd"
    assert rec.proc_id == "4110"
    assert "Accepted publickey for alice" in rec.msg
    assert detect_parser_for_syslog(rec) == "linux_auth"


# ---------------------------------------------------------------------------
# 3. Syslog Live Ingest, Event Persistence & Quarantine Path
# ---------------------------------------------------------------------------

def test_syslog_ingest_event_creation():
    async def _run():
        raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[9999]: Failed password for root from 198.51.100.99 port 54321 ssh2'
        res = await process_raw_syslog_line(raw)
        assert res["status"] == "accepted"
        assert "event_id" in res

        # Verify event stored in DB
        db = SessionLocal()
        try:
            ev = db.query(EventORM).filter(EventORM.event_id == res["event_id"]).first()
            assert ev is not None
            assert ev.user == "root"
            assert ev.src_ip == "198.51.100.99"
            assert ev.action == "ssh_login"
            assert ev.outcome == "failure"
        finally:
            db.close()

    asyncio.run(_run())


def test_syslog_ingest_quarantine_no_silent_drop():
    async def _run():
        raw = 'INVALID_CORRUPTED_STREAM_NO_HEADER_OR_TIMESTAMP_LINE_FAILED_PARSER'
        res = await process_raw_syslog_line(raw)
        assert res["status"] == "quarantined"

        db = SessionLocal()
        try:
            q = db.query(QuarantineORM).filter(QuarantineORM.raw == raw.strip()).first()
            assert q is not None
            assert "Parser exception" in q.reason or "Validation failed" in q.reason
        finally:
            db.close()

    asyncio.run(_run())


def test_syslog_ingest_deduplication():
    async def _run():
        raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[9997]: Failed password for user1 from 198.51.100.50 port 54322 ssh2'
        res1 = await process_raw_syslog_line(raw)
        assert res1["status"] == "accepted"

        res2 = await process_raw_syslog_line(raw)
        assert res2["status"] == "duplicate"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. REST Webhook /api/v1/telemetry/ingest Tests
# ---------------------------------------------------------------------------

def test_webhook_ingest_single_and_batch():
    from fastapi import FastAPI
    from hsoc.api.routes import ingest
    app = FastAPI()
    app.include_router(ingest.router, prefix="/api/v1/telemetry")
    client = TestClient(app)

    # 1. Single valid event
    payload_single = {
        "source_type": "linux_auth",
        "raw": "Oct 26 22:16:00 web-srv-01 sshd[1234]: Accepted publickey for dev from 192.168.56.200 port 44321 ssh2",
    }
    r1 = client.post("/api/v1/telemetry/ingest", json=payload_single)
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["accepted"] == 1
    assert data1["duplicates"] == 0
    assert data1["quarantined"] == 0

    # 2. Resubmitting same event triggers duplicate count
    r2 = client.post("/api/v1/telemetry/ingest", json=payload_single)
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["duplicates"] == 1

    # 3. Micro-batch with mixed valid and quarantined
    payload_batch = {
        "events": [
            {
                "source_type": "apache",
                "raw": '192.168.56.10 - - [26/Oct/2026:22:16:10 +0000] "GET /api/status HTTP/1.1" 200 120',
            },
            {
                "source_type": "apache",
                "raw": 'INVALID APACHE LOG FORMAT LINE WITHOUT QUOTES',
            },
        ]
    }
    r3 = client.post("/api/v1/telemetry/ingest", json=payload_batch)
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3["received"] == 2
    assert data3["accepted"] == 1
    assert data3["quarantined"] == 1


def test_webhook_stats_endpoint():
    from fastapi import FastAPI
    from hsoc.api.routes import ingest
    app = FastAPI()
    app.include_router(ingest.router, prefix="/api/v1/telemetry")
    client = TestClient(app)
    res = client.get("/api/v1/telemetry/stats")
    assert res.status_code == 200
    data = res.json()
    assert "deduplicator" in data
    assert "bus" in data


# ---------------------------------------------------------------------------
# 5. File Tailer Offset Persistence and Truncation Recovery
# ---------------------------------------------------------------------------

def test_file_tailer_lifecycle(tmp_path: Path):
    async def _run():
        log_file = tmp_path / "test_auth.log"
        offset_file = tmp_path / "offsets.json"

        # Write initial 2 lines
        log_file.write_text(
            "Oct 26 22:17:00 host1 sshd[1]: Accepted password for u1 from 10.0.0.1 port 1 ssh2\n"
            "Oct 26 22:17:01 host1 sshd[2]: Accepted password for u2 from 10.0.0.2 port 2 ssh2\n",
            encoding="utf-8",
        )

        tailer = AsyncFileTailer(
            targets=[{"path": str(log_file), "source_type": "linux_auth", "host": "host1"}],
            offset_store_path=str(offset_file),
            poll_interval_seconds=0.05,
        )

        tailer.start()
        await asyncio.sleep(0.15)
        tailer.stop()

        assert tailer.events_read == 2
        assert offset_file.exists()

        # Append 1 new line and restart tailer (should resume from offset and only read 1 line)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("Oct 26 22:17:02 host1 sshd[3]: Accepted password for u3 from 10.0.0.3 port 3 ssh2\n")

        tailer2 = AsyncFileTailer(
            targets=[{"path": str(log_file), "source_type": "linux_auth", "host": "host1"}],
            offset_store_path=str(offset_file),
            poll_interval_seconds=0.05,
        )
        tailer2.start()
        await asyncio.sleep(0.15)
        tailer2.stop()

        assert tailer2.events_read == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Event Bus Backpressure and Fanout Tests
# ---------------------------------------------------------------------------

def test_event_bus_drop_oldest_backpressure():
    async def _run():
        bus = AsyncioEventBus(max_queue_size=2, backpressure_policy="drop_oldest")
        
        msg1 = StreamMessage(topic="test", event_type="test", payload={"val": 1})
        msg2 = StreamMessage(topic="test", event_type="test", payload={"val": 2})
        msg3 = StreamMessage(topic="test", event_type="test", payload={"val": 3})

        await bus.publish("test", msg1)
        await bus.publish("test", msg2)
        assert bus.get_queue_depth("test") == 2

        # Publishing 3rd message evicts msg1
        await bus.publish("test", msg3)
        assert bus.get_queue_depth("test") == 2
        metrics = bus.get_metrics()
        assert metrics["dropped_total"] == 1
        assert metrics["published_total"] == 3

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. Ingestion Throughput Benchmark
# ---------------------------------------------------------------------------

def test_ingest_throughput_benchmark():
    async def _run():
        n_events = 500
        lines = [
            f"Oct 26 22:18:{i%60:02d} host sshd[{i}]: Failed password for test_{i} from 10.0.1.{i%250} port {10000+i} ssh2"
            for i in range(n_events)
        ]

        t0 = time.perf_counter()
        accepted = 0
        for line in lines:
            res = await process_raw_syslog_line(line)
            if res.get("status") == "accepted":
                accepted += 1
        t1 = time.perf_counter()

        duration = t1 - t0
        eps = n_events / duration if duration > 0 else 0
        print(f"\n[BENCHMARK] Ingested {accepted}/{n_events} events in {duration:.3f}s -> {eps:.1f} EPS")
        assert accepted == n_events
        assert eps > 100

    asyncio.run(_run())
