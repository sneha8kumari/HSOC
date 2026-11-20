"""
Unit and integration tests for Phase 2: Streaming Detection (CEP).
Tests:
  - In-memory sliding windows (O(1) deque eviction, bounded memory, TTL eviction)
  - Incremental rule evaluation (R-01, R-02, R-03, R-04, R-05, R-07, R-10)
  - Streaming fusion score calculation using batch pipeline weights
  - ML streaming inference and zero-cost fallback (< 5 ms per event)
  - End-to-end detection latency (< 50 ms threshold-crossing alert)
  - AlertORM persistence and Event Bus alert emission
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import time
import pytest

from hsoc.config import get_settings
from hsoc.db import AlertORM, EventORM, SessionLocal, init_db
from hsoc.detect.fusion import fuse_alert
from hsoc.detect.stream_detector import (
    MemorySlidingWindowStore,
    MLStreamScorer,
    StreamDetector,
    get_stream_detector,
    reset_stream_detector,
)
from hsoc.schema import Alert, AssetContext, Domain, Event, Outcome, SourceType, UserContext
from hsoc.streaming.bus import AsyncioEventBus, StreamMessage, reset_event_bus


def _make_event(
    event_id: str,
    action: str = "ssh_login",
    outcome: Outcome = Outcome.failure,
    src_ip: str = "192.168.1.50",
    dst_host: str = "auth-srv-01",
    dst_port: int | None = 22,
    user: str = "root",
    ts: datetime | None = None,
    features: dict | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        ts=ts or datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        host=dst_host,
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        dst_port=dst_port,
        user=user,
        action=action,
        outcome=outcome,
        asset=AssetContext(criticality=2, role="server", owner="secops"),
        user_ctx=UserContext(privileged=False, allowed_sudo=False),
        features=features or {},
        raw="mock raw log",
    )


# ---------------------------------------------------------------------------
# 1. Sliding Window Store Tests
# ---------------------------------------------------------------------------

def test_memory_sliding_window_pruning():
    store = MemorySlidingWindowStore(max_keys=100)
    now = datetime.now(timezone.utc)
    key = ("R-01", "10.0.0.5")

    # Add old event (120s ago)
    store.add_and_prune(key, now - timedelta(seconds=120), "fail", "ev-1", window_seconds=60)
    # Add recent event (10s ago)
    items = store.add_and_prune(key, now - timedelta(seconds=10), "fail", "ev-2", window_seconds=60)

    # Only recent event should remain in 60s window
    assert len(items) == 1
    assert items[0][2] == "ev-2"


def test_sliding_window_max_keys_bounded_memory():
    # Store bounded to 10 keys
    store = MemorySlidingWindowStore(max_keys=10)
    now = datetime.now(timezone.utc)

    # Insert 25 distinct keys
    for i in range(25):
        key = ("R-01", f"192.168.1.{i}")
        store.add_and_prune(key, now, "fail", f"ev-{i}", window_seconds=60)

    stats = store.get_stats()
    assert stats["active_keys"] <= 10, f"Memory exceeded key bound: {stats['active_keys']}"


def test_sliding_window_idle_ttl_eviction():
    store = MemorySlidingWindowStore(max_keys=100)
    now = datetime.now(timezone.utc)
    key = ("R-01", "10.0.0.99")
    store.add_and_prune(key, now, "fail", "ev-old", window_seconds=60)

    # Simulate access time 1000s in the past
    store._last_access[key] = time.time() - 1000
    evicted = store.evict_idle_keys(ttl_seconds=300)
    assert evicted == 1
    assert ("R-01", "10.0.0.99") not in store._windows


# ---------------------------------------------------------------------------
# 2. Incremental Rule Detection Tests
# ---------------------------------------------------------------------------

def test_stream_detector_r01_brute_force():
    reset_stream_detector()
    detector = StreamDetector()
    now = datetime.now(timezone.utc)
    src_ip = "192.168.56.220"

    # Feed 9 failures -> no alert
    for i in range(9):
        ev = _make_event(f"ev-bf-{i}", src_ip=src_ip, ts=now + timedelta(seconds=i))
        alerts = detector.process_event(ev)
        assert len(alerts) == 0

    # 10th failure crosses threshold (min_failures: 10)
    ev10 = _make_event("ev-bf-9", src_ip=src_ip, ts=now + timedelta(seconds=9))
    alerts = detector.process_event(ev10)
    assert len(alerts) == 1
    alt = alerts[0]
    assert "R-01" in alt.rule_ids
    assert alt.technique == "T1110.001"
    assert alt.tactic == "credential_access"
    assert alt.domain == Domain.authentication
    assert alt.src_ip == src_ip
    assert len(alt.evidence_event_ids) == 10

    # Verify persisted in DB
    db = SessionLocal()
    try:
        db_alt = db.query(AlertORM).filter(AlertORM.alert_id == alt.alert_id).first()
        assert db_alt is not None
        assert db_alt.conf == alt.conf
    finally:
        db.close()


def test_stream_detector_r02_password_spraying():
    reset_stream_detector()
    detector = StreamDetector()
    now = datetime.now(timezone.utc)
    src_ip = "192.168.56.221"

    users = ["user1", "user2", "user3", "user4"]
    for i, u in enumerate(users):
        ev = _make_event(f"ev-spray-{i}", src_ip=src_ip, user=u, ts=now + timedelta(seconds=i))
        assert len(detector.process_event(ev)) == 0

    # 5th distinct user triggers R-02
    ev5 = _make_event("ev-spray-4", src_ip=src_ip, user="user5", ts=now + timedelta(seconds=4))
    alerts = detector.process_event(ev5)
    assert len(alerts) == 1
    assert "R-02" in alerts[0].rule_ids
    assert alerts[0].technique == "T1110.003"


def test_stream_detector_r03_brute_force_then_success():
    reset_stream_detector()
    detector = StreamDetector()
    now = datetime.now(timezone.utc)
    src_ip = "192.168.56.222"
    target_user = "victim_admin"

    # 5 failed logins
    for i in range(5):
        ev = _make_event(f"ev-bf3-{i}", src_ip=src_ip, user=target_user, outcome=Outcome.failure, ts=now + timedelta(seconds=i))
        detector.process_event(ev)

    # Followed by a successful login
    ev_succ = _make_event("ev-bf3-succ", src_ip=src_ip, user=target_user, outcome=Outcome.success, ts=now + timedelta(seconds=6))
    alerts = detector.process_event(ev_succ)
    assert len(alerts) == 1
    assert "R-03" in alerts[0].rule_ids
    assert alerts[0].technique == "T1078"


def test_stream_detector_r04_vertical_port_scan():
    reset_stream_detector()
    detector = StreamDetector()
    now = datetime.now(timezone.utc)
    src_ip = "192.168.56.223"

    for port in range(1, 20):
        ev = _make_event(f"ev-ps-{port}", action="network_flow", outcome=Outcome.unknown, src_ip=src_ip, dst_port=port, ts=now + timedelta(seconds=port*0.1))
        assert len(detector.process_event(ev)) == 0

    # 20th distinct port triggers R-04
    ev20 = _make_event("ev-ps-20", action="network_flow", outcome=Outcome.unknown, src_ip=src_ip, dst_port=20, ts=now + timedelta(seconds=2.0))
    alerts = detector.process_event(ev20)
    assert len(alerts) == 1
    assert "R-04" in alerts[0].rule_ids
    assert alerts[0].technique == "T1046"


def test_stream_detector_r07_sudo_and_r10_account_creation():
    reset_stream_detector()
    detector = StreamDetector()

    # R-07 unauthorized sudo
    ev_sudo = _make_event("ev-sudo-1", action="sudo_command", features={"command": "/bin/bash"})
    alerts_sudo = detector.process_event(ev_sudo)
    assert len(alerts_sudo) == 1
    assert "R-07" in alerts_sudo[0].rule_ids

    # R-10 backdoor account creation
    ev_acc = _make_event("ev-acc-1", action="process_spawn", features={"command": "useradd -m hacker"})
    alerts_acc = detector.process_event(ev_acc)
    assert len(alerts_acc) == 1
    assert "R-10" in alerts_acc[0].rule_ids


# ---------------------------------------------------------------------------
# 3. Streaming Fusion & ML Fallback Tests
# ---------------------------------------------------------------------------

def test_streaming_fusion_formula():
    cfg = {"dual_signal_bonus": 0.1, "dual_signal_threshold": 0.5}

    # Single signal: no bonus
    score1 = fuse_alert(rule_conf=0.7, ml_score=None, fusion_cfg=cfg)
    assert score1 == 0.7

    # Both below threshold: max without bonus
    score2 = fuse_alert(rule_conf=0.4, ml_score=0.45, fusion_cfg=cfg)
    assert score2 == 0.45

    # Both above dual_signal_threshold (0.5): max + bonus
    score3 = fuse_alert(rule_conf=0.8, ml_score=0.85, fusion_cfg=cfg)
    assert score3 == min(1.0, 0.85 + 0.1)


def test_ml_stream_scorer_zero_cost_fallback():
    scorer = MLStreamScorer(models_dir="data/models/non_existent")
    ev = _make_event("ev-test-ml")

    t0 = time.perf_counter()
    score, model_id = scorer.score_event(ev)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert score is None
    assert model_id is None
    assert elapsed_ms < 1.0, f"Zero-cost fallback took {elapsed_ms} ms (budget < 1 ms)"


# ---------------------------------------------------------------------------
# 4. Latency & Event Bus Integration Benchmark (< 50 ms)
# ---------------------------------------------------------------------------

def test_stream_detector_latency_budget():
    reset_stream_detector()
    detector = StreamDetector()
    now = datetime.now(timezone.utc)
    src_ip = "192.168.56.225"

    for i in range(9):
        ev = _make_event(f"ev-lat-{i}", src_ip=src_ip, ts=now + timedelta(seconds=i))
        detector.process_event(ev)

    ev_trigger = _make_event("ev-lat-9", src_ip=src_ip, ts=now + timedelta(seconds=9))

    t0 = time.perf_counter()
    alerts = detector.process_event(ev_trigger)
    lat_ms = (time.perf_counter() - t0) * 1000.0

    print(f"\n[CEP BENCHMARK] Event-to-Alert latency: {lat_ms:.3f} ms")
    assert len(alerts) == 1
    assert lat_ms < 50.0, f"Detection latency {lat_ms:.3f} ms exceeded 50 ms SLA"


def test_stream_detector_event_bus_handle_message():
    async def _run():
        bus = AsyncioEventBus()
        detector = StreamDetector()
        now = datetime.now(timezone.utc)
        src_ip = "192.168.56.230"

        # Prime with 9 failures
        for i in range(9):
            ev = _make_event(f"ev-bus-{i}", src_ip=src_ip, ts=now + timedelta(seconds=i))
            detector.process_event(ev)

        # 10th failure as StreamMessage
        ev10 = _make_event("ev-bus-9", src_ip=src_ip, ts=now + timedelta(seconds=9))
        msg = StreamMessage(
            topic="events",
            event_type="event_ingested",
            payload={"event": ev10.model_dump()},
        )

        alerts = await detector.handle_stream_message(msg, bus)
        assert len(alerts) == 1
        assert "R-01" in alerts[0].rule_ids
        assert bus.get_queue_depth("alerts") == 1

    asyncio.run(_run())
