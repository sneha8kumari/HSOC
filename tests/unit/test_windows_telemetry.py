"""
Unit tests for Windows Laptop Telemetry Integration.
Tests:
  - Windows security event log parser normalization (Event IDs 4625, 4624, 7045, etc.)
  - Windows NetTCP connection metadata normalization
  - WindowsTelemetryCollector queueing and poll behavior
  - Windows router endpoints (/status, /collect, /ingest)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from hsoc.api.main import app
from hsoc.ingest.parsers.win_security import parse as parse_win_security_json
from hsoc.ingest.windows_collector import WindowsTelemetryCollector
from hsoc.schema import Event, SourceType


SAMPLE_WIN_LOGON_FAIL = {
    "Id": 4625,
    "TimeCreated": "2026-11-19T10:30:00.000Z",
    "MachineName": "DESKTOP-ANALYST1",
    "LogName": "Security",
    "Message": "An account failed to log on. Subject: User SID: S-1-0-0. Account Name: Administrator. Failure Reason: Unknown user name or bad password.",
    "Properties": [
        {"Value": "DESKTOP-ANALYST1"},
        {"Value": "Administrator"},
        {"Value": "0xC000006D"},
        {"Value": "192.168.1.105"},
        {"Value": "49200"}
    ]
}

SAMPLE_WIN_SERVICE_INSTALL = {
    "Id": 7045,
    "TimeCreated": "2026-11-19T10:35:00.000Z",
    "MachineName": "DESKTOP-ANALYST1",
    "LogName": "System",
    "Message": "A service was installed in the system. Service Name: PSServiceExec. Service File Name: C:\\Users\\Public\\bad.exe",
    "Properties": [
        {"Value": "PSServiceExec"},
        {"Value": "C:\\Users\\Public\\bad.exe"}
    ]
}

SAMPLE_NET_CONNECTION = {
    "LocalAddress": "192.168.1.55",
    "LocalPort": 49152,
    "RemoteAddress": "203.0.113.88",
    "RemotePort": 4444,
    "State": "Established",
    "OwningProcess": 4512,
    "ProcessName": "powershell.exe",
    "CreationTime": "2026-11-19T10:38:00.000Z"
}


def test_win_security_logon_fail_parsing():
    """Verify parse_win_security_json handles 4625 failed logons."""
    event = parse_win_security_json(SAMPLE_WIN_LOGON_FAIL)

    assert event["source"] == "windows_event"
    assert event["event_type"] == "windows_event_4625"
    assert event["entity_id"] == "DESKTOP-ANALYST1"
    assert event["is_simulated"] is False
    assert event["src_ip"] == "192.168.1.105"
    assert "Logon" in event["summary"] or "failed" in event["summary"].lower()


def test_win_system_service_install_parsing():
    """Verify parse_win_security_json handles 7045 service installation."""
    event = parse_win_security_json(SAMPLE_WIN_SERVICE_INSTALL)

    assert event["source"] == "windows_event"
    assert event["event_type"] == "windows_event_7045"
    assert event["entity_id"] == "DESKTOP-ANALYST1"
    assert "PSServiceExec" in event["summary"]


def test_win_network_connection_parsing():
    """Verify parse_win_security_json handles network connection records."""
    event = parse_win_security_json(SAMPLE_NET_CONNECTION)

    assert event["source"] == "windows_network"
    assert event["event_type"] == "windows_network_connection"
    assert event["src_ip"] == "192.168.1.55"
    assert event["dst_ip"] == "203.0.113.88"
    assert event["dst_port"] == 4444
    assert event["raw_payload"]["ProcessName"] == "powershell.exe"


def test_windows_collector_queue_and_poll():
    """Verify WindowsTelemetryCollector buffers and flushes events safely."""
    collector = WindowsTelemetryCollector(max_buffer_size=100)

    collector.buffer_events([SAMPLE_WIN_LOGON_FAIL, SAMPLE_NET_CONNECTION])
    status = collector.get_status()
    assert status["buffer_depth"] == 2

    flushed = collector.flush_buffer()
    assert len(flushed) == 2
    assert collector.get_status()["buffer_depth"] == 0


def test_windows_router_endpoints():
    """Verify FastAPI routes for Windows telemetry: /status and /ingest."""
    test_client = TestClient(app)

    # Status check
    status_res = test_client.get("/api/v1/telemetry/windows/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "status" in status_data
    assert "is_windows" in status_data

    # Ingest endpoint
    payload = {
        "events": [SAMPLE_WIN_LOGON_FAIL],
        "network_connections": [SAMPLE_NET_CONNECTION],
    }
    ingest_res = test_client.post("/api/v1/telemetry/windows/ingest", json=payload)
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert data["status"] == "success"
    assert data["accepted"] >= 1
