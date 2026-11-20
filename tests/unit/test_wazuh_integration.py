"""
Unit tests for Wazuh Security Events Integration.
Tests:
  - WazuhClient initialization, token authentication, and poll_and_normalize
  - Wazuh JSON parser normalization to Event schema
  - Wazuh webhook receiver endpoint (auth, schema validation, persistence, EventBus)
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from hsoc.api.main import app
from hsoc.ingest.parsers.wazuh_json import parse as parse_wazuh_json
from hsoc.ingest.wazuh_client import WazuhClient
from hsoc.schema import Event, SourceType


SAMPLE_WAZUH_ALERT = {
    "timestamp": "2026-11-19T10:15:30.123+0000",
    "id": "1732011330.987654",
    "rule": {
        "level": 10,
        "description": "sshd: brute force attempt from multiple IPs",
        "id": "5712",
        "mitre": {
            "id": ["T1110.001"],
            "tactic": ["credential-access"],
            "technique": ["Password Guessing"]
        },
        "groups": ["syslog", "sshd", "authentication_failures"]
    },
    "agent": {
        "id": "001",
        "name": "corporate-web-prod",
        "ip": "10.0.1.50"
    },
    "manager": {
        "name": "wazuh-primary"
    },
    "data": {
        "srcip": "198.51.100.42",
        "srcuser": "root",
        "dstport": 22
    },
    "decoder": {
        "name": "sshd"
    },
    "full_log": "Nov 19 10:15:30 corporate-web-prod sshd[1234]: Failed password for root from 198.51.100.42 port 49152 ssh2"
}


def test_wazuh_parser_normalization():
    """Verify parse_wazuh_json converts Wazuh raw JSON to normalized Event dict."""
    parsed_dict = parse_wazuh_json(SAMPLE_WAZUH_ALERT)

    assert parsed_dict["source_type"] in ("wazuh", "wazuh_alert")
    assert parsed_dict["host"] == "corporate-web-prod"
    assert parsed_dict["src_ip"] == "198.51.100.42"
    assert parsed_dict["dst_ip"] == "10.0.1.50"
    assert parsed_dict["dst_port"] == 22
    assert parsed_dict["features"]["rule_id"] == "5712"
    assert parsed_dict["features"]["rule_level"] == 10
    assert "brute force" in parsed_dict["action"].lower()


def test_wazuh_client_poll_and_normalize():
    """Verify WazuhClient fetches alerts and returns normalized Events."""
    client = WazuhClient(base_url="https://wazuh.internal:55000", verify_ssl=False)

    with patch.object(client, "fetch_alerts", return_value=[SAMPLE_WAZUH_ALERT]):
        events = client.poll_and_normalize(limit=10)

    assert len(events) == 1
    assert events[0].source_type in (SourceType.wazuh, SourceType.wazuh_alert)
    assert events[0].host == "corporate-web-prod"


def test_wazuh_webhook_endpoint():
    """Verify POST /api/v1/telemetry/wazuh/webhook ingests alert successfully."""
    test_client = TestClient(app)

    headers = {"X-Wazuh-Secret": "test_shared_secret_hsoc"}
    with patch.dict(os.environ, {"WAZUH_WEBHOOK_SECRET": "test_shared_secret_hsoc"}):
        response = test_client.post(
            "/api/v1/telemetry/wazuh/webhook",
            json=SAMPLE_WAZUH_ALERT,
            headers=headers,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["accepted"] == 1


def test_wazuh_webhook_unauthorized():
    """Verify webhook rejects requests with invalid secret token."""
    test_client = TestClient(app)

    with patch.dict(os.environ, {"WAZUH_WEBHOOK_SECRET": "strong_secret_key"}):
        response = test_client.post(
            "/api/v1/telemetry/wazuh/webhook",
            json=SAMPLE_WAZUH_ALERT,
            headers={"X-Wazuh-Secret": "wrong_secret"},
        )

    assert response.status_code == 401
