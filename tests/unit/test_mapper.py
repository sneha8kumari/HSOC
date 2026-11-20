"""
Unit tests for mapper and quarantine logic.
"""

from hsoc.ingest.mapper import map_to_event
from hsoc.schema import Event, QuarantineRecord, SourceType


def test_mapper_valid_dict():
    parsed = {
        "ts": "2026-10-25T14:02:10+00:00",
        "source_type": "linux_auth",
        "host": "srv-01",
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "dst_port": 22,
        "user": "alice",
        "action": "ssh_login",
        "outcome": "success",
        "raw": "raw ssh line",
    }
    result = map_to_event(parsed, "linux_auth")
    assert isinstance(result, Event)
    assert result.source_type == SourceType.linux_auth
    assert result.user == "alice"
    assert result.action == "ssh_login"


def test_mapper_quarantine_on_invalid_timestamp():
    parsed = {
        "ts": "not-a-valid-timestamp",
        "source_type": "linux_auth",
        "action": "ssh_login",
        "raw": "bad timestamp log line",
    }
    result = map_to_event(parsed, "linux_auth")
    assert isinstance(result, QuarantineRecord)
    assert result.parser == "linux_auth"
    assert "Validation failed" in result.reason
    assert result.raw == "bad timestamp log line"


def test_mapper_quarantine_on_missing_action():
    parsed = {
        "ts": "2026-10-25T14:02:10+00:00",
        "source_type": "linux_auth",
        # missing action
        "raw": "line without action",
    }
    result = map_to_event(parsed, "linux_auth")
    assert isinstance(result, QuarantineRecord)
    assert "action" in result.reason
