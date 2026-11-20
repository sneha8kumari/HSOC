"""
Parse Windows Security Event logs (Event IDs 4624, 4625, 4720, 4728, etc.).

Supports JSON serialized Windows Event format or key-value event lines.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def parse(line: str | dict[str, Any]) -> dict[str, Any]:
    """
    Parse a single Windows Security event line (JSON, dict, or structured text).

    Args:
        line: Raw log string or dict.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    if isinstance(line, dict):
        data = line
        event_id = str(data.get("EventID") or data.get("event_id") or data.get("Id") or data.get("id", ""))
        ts_raw = data.get("TimeCreated") or data.get("timestamp") or data.get("@timestamp")
        if ts_raw:
            try:
                dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        user = data.get("TargetUserName") or data.get("user") or data.get("SubjectUserName")
        host = data.get("MachineName") or data.get("Computer") or data.get("host") or "localhost"
        src_ip = data.get("IpAddress") or data.get("src_ip") or data.get("SourceNetworkAddress") or data.get("LocalAddress")
        dst_ip = data.get("dst_ip") or data.get("RemoteAddress")
        dst_port = data.get("dst_port") or data.get("RemotePort")
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = None

        if not src_ip and isinstance(data.get("Properties"), list):
            for prop in data["Properties"]:
                val = str(prop.get("Value", "")) if isinstance(prop, dict) else str(prop)
                if val.count(".") == 3 and not val.endswith(".exe"):
                    src_ip = val
                    break

        action = "logon_failure" if event_id in ("4625", "4776") else "logon_success" if event_id == "4624" else f"event_{event_id}"
        summary = data.get("Message") or f"Windows Event {event_id} on {host}"

        return {
            "timestamp": dt.isoformat(),
            "event_type": f"windows_event_{event_id}" if event_id else "windows_network_connection",
            "source": "windows_network" if "RemoteAddress" in data or "LocalAddress" in data else "windows_event",
            "entity_id": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "user": user,
            "action": action,
            "summary": summary,
            "raw_payload": data,
            "is_simulated": False,
        }

    line = line.strip()
    if not line:
        raise ValueError("Empty Windows Security log line")

    # Attempt JSON parse first (Wazuh/Sysmon/Winlogbeat format)
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in Windows log: {exc}") from exc

        event_id = str(data.get("EventID") or data.get("event_id") or data.get("id", ""))
        ts_raw = data.get("TimeCreated") or data.get("timestamp") or data.get("@timestamp")
        if ts_raw:
            try:
                dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        user = data.get("TargetUserName") or data.get("user") or data.get("SubjectUserName")
        src_ip = data.get("IpAddress") or data.get("src_ip")
        if src_ip in ("-", "127.0.0.1", "::1"):
            src_ip = None
        host = data.get("Computer") or data.get("host") or data.get("WorkstationName")

        outcome = "unknown"
        action = f"win_event_{event_id}" if event_id else "win_security"

        if event_id == "4624":
            action = "win_logon"
            outcome = "success"
        elif event_id == "4625":
            action = "win_logon"
            outcome = "failure"
        elif event_id == "4720":
            action = "user_created"
            outcome = "success"
        elif event_id in ("4728", "4732"):
            action = "group_membership_add"
            outcome = "success"
        elif event_id == "7045":
            action = "service_installed"
            outcome = "success"
        elif event_id == "4688":
            action = "process_create"
            outcome = "success"
        elif event_id == "4672":
            action = "special_privilege_assigned"
            outcome = "success"
        elif event_id == "5140":
            action = "network_share_access"
            outcome = "success"
        elif data.get("type") == "network_connection" or data.get("source_type") == "windows_network":
            action = "network_connection"
            outcome = "success"

        dst_ip = data.get("DestinationIp") or data.get("dst_ip") or data.get("RemoteAddress")
        if dst_ip in ("-", "127.0.0.1", "::1"):
            dst_ip = None
        dst_port_raw = data.get("DestinationPort") or data.get("dst_port") or data.get("RemotePort")
        dst_port = int(dst_port_raw) if dst_port_raw and str(dst_port_raw).isdigit() else None

        return {
            "ts": dt.isoformat(),
            "source_type": "win_security",
            "host": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "user": user,
            "action": action,
            "outcome": outcome,
            "raw": line,
            "features": {"event_id": event_id, "data": data},
        }

    # Tab/comma/space separated key=value format fallback
    parts = dict(re_kv.split("=", 1) for re_kv in line.split() if "=" in re_kv)
    if not parts:
        raise ValueError(f"Unrecognized Windows Security format: {line[:50]}...")

    ts_raw = parts.get("ts") or parts.get("TimeCreated")
    dt = (
        datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        if ts_raw
        else datetime.now(timezone.utc)
    )
    event_id = str(parts.get("EventID") or parts.get("event_id", ""))

    outcome = "unknown"
    if event_id == "4624":
        action = "win_logon"
        outcome = "success"
    elif event_id == "4625":
        action = "win_logon"
        outcome = "failure"
    elif event_id == "4720":
        action = "user_created"
        outcome = "success"
    elif event_id in ("4728", "4732"):
        action = "group_membership_add"
        outcome = "success"
    else:
        action = f"win_event_{event_id}" if event_id else "win_security"

    return {
        "ts": dt.isoformat(),
        "source_type": "win_security",
        "host": parts.get("host") or parts.get("Computer"),
        "src_ip": parts.get("src_ip") or parts.get("IpAddress"),
        "dst_ip": parts.get("dst_ip"),
        "dst_port": None,
        "user": parts.get("user") or parts.get("TargetUserName"),
        "action": action,
        "outcome": outcome,
        "raw": line,
        "features": {"event_id": event_id},
    }
