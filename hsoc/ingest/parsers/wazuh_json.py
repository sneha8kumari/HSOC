"""
Parse Wazuh alert JSON records.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def parse(line: str | dict[str, Any]) -> dict[str, Any]:
    """
    Parse a single Wazuh JSON log line or dictionary.

    Args:
        line: Raw JSON line string or dict.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    if isinstance(line, dict):
        doc = line
    else:
        line_str = str(line).strip()
        if not line_str:
            raise ValueError("Empty Wazuh log line")
        try:
            doc = json.loads(line_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in Wazuh alert: {exc}") from exc

    ts_raw = doc.get("timestamp") or doc.get("@timestamp")
    if ts_raw:
        try:
            dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    agent = doc.get("agent", {})
    host = agent.get("name") if isinstance(agent, dict) else str(agent)
    agent_id = agent.get("id") if isinstance(agent, dict) else None
    agent_ip = agent.get("ip") if isinstance(agent, dict) else None

    data = doc.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
    rule = doc.get("rule", {})

    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or win_eventdata.get("ipAddress")
        or doc.get("predecoder", {}).get("srcip")
    )
    if src_ip in ("-", "127.0.0.1", "::1"):
        src_ip = None

    dst_ip = (
        data.get("dstip")
        or data.get("dst_ip")
        or win_eventdata.get("destAddress")
        or agent_ip
    )
    if dst_ip in ("-", "127.0.0.1", "::1"):
        dst_ip = None

    dst_port_raw = (
        data.get("dstport")
        or data.get("dst_port")
        or win_eventdata.get("destPort")
    )
    dst_port: int | None = None
    if dst_port_raw and str(dst_port_raw).isdigit():
        dst_port = int(dst_port_raw)

    user = (
        data.get("dstuser")
        or data.get("srcuser")
        or win_eventdata.get("targetUserName")
        or win_eventdata.get("subjectUserName")
    )

    action = rule.get("description", "wazuh_alert")
    level = rule.get("level", 1)
    outcome = "failure" if level >= 5 else "success"

    # Extract MITRE techniques and tactics
    mitre_data = rule.get("mitre", {})
    mitre_techniques = []
    mitre_tactics = []
    if isinstance(mitre_data, dict):
        tech_id = mitre_data.get("id")
        if tech_id:
            mitre_techniques = [tech_id] if isinstance(tech_id, str) else list(tech_id)
        tact_name = mitre_data.get("tactic")
        if tact_name:
            mitre_tactics = [tact_name] if isinstance(tact_name, str) else list(tact_name)

    decoder = doc.get("decoder", {})
    decoder_name = decoder.get("name") if isinstance(decoder, dict) else str(decoder)
    manager = doc.get("manager", {})
    manager_name = manager.get("name") if isinstance(manager, dict) else str(manager)

    return {
        "ts": dt.isoformat(),
        "source_type": "wazuh",
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": user,
        "action": action,
        "outcome": outcome,
        "raw": line,
        "features": {
            "rule_id": rule.get("id"),
            "rule_level": level,
            "groups": rule.get("groups", []),
            "mitre": mitre_data,
            "mitre_techniques": mitre_techniques,
            "mitre_tactics": mitre_tactics,
            "agent_id": agent_id,
            "agent_ip": agent_ip,
            "manager_name": manager_name,
            "decoder_name": decoder_name,
            "location": doc.get("location"),
            "full_log": doc.get("full_log"),
        },
    }
