"""
Parse LANL Cybersecurity Dataset auth.txt rows.

Format:
  time,source_user@domain,dest_user@domain,source_computer,dest_computer,auth_type,logon_type,auth_orientation,success_or_failure
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# Baseline reference epoch for LANL integer timestamps
_LANL_EPOCH = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def parse(line: str) -> dict[str, Any]:
    """
    Parse a single LANL authentication CSV line.

    Args:
        line: Raw comma-separated string line.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty LANL auth line")

    parts = line.split(",")
    if len(parts) < 9:
        raise ValueError(f"LANL auth line requires 9 columns, found {len(parts)}")

    time_sec_str, src_user, dst_user, src_comp, dst_comp, auth_type, logon_type, orientation, status = (
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
        parts[5],
        parts[6],
        parts[7],
        parts[8],
    )

    try:
        sec = int(time_sec_str)
        dt = _LANL_EPOCH + timedelta(seconds=sec)
    except ValueError:
        # If timestamp is already ISO string
        try:
            dt = datetime.fromisoformat(time_sec_str.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)

    user = dst_user if dst_user and dst_user != "?" else src_user
    outcome = "success" if status.lower().startswith("succ") else "failure"

    return {
        "ts": dt.isoformat(),
        "source_type": "lanl_auth",
        "host": dst_comp,
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "user": user,
        "action": f"lanl_{logon_type.lower()}",
        "outcome": outcome,
        "raw": line,
        "features": {
            "auth_type": auth_type,
            "logon_type": logon_type,
            "auth_orientation": orientation,
            "source_computer": src_comp,
            "dest_computer": dst_comp,
        },
    }
