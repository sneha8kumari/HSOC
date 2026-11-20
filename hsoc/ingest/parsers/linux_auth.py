"""
Parse Linux /var/log/auth.log lines (sshd, sudo, su events).

Returns a dict with normalised fields; the mapper converts it to Event.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Example lines:
# Oct 25 14:02:10 srv-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 44322 ssh2
# Oct 25 14:02:15 srv-01 sshd[1235]: Accepted password for alice from 192.168.1.50 port 44324 ssh2
# Oct 25 14:05:00 srv-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
# 2026-10-25T14:02:10Z srv-01 sshd[1234]: Failed password for admin from 192.168.1.100 port 44322 ssh2

_SSHD_FAIL_RE = re.compile(
    r"(?:Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)|"
    r"authentication failure;.*user=(?P<user2>\S+).*rhost=(?P<src_ip2>\S+))"
)
_SSHD_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"(?:sudo:\s+)?(?P<user>\S+)\s+:.*USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)"
)
_SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)|(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)


def parse(line: str) -> dict[str, Any]:
    """
    Parse a single raw auth.log line.

    Args:
        line: Raw log line string.

    Returns:
        Dict with normalised keys, or raises ValueError on parse failure.
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty log line")

    match = _SYSLOG_PREFIX_RE.match(line)
    if not match:
        raise ValueError(f"Unrecognized syslog format: {line[:50]}...")

    ts_raw = match.group("ts")
    host = match.group("host")
    msg = match.group("msg")

    # Timestamp normalization
    if "T" in ts_raw:
        dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    else:
        # Standard syslog format without year: "Oct 25 14:02:10"
        current_year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{current_year} {ts_raw}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )

    event_data: dict[str, Any] = {
        "ts": dt.isoformat(),
        "source_type": "linux_auth",
        "host": host,
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "user": None,
        "action": "auth_event",
        "outcome": "unknown",
        "raw": line,
        "features": {},
    }

    fail_m = _SSHD_FAIL_RE.search(msg)
    if fail_m:
        user = fail_m.group("user") or fail_m.group("user2")
        src_ip = fail_m.group("src_ip") or fail_m.group("src_ip2")
        port = fail_m.group("port")
        event_data.update(
            {
                "user": user,
                "src_ip": src_ip,
                "dst_port": int(port) if port else 22,
                "action": "ssh_login",
                "outcome": "failure",
            }
        )
        return event_data

    accept_m = _SSHD_ACCEPT_RE.search(msg)
    if accept_m:
        event_data.update(
            {
                "user": accept_m.group("user"),
                "src_ip": accept_m.group("src_ip"),
                "dst_port": int(accept_m.group("port")),
                "action": "ssh_login",
                "outcome": "success",
            }
        )
        return event_data

    sudo_m = _SUDO_RE.search(msg)
    if sudo_m:
        event_data.update(
            {
                "user": sudo_m.group("user"),
                "action": "sudo_command",
                "outcome": "success",
                "features": {
                    "target_user": sudo_m.group("target_user"),
                    "command": sudo_m.group("command"),
                },
            }
        )
        return event_data

    # Generic auth event
    event_data["action"] = "system_auth"
    event_data["outcome"] = "unknown"
    return event_data
