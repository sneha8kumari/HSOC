"""
Parse Apache combined access log lines.

Format:
  %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Example: 192.168.56.100 - admin [25/Oct/2026:14:02:10 +0000] "GET /admin HTTP/1.1" 401 512 "http://example.com" "Mozilla/5.0"
_APACHE_COMBINED_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def parse(line: str) -> dict[str, Any]:
    """
    Parse a single Apache combined access log line.

    Args:
        line: Raw log line string.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty Apache log line")

    match = _APACHE_COMBINED_RE.match(line)
    if not match:
        raise ValueError(f"Unrecognized Apache log format: {line[:50]}...")

    src_ip = match.group("src_ip")
    user_raw = match.group("user")
    user = None if user_raw == "-" else user_raw
    ts_raw = match.group("ts")

    # Time format: 25/Oct/2026:14:02:10 +0000
    try:
        dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        # Fallback without timezone or ISO format
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)

    status_code = int(match.group("status"))
    method = match.group("method")
    path = match.group("path")

    # Determine outcome based on HTTP status
    outcome = "success" if 200 <= status_code < 400 else "failure"

    return {
        "ts": dt.isoformat(),
        "source_type": "apache",
        "host": None,
        "src_ip": src_ip,
        "dst_ip": None,
        "dst_port": 80,
        "user": user,
        "action": f"http_{method.lower()}",
        "outcome": outcome,
        "raw": line,
        "features": {
            "method": method,
            "path": path,
            "status_code": status_code,
            "bytes": int(match.group("bytes")) if match.group("bytes") != "-" else 0,
            "user_agent": match.group("user_agent"),
        },
    }
