"""
Parse CICFlowMeter CSV flow rows.

Handles either a comma-delimited string line or a pre-split CSV row.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any


def parse(line: str) -> dict[str, Any]:
    """
    Parse a single CICFlowMeter CSV row.

    Args:
        line: Raw CSV row string.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty flow line")

    reader = csv.reader(io.StringIO(line))
    row = next(reader)
    if not row or len(row) < 5:
        raise ValueError(f"Too few columns in CICFlow row: {len(row)}")

    # Common CICFlow standard or simplified format:
    # Option A (Standard):
    # Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration...
    # Option B (Named or minimal):
    # ts, src_ip, src_port, dst_ip, dst_port, protocol, duration, fwd_pkts, bwd_pkts, label...

    # Auto-detect if headers are present
    if row[0].lower() in ("flow id", "ts", "timestamp", "source ip"):
        raise ValueError("Header row, not a data line")

    try:
        # Check if row[0] is a timestamp or an ID
        ts_val = row[0]
        try:
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            src_ip = row[1]
            src_port = int(row[2]) if row[2] else None
            dst_ip = row[3]
            dst_port = int(row[4]) if row[4] else None
            protocol = row[5] if len(row) > 5 else "TCP"
            label = row[-1] if len(row) > 6 else None
        except ValueError:
            # Maybe flow_id, src_ip, src_port, dst_ip, dst_port, proto, ts...
            src_ip = row[1]
            src_port = int(row[2]) if row[2] else None
            dst_ip = row[3]
            dst_port = int(row[4]) if row[4] else None
            protocol = row[5] if len(row) > 5 else "TCP"
            ts_val = row[6] if len(row) > 6 else datetime.now(timezone.utc).isoformat()
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            label = row[-1] if len(row) > 7 else None

    except Exception as exc:
        raise ValueError(f"Failed to parse flow row '{line[:40]}...': {exc}") from exc

    features: dict[str, Any] = {
        "protocol": protocol,
        "src_port": src_port,
    }
    if len(row) > 7:
        try:
            features["flow_duration"] = float(row[7])
        except (ValueError, IndexError):
            pass

    return {
        "ts": dt.isoformat(),
        "source_type": "flow",
        "host": None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": None,
        "action": "network_flow",
        "outcome": "success",
        "raw": line,
        "features": features,
        "label": label if label and label.lower() not in ("benign", "none") else None,
    }
