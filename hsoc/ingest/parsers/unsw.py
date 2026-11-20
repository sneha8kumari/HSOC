"""
Parse UNSW-NB15 CSV records.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any


def parse(line: str) -> dict[str, Any]:
    """
    Parse a single UNSW-NB15 CSV record.

    Args:
        line: Raw CSV row string.

    Returns:
        Dict with normalised fields, or raises ValueError on parse failure.
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty UNSW record")

    reader = csv.reader(io.StringIO(line))
    row = next(reader)
    if not row or len(row) < 5:
        raise ValueError(f"UNSW row too short: {len(row)} columns")

    # If header
    if row[0].lower() in ("srcip", "src_ip", "id"):
        raise ValueError("Header row, not a data line")

    # Standard UNSW-NB15 format usually has:
    # srcip, sport, dstip, dsport, proto...
    src_ip = row[0]
    try:
        src_port = int(row[1]) if row[1] else None
    except ValueError:
        src_port = None

    dst_ip = row[2]
    try:
        dst_port = int(row[3]) if row[3] else None
    except ValueError:
        dst_port = None

    proto = row[4] if len(row) > 4 else "tcp"
    label = row[-1] if len(row) > 10 else None

    dt = datetime.now(timezone.utc)

    return {
        "ts": dt.isoformat(),
        "source_type": "flow",
        "host": None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": None,
        "action": "unsw_flow",
        "outcome": "success",
        "raw": line,
        "features": {
            "proto": proto,
            "src_port": src_port,
        },
        "label": label if label and label not in ("0", "normal", "benign") else None,
    }
