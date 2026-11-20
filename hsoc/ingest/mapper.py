"""
Mapper: normalises parsed dicts into Event Pydantic models.

Each parser returns a raw dict; this module applies field mapping,
coerces types, and handles unknown keys gracefully.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError

from hsoc.schema import Event, QuarantineRecord, SourceType

logger = logging.getLogger(__name__)


def map_to_event(parsed: dict[str, Any], parser: str) -> Event | QuarantineRecord:
    """
    Convert a parser output dict to an Event or a QuarantineRecord.

    Args:
        parsed: Raw dict from a parser.
        parser: Name of the parser that produced it (for quarantine attribution).

    Returns:
        An Event on success, or a QuarantineRecord on validation failure.
    """
    raw_str = str(parsed.get("raw", ""))
    source_type_raw = parsed.get("source_type")

    try:
        # Validate or coerce source_type enum
        if isinstance(source_type_raw, str):
            if source_type_raw == "wazuh_json":
                parsed["source_type"] = SourceType.wazuh
            elif source_type_raw == "cicflow":
                parsed["source_type"] = SourceType.flow
            else:
                parsed["source_type"] = SourceType(source_type_raw)

        # Build Event
        event = Event(**parsed)
        return event

    except (ValidationError, ValueError, TypeError) as exc:
        logger.warning(
            "Validation failure in mapper for parser %s: %s (raw: %s)",
            parser,
            exc,
            raw_str[:100],
        )
        return QuarantineRecord(
            source_type=str(source_type_raw) if source_type_raw else parser,
            raw=raw_str or str(parsed),
            reason=f"Validation failed: {str(exc)}",
            parser=parser,
        )
