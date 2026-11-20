"""Parser modules for each log / flow source type."""

from __future__ import annotations

from typing import Any, Callable

from hsoc.ingest.parsers import (
    apache,
    cicflow,
    lanl_auth,
    linux_auth,
    unsw,
    wazuh_json,
    win_security,
)

PARSER_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    "linux_auth": linux_auth.parse,
    "win_security": win_security.parse,
    "apache": apache.parse,
    "flow": cicflow.parse,
    "cicflow": cicflow.parse,
    "lanl_auth": lanl_auth.parse,
    "wazuh": wazuh_json.parse,
    "wazuh_json": wazuh_json.parse,
    "wazuh_alert": wazuh_json.parse,
    "windows_event": win_security.parse,
    "windows_network": win_security.parse,
    "unsw": unsw.parse,
}

__all__ = [
    "PARSER_REGISTRY",
    "apache",
    "cicflow",
    "lanl_auth",
    "linux_auth",
    "unsw",
    "wazuh_json",
    "win_security",
]
