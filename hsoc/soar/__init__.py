"""
H-SOC SOAR (Security Orchestration, Automation, and Response) Containment Module.

Provides safe, simulated containment actions (block_ip, isolate_host, disable_user)
with strict target validation, safety guardrails, audit logging, and rollback.
"""

from hsoc.soar.actions import (
    ContainmentAction,
    BlockIPAction,
    IsolateHostAction,
    DisableUserAction,
    SOAREngine,
    get_soar_engine,
)

__all__ = [
    "ContainmentAction",
    "BlockIPAction",
    "IsolateHostAction",
    "DisableUserAction",
    "SOAREngine",
    "get_soar_engine",
]
