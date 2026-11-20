"""
Attack-chain builder: constructs timeline and analyzes kill-chain progression.

Sorts alerts chronologically, constructs TimelineItem objects,
and flags out_of_order_stage if tactics go backwards in kill-chain order.
"""

from __future__ import annotations

from hsoc.investigate.domain import TACTIC_ORDER
from hsoc.schema import Alert, Incident, TimelineItem


def build_chain(incident: Incident, alerts: list[Alert]) -> Incident:
    """
    Build the attack-chain graph and sorted timeline for an incident.

    Args:
        incident: The incident to enrich.
        alerts: All alerts belonging to this incident.

    Returns:
        The incident with timeline and out_of_order_stage set.
    """
    if not alerts:
        incident.timeline = []
        incident.out_of_order_stage = False
        return incident

    # Chronological sort
    sorted_alerts = sorted(alerts, key=lambda a: a.ts)

    timeline: list[TimelineItem] = []
    techniques: list[str] = []
    tactics: list[str] = []

    last_tactic_idx = -1
    has_out_of_order = False

    for al in sorted_alerts:
        tactic_name = (al.tactic or "").lower()
        is_step_out_of_order = False

        if tactic_name in TACTIC_ORDER:
            curr_idx = TACTIC_ORDER.index(tactic_name)
            if last_tactic_idx >= 0 and curr_idx < last_tactic_idx:
                is_step_out_of_order = True
                has_out_of_order = True
            last_tactic_idx = max(last_tactic_idx, curr_idx)

        item = TimelineItem(
            alert_id=al.alert_id,
            ts=al.ts,
            technique=al.technique,
            tactic=al.tactic,
            description=al.description,
            out_of_order=is_step_out_of_order,
        )
        timeline.append(item)

        if al.technique and al.technique not in techniques:
            techniques.append(al.technique)
        if al.tactic and al.tactic not in tactics:
            tactics.append(al.tactic)

    incident.timeline = timeline
    incident.techniques = techniques
    incident.tactics = tactics
    incident.out_of_order_stage = has_out_of_order
    return incident
