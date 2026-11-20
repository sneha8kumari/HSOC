"""
InvestigatorAgent: Discovers and calls allow-listed read-only tools to assemble evidence.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from hsoc.config import get_settings
from hsoc.genai.agents.context import IncidentContext
from hsoc.genai.agents.tools import ToolDispatcher
from hsoc.genai.sanitize import wrap_evidence

logger = logging.getLogger(__name__)


class InvestigatorAgent:
    """Gathers events, graph connections, asset criticality, and user identity."""

    def __init__(self, name: str = "InvestigatorAgent") -> None:
        self.name = name

    def execute(self, context: IncidentContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        incident = context.incident
        tool_records: list[dict[str, Any]] = []

        all_events: list[dict[str, Any]] = []
        assets_info: dict[str, Any] = {}
        users_info: dict[str, Any] = {}
        all_neighbors: set[str] = set()

        max_lines = int(get_settings().genai.get("max_evidence_lines", 20))

        # 1. Investigate each entity key (IP, host, user)
        for entity in incident.entity_keys:
            # Query historical events
            t_start = time.perf_counter()
            events = ToolDispatcher.call("get_events", entity=entity, window_minutes=30, limit=max_lines)
            t_events = round((time.perf_counter() - t_start) * 1000, 2)
            tool_records.append({
                "tool": "get_events",
                "args": {"entity": entity, "window_minutes": 30},
                "latency_ms": t_events,
                "result_count": len(events),
            })
            all_events.extend(events)

            # Discover graph neighbors
            t_start = time.perf_counter()
            neighbors = ToolDispatcher.call("get_graph_neighbors", entity=entity, incident=incident)
            t_neighbors = round((time.perf_counter() - t_start) * 1000, 2)
            tool_records.append({
                "tool": "get_graph_neighbors",
                "args": {"entity": entity},
                "latency_ms": t_neighbors,
                "result_count": len(neighbors),
            })
            all_neighbors.update(neighbors)

            # Asset lookup if entity looks like host or IP
            if any(k in entity.lower() for k in ("srv", "ws-", "host:", "192.", "10.", "172.")):
                t_start = time.perf_counter()
                asset_data = ToolDispatcher.call("lookup_asset", host_or_ip=entity)
                t_asset = round((time.perf_counter() - t_start) * 1000, 2)
                tool_records.append({
                    "tool": "lookup_asset",
                    "args": {"host_or_ip": entity},
                    "latency_ms": t_asset,
                    "result": asset_data.get("role"),
                })
                assets_info[entity] = asset_data

            # User lookup if entity is user
            if "user:" in entity.lower() or not any(c in entity for c in (".", ":", "-")):
                t_start = time.perf_counter()
                user_data = ToolDispatcher.call("lookup_user", username=entity)
                t_user = round((time.perf_counter() - t_start) * 1000, 2)
                tool_records.append({
                    "tool": "lookup_user",
                    "args": {"username": entity},
                    "latency_ms": t_user,
                    "result": user_data.get("role"),
                })
                users_info[entity] = user_data

        # 2. Build sanitized evidence lines
        evidence_lines = []
        for e in all_events[:max_lines]:
            evidence_lines.append(
                f"[{e['ts']}] action={e['action']} outcome={e['outcome']} src={e['src_ip']} dst={e['dst_ip']} host={e['host']} user={e['user']}"
            )

        # Fallback to incident timeline if no historical events in DB
        if not evidence_lines:
            for t in incident.timeline[:max_lines]:
                evidence_lines.append(
                    f"[{t.ts.isoformat()}] alert_id={t.alert_id} tech={t.technique} tactic={t.tactic} desc={t.description}"
                )

        sanitized_bundle = wrap_evidence(evidence_lines)

        evidence_pack = {
            "events_count": len(all_events),
            "graph_neighbors": sorted(list(all_neighbors)),
            "assets": assets_info,
            "users": users_info,
            "evidence_lines": evidence_lines,
            "sanitized_bundle": sanitized_bundle,
        }

        context.evidence_pack = evidence_pack
        latency_ms = (time.perf_counter() - t0) * 1000

        msg_text = (
            f"Investigation completed: gathered {len(all_events)} events, "
            f"{len(all_neighbors)} graph neighbors, {len(assets_info)} assets, {len(users_info)} users."
        )

        context.add_trace(
            agent_name=self.name,
            state="INVESTIGATE",
            inputs={"entities": incident.entity_keys},
            tool_calls=tool_records,
            output_message=msg_text,
            latency_ms=latency_ms,
            tokens=120,
        )

        context.send_message(
            sender=self.name,
            recipient="ForecasterAgent",
            message_type="EVIDENCE_GATHERED",
            payload=evidence_pack,
        )

        return evidence_pack
