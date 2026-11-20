"""
Allow-listed read-only tools available to agents.

Enforces strict input validation and access gating — no write or shell tools allowed.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from hsoc.config import get_settings
from hsoc.db import EventORM, SessionLocal
from hsoc.investigate.predictor import MarkovPredictor

logger = logging.getLogger(__name__)

# Allow-list of tools verified for safe agent invocation
ALLOWED_TOOLS = frozenset([
    "get_events",
    "get_graph_neighbors",
    "lookup_asset",
    "lookup_user",
    "predict_markov_trajectory",
])


def get_events(entity: str, window_minutes: int = 30, limit: int = 50) -> list[dict[str, Any]]:
    """
    Query historical events for an entity within a sliding time window.

    Args:
        entity: IP address, hostname, or username.
        window_minutes: Time window in minutes.
        limit: Max events to return.
    """
    db = SessionLocal()
    try:
        # Strip prefixes like 'ip:', 'host:', 'user:' if present
        clean_entity = entity.split(":", 1)[-1] if ":" in entity else entity
        query = (
            db.query(EventORM)
            .filter(
                (EventORM.src_ip == clean_entity)
                | (EventORM.dst_ip == clean_entity)
                | (EventORM.host == clean_entity)
                | (EventORM.user == clean_entity)
            )
            .order_by(EventORM.ts.desc())
            .limit(limit)
        )
        events = query.all()
        return [
            {
                "event_id": e.event_id,
                "ts": e.ts.isoformat(),
                "action": e.action,
                "outcome": e.outcome,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "host": e.host,
                "user": e.user,
                "raw": e.raw,
            }
            for e in events
        ]
    except Exception as exc:
        logger.warning("Error querying events for entity %s: %s", entity, exc)
        return []
    finally:
        db.close()


def get_graph_neighbors(entity: str, incident: Any = None) -> list[str]:
    """
    Discover graph neighbors (co-occurring IPs, hosts, or users) for an entity.
    """
    clean_entity = entity.split(":", 1)[-1] if ":" in entity else entity
    neighbors: set[str] = set()

    if incident and hasattr(incident, "entity_keys"):
        for k in incident.entity_keys:
            val = k.split(":", 1)[-1] if ":" in k else k
            if val != clean_entity:
                neighbors.add(k)

    return sorted(list(neighbors))


def lookup_asset(host_or_ip: str) -> dict[str, Any]:
    """
    Look up asset criticality, role, owner, and environment from asset inventory.
    """
    clean_target = host_or_ip.split(":", 1)[-1] if ":" in host_or_ip else host_or_ip
    csv_path = get_settings().asset_inventory_path

    if csv_path.exists():
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("asset_id") == clean_target or row.get("ip_address") == clean_target or row.get("hostname") == clean_target:
                    return {
                        "asset_id": row.get("asset_id"),
                        "hostname": row.get("hostname"),
                        "ip_address": row.get("ip_address"),
                        "criticality": int(row.get("criticality", 1)),
                        "role": row.get("role", "workstation"),
                        "owner": row.get("owner", "unknown"),
                        "environment": row.get("environment", "internal"),
                    }

    # Default unknown asset
    return {
        "asset_id": clean_target,
        "hostname": clean_target,
        "ip_address": clean_target,
        "criticality": 1,
        "role": "workstation",
        "owner": "unassigned",
        "environment": "unknown",
    }


def lookup_user(username: str) -> dict[str, Any]:
    """
    Look up user department, privilege level, and status from user catalog.
    """
    clean_user = username.split(":", 1)[-1] if ":" in username else username
    csv_path = get_settings().users_csv_path

    if csv_path.exists():
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("username", "").lower() == clean_user.lower():
                    return {
                        "username": row.get("username"),
                        "department": row.get("department", "general"),
                        "privileged": row.get("privileged", "false").lower() in ("true", "1"),
                        "role": row.get("role", "staff"),
                        "email": row.get("email", ""),
                    }

    return {
        "username": clean_user,
        "department": "unknown",
        "privileged": False,
        "role": "standard",
        "email": f"{clean_user}@example.local",
    }


def predict_markov_trajectory(current_tactic: str, top_n: int = 3) -> dict[str, Any]:
    """
    Query the Markov transition engine as a tool.
    """
    predictor = MarkovPredictor()
    predictions = predictor.predict(current_tactic, top_n=top_n)
    return {
        "current_tactic": current_tactic,
        "predictions": [
            {"tactic": p.tactic, "probability": p.probability}
            for p in predictions
        ],
    }


class ToolDispatcher:
    """Dispatches tool calls with strict allow-list verification."""

    @staticmethod
    def call(tool_name: str, **kwargs: Any) -> Any:
        if tool_name not in ALLOWED_TOOLS:
            raise PermissionError(f"Tool '{tool_name}' is not in the allow-list: {sorted(list(ALLOWED_TOOLS))}")

        if tool_name == "get_events":
            return get_events(
                entity=kwargs.get("entity", ""),
                window_minutes=int(kwargs.get("window_minutes", 30)),
                limit=int(kwargs.get("limit", 50)),
            )
        elif tool_name == "get_graph_neighbors":
            return get_graph_neighbors(
                entity=kwargs.get("entity", ""),
                incident=kwargs.get("incident"),
            )
        elif tool_name == "lookup_asset":
            return lookup_asset(host_or_ip=kwargs.get("host_or_ip", ""))
        elif tool_name == "lookup_user":
            return lookup_user(username=kwargs.get("username", ""))
        elif tool_name == "predict_markov_trajectory":
            return predict_markov_trajectory(
                current_tactic=kwargs.get("current_tactic", "unknown"),
                top_n=int(kwargs.get("top_n", 3)),
            )
        else:
            raise ValueError(f"Unknown tool implementation: {tool_name}")
