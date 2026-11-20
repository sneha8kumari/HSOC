"""
Enrichment: joins asset_inventory.csv and users.csv onto normalised events.

Adds AssetContext and UserContext to each Event.
Missing entries produce default (criticality=1, privileged=False) values.
"""

from __future__ import annotations

import csv
import logging
from functools import lru_cache
from pathlib import Path

from hsoc.config import get_settings
from hsoc.schema import AssetContext, Event, UserContext

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_asset_inventory(path: str | Path | None = None) -> dict[str, AssetContext]:
    """
    Load asset inventory CSV into a lookup dictionary keyed by IP and host.

    Format: host,ip,role,owner,criticality
    """
    if path is None:
        path = get_settings().asset_inventory_path
    path = Path(path)

    lookup: dict[str, AssetContext] = {}
    if not path.exists():
        logger.warning("Asset inventory file not found at %s", path)
        return lookup

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ctx = AssetContext(
                criticality=int(row.get("criticality", 1)),
                role=row.get("role", "unknown"),
                owner=row.get("owner", "unknown"),
            )
            host = row.get("host", "").strip()
            ip = row.get("ip", "").strip()
            if host:
                lookup[host] = ctx
            if ip:
                lookup[ip] = ctx

    return lookup


@lru_cache(maxsize=1)
def load_user_directory(path: str | Path | None = None) -> dict[str, UserContext]:
    """
    Load users CSV into a lookup dictionary keyed by username.

    Format: user,privileged,allowed_sudo,usual_hours_start,usual_hours_end
    """
    if path is None:
        path = get_settings().users_csv_path
    path = Path(path)

    lookup: dict[str, UserContext] = {}
    if not path.exists():
        logger.warning("Users directory file not found at %s", path)
        return lookup

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            user = row.get("user", "").strip()
            if not user:
                continue

            start_raw = row.get("usual_hours_start")
            end_raw = row.get("usual_hours_end")

            lookup[user] = UserContext(
                privileged=row.get("privileged", "").strip().lower() == "true",
                allowed_sudo=row.get("allowed_sudo", "").strip().lower() == "true",
                usual_hours_start=int(start_raw) if start_raw and start_raw.isdigit() else None,
                usual_hours_end=int(end_raw) if end_raw and end_raw.isdigit() else None,
            )

    return lookup


def enrich(event: Event) -> Event:
    """
    Enrich a normalised event with asset and user context.

    Args:
        event: A normalised Event (before enrichment).

    Returns:
        The same event with asset and user_ctx populated.
    """
    assets = load_asset_inventory()
    users = load_user_directory()

    # Asset context resolution
    asset_ctx = None
    if event.dst_ip and event.dst_ip in assets:
        asset_ctx = assets[event.dst_ip]
    elif event.host and event.host in assets:
        asset_ctx = assets[event.host]
    elif event.src_ip and event.src_ip in assets:
        asset_ctx = assets[event.src_ip]

    if asset_ctx:
        event.asset = asset_ctx

    # User context resolution
    if event.user and event.user in users:
        event.user_ctx = users[event.user]

    return event
