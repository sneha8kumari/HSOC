"""
Unit tests for event enrichment against asset inventory and users.
"""

from datetime import datetime, timezone

from hsoc.ingest.enrich import enrich
from hsoc.schema import Event, SourceType


def test_enrich_known_asset_and_privileged_user():
    event = Event(
        ts=datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        dst_ip="192.168.56.20",  # db-srv-01, criticality 5
        user="root",             # privileged=True, allowed_sudo=True
        action="ssh_login",
        raw="test line",
    )
    enriched = enrich(event)
    assert enriched.asset.criticality == 5
    assert enriched.asset.role == "database"
    assert enriched.user_ctx.privileged is True
    assert enriched.user_ctx.allowed_sudo is True


def test_enrich_non_privileged_user():
    event = Event(
        ts=datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        host="ws-01",            # criticality 2
        user="alice",            # privileged=False, allowed_sudo=False
        action="ssh_login",
        raw="test line",
    )
    enriched = enrich(event)
    assert enriched.asset.criticality == 2
    assert enriched.user_ctx.privileged is False
    assert enriched.user_ctx.allowed_sudo is False


def test_enrich_unknown_asset_and_user_defaults():
    event = Event(
        ts=datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        dst_ip="10.0.0.99",
        user="random_ghost_user",
        action="ssh_login",
        raw="test line",
    )
    enriched = enrich(event)
    assert enriched.asset.criticality == 1
    assert enriched.asset.role == "unknown"
    assert enriched.user_ctx.privileged is False
