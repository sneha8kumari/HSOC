"""
Collector: orchestrates ingestion from files or live sources.

Modes:
  - demo:   reads from data/processed/synthetic/
  - file:   reads from a provided path
  - wazuh:  polls/receives Wazuh alerts (live lab, optional)
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import EventORM, QuarantineORM, SessionLocal, init_db
from hsoc.ingest.enrich import enrich
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.parsers import PARSER_REGISTRY
from hsoc.schema import Event, QuarantineRecord

logger = logging.getLogger(__name__)


def compute_raw_hash(raw: str) -> str:
    """Compute SHA-256 hash of raw log string for deduplication."""
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


def process_lines(
    lines: list[str],
    parser_name: str,
    db: Session,
    batch_size: int = 500,
) -> dict[str, Any]:
    """
    Parse, map, enrich and persist a batch of log lines.

    Args:
        lines: Raw log lines.
        parser_name: Registered parser identifier.
        db: Active SQLAlchemy Session.
        batch_size: Number of records before database flush/commit.

    Returns:
        Summary metrics dictionary.
    """
    parser_fn = PARSER_REGISTRY.get(parser_name)
    if not parser_fn:
        raise ValueError(f"Unknown parser: '{parser_name}'")

    ingested = 0
    quarantined = 0
    deduped = 0
    t0 = time.perf_counter()

    event_orms: list[EventORM] = []
    quarantine_orms: list[QuarantineORM] = []

    # Get set of recent hashes to avoid duplicate primary key collisions in session
    existing_hashes = set()

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        raw_hash = compute_raw_hash(line_str)
        if raw_hash in existing_hashes:
            deduped += 1
            continue

        try:
            parsed_dict = parser_fn(line_str)
            item = map_to_event(parsed_dict, parser_name)
        except Exception as exc:
            quarantined += 1
            quarantine_orms.append(
                QuarantineORM(
                    record_id=str(QuarantineRecord(raw=line_str, reason=str(exc), parser=parser_name).record_id),
                    ts=None,
                    source_type=parser_name,
                    raw=line_str,
                    reason=f"Parser exception: {str(exc)}",
                    parser=parser_name,
                )
            )
            continue

        if isinstance(item, QuarantineRecord):
            quarantined += 1
            quarantine_orms.append(
                QuarantineORM(
                    record_id=item.record_id,
                    ts=item.ts,
                    source_type=item.source_type,
                    raw=item.raw,
                    reason=item.reason,
                    parser=item.parser,
                )
            )
        else:
            enriched_event = enrich(item)
            existing_hashes.add(raw_hash)
            ingested += 1
            event_orms.append(
                EventORM(
                    event_id=enriched_event.event_id,
                    ts=enriched_event.ts,
                    source_type=enriched_event.source_type.value,
                    host=enriched_event.host,
                    src_ip=enriched_event.src_ip,
                    dst_ip=enriched_event.dst_ip,
                    dst_port=enriched_event.dst_port,
                    user=enriched_event.user,
                    action=enriched_event.action,
                    outcome=enriched_event.outcome.value,
                    asset_criticality=enriched_event.asset.criticality,
                    asset_role=enriched_event.asset.role,
                    asset_owner=enriched_event.asset.owner,
                    user_privileged=enriched_event.user_ctx.privileged,
                    features=enriched_event.features,
                    label=enriched_event.label,
                    raw=enriched_event.raw,
                    repeat_count=enriched_event.repeat_count,
                    raw_hash=raw_hash,
                )
            )

        # Batch commit
        if (len(event_orms) + len(quarantine_orms)) >= batch_size:
            if event_orms:
                db.add_all(event_orms)
                event_orms.clear()
            if quarantine_orms:
                db.add_all(quarantine_orms)
                quarantine_orms.clear()
            db.commit()

    # Final flush
    if event_orms:
        db.add_all(event_orms)
    if quarantine_orms:
        db.add_all(quarantine_orms)
    db.commit()

    elapsed = max(time.perf_counter() - t0, 0.0001)
    rate = (ingested + quarantined) / elapsed

    return {
        "parser": parser_name,
        "processed_lines": len(lines),
        "ingested_events": ingested,
        "quarantined_records": quarantined,
        "deduped_records": deduped,
        "elapsed_seconds": round(elapsed, 4),
        "throughput_events_per_sec": round(rate, 2),
    }


def run(mode: str = "demo", **kwargs: Any) -> dict[str, Any]:
    """
    Entry point for the collector.

    Args:
        mode: One of demo, file, wazuh.
        **kwargs: Mode-specific arguments (e.g. path=, parser=).

    Returns:
        Aggregation of collector run metrics.
    """
    init_db()
    settings = get_settings()
    batch_size = int(settings.ingest.get("batch_size", 500))

    db = SessionLocal()
    metrics: dict[str, Any] = {"mode": mode, "runs": []}

    try:
        if mode == "demo":
            synthetic_dir = Path("data/processed/synthetic")
            targets = [
                (synthetic_dir / "auth.log", "linux_auth"),
                (synthetic_dir / "apache_access.log", "apache"),
                (synthetic_dir / "flows.csv", "flow"),
                (synthetic_dir / "wazuh_events.jsonl", "wazuh"),
            ]

            total_events = 0
            for file_path, parser_name in targets:
                if not file_path.exists():
                    continue
                content = file_path.read_text(encoding="utf-8")
                lines = [l for l in content.splitlines() if l.strip()]
                if not lines:
                    continue

                res = process_lines(lines, parser_name, db, batch_size=batch_size)
                metrics["runs"].append(res)
                total_events += res["ingested_events"]

            logger.info("Demo ingestion complete. Total ingested: %d events", total_events)

        elif mode == "file":
            file_path = Path(kwargs.get("path", ""))
            parser_name = kwargs.get("parser", "linux_auth")
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            lines = [l for l in file_path.read_text(encoding="utf-8").splitlines() if l.strip()]
            res = process_lines(lines, parser_name, db, batch_size=batch_size)
            metrics["runs"].append(res)

        elif mode == "wazuh":
            from hsoc.ingest.wazuh_client import get_wazuh_client
            client = get_wazuh_client()
            health = client.test_connection()
            if not health.get("connected"):
                logger.warning("Wazuh collector invoked but server not reachable: %s", health.get("message"))
                metrics["wazuh_status"] = health
                return metrics

            limit = int(kwargs.get("limit", 100))
            events = client.poll_and_normalize(limit=limit)
            persisted = 0
            for ev in events:
                raw_h = compute_raw_hash(ev.raw or ev.event_id)
                orm = EventORM(
                    event_id=ev.event_id,
                    ts=ev.ts,
                    source_type=ev.source_type.value,
                    host=ev.host,
                    src_ip=ev.src_ip,
                    dst_ip=ev.dst_ip,
                    dst_port=ev.dst_port,
                    user=ev.user,
                    action=ev.action,
                    outcome=ev.outcome.value,
                    asset_criticality=ev.asset.criticality,
                    asset_role=ev.asset.role,
                    asset_owner=ev.asset.owner,
                    user_privileged=ev.user_ctx.privileged,
                    features=ev.features,
                    label=ev.label,
                    raw=ev.raw,
                    repeat_count=ev.repeat_count,
                    raw_hash=raw_h,
                    is_simulated=False,
                )
                db.add(orm)
                persisted += 1
            db.commit()
            metrics["wazuh_status"] = health
            metrics["ingested_events"] = persisted
            logger.info("Wazuh polling complete: %d events ingested", persisted)

        else:
            raise ValueError(f"Unknown collector mode: {mode}")

    finally:
        db.close()

    return metrics


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="H-SOC log collector")
    parser.add_argument("--mode", default="demo", choices=["demo", "file", "wazuh"])
    parser.add_argument("--path", default=None, help="File path when mode=file")
    parser.add_argument("--parser", default="linux_auth", help="Parser name when mode=file")
    args = parser.parse_args()
    res = run(mode=args.mode, path=args.path, parser=args.parser)
    print(res)
