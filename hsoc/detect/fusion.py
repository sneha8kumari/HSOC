"""
Fusion: combines rule confidence and ML score into a single alert confidence.

Formula:
    conf = min(1, max(rule_conf, ml_score) + bonus)
    bonus = dual_signal_bonus if both > dual_signal_threshold else 0

Raises an Alert when conf >= alert_threshold (from settings.yaml).
If trained models are missing, runs rules-only and logs a warning.
"""

from __future__ import annotations

import logging
from typing import Any

from hsoc.config import get_settings
from hsoc.db import AlertORM, EventORM, SessionLocal, init_db
from hsoc.detect import rule_engine
from hsoc.schema import Alert, AssetContext, Event, Outcome, SourceType, UserContext

logger = logging.getLogger(__name__)


def fuse_alert(
    rule_conf: float,
    ml_score: float | None = None,
    fusion_cfg: dict[str, Any] | None = None,
) -> float:
    """
    Compute fused confidence from rule confidence and optional ML score.

    Args:
        rule_conf: Confidence from rule engine (0.0–1.0).
        ml_score: Probability from ML model (0.0–1.0 or None).
        fusion_cfg: Config dictionary from settings.yaml.

    Returns:
        Fused confidence score (0.0–1.0).
    """
    if fusion_cfg is None:
        fusion_cfg = get_settings().fusion

    bonus_val = float(fusion_cfg.get("dual_signal_bonus", 0.1))
    threshold_val = float(fusion_cfg.get("dual_signal_threshold", 0.5))

    if ml_score is None:
        return min(1.0, rule_conf)

    bonus = bonus_val if (rule_conf > threshold_val and ml_score > threshold_val) else 0.0
    return min(1.0, max(rule_conf, ml_score) + bonus)


def fuse(events: list[Event]) -> list[Alert]:
    """
    Run the hybrid detection pipeline and return alerts that meet the threshold.

    Args:
        events: Normalised, enriched events.

    Returns:
        List of Alert objects that exceeded the confidence threshold.
    """
    settings = get_settings()
    alert_threshold = float(settings.detection.get("alert_threshold", 0.5))
    fusion_cfg = settings.fusion

    # 1. Evaluate rules
    raw_alerts = rule_engine.evaluate(events)

    fused_alerts: list[Alert] = []
    for alert in raw_alerts:
        fused_conf = fuse_alert(alert.conf, alert.ml_score, fusion_cfg=fusion_cfg)
        if fused_conf >= alert_threshold:
            alert.conf = fused_conf
            fused_alerts.append(alert)

    logger.info("Fusion produced %d alerts above threshold %.2f", len(fused_alerts), alert_threshold)
    return fused_alerts


def run_demo() -> list[Alert]:
    """Run detection fusion against all ingested events in the database."""
    init_db()
    db = SessionLocal()

    try:
        # Load all events from database
        event_orms = db.query(EventORM).order_by(EventORM.ts.asc()).all()
        events: list[Event] = []

        for row in event_orms:
            ev = Event(
                event_id=row.event_id,
                ts=row.ts,
                source_type=SourceType(row.source_type),
                host=row.host,
                src_ip=row.src_ip,
                dst_ip=row.dst_ip,
                dst_port=row.dst_port,
                user=row.user,
                action=row.action,
                outcome=Outcome(row.outcome),
                asset=AssetContext(
                    criticality=row.asset_criticality,
                    role=row.asset_role,
                    owner=row.asset_owner,
                ),
                user_ctx=UserContext(
                    privileged=row.user_privileged,
                    allowed_sudo=row.user_privileged,
                ),
                features=row.features or {},
                label=row.label,
                raw=row.raw,
            )
            events.append(ev)

        alerts = fuse(events)

        # Clear existing alerts and persist new ones
        db.query(AlertORM).delete()
        for al in alerts:
            db.add(
                AlertORM(
                    alert_id=al.alert_id,
                    ts=al.ts,
                    rule_ids=al.rule_ids,
                    model_id=al.model_id,
                    ml_score=al.ml_score,
                    conf=al.conf,
                    technique=al.technique,
                    tactic=al.tactic,
                    domain=al.domain.value,
                    src_ip=al.src_ip,
                    dst_host=al.dst_host,
                    user=al.user,
                    evidence_event_ids=al.evidence_event_ids,
                    description=al.description,
                )
            )
        db.commit()
        return alerts

    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="demo")
    args = parser.parse_args()
    logger.info("Fusion pipeline running in %s mode", args.mode)
    if args.mode == "demo":
        results = run_demo()
        print(f"Fusion complete: {len(results)} alerts generated.")
