"""
Alert correlator: groups related alerts into incidents using union-find/graph components.

Entity keys: src_ip, user, dst_host.
Window: correlation.window_minutes from settings.yaml.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from hsoc.config import get_settings
from hsoc.db import AlertORM, IncidentORM, SessionLocal, init_db
from hsoc.genai.orchestrator import generate_report
from hsoc.investigate.chain import build_chain
from hsoc.investigate.domain import classify_domain
from hsoc.investigate.predictor import MarkovPredictor
from hsoc.investigate.severity import compute_severity
from hsoc.schema import Alert, Domain, Incident, IncidentStatus, Severity

logger = logging.getLogger(__name__)


def _extract_entity_keys(alert: Alert, ignore_entities: set[str]) -> set[str]:
    """Extract all entity tokens for incident metadata."""
    keys = set()
    if alert.src_ip and alert.src_ip not in ignore_entities:
        keys.add(f"ip:{alert.src_ip}")
    if alert.user and alert.user not in ignore_entities:
        keys.add(f"user:{alert.user}")
    if alert.dst_host and alert.dst_host not in ignore_entities:
        keys.add(f"host:{alert.dst_host}")
    return keys


def _extract_adversary_keys(alert: Alert, ignore_entities: set[str]) -> set[str]:
    """Extract primary adversary or actor pivot keys for clustering."""
    keys = set()
    if alert.src_ip and alert.src_ip not in ignore_entities:
        keys.add(f"ip:{alert.src_ip}")
    elif alert.user and alert.user not in ignore_entities:
        keys.add(f"user:{alert.user}")
    elif alert.dst_host and alert.dst_host not in ignore_entities:
        keys.add(f"host:{alert.dst_host}")
    return keys


def correlate(alerts: list[Alert]) -> list[Incident]:
    """
    Group alerts into incidents based on shared entity keys and temporal proximity.

    Args:
        alerts: Alerts from the fusion pipeline.

    Returns:
        List of enriched Incident objects.
    """
    if not alerts:
        return []

    settings = get_settings()
    window_min = int(settings.correlation.get("window_minutes", 30))
    ignore_entities = set(settings.correlation.get("ignore_entities", ["127.0.0.1", "::1"]))
    time_window = timedelta(minutes=window_min)

    # Union-find data structures
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        if parent[i] == i:
            return i
        parent[i] = find(parent[i])
        return parent[i]

    def union(i: int, j: int) -> None:
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    cluster_keys = [_extract_adversary_keys(a, ignore_entities) for a in alerts]

    # Cluster alerts sharing an adversary key within time_window
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            time_diff = abs(alerts[i].ts - alerts[j].ts)
            if time_diff <= time_window:
                if cluster_keys[i].intersection(cluster_keys[j]):
                    union(i, j)

    # Collect clusters
    clusters: dict[int, list[Alert]] = {}
    for idx, alert in enumerate(alerts):
        root = find(idx)
        clusters.setdefault(root, []).append(alert)

    predictor = MarkovPredictor()
    incidents: list[Incident] = []

    for root_id, group_alerts in clusters.items():
        all_keys = set()
        for a in group_alerts:
            all_keys.update(_extract_entity_keys(a, ignore_entities))

        first_ts = min(a.ts for a in group_alerts)
        last_ts = max(a.ts for a in group_alerts)

        incident = Incident(
            created_at=first_ts,
            updated_at=last_ts,
            status=IncidentStatus.open,
            alert_ids=[a.alert_id for a in group_alerts],
            entity_keys=list(all_keys),
        )

        # 1. Build chronological attack chain & timeline
        incident = build_chain(incident, group_alerts)

        # 2. Classify domain
        incident = classify_domain(incident, group_alerts)

        # 3. Compute asset-aware severity
        incident = compute_severity(incident, group_alerts)

        # 4. Predict next tactic using Markov chain
        last_tactic = incident.tactics[-1] if incident.tactics else "reconnaissance"
        incident.predicted_next = predictor.predict(last_tactic, top_n=3)

        incidents.append(incident)

    logger.info("Correlated %d alerts into %d incidents", len(alerts), len(incidents))
    return incidents


def run_demo(generate_reports: bool = True) -> list[Incident]:
    """
    Run correlation on database alerts, persist incidents, and optionally trigger reports.
    """
    init_db()
    db = SessionLocal()

    try:
        alert_orms = db.query(AlertORM).order_by(AlertORM.ts.asc()).all()
        alerts: list[Alert] = []

        for row in alert_orms:
            al = Alert(
                alert_id=row.alert_id,
                ts=row.ts,
                rule_ids=row.rule_ids or [],
                model_id=row.model_id,
                ml_score=row.ml_score,
                conf=row.conf,
                technique=row.technique,
                tactic=row.tactic,
                domain=Domain(row.domain) if row.domain in Domain.__members__ else Domain.unknown,
                src_ip=row.src_ip,
                dst_host=row.dst_host,
                user=row.user,
                evidence_event_ids=row.evidence_event_ids or [],
                description=row.description or "",
            )
            alerts.append(al)

        incidents = correlate(alerts)

        # Clear existing incidents and reports
        db.query(IncidentORM).delete()
        if generate_reports:
            from hsoc.db import ReportORM
            db.query(ReportORM).delete()

        for inc in incidents:
            report_id = None
            if generate_reports:
                try:
                    rep = generate_report(inc, db=db)
                    report_id = rep.report_id
                    inc.report_id = report_id
                except Exception as exc:
                    logger.error("Report generation failed for incident %s: %s", inc.incident_id, exc)

            db.add(
                IncidentORM(
                    incident_id=inc.incident_id,
                    created_at=inc.created_at,
                    updated_at=inc.updated_at,
                    status=inc.status.value,
                    alert_ids=inc.alert_ids,
                    entity_keys=inc.entity_keys,
                    timeline=[t.model_dump(mode="json") for t in inc.timeline],
                    techniques=inc.techniques,
                    tactics=inc.tactics,
                    domain=inc.domain.value,
                    secondary_domains=[d.value for d in inc.secondary_domains],
                    severity=inc.severity.value,
                    risk_score=inc.risk_score,
                    risk_rationale=inc.risk_rationale,
                    out_of_order_stage=inc.out_of_order_stage,
                    predicted_next=[p.model_dump(mode="json") for p in inc.predicted_next],
                    report_id=report_id,
                )
            )

        db.commit()
        return incidents

    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="print")
    args = parser.parse_args()

    results = run_demo(generate_reports=True)
    print("\n" + "=" * 70)
    print(f"CORRELATION COMPLETE: {len(results)} Incidents Produced")
    print("=" * 70)
    for idx, inc in enumerate(results, 1):
        print(f"\n[Incident #{idx}] ID: {inc.incident_id}")
        print(f"  Severity: {inc.severity.value.upper()} (Risk Score: {inc.risk_score})")
        print(f"  Domain:   {inc.domain.value}")
        print(f"  Tactics:  {' -> '.join(inc.tactics) if inc.tactics else 'None'}")
        print(f"  Entities: {', '.join(inc.entity_keys)}")
        print(f"  Next Expected Tactics:")
        for pred in inc.predicted_next:
            print(f"    - {pred.tactic} ({pred.probability * 100:.1f}%)")
        print(f"  Linked Report ID: {inc.report_id}")
