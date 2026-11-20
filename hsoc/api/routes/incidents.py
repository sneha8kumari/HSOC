"""
Incidents, Attack Graph, Replay, and Agent Traces API router.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from hsoc.db import AgentTraceORM, AlertORM, EventORM, IncidentORM, ReportORM, get_db

router = APIRouter()

# MITRE tactic order for timeline & out-of-order stage check
TACTIC_ORDER = {
    "reconnaissance": 1,
    "resource_development": 2,
    "initial_access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 7,
    "credential_access": 8,
    "discovery": 9,
    "lateral_movement": 10,
    "collection": 11,
    "command_and_control": 12,
    "exfiltration": 13,
    "impact": 14,
}


@router.get("", tags=["incidents"])
def list_incidents(
    severity: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """List all correlated incidents with calculated metadata and timeline summaries."""
    query = db.query(IncidentORM).order_by(IncidentORM.created_at.desc())

    if severity:
        query = query.filter(IncidentORM.severity == severity.lower())
    if domain:
        query = query.filter(IncidentORM.domain == domain.lower())
    if status:
        query = query.filter(IncidentORM.status == status.lower())

    incidents = query.all()
    results = []

    for inc in incidents:
        # Check out-of-order stage flags in timeline
        timeline_items = inc.timeline or []
        out_of_order_found = False
        highest_order = 0

        for item in timeline_items:
            tac = item.get("tactic", "").lower()
            order = TACTIC_ORDER.get(tac, 0)
            if order > 0:
                if order < highest_order and highest_order - order >= 2:
                    item["out_of_order"] = True
                    out_of_order_found = True
                else:
                    item["out_of_order"] = False
                    highest_order = max(highest_order, order)

        results.append(
            {
                "incident_id": inc.incident_id,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
                "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
                "status": inc.status,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "risk_rationale": inc.risk_rationale,
                "domain": inc.domain,
                "secondary_domains": inc.secondary_domains or [],
                "techniques": inc.techniques or [],
                "tactics": inc.tactics or [],
                "entity_keys": inc.entity_keys or [],
                "alert_ids": inc.alert_ids or [],
                "out_of_order_stage": out_of_order_found or inc.out_of_order_stage,
                "report_id": inc.report_id,
                "timeline": timeline_items,
            }
        )

    return results


@router.get("/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve full incident details, associated report, alerts, and timeline."""
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    # Fetch linked report
    report_data = None
    if inc.report_id:
        rep = db.query(ReportORM).filter(ReportORM.report_id == inc.report_id).first()
        if rep and rep.full_json:
            report_data = rep.full_json
        elif rep:
            report_data = {
                "report_id": rep.report_id,
                "generated_at": rep.generated_at.isoformat() if rep.generated_at else None,
                "summary": rep.summary,
                "severity": rep.severity,
                "evidence": rep.evidence or [],
                "attack_mapping": rep.attack_mapping or [],
                "predicted_next": rep.predicted_next or [],
                "remediation": rep.remediation or [],
                "chunk_ids_used": rep.chunk_ids_used or [],
                "valid": rep.valid,
            }

    # Fetch linked alerts
    alerts = db.query(AlertORM).filter(AlertORM.alert_id.in_(inc.alert_ids or [])).all()
    alert_items = []
    evidence_event_ids: set[str] = set()

    for a in alerts:
        ev_ids = a.evidence_event_ids or []
        evidence_event_ids.update(ev_ids)
        alert_items.append(
            {
                "alert_id": a.alert_id,
                "ts": a.ts.isoformat() if a.ts else None,
                "conf": a.conf,
                "technique": a.technique,
                "tactic": a.tactic,
                "domain": a.domain,
                "src_ip": a.src_ip,
                "dst_host": a.dst_host,
                "user": a.user,
                "description": a.description,
                "rule_ids": a.rule_ids or [],
                "evidence_event_ids": ev_ids,
            }
        )

    # Fetch raw events for evidence citations
    events = db.query(EventORM).filter(EventORM.event_id.in_(list(evidence_event_ids)[:50])).all()
    event_items = [
        {
            "event_id": e.event_id,
            "ts": e.ts.isoformat() if e.ts else None,
            "source_type": e.source_type,
            "raw": e.raw,
            "src_ip": e.src_ip,
            "dst_host": e.host,
            "user": e.user,
            "action": e.action,
            "outcome": e.outcome,
        }
        for e in events
    ]

    # Process out-of-order timeline
    timeline_items = inc.timeline or []
    highest_order = 0
    out_of_order_found = False
    for item in timeline_items:
        tac = item.get("tactic", "").lower()
        order = TACTIC_ORDER.get(tac, 0)
        if order > 0:
            if order < highest_order and highest_order - order >= 2:
                item["out_of_order"] = True
                out_of_order_found = True
            else:
                item["out_of_order"] = False
                highest_order = max(highest_order, order)

    return {
        "incident_id": inc.incident_id,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "status": inc.status,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "risk_rationale": inc.risk_rationale,
        "domain": inc.domain,
        "secondary_domains": inc.secondary_domains or [],
        "techniques": inc.techniques or [],
        "tactics": inc.tactics or [],
        "entity_keys": inc.entity_keys or [],
        "alert_ids": inc.alert_ids or [],
        "out_of_order_stage": out_of_order_found or inc.out_of_order_stage,
        "timeline": timeline_items,
        "alerts": alert_items,
        "events": event_items,
        "report": report_data,
    }


@router.get("/{incident_id}/graph", tags=["incidents"])
def get_incident_attack_graph(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Generate an interactive attack graph representation:
      - Nodes: root incident, alerts, IP entities, host entities, user entities.
      - Edges: alert correlation reasons (same host, same IP, time window, tactic progression).
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    alerts = db.query(AlertORM).filter(AlertORM.alert_id.in_(inc.alert_ids or [])).all()

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # 1. Incident Root Node
    root_node_id = f"inc_{inc.incident_id}"
    nodes.append(
        {
            "id": root_node_id,
            "label": f"Incident {inc.incident_id}",
            "type": "incident",
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "domain": inc.domain,
        }
    )

    entity_nodes: set[str] = set()

    for idx, al in enumerate(alerts):
        al_node_id = f"alt_{al.alert_id}"
        nodes.append(
            {
                "id": al_node_id,
                "label": f"{al.technique or 'Alert'} ({al.tactic or 'Stage'})",
                "type": "alert",
                "alert_id": al.alert_id,
                "technique": al.technique,
                "tactic": al.tactic,
                "conf": al.conf,
                "domain": al.domain,
                "ts": al.ts.isoformat() if al.ts else None,
            }
        )

        # Link alert to root
        edges.append(
            {
                "source": root_node_id,
                "target": al_node_id,
                "relation": "correlated_in",
                "label": "member_alert",
            }
        )

        # Connect consecutive alerts to illustrate attack progression
        if idx > 0:
            prev_al_node_id = f"alt_{alerts[idx - 1].alert_id}"
            edges.append(
                {
                    "source": prev_al_node_id,
                    "target": al_node_id,
                    "relation": "tactic_progression",
                    "label": f"{alerts[idx-1].tactic} -> {al.tactic}",
                }
            )

        # Add entity nodes & edges
        if al.src_ip:
            ip_node_id = f"ent_ip_{al.src_ip}"
            if ip_node_id not in entity_nodes:
                entity_nodes.add(ip_node_id)
                nodes.append({"id": ip_node_id, "label": al.src_ip, "type": "entity_ip", "val": al.src_ip})
            edges.append(
                {"source": al_node_id, "target": ip_node_id, "relation": "source_ip", "label": "originated_from"}
            )

        if al.dst_host:
            host_node_id = f"ent_host_{al.dst_host}"
            if host_node_id not in entity_nodes:
                entity_nodes.add(host_node_id)
                nodes.append({"id": host_node_id, "label": al.dst_host, "type": "entity_host", "val": al.dst_host})
            edges.append(
                {"source": al_node_id, "target": host_node_id, "relation": "target_host", "label": "targeted_host"}
            )

        if al.user:
            user_node_id = f"ent_user_{al.user}"
            if user_node_id not in entity_nodes:
                entity_nodes.add(user_node_id)
                nodes.append({"id": user_node_id, "label": al.user, "type": "entity_user", "val": al.user})
            edges.append(
                {"source": al_node_id, "target": user_node_id, "relation": "targeted_user", "label": "targeted_user"}
            )

    return {
        "incident_id": inc.incident_id,
        "nodes": nodes,
        "edges": edges,
    }


@router.get("/{incident_id}/replay", tags=["incidents"])
def get_incident_replay_data(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Retrieve chronological telemetry events and stages for 10x replay mode.
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    alerts = (
        db.query(AlertORM)
        .filter(AlertORM.alert_id.in_(inc.alert_ids or []))
        .order_by(AlertORM.ts.asc())
        .all()
    )

    ev_ids: set[str] = set()
    for a in alerts:
        ev_ids.update(a.evidence_event_ids or [])

    events = db.query(EventORM).filter(EventORM.event_id.in_(list(ev_ids))).order_by(EventORM.ts.asc()).all()

    replay_steps: list[dict[str, Any]] = []
    base_time = events[0].ts if events else (alerts[0].ts if alerts else datetime.now(timezone.utc))

    for idx, ev in enumerate(events, start=1):
        offset = max(0.0, (ev.ts - base_time).total_seconds()) if ev.ts else float(idx * 2)
        replay_steps.append(
            {
                "step": idx,
                "event_id": ev.event_id,
                "timestamp": ev.ts.isoformat() if ev.ts else None,
                "offset_seconds": round(offset, 2),
                "source_type": ev.source_type,
                "raw": ev.raw,
                "src_ip": ev.src_ip,
                "dst_host": ev.host,
                "user": ev.user,
                "action": ev.action,
                "outcome": ev.outcome,
                "triggered_alert": next((a.alert_id for a in alerts if ev.event_id in (a.evidence_event_ids or [])), None),
            }
        )

    return {
        "incident_id": incident_id,
        "total_events": len(replay_steps),
        "total_duration_seconds": replay_steps[-1]["offset_seconds"] if replay_steps else 0,
        "recommended_speed": 10,
        "steps": replay_steps,
    }


@router.get("/{incident_id}/traces", tags=["incidents", "traces"])
def get_incident_traces(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve all multi-agent execution traces for an incident."""
    traces = (
        db.query(AgentTraceORM)
        .filter(AgentTraceORM.incident_id == incident_id)
        .order_by(AgentTraceORM.step_index.asc())
        .all()
    )

    if not traces:
        inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    trace_items = [
        {
            "trace_id": t.trace_id,
            "step_index": t.step_index,
            "agent_name": t.agent_name,
            "state": t.state,
            "inputs": t.inputs,
            "tool_calls": t.tool_calls,
            "output_message": t.output_message,
            "latency_ms": t.latency_ms,
            "tokens": t.tokens,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in traces
    ]

    total_latency_ms = sum(t["latency_ms"] for t in trace_items)
    total_tokens = sum(t["tokens"] for t in trace_items)

    return {
        "incident_id": incident_id,
        "total_steps": len(trace_items),
        "total_latency_ms": round(total_latency_ms, 2),
        "total_tokens": total_tokens,
        "traces": trace_items,
    }


@router.get("/traces/{trace_id}", tags=["traces"])
def get_trace_detail(trace_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve detailed execution trace by trace_id."""
    trace = db.query(AgentTraceORM).filter(AgentTraceORM.trace_id == trace_id).first()
    if not trace:
        raise HTTPException(status_code=404, detail=f"Trace '{trace_id}' not found.")

    return {
        "trace_id": trace.trace_id,
        "incident_id": trace.incident_id,
        "step_index": trace.step_index,
        "agent_name": trace.agent_name,
        "state": trace.state,
        "inputs": trace.inputs,
        "tool_calls": trace.tool_calls,
        "output_message": trace.output_message,
        "latency_ms": trace.latency_ms,
        "tokens": trace.tokens,
        "created_at": trace.created_at.isoformat() if trace.created_at else None,
    }
