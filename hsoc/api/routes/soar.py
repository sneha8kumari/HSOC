"""
SOAR Containment Action API Router.

Endpoints:
  POST /api/v1/soar/actions          - Approve (execute/dry-run) or Reject a containment step
  POST /api/v1/soar/actions/{id}/rollback - Roll back an executed containment action
  GET  /api/v1/soar/actions          - List audit records (filtered by incident_id)
  GET  /api/v1/soar/status           - Get SOAR operational status & configuration
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import SOARActionORM, get_db
from hsoc.soar.actions import get_soar_engine

logger = logging.getLogger(__name__)

router = APIRouter()


class SOARActionRequest(BaseModel):
    """Payload for approving or rejecting a containment step."""
    incident_id: str = Field(..., description="ID of the incident requiring containment")
    step: str = Field(..., description="Recommended remediation text or action description")
    decision: str = Field("approved", description="'approved' or 'rejected'")
    action_type: str | None = Field(None, description="Explicit action override: block_ip, isolate_host, disable_user")
    target: str | None = Field(None, description="Explicit target override (IP, hostname, or user)")
    approved_by: str = Field("analyst", description="Identity or username of approving analyst")
    asset_criticality: int = Field(0, description="Target asset criticality score (1-5)")
    evidence_alert_ids: list[str] = Field(default_factory=list, description="IDs of alerts providing evidence")


class SOARRollbackRequest(BaseModel):
    """Payload for rolling back an action."""
    reason: str = Field("Analyst requested rollback", description="Reason for rollback")


@router.post("/actions", tags=["soar"])
def handle_action(
    payload: SOARActionRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Handle analyst decision on a recommended containment step.
    If approved: validates target, checks safety guardrails, performs simulated containment, and logs audit record.
    If rejected: records the decision in audit log and analyst feedback without executing.
    """
    engine = get_soar_engine()
    
    # Auto-expire any stale actions first
    engine.check_expirations()

    decision_norm = payload.decision.strip().lower()

    if decision_norm == "rejected":
        result = engine.reject_action(
            incident_id=payload.incident_id,
            step=payload.step,
            action_type=payload.action_type,
            target=payload.target,
            rejected_by=payload.approved_by,
        )
        return result

    elif decision_norm == "approved":
        result = engine.execute_action(
            incident_id=payload.incident_id,
            step=payload.step,
            action_type=payload.action_type,
            target=payload.target,
            approved_by=payload.approved_by,
            asset_criticality=payload.asset_criticality,
            evidence_alert_ids=payload.evidence_alert_ids,
        )
        return result

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{payload.decision}'. Expected 'approved' or 'rejected'.",
        )


@router.post("/actions/{action_id}/rollback", tags=["soar"])
def rollback_action(
    action_id: str,
    payload: SOARRollbackRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Roll back an active or simulated containment action.
    """
    engine = get_soar_engine()
    reason = payload.reason if payload else "Analyst requested rollback"
    res = engine.rollback_action(action_id=action_id, reason=reason)
    if not res.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("message"))
    return res


@router.get("/actions", tags=["soar"])
def list_actions(
    incident_id: str | None = Query(None, description="Filter by incident ID"),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """
    List SOAR containment action audit records.
    """
    engine = get_soar_engine()
    engine.check_expirations()

    query = db.query(SOARActionORM)
    if incident_id:
        query = query.filter(SOARActionORM.incident_id == incident_id)

    rows = query.order_by(SOARActionORM.created_at.desc()).all()

    return [
        {
            "id": r.id,
            "action_id": r.action_id,
            "incident_id": r.incident_id,
            "action_type": r.action_type,
            "target": r.target,
            "status": r.status,
            "is_dry_run": r.is_dry_run,
            "approved_by": r.approved_by,
            "evidence_alert_ids": r.evidence_alert_ids or [],
            "details": r.details or {},
            "ttl_minutes": r.ttl_minutes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "rolled_back_at": r.rolled_back_at.isoformat() if r.rolled_back_at else None,
            "rollback_reason": r.rollback_reason,
        }
        for r in rows
    ]


@router.get("/status", tags=["soar"])
def get_soar_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Get SOAR operational status, kill switch, and active containment count.
    """
    engine = get_soar_engine()
    engine.check_expirations()

    cfg = get_settings().soar
    active_count = db.query(SOARActionORM).filter(SOARActionORM.status.in_(["simulated", "executed"])).count()

    return {
        "enabled": bool(cfg.get("enabled", True)),
        "dry_run": bool(cfg.get("dry_run", True)),
        "kill_switch": bool(cfg.get("kill_switch", False)),
        "ttl_minutes": int(cfg.get("ttl_minutes", 30)),
        "active_containments": active_count,
        "protected": cfg.get("protected", {}),
    }
