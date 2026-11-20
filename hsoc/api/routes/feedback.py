"""
Analyst feedback endpoint closing the loop with the Markov predictor and drift monitoring.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from hsoc.db import FeedbackORM, IncidentORM, get_db
from hsoc.investigate.predictor import MarkovPredictor, ModelRegistry
from hsoc.schema import Feedback, FeedbackDecision

logger = logging.getLogger(__name__)
router = APIRouter()

# Shared singleton predictor and registry for API process
_ACTIVE_PREDICTOR = MarkovPredictor()
_REGISTRY = ModelRegistry()

# Initialize baseline version if registry empty
if _REGISTRY.get_current_version() == 0:
    _REGISTRY.save_version(_ACTIVE_PREDICTOR, description="Initial Baseline Markov Model")


def get_active_predictor() -> MarkovPredictor:
    """Return the currently active Markov predictor instance."""
    return _ACTIVE_PREDICTOR


def get_model_registry() -> ModelRegistry:
    """Return the active model registry."""
    return _REGISTRY


@router.post("", tags=["feedback"])
def submit_feedback(
    feedback: Feedback,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Submit analyst feedback on an incident report.

    Closes the loop by executing a Bayesian Dirichlet update on the Markov model,
    calculating rolling KL-divergence drift, and saving a versioned model snapshot.
    """
    # 1. Persist feedback to database
    orm = FeedbackORM(
        feedback_id=feedback.feedback_id,
        report_id=feedback.report_id,
        incident_id=feedback.incident_id,
        ts=feedback.ts,
        decision=feedback.decision.value,
        edited_report=feedback.edited_report,
        comment=feedback.comment,
        approved_steps=feedback.approved_steps,
        declined_steps=feedback.declined_steps,
    )
    db.add(orm)
    db.commit()

    # 2. Look up incident to retrieve attack tactic transitions
    incident_row = db.query(IncidentORM).filter(IncidentORM.incident_id == feedback.incident_id).first()
    tactics = incident_row.tactics if incident_row else []

    # 3. Apply Bayesian Dirichlet update to transitions
    update_summaries = []
    if len(tactics) >= 2:
        for i in range(len(tactics) - 1):
            src, dst = tactics[i], tactics[i + 1]
            corrected = None
            if feedback.decision == FeedbackDecision.edited and feedback.edited_report:
                edited_tactics = feedback.edited_report.get("tactics", [])
                if len(edited_tactics) > i + 1:
                    corrected = edited_tactics[i + 1]

            res = _ACTIVE_PREDICTOR.update_bayesian(
                src=src,
                dst=dst,
                decision=feedback.decision,
                corrected_dst=corrected,
            )
            update_summaries.append(res)
    elif len(tactics) == 1:
        # Single observed tactic: evaluate against predicted next
        src = tactics[0]
        dst = "initial_access" if src == "reconnaissance" else "impact"
        res = _ACTIVE_PREDICTOR.update_bayesian(
            src=src,
            dst=dst,
            decision=feedback.decision,
        )
        update_summaries.append(res)

    # 4. Check for model drift via rolling KL divergence
    is_drifted, kl_val, drift_notice = _ACTIVE_PREDICTOR.check_drift()

    # 5. Save versioned model snapshot
    new_version = _REGISTRY.save_version(
        _ACTIVE_PREDICTOR,
        description=f"Update from feedback {feedback.feedback_id} ({feedback.decision.value})",
    )

    return {
        "status": "success",
        "feedback_id": feedback.feedback_id,
        "incident_id": feedback.incident_id,
        "decision": feedback.decision.value,
        "transitions_updated": update_summaries,
        "model_version": new_version,
        "kl_divergence": kl_val,
        "model_drift_detected": is_drifted,
        "model_drift_notice": drift_notice if is_drifted else None,
    }


@router.post("/rollback", tags=["feedback"])
def rollback_model(
    version: int | None = None,
) -> dict[str, Any]:
    """
    Roll back the active Markov model to a previous version in the registry.
    """
    try:
        restored_ver = _REGISTRY.rollback(_ACTIVE_PREDICTOR, version=version)
        is_drifted, kl_val, notice = _ACTIVE_PREDICTOR.check_drift()
        return {
            "status": "success",
            "action": "rollback",
            "restored_version": restored_ver,
            "kl_divergence": kl_val,
            "model_drift_detected": is_drifted,
            "notice": notice,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
