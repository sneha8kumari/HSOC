"""
Action Guardrail: Enforces that LLM outputs can ONLY RECOMMEND remediation steps.

Autonomous execution of disruptive security operations is strictly blocked.
Execution of disruptive actions requires explicit, verified human analyst approval
recorded in the database (FeedbackORM).

Key guardrails:
  1. Recommendation-only enforcement:
     All remediation steps are treated as recommendations.
     Disruptive verbs (block, isolate, kill, disable, delete, shutdown, revoke, quarantine)
     are force-flagged with needs_approval=True, regardless of LLM generation.
  2. Execution gatekeeping:
     Any call to execute_remediation_step must check for a corresponding human analyst
     approval in FeedbackORM. If unapproved or declined, execution is denied.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from hsoc.config import get_settings
from hsoc.db import FeedbackORM
from hsoc.schema import RemediationStep

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Outcome of attempting to execute a remediation action."""

    status: str  # "EXECUTED" | "BLOCKED"
    executed: bool
    reason: str
    target: str
    step_text: str
    approved_by: str | None = None


class ActionGuardrail:
    """
    Enforces recommendation boundaries and execution authorization checks.
    """

    def __init__(self) -> None:
        cfg = get_settings().genai.get("action_guardrail", {})
        self.enforce_approval = cfg.get("enforce_analyst_approval", True)
        self.disruptive_verbs = frozenset(
            cfg.get(
                "disruptive_verbs",
                [
                    "disable",
                    "block",
                    "kill",
                    "isolate",
                    "delete",
                    "shutdown",
                    "revoke",
                    "quarantine",
                ],
            )
        )
        self.allowed_autonomous_verbs = frozenset(
            cfg.get(
                "allowed_autonomous_verbs",
                ["log", "notify", "document", "record"],
            )
        )

    def is_disruptive(self, step_text: str) -> bool:
        """Check if action text contains any disruptive operational verb."""
        lower = step_text.lower()
        return any(verb in lower for verb in self.disruptive_verbs)

    def is_autonomous_allowed(self, step_text: str) -> bool:
        """Check if action text is in the safe autonomous allowlist."""
        lower = step_text.lower()
        has_auto = any(verb in lower for verb in self.allowed_autonomous_verbs)
        has_disruptive = self.is_disruptive(step_text)
        return has_auto and not has_disruptive

    def enforce_recommendation_flags(
        self,
        steps: list[RemediationStep | dict[str, Any]],
    ) -> list[RemediationStep]:
        """
        Verify that all disruptive actions have needs_approval=True.
        Prevents LLM or prompt injection from claiming auto-execution rights.
        """
        validated_steps: list[RemediationStep] = []
        for step in steps:
            if isinstance(step, dict):
                step_obj = RemediationStep(**step)
            else:
                step_obj = step

            if self.is_disruptive(step_obj.step):
                step_obj.needs_approval = True

            validated_steps.append(step_obj)
        return validated_steps

    def can_execute(
        self,
        step: RemediationStep | dict[str, Any],
        incident_id: str,
        db: Session | None = None,
        step_index: int | None = None,
    ) -> tuple[bool, str]:
        """
        Evaluate whether a remediation step is authorized for execution.

        Args:
            step: The RemediationStep or dict.
            incident_id: Associated incident ID.
            db: Active SQLAlchemy database session.
            step_index: 0-indexed position of step within report.

        Returns:
            (authorized: bool, reason: str)
        """
        step_text = step.step if isinstance(step, RemediationStep) else step.get("step", "")
        needs_approval = (
            step.needs_approval if isinstance(step, RemediationStep) else step.get("needs_approval", True)
        )

        # Autonomous non-disruptive actions (e.g. logging/documenting)
        if not needs_approval and self.is_autonomous_allowed(step_text):
            return True, "Autonomous execution permitted for non-disruptive telemetry action."

        # If approval is disabled in test settings
        if not self.enforce_approval:
            return True, "Action approval enforcement disabled in configuration."

        # Disruptive or approval-requiring actions require explicit DB analyst feedback
        if db is None:
            return False, "Execution blocked: No database session provided to verify analyst approval."

        feedback: FeedbackORM | None = (
            db.query(FeedbackORM)
            .filter(FeedbackORM.incident_id == incident_id)
            .order_by(FeedbackORM.ts.desc())
            .first()
        )

        if feedback is None:
            return (
                False,
                f"Execution blocked: Disruptive action '{step_text}' requires explicit human analyst approval. "
                f"No feedback record found for incident {incident_id}.",
            )

        if feedback.decision == "rejected":
            return (
                False,
                f"Execution blocked: Analyst rejected remediation plan for incident {incident_id}. "
                f"Comment: '{feedback.comment}'",
            )

        # Check declined steps list
        declined = set(feedback.declined_steps or [])
        if step_index is not None and step_index in declined:
            return (
                False,
                f"Execution blocked: Step {step_index} ('{step_text}') was explicitly declined by analyst.",
            )

        # Check approved steps list or full acceptance
        approved = set(feedback.approved_steps or [])
        if step_index is not None and step_index in approved:
            return True, f"Approved: Step {step_index} confirmed in analyst approved_steps."

        if feedback.decision == "accepted":
            return True, "Approved: Analyst accepted complete remediation plan."

        return (
            False,
            f"Execution blocked: Step '{step_text}' lacks explicit approval in analyst feedback decision '{feedback.decision}'.",
        )

    def execute_action(
        self,
        step: RemediationStep | dict[str, Any],
        incident_id: str,
        db: Session | None = None,
        step_index: int | None = None,
        analyst_user: str | None = None,
    ) -> ExecutionResult:
        """
        Attempt execution of a remediation step through the guardrail.

        Args:
            step: Remediation step.
            incident_id: Incident identifier.
            db: Database session.
            step_index: Step index.
            analyst_user: Username of requesting analyst.

        Returns:
            ExecutionResult indicating EXECUTED or BLOCKED.
        """
        step_obj = step if isinstance(step, RemediationStep) else RemediationStep(**step)
        authorized, reason = self.can_execute(
            step=step_obj,
            incident_id=incident_id,
            db=db,
            step_index=step_index,
        )

        target_val = getattr(step_obj, "target", "")
        if not authorized:
            logger.warning(
                "ActionGuardrail BLOCKED execution on incident %s: %s",
                incident_id,
                reason,
            )
            return ExecutionResult(
                status="BLOCKED",
                executed=False,
                reason=reason,
                target=target_val,
                step_text=step_obj.step,
                approved_by=None,
            )

        logger.info(
            "ActionGuardrail AUTHORIZED execution on incident %s: %s (target=%s)",
            incident_id,
            step_obj.step,
            target_val,
        )
        return ExecutionResult(
            status="EXECUTED",
            executed=True,
            reason=reason,
            target=target_val,
            step_text=step_obj.step,
            approved_by=analyst_user or "analyst",
        )


# Global guardrail helper instance
_GUARDRAIL = ActionGuardrail()


def get_action_guardrail() -> ActionGuardrail:
    return _GUARDRAIL
