"""
SOAR Containment Actions, Safety Guardrails, and Audit Engine for H-SOC.

Implements simulated, non-destructive containment actions:
  - block_ip (with TTL auto-expiration)
  - isolate_host
  - disable_user

Enforces strict safety guardrails:
  - Regex & IP validation preventing command injection
  - Refusal of protected infrastructure and high-criticality assets
  - Global kill switch
  - Audit logging to soar_actions table
  - Rollback capability restoring state
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import re
from typing import Any, Tuple
import uuid

from hsoc.config import get_settings
from hsoc.db import FeedbackORM, IncidentORM, SOARActionORM, SessionLocal

logger = logging.getLogger(__name__)

# Strict validation patterns
_HOSTNAME_REGEX = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)
_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_DANGEROUS_CHARS = set(";&|`$><\n\r\t")


def validate_target(action_type: str, target: str) -> tuple[bool, str]:
    """
    Validate target string against strict syntax.
    Guarantees untrusted log text cannot inject command sequences.
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"
    target_clean = target.strip()
    # 1. Reject any dangerous shell metacharacters or whitespace
    if any(c in _DANGEROUS_CHARS for c in target_clean) or " " in target_clean:
        return False, f"Target '{target_clean}' contains disallowed shell metacharacters or spaces"

    # 2. Type-specific validation
    if action_type == "block_ip":
        try:
            ipaddress.ip_address(target_clean)
            return True, ""
        except ValueError:
            res = resolve_asset_entity(target_clean)
            if res.get("resolved_ip"):
                return True, ""
            return False, f"Invalid IP address format: '{target_clean}'"

    elif action_type == "isolate_host":
        is_valid_host = bool(_HOSTNAME_REGEX.match(target_clean))
        is_valid_ip = False
        try:
            ipaddress.ip_address(target_clean)
            is_valid_ip = True
        except ValueError:
            pass
        if is_valid_host or is_valid_ip:
            return True, ""
        return False, f"Invalid hostname or host IP format: '{target_clean}'"

    elif action_type == "disable_user":
        if _USERNAME_REGEX.match(target_clean):
            return True, ""
        return False, f"Invalid username format: '{target_clean}'"

    else:
        return False, f"Unknown action type: '{action_type}'"


def resolve_asset_entity(target: str) -> dict[str, Any]:
    """
    Resolve target IP and hostname bidirectionally using asset inventory.
    Returns dict with target, resolved_ip, resolved_host, criticality, role, owner, found.
    """
    res: dict[str, Any] = {
        "target": target,
        "resolved_ip": None,
        "resolved_host": None,
        "criticality": 1,
        "role": "unknown",
        "owner": "unknown",
        "found": False,
    }
    if not target or not isinstance(target, str):
        return res

    target_clean = target.strip()
    try:
        inv_path = get_settings().asset_inventory_path
        if inv_path and inv_path.exists():
            import csv
            with open(inv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    h = (row.get("host") or "").strip()
                    ip = (row.get("ip") or "").strip()
                    crit = int(row.get("criticality") or 1)
                    r = (row.get("role") or "").strip()
                    o = (row.get("owner") or "").strip()

                    if target_clean.lower() == h.lower() or target_clean == ip:
                        res["resolved_host"] = h
                        res["resolved_ip"] = ip
                        res["criticality"] = crit
                        res["role"] = r
                        res["owner"] = o
                        res["found"] = True
                        return res
    except Exception as exc:
        logger.debug("Failed resolving target %s in asset inventory: %s", target, exc)

    return res



def is_target_protected(action_type: str, target: str, asset_criticality: int = 0) -> tuple[bool, str]:
    """
    Evaluate whether a target is protected infrastructure or high-criticality asset.
    """
    cfg = get_settings().soar
    protected = cfg.get("protected", {})
    # 1. Criticality threshold check
    max_crit = int(protected.get("criticality_threshold", 4))
    if asset_criticality >= max_crit:
        return True, f"Asset criticality ({asset_criticality}) >= protected threshold ({max_crit})"

    target_lower = target.strip().lower()
    # 2. Loopback and default infrastructure IPs
    protected_ips = [ip.lower() for ip in protected.get("ips", ["127.0.0.1", "::1", "0.0.0.0", "192.168.56.1"])]
    if target_lower in protected_ips or target_lower in ("127.0.0.1", "::1", "0.0.0.0", "localhost"):
        return True, f"Target IP '{target}' is protected core infrastructure"

    # 3. Protected hostnames (e.g. domain controllers, gateways)
    protected_hosts = [h.lower() for h in protected.get("hostnames", ["localhost", "dc-01", "dc-02", "hsoc-core", "gateway"])]
    if target_lower in protected_hosts or "dc-" in target_lower or "gateway" in target_lower:
        return True, f"Target host '{target}' is protected domain infrastructure"

    # 4. Protected system users
    protected_users = [u.lower() for u in protected.get("users", ["root", "administrator", "system", "hsoc"])]
    if target_lower in protected_users:
        return True, f"Target user '{target}' is protected system account"

    return False, ""


def parse_step_to_action(step_text: str, incident_data: dict | Any = None) -> tuple[str, str]:
    """
    Extract action_type and target from a human-readable recommendation string.
    The action target MUST come from the recommended step itself if present,
    never from another incident field.
    """
    text = (step_text or "").strip()
    text_lower = text.lower()

    # 1. Determine action type (note: check 'block' before 'lock' to avoid matching 'b-lock')
    if any(k in text_lower for k in ["block", "firewall", "iptables", "drop"]):
        action_type = "block_ip"
    elif any(k in text_lower for k in ["isolate", "vlan", "quarantine"]):
        action_type = "isolate_host"
    elif any(k in text_lower for k in ["disable", "revoke", "user", "account"]) or bool(re.search(r"\block\b", text_lower)):
        action_type = "disable_user"
    else:
        action_type = "block_ip"

    # 2. Extract target strictly from step_text first
    target = None

    if action_type == "isolate_host":
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        host_match = re.search(r"\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\b", text, re.I)

        if ip_match:
            target = ip_match.group(0)
        elif host_match:
            target = host_match.group(0)

        # If no direct match, check token after host
        if not target:
            after_host = re.search(r"\bhost\s+([a-zA-Z0-9.-]+)\b", text, re.I)
            if after_host and after_host.group(1).lower() not in ["from", "the", "and", "to", "subnets"]:
                target = after_host.group(1)

        # Fallback to incident data ONLY if step text contained no target at all
        if not target:
            if incident_data:
                if isinstance(incident_data, dict):
                    target = incident_data.get("affected_host") or incident_data.get("dst_host") or incident_data.get("src_ip")
                else:
                    target = getattr(incident_data, "affected_host", None) or getattr(incident_data, "dst_host", None) or getattr(incident_data, "src_ip", None)
            target = target or "web-srv-01"

        return "isolate_host", target

    elif action_type == "disable_user":
        user_kw_match = re.search(r"\b(?:user|account)\s+([a-zA-Z0-9._-]+)\b", text, re.I)
        verb_match = re.search(r"\b(?:disable|revoke|lock)\s+(?:user\s+|account\s+)?([a-zA-Z0-9._-]+)\b", text, re.I)
        if user_kw_match:
            target = user_kw_match.group(1)
        elif verb_match and verb_match.group(1).lower() not in ["user", "account", "access", "tokens", "session"]:
            target = verb_match.group(1)

        if not target:
            if incident_data:
                target = incident_data.get("user") if isinstance(incident_data, dict) else getattr(incident_data, "user", None)
            target = target or "compromised_user"

        return "disable_user", target

    else:  # block_ip
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        if ip_match:
            target = ip_match.group(0)
        else:
            host_match = re.search(r"\b(?:host|srv|server|node|ws|app|db|auth|file|legacy)-[a-zA-Z0-9-]+\b", text, re.I)
            if host_match:
                res = resolve_asset_entity(host_match.group(0))
                target = res.get("resolved_ip") or host_match.group(0)

        if not target:
            if incident_data:
                target = incident_data.get("src_ip") if isinstance(incident_data, dict) else getattr(incident_data, "src_ip", None)
            target = target or "192.168.56.200"

        return "block_ip", target



class ContainmentAction(ABC):
    """Abstract base class for all simulated containment actions."""

    def __init__(self, target: str, incident_id: str, ttl_minutes: int = 30, is_dry_run: bool = True) -> None:
        self.target = target
        self.incident_id = incident_id
        self.ttl_minutes = ttl_minutes
        self.is_dry_run = is_dry_run
        self.action_type = self.__class__.__name__

    @abstractmethod
    def dry_run(self) -> dict[str, Any]:
        """Simulate action execution without system changes."""
        ...

    @abstractmethod
    def execute(self) -> dict[str, Any]:
        """Execute simulated containment record."""
        ...

    @abstractmethod
    def rollback(self) -> dict[str, Any]:
        """Rollback simulated containment action."""
        ...


class BlockIPAction(ContainmentAction):
    """Simulated firewall perimeter IP blocking with TTL."""

    def dry_run(self) -> dict[str, Any]:
        return {
            "action": "block_ip",
            "target": self.target,
            "simulated_command": f"iptables -A INPUT -s {self.target} -j DROP",
            "mode": "dry_run",
            "summary": f"[DRY RUN] Would block IP {self.target} at perimeter firewall for {self.ttl_minutes} min",
        }

    def execute(self) -> dict[str, Any]:
        return {
            "action": "block_ip",
            "target": self.target,
            "simulated_command": f"iptables -A INPUT -s {self.target} -j DROP",
            "mode": "simulated_active",
            "summary": f"Blocked IP {self.target} for {self.ttl_minutes} min (simulated firewall rule)",
        }

    def rollback(self) -> dict[str, Any]:
        return {
            "action": "unblock_ip",
            "target": self.target,
            "simulated_command": f"iptables -D INPUT -s {self.target} -j DROP",
            "summary": f"Unblocked IP {self.target} (firewall rule deleted)",
        }


class IsolateHostAction(ContainmentAction):
    """Simulated endpoint/host network isolation."""

    def dry_run(self) -> dict[str, Any]:
        return {
            "action": "isolate_host",
            "target": self.target,
            "simulated_command": f"agent_ctl isolate --host {self.target} --quarantine-vlan 999",
            "mode": "dry_run",
            "summary": f"[DRY RUN] Would isolate host {self.target} to quarantine VLAN for {self.ttl_minutes} min",
        }

    def execute(self) -> dict[str, Any]:
        return {
            "action": "isolate_host",
            "target": self.target,
            "simulated_command": f"agent_ctl isolate --host {self.target} --quarantine-vlan 999",
            "mode": "simulated_active",
            "summary": f"Isolated host {self.target} from production network for {self.ttl_minutes} min (simulated)",
        }

    def rollback(self) -> dict[str, Any]:
        return {
            "action": "reconnect_host",
            "target": self.target,
            "simulated_command": f"agent_ctl unisolate --host {self.target}",
            "summary": f"Restored network access for host {self.target}",
        }


class DisableUserAction(ContainmentAction):
    """Simulated user account lockout."""

    def dry_run(self) -> dict[str, Any]:
        return {
            "action": "disable_user",
            "target": self.target,
            "simulated_command": f"usermod -L {self.target}",
            "mode": "dry_run",
            "summary": f"[DRY RUN] Would lock account for user {self.target}",
        }

    def execute(self) -> dict[str, Any]:
        return {
            "action": "disable_user",
            "target": self.target,
            "simulated_command": f"usermod -L {self.target}",
            "mode": "simulated_active",
            "summary": f"Locked account for user {self.target} (simulated)",
        }

    def rollback(self) -> dict[str, Any]:
        return {
            "action": "enable_user",
            "target": self.target,
            "simulated_command": f"usermod -U {self.target}",
            "summary": f"Unlocked account for user {self.target}",
        }


_ACTION_CLASSES = {
    "block_ip": BlockIPAction,
    "isolate_host": IsolateHostAction,
    "disable_user": DisableUserAction,
}


class SOAREngine:
    """
    Central SOAR Engine for executing and auditing containment actions.
    """

    def execute_action(
        self,
        incident_id: str,
        step: str,
        action_type: str | None = None,
        target: str | None = None,
        approved_by: str = "analyst",
        asset_criticality: int = 0,
        evidence_alert_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Validate, execute (or dry-run), and persist a containment action.
        """
        cfg = get_settings().soar
        enabled = bool(cfg.get("enabled", True))
        kill_switch = bool(cfg.get("kill_switch", False))
        is_dry_run = bool(cfg.get("dry_run", True))
        ttl_minutes = int(cfg.get("ttl_minutes", 30))

        # Check incident in DB if needed
        db = SessionLocal()
        incident_row = None
        try:
            incident_row = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
        finally:
            db.close()

        # Parse action and target if not explicitly passed
        if not action_type or not target:
            parsed_type, parsed_target = parse_step_to_action(step, incident_row)
            action_type = action_type or parsed_type
            target = target or parsed_target

        action_id = f"ACT-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=ttl_minutes)

        # 1. Kill Switch Check
        if not enabled or kill_switch:
            record = self._persist_record(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                status="refused",
                is_dry_run=is_dry_run,
                approved_by=approved_by,
                evidence_alert_ids=evidence_alert_ids or [],
                details={"reason": "SOAR kill switch active or SOAR disabled", "step": step},
                ttl_minutes=ttl_minutes,
                created_at=now,
                expires_at=None,
            )
            return {
                "success": False,
                "status": "refused",
                "action_id": action_id,
                "target": target,
                "action_type": action_type,
                "message": "Action refused: SOAR kill switch is active.",
                "record": record,
            }

        # 2. Strict Target Validation Check
        valid, val_err = validate_target(action_type, target)
        if not valid:
            record = self._persist_record(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                status="refused",
                is_dry_run=is_dry_run,
                approved_by=approved_by,
                evidence_alert_ids=evidence_alert_ids or [],
                details={"reason": val_err, "step": step},
                ttl_minutes=ttl_minutes,
                created_at=now,
                expires_at=None,
            )
            return {
                "success": False,
                "status": "refused",
                "action_id": action_id,
                "target": target,
                "action_type": action_type,
                "message": f"Action refused: {val_err}",
                "record": record,
            }

        # 3. Protected Infrastructure Check
        crit_val = asset_criticality or (getattr(incident_row, "asset_criticality", 0) if incident_row else 0)
        protected, prot_err = is_target_protected(action_type, target, asset_criticality=crit_val)
        if protected:
            record = self._persist_record(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                status="refused",
                is_dry_run=is_dry_run,
                approved_by=approved_by,
                evidence_alert_ids=evidence_alert_ids or [],
                details={"reason": prot_err, "step": step},
                ttl_minutes=ttl_minutes,
                created_at=now,
                expires_at=None,
            )
            return {
                "success": False,
                "status": "refused",
                "action_id": action_id,
                "target": target,
                "action_type": action_type,
                "message": f"Action refused: {prot_err}",
                "record": record,
            }

        # 4. Instantiate Action Implementation
        action_cls = _ACTION_CLASSES.get(action_type, BlockIPAction)
        action_instance = action_cls(target=target, incident_id=incident_id, ttl_minutes=ttl_minutes, is_dry_run=is_dry_run)

        # Execute or Dry Run
        if is_dry_run:
            exec_res = action_instance.dry_run()
            status_val = "simulated"
        else:
            exec_res = action_instance.execute()
            status_val = "executed"

        # Resolve target through asset inventory
        asset_info = resolve_asset_entity(target)
        resolved_host = asset_info.get("resolved_host")
        resolved_ip = asset_info.get("resolved_ip")

        # 5. Persist Audit Record in soar_actions table
        record = self._persist_record(
            action_id=action_id,
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            status=status_val,
            is_dry_run=is_dry_run,
            approved_by=approved_by,
            evidence_alert_ids=evidence_alert_ids or (getattr(incident_row, "alert_ids", []) if incident_row else []),
            details={
                "step": step,
                "execution": exec_res,
                "resolved_host": resolved_host,
                "resolved_ip": resolved_ip,
                "role": asset_info.get("role"),
            },
            ttl_minutes=ttl_minutes,
            created_at=now,
            expires_at=expires_at,
        )

        # 6. Feed Analyst Feedback Loop
        self._record_analyst_feedback(incident_id, decision="accepted", approved_step=step)

        # Format status text using real action name: "Isolated <target> (simulated) for 30 min"
        if action_type == "isolate_host":
            action_verb = "Isolated"
        elif action_type == "block_ip":
            action_verb = "Blocked"
        elif action_type == "disable_user":
            action_verb = "Disabled"
        else:
            action_verb = action_type.replace("_", " ").title()

        status_line = f"{action_verb} {target} (simulated) for {ttl_minutes} min"

        return {
            "success": True,
            "status": status_val,
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "ttl_minutes": ttl_minutes,
            "status_line": status_line,
            "expires_at": expires_at.isoformat(),
            "execution": exec_res,
            "record": record,
        }

    def reject_action(
        self,
        incident_id: str,
        step: str,
        action_type: str | None = None,
        target: str | None = None,
        rejected_by: str = "analyst",
        reason: str = "Analyst rejected recommended step",
    ) -> dict[str, Any]:
        """
        Record analyst rejection in audit log and analyst feedback without executing.
        """
        action_id = f"ACT-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        parsed_type, parsed_target = parse_step_to_action(step)
        action_type = action_type or parsed_type
        target = target or parsed_target

        record = self._persist_record(
            action_id=action_id,
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            status="rejected",
            is_dry_run=True,
            approved_by=rejected_by,
            evidence_alert_ids=[],
            details={"step": step, "reason": reason},
            ttl_minutes=0,
            created_at=now,
            expires_at=None,
        )

        # Feed Analyst Feedback Loop
        self._record_analyst_feedback(incident_id, decision="rejected", declined_step=step)

        return {
            "success": True,
            "status": "rejected",
            "action_id": action_id,
            "message": f"Remediation step rejected by {rejected_by}.",
            "record": record,
        }

    def rollback_action(self, action_id: str, reason: str = "Analyst requested rollback") -> dict[str, Any]:
        """
        Roll back an active or simulated containment action.
        """
        db = SessionLocal()
        try:
            row = db.query(SOARActionORM).filter(SOARActionORM.action_id == action_id).first()
            if not row:
                return {"success": False, "message": f"Action ID '{action_id}' not found."}

            if row.status == "rolled_back":
                return {"success": False, "message": f"Action '{action_id}' is already rolled back."}

            action_cls = _ACTION_CLASSES.get(row.action_type, BlockIPAction)
            action_instance = action_cls(target=row.target, incident_id=row.incident_id)
            rollback_res = action_instance.rollback()

            now = datetime.now(timezone.utc)
            row.status = "rolled_back"
            row.rolled_back_at = now
            row.rollback_reason = reason
            
            # Update details
            curr_details = dict(row.details or {})
            curr_details["rollback"] = rollback_res
            row.details = curr_details

            db.commit()

            return {
                "success": True,
                "status": "rolled_back",
                "action_id": action_id,
                "target": row.target,
                "rollback": rollback_res,
                "message": f"Successfully rolled back action on {row.target}.",
            }
        except Exception as exc:
            db.rollback()
            logger.error("Failed rolling back action %s: %s", action_id, exc)
            return {"success": False, "message": f"Rollback failed: {str(exc)}"}
        finally:
            db.close()

    def check_expirations(self) -> list[str]:
        """
        Auto-expire actions whose TTL has passed.
        """
        db = SessionLocal()
        expired_ids = []
        try:
            now = datetime.now(timezone.utc)
            rows = db.query(SOARActionORM).filter(
                SOARActionORM.status.in_(["simulated", "executed"]),
                SOARActionORM.expires_at <= now,
            ).all()

            for r in rows:
                r.status = "expired"
                expired_ids.append(r.action_id)

            if expired_ids:
                db.commit()
                logger.info("Auto-expired %d SOAR containment actions: %s", len(expired_ids), expired_ids)
            return expired_ids
        except Exception as exc:
            db.rollback()
            logger.error("Error auto-expiring SOAR actions: %s", exc)
            return []
        finally:
            db.close()

    def _persist_record(
        self,
        action_id: str,
        incident_id: str,
        action_type: str,
        target: str,
        status: str,
        is_dry_run: bool,
        approved_by: str,
        evidence_alert_ids: list,
        details: dict,
        ttl_minutes: int,
        created_at: datetime,
        expires_at: datetime | None,
    ) -> dict[str, Any]:
        """Write audit log entry into soar_actions table."""
        db = SessionLocal()
        try:
            orm = SOARActionORM(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                status=status,
                is_dry_run=is_dry_run,
                approved_by=approved_by,
                evidence_alert_ids=evidence_alert_ids,
                details=details,
                ttl_minutes=ttl_minutes,
                created_at=created_at,
                expires_at=expires_at,
            )
            db.add(orm)
            db.commit()
            return {
                "action_id": action_id,
                "incident_id": incident_id,
                "action_type": action_type,
                "target": target,
                "status": status,
                "is_dry_run": is_dry_run,
                "approved_by": approved_by,
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat() if expires_at else None,
                "details": details,
            }
        except Exception as exc:
            db.rollback()
            logger.error("Failed persisting SOAR audit record: %s", exc)
            return {}
        finally:
            db.close()

    def _record_analyst_feedback(
        self,
        incident_id: str,
        decision: str,
        approved_step: str | None = None,
        declined_step: str | None = None,
    ) -> None:
        """Feed the existing analyst feedback table with the decision."""
        db = SessionLocal()
        try:
            fb = FeedbackORM(
                feedback_id=f"FB-{uuid.uuid4().hex[:12]}",
                report_id="",
                incident_id=incident_id,
                ts=datetime.now(timezone.utc),
                decision=decision,
                comment=f"SOAR {decision} remediation action",
                approved_steps=[approved_step] if approved_step else [],
                declined_steps=[declined_step] if declined_step else [],
            )
            db.add(fb)
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.debug("Non-critical: could not persist analyst feedback: %s", exc)
        finally:
            db.close()


_global_soar_engine: SOAREngine | None = None


def get_soar_engine() -> SOAREngine:
    """Return the global SOAREngine singleton."""
    global _global_soar_engine
    if _global_soar_engine is None:
        _global_soar_engine = SOAREngine()
    return _global_soar_engine
