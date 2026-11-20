"""
Real-time streaming engine for H-SOC.
Emits live attack scenario events (MITRE S1–S8) and benign background traffic
into the database and broadcasts over Server-Sent Events (SSE).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from hsoc.db import AlertORM, EventORM, IncidentORM, SessionLocal

logger = logging.getLogger(__name__)

# Predefined realistic attack scenario stages based on MITRE ATT&CK S1-S8
SCENARIOS_CATALOG = [
    {
        "id": "S8",
        "name": "Full Multi-stage APT Attack Chain",
        "target_host": "192.168.56.20",
        "target_asset": "192.168.56.20",
        "attacker_ip": "203.0.113.11",
        "severity": "critical",
        "steps": [
            {
                "tactic": "reconnaissance",
                "technique": "T1046",
                "stage": "Vertical SYN port scan: 35 distinct ports probed",
                "source_type": "flow",
                "action": "port_scan",
                "outcome": "success",
                "user": None,
                "raw": "TCP SYN scan from 203.0.113.11 against 192.168.56.20 (ports 20-100 probed)",
                "risk_delta": 15,
            },
            {
                "tactic": "initial_access",
                "technique": "CWE-319",
                "stage": "Insecure cleartext protocol (port 21 FTP) authentication exploit",
                "source_type": "auth",
                "action": "exploit",
                "outcome": "success",
                "user": "anonymous",
                "raw": "FTP cleartext login accepted from 203.0.113.11 on port 21",
                "risk_delta": 25,
            },
            {
                "tactic": "credential_access",
                "technique": "T1110.001",
                "stage": "SSH password brute force attack (15 failed password attempts)",
                "source_type": "auth",
                "action": "login",
                "outcome": "failure",
                "user": "admin",
                "raw": "Failed password for admin from 203.0.113.11 port 44820 ssh2 (15 attempts)",
                "risk_delta": 15,
            },
            {
                "tactic": "privilege_escalation",
                "technique": "T1548.003",
                "stage": "Sudo privilege escalation: spawned root bash shell",
                "source_type": "auth",
                "action": "sudo_command",
                "outcome": "success",
                "user": "admin",
                "raw": "sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
                "risk_delta": 25,
            },
            {
                "tactic": "discovery",
                "technique": "T1087",
                "stage": "Account and permission discovery on target workstation",
                "source_type": "auth",
                "action": "command",
                "outcome": "success",
                "user": "root",
                "raw": "cmd: /usr/bin/id ; cat /etc/passwd ; netstat -tulpn",
                "risk_delta": 10,
            },
            {
                "tactic": "lateral_movement",
                "technique": "T1021.004",
                "stage": "Internal lateral movement attempt to auth-srv-02 (port 22)",
                "source_type": "flow",
                "action": "lateral_connect",
                "outcome": "success",
                "user": "root",
                "raw": "Inbound connection from 192.168.56.20 to auth-srv-02 (192.168.56.12:22)",
                "risk_delta": 10,
            },
        ],
    },
    {
        "id": "S5",
        "name": "Web exploit and unauthorized sensitive path traversal",
        "target_host": "legacy-srv",
        "target_asset": "192.168.56.30",
        "attacker_ip": "203.0.113.15",
        "severity": "high",
        "steps": [
            {
                "tactic": "reconnaissance",
                "technique": "T1595.003",
                "stage": "Rapid HTTP 403 probing for /admin and /.env sensitive configs",
                "source_type": "web",
                "action": "http_request",
                "outcome": "blocked",
                "user": "-",
                "raw": '203.0.113.15 - - [26/Oct/2026:22:10:00 +0000] "GET /.env HTTP/1.1" 403 240',
                "risk_delta": 20,
            },
            {
                "tactic": "initial_access",
                "technique": "T1190",
                "stage": "Exploit public-facing application via SQL injection parameter",
                "source_type": "web",
                "action": "http_request",
                "outcome": "success",
                "user": "-",
                "raw": '203.0.113.15 - - [26/Oct/2026:22:10:15 +0000] "POST /api/v1/query?id=1\'%20OR%20\'1\'=\'1 HTTP/1.1" 200 1420',
                "risk_delta": 30,
            },
            {
                "tactic": "persistence",
                "technique": "T1505.003",
                "stage": "Web shell dropped in /var/www/html/uploads/shell.php",
                "source_type": "web",
                "action": "file_upload",
                "outcome": "success",
                "user": "www-data",
                "raw": 'Web shell detected in upload directory: shell.php executed with cmd=whoami',
                "risk_delta": 25,
            },
        ],
    },
    {
        "id": "S2",
        "name": "Distributed SSH brute force and credential access",
        "target_host": "auth-srv-02",
        "target_asset": "auth-srv-02",
        "attacker_ip": "198.51.100.88",
        "severity": "high",
        "steps": [
            {
                "tactic": "credential_access",
                "technique": "T1110.001",
                "stage": "SSH authentication failure storm: 64 invalid attempts",
                "source_type": "auth",
                "action": "login",
                "outcome": "failure",
                "user": "root",
                "raw": "sshd[8812]: Failed password for invalid user root from 198.51.100.88 port 51234 ssh2",
                "risk_delta": 25,
            },
            {
                "tactic": "credential_access",
                "technique": "T1110.003",
                "stage": "Password spraying against multiple domain accounts",
                "source_type": "auth",
                "action": "password_spray",
                "outcome": "failure",
                "user": "service_account",
                "raw": "sshd[8845]: Failed password for service_account from 198.51.100.88 port 51280 ssh2",
                "risk_delta": 20,
            },
            {
                "tactic": "initial_access",
                "technique": "T1078",
                "stage": "Successful compromised credential login on auth-srv-02",
                "source_type": "auth",
                "action": "login",
                "outcome": "success",
                "user": "backup_user",
                "raw": "sshd[8901]: Accepted password for backup_user from 198.51.100.88 port 51310 ssh2",
                "risk_delta": 30,
            },
        ],
    },
]

BENIGN_SAMPLES = [
    {
        "source_type": "auth",
        "host": "ws-01",
        "src_ip": "192.168.56.105",
        "user": "alice",
        "action": "login",
        "outcome": "success",
        "raw": "sshd[4110]: Accepted publickey for alice from 192.168.56.105 port 55412 ssh2",
    },
    {
        "source_type": "web",
        "host": "legacy-srv",
        "src_ip": "192.168.56.110",
        "user": "-",
        "action": "http_request",
        "outcome": "success",
        "raw": '192.168.56.110 - - "GET /healthz HTTP/1.1" 200 45 "HealthCheck/2.1"',
    },
    {
        "source_type": "flow",
        "host": "db-srv-01",
        "src_ip": "192.168.56.100",
        "user": None,
        "action": "db_query",
        "outcome": "success",
        "raw": "PostgreSQL internal replication sync 192.168.56.100:5432 -> 192.168.56.20:5432 OK",
    },
]


class StreamEngine:
    """Singleton stream engine managing live playback and event dissemination."""

    def __init__(self) -> None:
        self.is_running: bool = True
        self.speed: int = 5  # 1x, 5x, 10x
        self.subscribers: set[asyncio.Queue] = set()
        self.scenario_idx: int = 0
        self.step_idx: int = 0
        self.events_emitted: int = 0
        self.active_incident_id: str | None = None
        self._loop_task: asyncio.Task | None = None

    def start_background_task(self) -> None:
        """Start the background generation loop if not already running."""
        if self._loop_task is None or self._loop_task.done():
            self._loop_task = asyncio.create_task(self._run_loop())
            logger.info("StreamEngine background loop launched.")

    async def _run_loop(self) -> None:
        """Main async loop emitting events."""
        while True:
            try:
                # Interval scaled by playback speed (1x = 4s, 5x = 1.2s, 10x = 0.6s)
                interval = max(0.4, 4.0 / self.speed)
                await asyncio.sleep(interval)

                if not self.is_running:
                    continue

                # 70% chance attack scenario step, 30% chance benign noise
                if random.random() < 0.7:
                    await self._emit_scenario_step()
                else:
                    await self._emit_benign_event()

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in StreamEngine loop: %s", exc, exc_info=True)
                await asyncio.sleep(2.0)

    async def _emit_scenario_step(self) -> None:
        """Emit the next attack step from the active scenario into DB and subscribers."""
        scenario = SCENARIOS_CATALOG[self.scenario_idx % len(SCENARIOS_CATALOG)]
        steps = scenario["steps"]
        step = steps[self.step_idx % len(steps)]

        now = datetime.now(timezone.utc)
        ev_id = f"EVT-{uuid.uuid4().hex[:8]}"
        alt_id = f"ALT-{uuid.uuid4().hex[:8]}"

        db = SessionLocal()
        try:
            # 1. Create EventORM
            ev = EventORM(
                event_id=ev_id,
                ts=now,
                source_type=step["source_type"],
                host=scenario["target_host"],
                src_ip=scenario["attacker_ip"],
                dst_ip=scenario["target_asset"] if scenario["target_asset"] != scenario["target_host"] else None,
                dst_port=22 if step["source_type"] == "auth" else 80,
                user=step.get("user"),
                action=step["action"],
                outcome=step["outcome"],
                asset_criticality=3 if scenario["severity"] == "critical" else 2,
                raw=step["raw"],
                raw_hash=uuid.uuid4().hex,
            )
            db.add(ev)

            # 2. Find or create correlated IncidentORM
            inc: IncidentORM | None = None
            if self.active_incident_id:
                inc = db.query(IncidentORM).filter(IncidentORM.incident_id == self.active_incident_id).first()

            if not inc:
                # Find an existing open incident matching the scenario target asset or host
                target_asset = str(scenario.get("target_asset", "")).lower()
                target_host = str(scenario.get("target_host", "")).lower()
                open_incs = db.query(IncidentORM).filter(IncidentORM.status == "open").all()
                for candidate in open_incs:
                    cand_keys = [str(k).lower() for k in (candidate.entity_keys or [])]
                    if any(target_asset in k or target_host in k or k in (target_asset, target_host) for k in cand_keys):
                        inc = candidate
                        self.active_incident_id = inc.incident_id
                        break

            if not inc:
                # Create a fresh incident for this scenario only if none exists
                inc_id = str(uuid.uuid4())
                self.active_incident_id = inc_id
                inc = IncidentORM(
                    incident_id=inc_id,
                    created_at=now,
                    updated_at=now,
                    status="open",
                    severity=scenario["severity"],
                    risk_score=min(98, 40 + step["risk_delta"]),
                    domain="network" if step["source_type"] == "flow" else "endpoint",
                    tactics=[step["tactic"]],
                    techniques=[step["technique"]],
                    entity_keys=[scenario["target_asset"]],
                    alert_ids=[alt_id],
                    timeline=[
                        {
                            "step": 1,
                            "stage": step["stage"],
                            "tactic": step["tactic"],
                            "technique": step["technique"],
                            "timestamp": now.strftime("%H:%M:%S"),
                            "evidence_id": alt_id,
                            "telemetry_log": step["raw"],
                            "out_of_order": False,
                        }
                    ],
                )
                db.add(inc)
            else:
                # Append stage to existing incident timeline or refresh existing stage
                inc.updated_at = now
                inc.risk_score = min(98, max(inc.risk_score or 50, 50 + step["risk_delta"]))
                timeline = list(inc.timeline or [])

                # Check out-of-order stage
                out_of_order = False
                if step["tactic"] == "reconnaissance" and len(timeline) > 0:
                    out_of_order = True
                    inc.out_of_order_stage = True

                # Check if this exact stage is already in the timeline
                existing_stage = next((s for s in timeline if s.get("stage") == step["stage"]), None)
                if existing_stage:
                    existing_stage["timestamp"] = now.strftime("%H:%M:%S")
                    existing_stage["evidence_id"] = alt_id
                    existing_stage["telemetry_log"] = step["raw"]
                else:
                    stage_item = {
                        "step": len(timeline) + 1,
                        "stage": step["stage"],
                        "tactic": step["tactic"],
                        "technique": step["technique"],
                        "timestamp": now.strftime("%H:%M:%S"),
                        "evidence_id": alt_id,
                        "telemetry_log": step["raw"],
                        "out_of_order": out_of_order,
                    }
                    timeline.append(stage_item)
                inc.timeline = timeline

                # Update tactics & techniques
                tactics = list(inc.tactics or [])
                if step["tactic"] not in tactics:
                    tactics.append(step["tactic"])
                inc.tactics = tactics

                techniques = list(inc.techniques or [])
                if step["technique"] not in techniques:
                    techniques.append(step["technique"])
                inc.techniques = techniques

                alert_ids = list(inc.alert_ids or [])
                if alt_id not in alert_ids:
                    alert_ids.append(alt_id)
                inc.alert_ids = alert_ids

            # 3. Create AlertORM
            alt = AlertORM(
                alert_id=alt_id,
                ts=now,
                rule_ids=["LIVE-STREAM-DETECTION"],
                conf=0.92,
                technique=step["technique"],
                tactic=step["tactic"],
                domain=inc.domain,
                src_ip=scenario["attacker_ip"],
                dst_host=scenario["target_host"],
                user=step.get("user"),
                evidence_event_ids=[ev_id],
                description=step["stage"],
                incident_id=inc.incident_id,
            )
            db.add(alt)
            db.commit()

            self.events_emitted += 1

            # Prepare broadcast payload
            payload = {
                "type": "attack_event",
                "scenario_id": scenario["id"],
                "scenario_name": scenario["name"],
                "event": {
                    "event_id": ev_id,
                    "timestamp": now.strftime("%H:%M:%S"),
                    "source_type": step["source_type"],
                    "host": scenario["target_host"],
                    "src_ip": scenario["attacker_ip"],
                    "user": step.get("user"),
                    "action": step["action"],
                    "outcome": step["outcome"],
                    "raw": step["raw"],
                },
                "alert": {
                    "alert_id": alt_id,
                    "tactic": step["tactic"],
                    "technique": step["technique"],
                    "description": step["stage"],
                },
                "incident": {
                    "incident_id": inc.incident_id,
                    "title": f"Live: {step['stage']} on {scenario['target_asset']}",
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                    "target": scenario["target_asset"],
                    "tactic": step["tactic"],
                    "technique": step["technique"],
                    "timeline_length": len(inc.timeline or []),
                    "out_of_order": inc.out_of_order_stage,
                    "updated_at": now.isoformat(),
                },
            }

            await self.broadcast(payload)

            # Advance step index
            self.step_idx += 1
            if self.step_idx >= len(steps):
                self.step_idx = 0
                self.scenario_idx += 1
                # Switch active_incident_id to next scenario's existing incident
                next_scenario = SCENARIOS_CATALOG[self.scenario_idx % len(SCENARIOS_CATALOG)]
                next_asset = str(next_scenario.get("target_asset", "")).lower()
                next_host = str(next_scenario.get("target_host", "")).lower()
                open_incs = db.query(IncidentORM).filter(IncidentORM.status == "open").all()
                next_inc_id = None
                for candidate in open_incs:
                    cand_keys = [str(k).lower() for k in (candidate.entity_keys or [])]
                    if any(next_asset in k or next_host in k or k in (next_asset, next_host) for k in cand_keys):
                        next_inc_id = candidate.incident_id
                        break
                self.active_incident_id = next_inc_id

        finally:
            db.close()

    async def _emit_benign_event(self) -> None:
        """Emit a quiet benign telemetry record."""
        sample = random.choice(BENIGN_SAMPLES)
        now = datetime.now(timezone.utc)
        ev_id = f"EVT-{uuid.uuid4().hex[:8]}"

        db = SessionLocal()
        try:
            ev = EventORM(
                event_id=ev_id,
                ts=now,
                source_type=sample["source_type"],
                host=sample["host"],
                src_ip=sample["src_ip"],
                user=sample.get("user"),
                action=sample["action"],
                outcome=sample["outcome"],
                asset_criticality=1,
                raw=sample["raw"],
                raw_hash=uuid.uuid4().hex,
            )
            db.add(ev)
            db.commit()
            self.events_emitted += 1

            payload = {
                "type": "benign_event",
                "event": {
                    "event_id": ev_id,
                    "timestamp": now.strftime("%H:%M:%S"),
                    "source_type": sample["source_type"],
                    "host": sample["host"],
                    "src_ip": sample["src_ip"],
                    "user": sample.get("user"),
                    "action": sample["action"],
                    "outcome": sample["outcome"],
                    "raw": sample["raw"],
                },
            }
            await self.broadcast(payload)
        finally:
            db.close()

    async def inject_step(self, scenario_id: str | None = None) -> dict[str, Any]:
        """Manually trigger immediate injection of an attack step."""
        if scenario_id:
            for idx, sc in enumerate(SCENARIOS_CATALOG):
                if sc["id"] == scenario_id:
                    self.scenario_idx = idx
                    self.step_idx = 0
                    break
        await self._emit_scenario_step()
        return self.get_status()

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Push JSON payload to all active SSE subscriber queues."""
        msg = f"data: {json.dumps(payload)}\n\n"
        for q in list(self.subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    async def subscribe(self) -> AsyncGenerator[str, None]:
        """Generator yielding SSE formatted strings for a connected client."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.subscribers.add(q)
        try:
            # Initial status handshake
            init_msg = json.dumps({"type": "connected", "status": self.get_status()})
            yield f"data: {init_msg}\n\n"

            while True:
                data = await q.get()
                yield data
        finally:
            self.subscribers.discard(q)

    def get_status(self) -> dict[str, Any]:
        """Return the current engine state."""
        scenario = SCENARIOS_CATALOG[self.scenario_idx % len(SCENARIOS_CATALOG)]
        return {
            "running": self.is_running,
            "speed": self.speed,
            "current_scenario_id": scenario["id"],
            "current_scenario_name": scenario["name"],
            "current_step": (self.step_idx % len(scenario["steps"])) + 1,
            "total_steps": len(scenario["steps"]),
            "events_emitted": self.events_emitted,
            "active_incident_id": self.active_incident_id,
            "connected_clients": len(self.subscribers),
        }

    def set_running(self, running: bool) -> None:
        self.is_running = running

    def set_speed(self, speed: int) -> None:
        if speed in (1, 5, 10):
            self.speed = speed


# Global engine singleton
engine = StreamEngine()
