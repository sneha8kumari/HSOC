"""
Rule engine: evaluates YAML detection rules against event windows.

Each rule is loaded from settings.yaml via config.py.
All thresholds, windows and weights come from settings — never hard-coded.
"""

from __future__ import annotations

import logging
from typing import Any

from hsoc.config import get_settings
from hsoc.detect.windows import WindowManager
from hsoc.schema import Alert, Domain, Event, Outcome

logger = logging.getLogger(__name__)


def evaluate(events: list[Event], wm: WindowManager | None = None) -> list[Alert]:
    """
    Evaluate all configured detection rules against events.

    Args:
        events: Normalised, enriched events.
        wm: Optional pre-populated WindowManager.

    Returns:
        List of Alert objects for every rule that fired.
    """
    if not events:
        return []

    if wm is None:
        wm = WindowManager()
        for ev in events:
            wm.add(ev)

    rules_cfg = get_settings().detection.get("rules", {})
    alerts: list[Alert] = []

    # 1. Evaluate R-01: SSH/Login brute force (single host)
    r01 = rules_cfg.get("R-01", {})
    if r01:
        w_sec = int(r01.get("window_seconds", 60))
        min_fail = int(r01.get("min_failures", 10))
        for src_ip in wm.get_all_entities("src_ip"):
            w_events = wm.get_window("src_ip", src_ip, window_seconds=w_sec)
            fail_events = [e for e in w_events if e.outcome == Outcome.failure and e.action in ("ssh_login", "win_logon", "system_auth")]
            if len(fail_events) >= min_fail:
                evidence_ids = [e.event_id for e in fail_events[:min_fail]]
                target_host = fail_events[0].host or fail_events[0].dst_ip
                alerts.append(
                    Alert(
                        ts=fail_events[0].ts,
                        rule_ids=["R-01"],
                        conf=float(r01.get("weight", 0.9)),
                        technique=r01.get("technique", "T1110.001"),
                        tactic="credential_access",
                        domain=Domain(r01.get("domain", "authentication")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        user=fail_events[0].user,
                        evidence_event_ids=evidence_ids,
                        description=f"SSH/Login brute force detected: {len(fail_events)} failures from {src_ip}",
                    )
                )

    # 2. Evaluate R-04: Vertical Port Scan
    r04 = rules_cfg.get("R-04", {})
    if r04:
        w_sec = int(r04.get("window_seconds", 60))
        min_ports = int(r04.get("min_distinct_dst_ports", 20))
        for src_ip in wm.get_all_entities("src_ip"):
            w_events = wm.get_window("src_ip", src_ip, window_seconds=w_sec)
            flow_events = [e for e in w_events if e.dst_port is not None]
            distinct_ports = {e.dst_port for e in flow_events}
            if len(distinct_ports) >= min_ports:
                evidence_ids = [e.event_id for e in flow_events[:min_ports]]
                target = flow_events[0].dst_ip or flow_events[0].host
                alerts.append(
                    Alert(
                        ts=flow_events[0].ts,
                        rule_ids=["R-04"],
                        conf=float(r04.get("weight", 0.8)),
                        technique=r04.get("technique", "T1046"),
                        tactic="reconnaissance",
                        domain=Domain(r04.get("domain", "reconnaissance")),
                        src_ip=src_ip,
                        dst_host=target,
                        evidence_event_ids=evidence_ids,
                        description=f"Vertical port scan detected: {len(distinct_ports)} distinct ports probed by {src_ip}",
                    )
                )

    # 3. Evaluate R-07: Unauthorized sudo / local group modification
    r07 = rules_cfg.get("R-07", {})
    if r07:
        weight = float(r07.get("weight", 0.9))
        for ev in events:
            if ev.action == "sudo_command":
                # Check if user is not allowed sudo according to enrichment
                if not ev.user_ctx.allowed_sudo:
                    alerts.append(
                        Alert(
                            ts=ev.ts,
                            rule_ids=["R-07"],
                            conf=weight,
                            technique=r07.get("technique", "T1548.003"),
                            tactic="privilege_escalation",
                            domain=Domain(r07.get("domain", "authorization")),
                            src_ip=ev.src_ip,
                            dst_host=ev.host or ev.dst_ip,
                            user=ev.user,
                            evidence_event_ids=[ev.event_id],
                            description=f"Unauthorized sudo execution by user {ev.user}: {ev.features.get('command', '')}",
                        )
                    )

    # 4. Evaluate R-08: Web auth brute force / admin path probing
    r08 = rules_cfg.get("R-08", {})
    if r08:
        w_sec = int(r08.get("window_seconds", 120))
        min_probes = int(r08.get("min_401_403", 30))
        suspicious_paths = [p.lower() for p in r08.get("suspicious_paths", [])]
        for src_ip in wm.get_all_entities("src_ip"):
            w_events = wm.get_window("src_ip", src_ip, window_seconds=w_sec)
            web_probes = []
            for e in w_events:
                status = e.features.get("status_code", 200)
                path = str(e.features.get("path", "")).lower()
                is_suspicious = any(sp in path for sp in suspicious_paths)
                if status in (401, 403, 404) or is_suspicious:
                    web_probes.append(e)

            if len(web_probes) >= min_probes:
                evidence_ids = [e.event_id for e in web_probes[:min_probes]]
                target = web_probes[0].host or web_probes[0].dst_ip
                alerts.append(
                    Alert(
                        ts=web_probes[0].ts,
                        rule_ids=["R-08"],
                        conf=float(r08.get("weight", 0.75)),
                        technique=r08.get("technique", "T1595.003"),
                        tactic="reconnaissance",
                        domain=Domain(r08.get("domain", "access_control")),
                        src_ip=src_ip,
                        dst_host=target,
                        evidence_event_ids=evidence_ids,
                        description=f"Web path probing / brute force: {len(web_probes)} requests from {src_ip}",
                    )
                )

    # 5. Evaluate R-10: Persistence / Local Account Creation
    r10 = rules_cfg.get("R-10", {})
    if r10:
        weight = float(r10.get("weight", 0.85))
        for ev in events:
            is_persistence = False
            command = str(ev.features.get("command", "")).lower()
            if "useradd" in command or "adduser" in command or ev.action == "user_created":
                is_persistence = True

            if is_persistence:
                alerts.append(
                    Alert(
                        ts=ev.ts,
                        rule_ids=["R-10"],
                        conf=weight,
                        technique=r10.get("technique", "T1136.001"),
                        tactic="persistence",
                        domain=Domain(r10.get("domain", "authorization")),
                        src_ip=ev.src_ip,
                        dst_host=ev.host or ev.dst_ip,
                        user=ev.user,
                        evidence_event_ids=[ev.event_id],
                        description=f"Local backdoor account creation detected on {ev.host}: {command or ev.action}",
                    )
                )

    # 6. Evaluate R-09: Cleartext / weak protocol on critical asset
    r09 = rules_cfg.get("R-09", {})
    if r09:
        cleartext_ports = set(r09.get("cleartext_ports", [21, 23, 80]))
        min_crit = int(r09.get("min_asset_criticality", 3))
        for ev in events:
            if ev.dst_port in cleartext_ports and ev.asset.criticality >= min_crit and ev.dst_port != 80:
                alerts.append(
                    Alert(
                        ts=ev.ts,
                        rule_ids=["R-09"],
                        conf=float(r09.get("weight", 0.7)),
                        technique=r09.get("technique", "CWE-319"),
                        tactic="initial_access",
                        domain=Domain(r09.get("domain", "encryption_config")),
                        src_ip=ev.src_ip,
                        dst_host=ev.host or ev.dst_ip,
                        evidence_event_ids=[ev.event_id],
                        description=f"Insecure cleartext protocol (port {ev.dst_port}) used against critical asset {ev.host or ev.dst_ip}",
                    )
                )

    return alerts
