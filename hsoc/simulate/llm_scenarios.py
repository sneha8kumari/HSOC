"""
LLM-guided Red-Team Campaign Planner.

Generates realistic multi-stage cyber attack campaigns as scenario YAML files,
constrained by the MITRE ATT&CK graph and Markov transition probabilities.

Features:
  1. Constrained trajectory sampling along ATT&CK kill-chain graph & Markov matrix.
  2. Realistic variation: diverse actor profiles, asset targets, techniques, jitter.
  3. Noise & benign confounders: interleaved background telemetry to stress SOC correlation.
  4. Strict S1 YAML schema validation for every generated campaign.
  5. Automated ground-truth sidecar labeling (distinguishing attack from benign steps).
  6. Dataset generator partitioning into train, validation, and test splits (50+ campaigns).
  7. Markov model trainer and evaluator reporting Top-1/Top-3 accuracy and perplexity
     with non-parametric bootstrap confidence intervals.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import math
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from hsoc.config import get_settings
from hsoc.investigate.predictor import MarkovPredictor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK Graph & Tactic Definitions
# ---------------------------------------------------------------------------

ALL_TACTICS = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# Directed transitions allowable in realistic enterprise ATT&CK campaigns
ATTACK_GRAPH: dict[str, list[str]] = {
    "reconnaissance": ["initial_access", "credential_access", "discovery", "execution"],
    "initial_access": ["execution", "privilege_escalation", "persistence", "discovery", "credential_access"],
    "execution": ["privilege_escalation", "persistence", "defense_evasion", "credential_access", "discovery"],
    "persistence": ["privilege_escalation", "defense_evasion", "credential_access", "lateral_movement"],
    "privilege_escalation": ["defense_evasion", "credential_access", "discovery", "lateral_movement", "persistence"],
    "defense_evasion": ["credential_access", "discovery", "lateral_movement", "collection", "persistence"],
    "credential_access": ["discovery", "lateral_movement", "privilege_escalation", "collection", "initial_access"],
    "discovery": ["lateral_movement", "collection", "credential_access", "privilege_escalation"],
    "lateral_movement": ["execution", "credential_access", "discovery", "collection", "command_and_control"],
    "collection": ["command_and_control", "exfiltration", "impact"],
    "command_and_control": ["exfiltration", "impact", "collection", "lateral_movement"],
    "exfiltration": ["impact", "defense_evasion"],
    "impact": [],
}

# Technique templates per tactic
TECHNIQUE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "reconnaissance": [
        {
            "technique": "T1046",
            "name": "Network Service Discovery",
            "type": "flow",
            "description": "SYN port scan against target services",
            "dst_ports": "21-1024",
            "duration_seconds": 35,
            "packets_per_flow": 1,
            "label": "recon_port_scan",
        },
        {
            "technique": "T1595.003",
            "name": "Active Scanning: Wordlist Probing",
            "type": "web",
            "description": "Automated scan probing for admin panels, env files and git repos",
            "paths": ["/admin", "/.env", "/.git/config", "/api/v1/auth", "/debug", "/phpmyadmin"],
            "status_codes": [401, 403, 404],
            "count": 30,
            "duration_seconds": 45,
            "label": "recon_web_scan",
        },
    ],
    "initial_access": [
        {
            "technique": "T1078",
            "name": "Valid Accounts",
            "type": "auth",
            "description": "Logon via compromised credentials from unusual external address",
            "user": "admin",
            "attempts": 1,
            "outcome": "success",
            "duration_seconds": 10,
            "label": "initial_access_valid_login",
        },
        {
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
            "type": "web",
            "description": "Command injection attempt on public web endpoint",
            "paths": ["/api/v1/upload", "/cgi-bin/test.cgi", "/login?redirect=1"],
            "status_codes": [500, 200],
            "count": 15,
            "duration_seconds": 25,
            "label": "initial_access_cve_exploit",
        },
    ],
    "execution": [
        {
            "technique": "T1059.004",
            "name": "Unix Shell Execution",
            "type": "auth",
            "description": "Interactive command execution via spawn shell",
            "user": "root",
            "command": "/bin/bash -c 'id && uname -a && cat /etc/passwd'",
            "outcome": "success",
            "duration_seconds": 15,
            "label": "execution_unix_shell",
        },
        {
            "technique": "T1059.001",
            "name": "Command Scripting Interpreter",
            "type": "auth",
            "description": "Execution of encoded staged payloads",
            "user": "service_acc",
            "command": "python3 -c 'import os; os.system(\"whoami\")'",
            "outcome": "success",
            "duration_seconds": 20,
            "label": "execution_scripting",
        },
    ],
    "persistence": [
        {
            "technique": "T1136.001",
            "name": "Create Local Account",
            "type": "auth",
            "description": "Backdoor persistence via creation of unauthorized local user",
            "user": "root",
            "command": "useradd -m -s /bin/bash sys_backup_svc",
            "outcome": "success",
            "duration_seconds": 15,
            "label": "persistence_account_creation",
        },
        {
            "technique": "T1053.003",
            "name": "Scheduled Task / Cron Job",
            "type": "auth",
            "description": "Cron job modification for persistent execution callback",
            "user": "admin",
            "command": "crontab -l | { cat; echo '*/30 * * * * /tmp/.svc'; } | crontab -",
            "outcome": "success",
            "duration_seconds": 15,
            "label": "persistence_cron_task",
        },
    ],
    "privilege_escalation": [
        {
            "technique": "T1548.003",
            "name": "Sudo Abuse & Priv-Esc",
            "type": "auth",
            "description": "Abuse of NOPASSWD sudo privileges to spawn privileged bash shell",
            "user": "admin",
            "command": "sudo /bin/bash",
            "outcome": "success",
            "duration_seconds": 10,
            "label": "priv_esc_sudo_abuse",
        },
        {
            "technique": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "type": "auth",
            "description": "Local privilege escalation via kernel vulnerability exploit",
            "user": "guest",
            "command": "./priv_escalate_cve --target=root",
            "outcome": "success",
            "duration_seconds": 20,
            "label": "priv_esc_local_exploit",
        },
    ],
    "defense_evasion": [
        {
            "technique": "T1070.004",
            "name": "File Deletion / Indicator Removal",
            "type": "auth",
            "description": "Purging access logs and bash history to evade detection",
            "user": "root",
            "command": "rm -f /var/log/auth.log.old ~/.bash_history",
            "outcome": "success",
            "duration_seconds": 10,
            "label": "defense_evasion_log_wipe",
        },
        {
            "technique": "T1562.001",
            "name": "Disable Security Tools",
            "type": "auth",
            "description": "Stopping host audit daemon and security sensors",
            "user": "root",
            "command": "systemctl stop auditd wazuh-agent",
            "outcome": "success",
            "duration_seconds": 10,
            "label": "defense_evasion_disable_sensor",
        },
    ],
    "credential_access": [
        {
            "technique": "T1110.001",
            "name": "Password Guessing / Brute Force",
            "type": "auth",
            "description": "Targeted SSH password brute force targeting root and service accounts",
            "user": "root",
            "attempts": 16,
            "outcome": "failure",
            "duration_seconds": 45,
            "label": "cred_access_ssh_bruteforce",
        },
        {
            "technique": "T1110.003",
            "name": "Password Spraying",
            "type": "auth",
            "description": "Horizontal password spray against multiple domain users",
            "users": ["admin", "root", "dev_user", "ops_lead", "backup"],
            "attempts": 6,
            "outcome": "failure",
            "duration_seconds": 60,
            "label": "cred_access_pass_spray",
        },
    ],
    "discovery": [
        {
            "technique": "T1082",
            "name": "System Information Discovery",
            "type": "auth",
            "description": "Reconnaissance of OS build, hardware architecture and patch level",
            "user": "admin",
            "command": "uname -a && cat /etc/os-release && lscpu",
            "outcome": "success",
            "duration_seconds": 12,
            "label": "discovery_sys_info",
        },
        {
            "technique": "T1018",
            "name": "Remote System Discovery",
            "type": "flow",
            "description": "Internal subnet sweep to discover adjacent database and storage servers",
            "dst_ports": "22,80,443,3306,5432",
            "duration_seconds": 30,
            "packets_per_flow": 1,
            "label": "discovery_internal_sweep",
        },
    ],
    "lateral_movement": [
        {
            "technique": "T1021.004",
            "name": "SSH Pivoting to Internal Asset",
            "type": "auth",
            "description": "Pivoting via harvested SSH credentials to internal database vault",
            "user": "admin",
            "attempts": 1,
            "outcome": "success",
            "duration_seconds": 15,
            "label": "lateral_movement_ssh_pivot",
        },
        {
            "technique": "T1021.002",
            "name": "Remote Services / Share Access",
            "type": "flow",
            "description": "SMB communication connecting to internal backup share",
            "dst_ports": "445",
            "duration_seconds": 25,
            "packets_per_flow": 1,
            "label": "lateral_movement_smb_share",
        },
    ],
    "collection": [
        {
            "technique": "T1560",
            "name": "Archive Collected Data",
            "type": "auth",
            "description": "Compressing customer databases and private keys into encrypted archive",
            "user": "admin",
            "command": "tar -czf /tmp/.dump.tar.gz /var/lib/mysql /etc/ssl/private",
            "outcome": "success",
            "duration_seconds": 25,
            "label": "collection_archive_data",
        }
    ],
    "command_and_control": [
        {
            "technique": "T1071.001",
            "name": "Web Protocols C2 Beaconing",
            "type": "web",
            "description": "Periodic HTTPS beaconing to remote adversary C2 server",
            "paths": ["/api/v2/telemetry/sync", "/beacon/ping", "/data/heartbeat"],
            "status_codes": [200],
            "count": 10,
            "duration_seconds": 30,
            "label": "c2_web_beaconing",
        }
    ],
    "exfiltration": [
        {
            "technique": "T1048.002",
            "name": "Exfiltration Over Asymmetric Protocol",
            "type": "flow",
            "description": "High-volume encrypted outbound transfer to unauthorized external endpoint",
            "dst_ports": "443,8443",
            "duration_seconds": 50,
            "packets_per_flow": 1,
            "label": "exfiltration_outbound_stream",
        }
    ],
    "impact": [
        {
            "technique": "T1485",
            "name": "Data Destruction",
            "type": "auth",
            "description": "Wiping primary database tables and transaction logs",
            "user": "root",
            "command": "rm -rf /var/lib/mysql/* /var/backups/*",
            "outcome": "success",
            "duration_seconds": 15,
            "label": "impact_data_destruction",
        }
    ],
}

# Benign operational confounders / noise templates
BENIGN_CONFOUNDERS: list[dict[str, Any]] = [
    {
        "type": "flow",
        "description": "Routine NTP network time synchronization check",
        "dst_ports": "123",
        "duration_seconds": 5,
        "packets_per_flow": 1,
        "label": "benign_ntp_sync",
        "src_ip": "192.168.56.40",
    },
    {
        "type": "auth",
        "description": "Scheduled DevOps maintenance health check",
        "user": "devops_automation",
        "attempts": 1,
        "outcome": "success",
        "command": "uptime && df -h",
        "duration_seconds": 5,
        "label": "benign_health_check",
        "src_ip": "192.168.56.41",
    },
    {
        "type": "web",
        "description": "Internal Prometheus metrics scraping query",
        "paths": ["/metrics", "/healthz"],
        "status_codes": [200],
        "count": 4,
        "duration_seconds": 5,
        "label": "benign_metrics_scrape",
        "src_ip": "192.168.56.42",
    },
]

# Threat actor profiles for rich variation
ACTOR_PROFILES = [
    {
        "name": "APT28-Emulation",
        "style": "stealthy",
        "desc": "Nation-state threat actor focusing on credential harvesting, defense evasion and exfiltration.",
        "preferred_tactics": ["reconnaissance", "credential_access", "privilege_escalation", "exfiltration"],
    },
    {
        "name": "FIN7-Syndicate",
        "style": "financially-motivated",
        "desc": "Financially motivated threat group targeting e-commerce web applications and payment databases.",
        "preferred_tactics": ["initial_access", "execution", "discovery", "collection"],
    },
    {
        "name": "Lazarus-Campaign",
        "style": "destructive",
        "desc": "Aggressive state-sponsored adversary deploying persistent backdoors and destructive impact.",
        "preferred_tactics": ["initial_access", "persistence", "privilege_escalation", "impact"],
    },
    {
        "name": "Malicious-Insider",
        "style": "privileged-abuse",
        "desc": "Disgruntled employee abusing authorized credentials to harvest internal database assets.",
        "preferred_tactics": ["initial_access", "privilege_escalation", "collection", "exfiltration"],
    },
    {
        "name": "Opportunistic-RedTeam",
        "style": "broad-probing",
        "desc": "Authorized red-team exercise testing boundary defenses via horizontal port scans and sprays.",
        "preferred_tactics": ["reconnaissance", "initial_access", "defense_evasion", "lateral_movement"],
    },
]

KNOWN_ASSETS = [
    {"host": "db-srv-01", "ip": "192.168.56.20"},
    {"host": "auth-srv-02", "ip": "192.168.56.21"},
    {"host": "legacy-srv", "ip": "192.168.56.30"},
    {"host": "web-srv-01", "ip": "192.168.56.15"},
    {"host": "backup-vault", "ip": "192.168.56.50"},
]


# ---------------------------------------------------------------------------
# S1 Schema Validator
# ---------------------------------------------------------------------------

_TECHNIQUE_REGEX = re.compile(r"^(T\d{4}(\.\d{3})?|CWE-\d+)$")


def validate_scenario_s1_schema(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate a scenario dictionary against the S1 YAML specification.

    Rules:
      - Top-level: id, name, description, targets, techniques, tactic, steps
      - targets: list of objects with host (str) and ip (str)
      - techniques: non-empty list of valid MITRE technique IDs
      - steps: list of step objects with step (int >= 1), type (flow|auth|web),
        description (str), src_ip (str), and type-specific fields.

    Returns:
        (is_valid: bool, errors: list[str])
    """
    errors: list[str] = []

    required_top = ["id", "name", "description", "targets", "techniques", "tactic", "steps"]
    for req in required_top:
        if req not in data:
            errors.append(f"Missing required top-level property '{req}'.")

    if not isinstance(data.get("id"), str) or not data.get("id"):
        errors.append("Property 'id' must be a non-empty string.")

    if not isinstance(data.get("name"), str) or not data.get("name"):
        errors.append("Property 'name' must be a non-empty string.")

    # Targets
    targets = data.get("targets")
    if not isinstance(targets, list) or len(targets) == 0:
        errors.append("Property 'targets' must be a non-empty list.")
    else:
        for idx, tgt in enumerate(targets):
            if not isinstance(tgt, dict):
                errors.append(f"Target at index {idx} must be a dictionary.")
            else:
                if not tgt.get("host") or not isinstance(tgt["host"], str):
                    errors.append(f"Target at index {idx} missing valid 'host'.")
                if not tgt.get("ip") or not isinstance(tgt["ip"], str):
                    errors.append(f"Target at index {idx} missing valid 'ip'.")

    # Techniques
    techs = data.get("techniques")
    if not isinstance(techs, list) or len(techs) == 0:
        errors.append("Property 'techniques' must be a non-empty list of technique IDs.")
    else:
        for tech in techs:
            if not isinstance(tech, str) or not _TECHNIQUE_REGEX.match(tech):
                errors.append(f"Invalid MITRE technique identifier format: '{tech}'.")

    # Steps
    steps = data.get("steps")
    if not isinstance(steps, list) or len(steps) == 0:
        errors.append("Property 'steps' must be a non-empty list of step definitions.")
    else:
        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"Step {idx} must be a dictionary.")
                continue

            if step.get("step") != idx:
                errors.append(f"Step {idx} has invalid 'step' number: {step.get('step')} (expected {idx}).")

            st_type = step.get("type")
            if st_type not in ("flow", "auth", "web"):
                errors.append(f"Step {idx} has invalid type '{st_type}'. Allowed: flow, auth, web.")

            if not step.get("description") or not isinstance(step["description"], str):
                errors.append(f"Step {idx} missing valid 'description'.")

            if not step.get("src_ip") or not isinstance(step["src_ip"], str):
                errors.append(f"Step {idx} missing valid 'src_ip'.")

            duration = step.get("duration_seconds")
            if not isinstance(duration, (int, float)) or duration <= 0:
                errors.append(f"Step {idx} duration_seconds must be positive number.")

            # Type-specific validation
            if st_type == "flow":
                if not step.get("dst_ports") and not step.get("dst_port"):
                    errors.append(f"Step {idx} (flow) missing destination ports specification.")
                if not step.get("label"):
                    errors.append(f"Step {idx} (flow) missing 'label'.")

            elif st_type == "auth":
                if not step.get("host"):
                    errors.append(f"Step {idx} (auth) missing 'host'.")
                if not step.get("user") and not step.get("users"):
                    errors.append(f"Step {idx} (auth) missing 'user' or 'users'.")
                if step.get("outcome") not in ("success", "failure"):
                    errors.append(f"Step {idx} (auth) outcome must be 'success' or 'failure'.")
                if not step.get("label"):
                    errors.append(f"Step {idx} (auth) missing 'label'.")

            elif st_type == "web":
                if not step.get("host"):
                    errors.append(f"Step {idx} (web) missing 'host'.")
                if not step.get("paths") or not isinstance(step["paths"], list):
                    errors.append(f"Step {idx} (web) missing 'paths' list.")
                if not step.get("status_codes") or not isinstance(step["status_codes"], list):
                    errors.append(f"Step {idx} (web) missing 'status_codes' list.")
                if not step.get("count") or step.get("count", 0) < 1:
                    errors.append(f"Step {idx} (web) count must be >= 1.")
                if not step.get("label"):
                    errors.append(f"Step {idx} (web) missing 'label'.")

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Red-Team Campaign Planner
# ---------------------------------------------------------------------------

class RedTeamPlanner:
    """
    Generates multi-stage attack campaigns constrained by the ATT&CK graph
    and Markov transition probabilities.
    """

    def __init__(self, predictor: MarkovPredictor | None = None) -> None:
        self.predictor = predictor or MarkovPredictor()
        # Configuration parameters
        cfg = get_settings().simulation.get("llm_planner", {})
        self.min_stages = int(cfg.get("min_stages", 3))
        self.max_stages = int(cfg.get("max_stages", 6))
        self.noise_ratio = float(cfg.get("noise_confounder_ratio", 0.25))

    def sample_trajectory(self, start_tactic: str | None = None, length: int | None = None) -> list[str]:
        """
        Sample a valid tactic trajectory constrained by the ATT&CK graph
        and weighted by the Markov transition matrix.

        Args:
            start_tactic: Optional initial tactic (default sampled from entry tactics).
            length: Number of stages to generate.

        Returns:
            List of tactics representing the campaign kill-chain sequence.
        """
        entry_tactics = ["reconnaissance", "initial_access", "credential_access"]
        current = start_tactic or random.choice(entry_tactics)
        trajectory = [current]

        target_len = length or random.randint(self.min_stages, self.max_stages)

        while len(trajectory) < target_len:
            # Candidate next tactics allowed in the ATT&CK graph
            cands = ATTACK_GRAPH.get(current, [])
            if not cands:
                break

            # Markov probability weights P(cand | current)
            weights: list[float] = []
            for cand in cands:
                p = self.predictor.get_transition_probability(current, cand)
                weights.append(max(p, 1e-4))

            # Sample next tactic according to Markov weights
            next_tactic = random.choices(cands, weights=weights, k=1)[0]
            trajectory.append(next_tactic)
            current = next_tactic

        return trajectory

    def generate_campaign(
        self,
        campaign_id: str,
        trajectory: list[str] | None = None,
        actor: dict[str, Any] | None = None,
        seed: int | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """
        Synthesize a complete multi-stage campaign scenario and its ground-truth labels.

        Args:
            campaign_id: Identifier (e.g. 'CMP-001').
            trajectory: Pre-specified tactic sequence, or None to sample.
            actor: Optional threat actor profile.
            seed: Optional random seed for reproducible variation.

        Returns:
            (scenario_dict: dict, ground_truth_labels: list[dict])
        """
        if seed is not None:
            random.seed(seed)

        actor_prof = actor or random.choice(ACTOR_PROFILES)
        traj = trajectory or self.sample_trajectory(length=random.randint(self.min_stages, self.max_stages))

        attacker_subnet = random.randint(10, 80)
        attacker_ip = f"203.0.113.{attacker_subnet}"
        target_asset = random.choice(KNOWN_ASSETS)

        scenario_name = f"{actor_prof['name']} Multi-Stage Campaign {campaign_id}"
        scenario_desc = (
            f"Multi-stage operation by {actor_prof['name']} targeting {target_asset['host']}. "
            f"Stages follow ATT&CK progression: {' -> '.join(traj)}."
        )

        steps: list[dict[str, Any]] = []
        ground_truth: list[dict[str, Any]] = []
        campaign_techniques: list[str] = []

        step_counter = 1
        base_time = datetime.now(timezone.utc).replace(microsecond=0)
        current_time = base_time

        for tactic in traj:
            # Option to inject a benign confounder right before or after this stage
            if random.random() < self.noise_ratio and BENIGN_CONFOUNDERS:
                confounder_tpl = copy.deepcopy(random.choice(BENIGN_CONFOUNDERS))
                confounder_dur = confounder_tpl.get("duration_seconds", 10)
                confounder_step = {
                    "step": step_counter,
                    "type": confounder_tpl["type"],
                    "description": f"[Benign Noise] {confounder_tpl['description']}",
                    "src_ip": confounder_tpl.get("src_ip", "192.168.56.40"),
                    "duration_seconds": confounder_dur,
                    "label": f"{campaign_id}_{confounder_tpl['label']}",
                }
                # Add type-specific attributes
                if confounder_tpl["type"] == "flow":
                    confounder_step["dst_ips"] = [target_asset["ip"]]
                    confounder_step["dst_ports"] = confounder_tpl["dst_ports"]
                    confounder_step["packets_per_flow"] = confounder_tpl.get("packets_per_flow", 1)
                elif confounder_tpl["type"] == "auth":
                    confounder_step["host"] = target_asset["host"]
                    confounder_step["user"] = confounder_tpl["user"]
                    confounder_step["attempts"] = confounder_tpl["attempts"]
                    confounder_step["outcome"] = confounder_tpl["outcome"]
                    confounder_step["command"] = confounder_tpl.get("command")
                elif confounder_tpl["type"] == "web":
                    confounder_step["host"] = target_asset["host"]
                    confounder_step["paths"] = confounder_tpl["paths"]
                    confounder_step["status_codes"] = confounder_tpl["status_codes"]
                    confounder_step["count"] = confounder_tpl["count"]

                steps.append(confounder_step)
                ground_truth.append(
                    {
                        "scenario_id": campaign_id,
                        "step": step_counter,
                        "is_attack": False,
                        "type": confounder_tpl["type"],
                        "description": confounder_step["description"],
                        "techniques": [],
                        "tactic": "benign_operational_telemetry",
                        "src_ip": confounder_step["src_ip"],
                        "target": target_asset["host"],
                        "start_time": current_time.isoformat(),
                        "end_time": (current_time + timedelta(seconds=confounder_dur)).isoformat(),
                        "label": confounder_step["label"],
                    }
                )
                current_time += timedelta(seconds=confounder_dur + random.randint(3, 10))
                step_counter += 1

            # Select attack technique template for tactic
            templates = TECHNIQUE_TEMPLATES.get(tactic, TECHNIQUE_TEMPLATES["reconnaissance"])
            tpl = copy.deepcopy(random.choice(templates))
            tech_id = tpl["technique"]
            if tech_id not in campaign_techniques:
                campaign_techniques.append(tech_id)

            duration = tpl.get("duration_seconds", 30) + random.randint(-5, 10)
            duration = max(5, duration)

            attack_step: dict[str, Any] = {
                "step": step_counter,
                "type": tpl["type"],
                "description": f"{tactic.upper()}: {tpl['description']}",
                "src_ip": attacker_ip,
                "duration_seconds": duration,
                "label": f"{campaign_id}_{tpl['label']}",
            }

            if tpl["type"] == "flow":
                attack_step["dst_ips"] = [target_asset["ip"]]
                attack_step["dst_ports"] = tpl.get("dst_ports", "80")
                attack_step["packets_per_flow"] = tpl.get("packets_per_flow", 1)
            elif tpl["type"] == "auth":
                attack_step["host"] = target_asset["host"]
                if "users" in tpl:
                    attack_step["users"] = tpl["users"]
                else:
                    attack_step["user"] = tpl.get("user", "admin")
                attack_step["attempts"] = tpl.get("attempts", 1)
                attack_step["outcome"] = tpl.get("outcome", "success")
                if "command" in tpl:
                    attack_step["command"] = tpl["command"]
            elif tpl["type"] == "web":
                attack_step["host"] = target_asset["host"]
                attack_step["paths"] = tpl.get("paths", ["/admin"])
                attack_step["status_codes"] = tpl.get("status_codes", [401])
                attack_step["count"] = tpl.get("count", 20)

            steps.append(attack_step)
            ground_truth.append(
                {
                    "scenario_id": campaign_id,
                    "step": step_counter,
                    "is_attack": True,
                    "type": tpl["type"],
                    "description": attack_step["description"],
                    "techniques": [tech_id],
                    "tactic": tactic,
                    "src_ip": attacker_ip,
                    "target": target_asset["host"],
                    "start_time": current_time.isoformat(),
                    "end_time": (current_time + timedelta(seconds=duration)).isoformat(),
                    "label": attack_step["label"],
                }
            )
            current_time += timedelta(seconds=duration + random.randint(5, 15))
            step_counter += 1

        scenario: dict[str, Any] = {
            "id": campaign_id,
            "name": scenario_name,
            "description": scenario_desc,
            "actor": actor_prof["name"],
            "targets": [target_asset],
            "techniques": campaign_techniques,
            "tactic": "kill_chain",
            "tactic_trajectory": traj,
            "steps": steps,
        }

        # Validate against S1 YAML schema
        is_valid, validation_errors = validate_scenario_s1_schema(scenario)
        if not is_valid:
            raise ValueError(f"Generated scenario {campaign_id} failed S1 schema: {validation_errors}")

        return scenario, ground_truth


# ---------------------------------------------------------------------------
# Dataset Generation & Split Management
# ---------------------------------------------------------------------------

def generate_campaign_dataset(
    num_campaigns: int = 60,
    train_split: float = 0.70,
    val_split: float = 0.15,
    test_split: float = 0.15,
    out_dir: str = "data/scenarios/generated",
    seed: int = 42,
) -> dict[str, Any]:
    """
    Generate 50+ validated campaigns split into train, validation, and test sets.

    Saves:
      - YAML scenarios in {out_dir}/train/, {out_dir}/val/, {out_dir}/test/
      - Ground-truth annotations in {out_dir}/ground_truth_{split}.jsonl
      - Combined ground truth in {out_dir}/ground_truth.jsonl
      - Manifest metadata in {out_dir}/dataset_manifest.json

    Returns:
        Summary dict containing split sizes, sequences, and paths.
    """
    random.seed(seed)
    planner = RedTeamPlanner()

    base_dir = Path(out_dir)
    train_dir = base_dir / "train"
    val_dir = base_dir / "val"
    test_dir = base_dir / "test"

    for d in (train_dir, val_dir, test_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Determine partition boundaries
    n_train = int(num_campaigns * train_split)
    n_val = int(num_campaigns * val_split)
    n_test = num_campaigns - (n_train + n_val)

    splits: list[tuple[str, Path, int]] = [
        ("train", train_dir, n_train),
        ("val", val_dir, n_val),
        ("test", test_dir, n_test),
    ]

    all_ground_truth: list[dict[str, Any]] = []
    split_manifest: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_campaigns": num_campaigns,
        "seed": seed,
        "splits": {},
    }

    campaign_index = 1

    for split_name, target_dir, count in splits:
        split_sequences: list[list[str]] = []
        split_records: list[dict[str, Any]] = []

        for _ in range(count):
            c_id = f"CMP-{campaign_index:03d}"
            scenario, gt = planner.generate_campaign(campaign_id=c_id, seed=seed + campaign_index)

            # Write scenario YAML
            yaml_path = target_dir / f"{c_id}.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(scenario, f, sort_keys=False, default_flow_style=False)

            split_sequences.append(scenario["tactic_trajectory"])
            split_records.extend(gt)
            all_ground_truth.extend(gt)
            campaign_index += 1

        # Write split ground-truth
        gt_path = base_dir / f"ground_truth_{split_name}.jsonl"
        with open(gt_path, "w", encoding="utf-8") as f:
            for rec in split_records:
                f.write(json.dumps(rec) + "\n")

        split_manifest["splits"][split_name] = {
            "count": count,
            "directory": str(target_dir),
            "ground_truth_file": str(gt_path),
            "sequences": split_sequences,
        }

    # Write combined ground truth & manifest
    combined_gt_path = base_dir / "ground_truth.jsonl"
    with open(combined_gt_path, "w", encoding="utf-8") as f:
        for rec in all_ground_truth:
            f.write(json.dumps(rec) + "\n")

    manifest_path = base_dir / "dataset_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(split_manifest, f, indent=2)

    logger.info(
        "Successfully generated %d campaigns in %s (Train: %d, Val: %d, Test: %d)",
        num_campaigns,
        out_dir,
        n_train,
        n_val,
        n_test,
    )

    return split_manifest


# ---------------------------------------------------------------------------
# Markov Model Training & Evaluation with Bootstrap Confidence Intervals
# ---------------------------------------------------------------------------

def evaluate_markov_on_campaigns(
    train_sequences: list[list[str]],
    test_sequences: list[list[str]],
    num_bootstraps: int = 1000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Train Markov model on train split and evaluate on test split,
    reporting Top-1, Top-3 accuracy and perplexity with bootstrap confidence intervals.

    Args:
        train_sequences: List of tactic sequences from train campaigns.
        test_sequences: List of tactic sequences from test campaigns.
        num_bootstraps: Number of bootstrap iterations for CI calculation.
        ci_level: Confidence level (default 0.95 for 95% CI).
        seed: Random seed for bootstrapping reproducibility.

    Returns:
        Dictionary of benchmark metrics and confidence intervals.
    """
    random.seed(seed)
    predictor = MarkovPredictor()
    predictor.train(train_sequences)

    # Collect transition evaluations from test set
    eval_instances: list[dict[str, Any]] = []

    for seq in test_sequences:
        if len(seq) < 2:
            continue
        for i in range(len(seq) - 1):
            src = seq[i].lower()
            true_dst = seq[i + 1].lower()

            predictions = predictor.predict(src, top_n=3)
            pred_tactics = [p.tactic for p in predictions]

            top1_hit = 1.0 if (pred_tactics and pred_tactics[0] == true_dst) else 0.0
            top3_hit = 1.0 if true_dst in pred_tactics else 0.0

            prob = predictor.get_transition_probability(src, true_dst)
            nll = -math.log(max(prob, 1e-6))

            eval_instances.append(
                {
                    "src": src,
                    "dst": true_dst,
                    "top1_hit": top1_hit,
                    "top3_hit": top3_hit,
                    "prob": prob,
                    "nll": nll,
                }
            )

    n_transitions = len(eval_instances)
    if n_transitions == 0:
        raise ValueError("Test sequences contain no transitions to evaluate.")

    # Empirical point estimates
    mean_top1 = sum(item["top1_hit"] for item in eval_instances) / n_transitions
    mean_top3 = sum(item["top3_hit"] for item in eval_instances) / n_transitions
    mean_nll = sum(item["nll"] for item in eval_instances) / n_transitions
    perplexity = math.exp(mean_nll)

    # Non-parametric Bootstrap for Confidence Intervals
    boot_top1: list[float] = []
    boot_top3: list[float] = []
    boot_perp: list[float] = []

    for _ in range(num_bootstraps):
        resample = random.choices(eval_instances, k=n_transitions)
        b_top1 = sum(item["top1_hit"] for item in resample) / n_transitions
        b_top3 = sum(item["top3_hit"] for item in resample) / n_transitions
        b_nll = sum(item["nll"] for item in resample) / n_transitions
        boot_top1.append(b_top1)
        boot_top3.append(b_top3)
        boot_perp.append(math.exp(b_nll))

    alpha_tail = (1.0 - ci_level) / 2.0
    low_idx = int(alpha_tail * num_bootstraps)
    high_idx = int((1.0 - alpha_tail) * num_bootstraps)

    boot_top1.sort()
    boot_top3.sort()
    boot_perp.sort()

    ci_top1 = (round(boot_top1[low_idx], 4), round(boot_top1[high_idx], 4))
    ci_top3 = (round(boot_top3[low_idx], 4), round(boot_top3[high_idx], 4))
    ci_perp = (round(boot_perp[low_idx], 4), round(boot_perp[high_idx], 4))

    return {
        "train_sequences_count": len(train_sequences),
        "test_sequences_count": len(test_sequences),
        "test_transitions_count": n_transitions,
        "ci_level": ci_level,
        "bootstrap_samples": num_bootstraps,
        "top1_accuracy": round(mean_top1, 4),
        "top1_ci": ci_top1,
        "top3_accuracy": round(mean_top3, 4),
        "top3_ci": ci_top3,
        "mean_negative_log_likelihood": round(mean_nll, 4),
        "perplexity": round(perplexity, 4),
        "perplexity_ci": ci_perp,
    }


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="H-SOC Red-Team LLM Scenario Planner")
    parser.add_argument("--count", type=int, default=60, help="Number of campaigns to generate (>=50)")
    parser.add_argument("--out-dir", type=str, default="data/scenarios/generated", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--eval", action="store_true", help="Train and evaluate Markov model with CIs")
    args = parser.parse_args()

    manifest = generate_campaign_dataset(
        num_campaigns=args.count,
        out_dir=args.out_dir,
        seed=args.seed,
    )

    if args.eval:
        train_seqs = manifest["splits"]["train"]["sequences"]
        test_seqs = manifest["splits"]["test"]["sequences"]
        results = evaluate_markov_on_campaigns(train_seqs, test_seqs, seed=args.seed)
        print("\n=== Markov Model Evaluation with Confidence Intervals ===")
        print(f"Top-1 Accuracy: {results['top1_accuracy'] * 100:.2f}% (95% CI: [{results['top1_ci'][0]*100:.2f}%, {results['top1_ci'][1]*100:.2f}%])")
        print(f"Top-3 Accuracy: {results['top3_accuracy'] * 100:.2f}% (95% CI: [{results['top3_ci'][0]*100:.2f}%, {results['top3_ci'][1]*100:.2f}%])")
        print(f"Perplexity:     {results['perplexity']:.4f} (95% CI: [{results['perplexity_ci'][0]:.4f}, {results['perplexity_ci'][1]:.4f}])")
