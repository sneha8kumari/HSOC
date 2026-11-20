"""
MITRE ATT&CK STIX 2.1 knowledge source ingestion.

Provides structured techniques, tactics, mitigations, detection strategies,
and platform associations across Enterprise ATT&CK.
"""

from __future__ import annotations

import json
from typing import Any

# Authoritative subset of core Enterprise ATT&CK techniques with STIX 2.1 structure
ATTACK_TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "attack-pattern--t1046",
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["discovery", "reconnaissance"],
        "platforms": ["linux", "windows", "network", "macos"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including port scanning (e.g. TCP SYN scan, vertical port sweeps) to identify listening services and potential vulnerabilities.",
        "mitigations": [
            "M1030: Network Traffic Filtering - Configure stateful firewall rules to block unsolicited scanning traffic and rate-limit SYN packets.",
            "M1031: Network Intrusion Prevention - Deploy NIDS/NIPS with signatures for sequential and distributed port sweep anomalies.",
            "M1038: Execution Prevention - Disable unneeded external daemons and bind sensitive management ports to localhost."
        ],
        "detection": "Monitor network flows (NetFlow/IPFIX) and firewall logs for high volume of SYN packets or connections across multiple destination ports in a short duration.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1110-001",
        "technique_id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactics": ["credential_access"],
        "platforms": ["linux", "windows", "macos", "cloud", "saas"],
        "description": "Adversaries may systematically guess passwords to authenticate to user accounts on single hosts or services like SSH, RDP, or web portals.",
        "mitigations": [
            "M1036: Account Use Policies - Implement account lockouts or exponential authentication delays (e.g., fail2ban) after repeated failed attempts.",
            "M1032: Multi-Factor Authentication - Mandate hardware security keys or TOTP MFA for all interactive and remote sessions.",
            "M1027: Password Policies - Enforce robust password length and complexity requirements."
        ],
        "detection": "Correlate authentication failures (Event ID 4625 on Windows, 'Failed password' in /var/log/auth.log) from a single source host or account within brief sliding windows.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1110-003",
        "technique_id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactics": ["credential_access"],
        "platforms": ["linux", "windows", "macos", "cloud", "saas"],
        "description": "Adversaries may attempt a small number of commonly used passwords against many different accounts to avoid account lockout thresholds.",
        "mitigations": [
            "M1032: Multi-Factor Authentication - Enforce modern MFA mechanisms across all single sign-on (SSO) and LDAP endpoints.",
            "M1036: Account Use Policies - Monitor distributed authentication patterns across multiple accounts originating from identical ASN or IP subnets.",
            "M1017: User Training - Educate users on credential exposure and common dictionary passwords."
        ],
        "detection": "Track failed logon events across multiple distinct usernames originating from a single IP address or subnet over a 5 to 15 minute window.",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1078",
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["defense_evasion", "persistence", "privilege_escalation", "initial_access"],
        "platforms": ["linux", "windows", "macos", "cloud", "network"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "mitigations": [
            "M1015: Privileged Account Management - Restrict privileged accounts from interactive logons on standard workstations.",
            "M1026: Privileged Process Integrity - Implement Just-In-Time (JIT) access and ephemeral credentials.",
            "M1032: Multi-Factor Authentication - Require phishing-resistant MFA on all administrative interfaces."
        ],
        "detection": "Identify anomalous logins following failed brute-force bursts, unexpected geolocation shifts, or off-hours administrative access.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1548-003",
        "technique_id": "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactics": ["privilege_escalation", "defense_evasion"],
        "platforms": ["linux", "macos"],
        "description": "Adversaries may execute commands with sudo rights or abuse misconfigured sudoers files and cached credentials to elevate to root.",
        "mitigations": [
            "M1026: Privileged Process Integrity - Configure sudoers to require explicit re-authentication (timestamp_timeout=0) and avoid wildcard NOPASSWD entries.",
            "M1022: Restrict File and Directory Permissions - Restrict write permissions to /etc/sudoers and /etc/sudoers.d/ to root only.",
            "M1028: Operating System Configuration - Enforce least privilege and remove unneeded users from the sudo/wheel groups."
        ],
        "detection": "Monitor syslog and auditd for 'COMMAND=' executions with sudo by accounts not belonging to authorized system administration groups.",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1136-001",
        "technique_id": "T1136.001",
        "name": "Create Account: Local Account",
        "tactics": ["persistence"],
        "platforms": ["linux", "windows", "macos"],
        "description": "Adversaries may create a local account to maintain access to victim systems without needing to maintain active malware payloads.",
        "mitigations": [
            "M1018: User Account Management - Audit user creation events and automatically alert on new accounts created outside central IAM workflows.",
            "M1026: Privileged Process Integrity - Limit useradd, adduser, and net user execution rights to authorized orchestration agents.",
            "M1028: Operating System Configuration - Regularly audit /etc/passwd and SAM databases for unauthorized accounts."
        ],
        "detection": "Detect useradd/adduser in Linux syslog or Windows Event ID 4720 (A user account was created) that lack associated service desk tickets.",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1595-003",
        "technique_id": "T1595.003",
        "name": "Active Scanning: Wordlist Scanning",
        "tactics": ["reconnaissance"],
        "platforms": ["network", "web"],
        "description": "Adversaries may probe web servers using dictionary lists of paths (e.g., /admin, /.git, /.env, /config) to discover unlinked or sensitive directories.",
        "mitigations": [
            "M1021: Restrict Web-Based Content - Disable public access to hidden directories, dotfiles, and administration portals.",
            "M1050: Exploit Protection - Implement a Web Application Firewall (WAF) configured to rate limit and ban IPs scanning non-existent paths.",
            "M1030: Network Traffic Filtering - Restrict administrative interfaces to internal corporate VPNs."
        ],
        "detection": "Look for high frequencies of HTTP 404, 401, or 403 status codes in web server access logs targeting sensitive URLs.",
        "url": "https://attack.mitre.org/techniques/T1595/003/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1059-004",
        "technique_id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactics": ["execution"],
        "platforms": ["linux", "macos"],
        "description": "Adversaries may abuse Unix shells (bash, sh, zsh) to execute arbitrary commands, download secondary payloads, and chain lateral attacks.",
        "mitigations": [
            "M1038: Execution Prevention - Restrict execution of interactive shells by unprivileged service daemons (e.g. www-data).",
            "M1026: Privileged Process Integrity - Deploy process whitelisting via AppArmor or SELinux.",
            "M1047: Audit - Enable Linux auditd execve logging."
        ],
        "detection": "Detect abnormal parent-child process relationships, such as apache/nginx or python spawning /bin/sh or /bin/bash.",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1021-004",
        "technique_id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactics": ["lateral_movement"],
        "platforms": ["linux", "macos"],
        "description": "Adversaries may log in to remote machines using SSH with stolen credentials or hijacked SSH keys to move laterally across an internal subnet.",
        "mitigations": [
            "M1035: Limit Access to Resource over Network - Segment management networks and restrict SSH access to jump hosts/bastions.",
            "M1032: Multi-Factor Authentication - Require hardware MFA for all SSH sessions.",
            "M1027: Password Policies - Disable password-based SSH authentication in favor of ed25519 public keys."
        ],
        "detection": "Alert on east-west SSH connections between non-bastion workstations or unusual jump sequences across production tiers.",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
        "version": "14.1",
    },
    {
        "id": "attack-pattern--t1486",
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["impact"],
        "platforms": ["linux", "windows", "macos"],
        "description": "Adversaries may encrypt data on target systems or attached network storage to disrupt system availability and demand ransom.",
        "mitigations": [
            "M1053: Data Backup - Maintain immutable, air-gapped backups of critical systems and test restore procedures regularly.",
            "M1022: Restrict File and Directory Permissions - Enforce strict write and execute access controls on shared storage and databases.",
            "M1040: Behavior Prevention on Endpoint - Deploy EDR with automated anti-ransomware heuristic file-modification blocks."
        ],
        "detection": "Monitor for rapid file modification/rename operations, deletion of volume shadow copies (vssadmin), or bulk creation of ransom notes.",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "version": "14.1",
    },
]


def load_attack_stix_documents() -> list[dict[str, Any]]:
    """Return MITRE ATT&CK STIX documents formatted for chunking."""
    documents = []
    for tech in ATTACK_TECHNIQUES:
        text_content = (
            f"Technique ID: {tech['technique_id']} - {tech['name']}\n"
            f"Tactics: {', '.join(tech['tactics'])}\n"
            f"Platforms: {', '.join(tech['platforms'])}\n"
            f"Description: {tech['description']}\n\n"
            f"Remediation & Mitigations:\n" + "\n".join(f"- {m}" for m in tech['mitigations']) + "\n\n"
            f"Detection Guidance:\n{tech['detection']}"
        )
        documents.append({
            "source": f"MITRE ATT&CK ({tech['technique_id']})",
            "source_type": "stix",
            "title": f"MITRE ATT&CK {tech['technique_id']}: {tech['name']}",
            "url": tech["url"],
            "version": tech["version"],
            "domain_tag": tech["tactics"][0],
            "tactics": tech["tactics"],
            "techniques": [tech["technique_id"]],
            "platforms": tech["platforms"],
            "text": text_content,
        })
    return documents
