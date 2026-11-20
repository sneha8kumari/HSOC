"""
Incident response operational playbooks (markdown formatted)
for SOC analysts and autonomous agent remediation.
"""

from __future__ import annotations

from typing import Any

PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "IR-PB-01",
        "title": "Incident Playbook: SSH Brute Force and Credential Stuffing Remediation",
        "url": "https://hsoc.local/playbooks/ir-pb-01-ssh-bruteforce.md",
        "domain_tag": "authentication",
        "techniques": ["T1110", "T1110.001", "T1110.003", "T1078"],
        "tactics": ["credential_access", "initial_access"],
        "platforms": ["linux", "network"],
        "text": (
            "# Playbook IR-PB-01: SSH Brute Force & Credential Access Containment\n\n"
            "## 1. Triage & Assessment\n"
            "- Verify whether source IP is an internal scanner or external malicious adversary.\n"
            "- Check if any failed attempts were followed by an 'Accepted password' or 'Accepted publickey' event.\n\n"
            "## 2. Containment Actions\n"
            "- Immediate Network Isolation: Insert firewall rule dropping all incoming packets from the offending source IP at edge router.\n"
            "- Fail2ban / Dynamic Jails: Ensure automated ban jail is activated with minimum 24-hour retention.\n"
            "- If successful login occurred: Immediately terminate active user sessions (`pkill -u <username> -9`) and lock the account.\n\n"
            "## 3. Eradication & Recovery\n"
            "- Force credential rotation for targeted accounts across all corporate SSO endpoints.\n"
            "- Disable password authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`). Mandate ed25519 keys."
        ),
    },
    {
        "id": "IR-PB-02",
        "title": "Incident Playbook: Network Service Scanning & Reconnaissance Containment",
        "url": "https://hsoc.local/playbooks/ir-pb-02-portscan.md",
        "domain_tag": "reconnaissance",
        "techniques": ["T1046"],
        "tactics": ["reconnaissance", "discovery"],
        "platforms": ["linux", "windows", "network"],
        "text": (
            "# Playbook IR-PB-02: Network Service Scanning & Port Sweep Containment\n\n"
            "## 1. Triage & Assessment\n"
            "- Determine scope: Vertical scan (single host, many ports) or Horizontal scan (many hosts, single port).\n"
            "- Evaluate criticality of scanned destination assets against asset inventory catalog.\n\n"
            "## 2. Containment Actions\n"
            "- Perimeter Filtering: Add null route (blackhole) or stateful ACL drop for source IP.\n"
            "- Rate Limiting: Apply SYN flood protections and connection rate thresholds on perimeter firewalls.\n\n"
            "## 3. Eradication & Hardening\n"
            "- Audit exposed services on scanned hosts; shut down unnecessary listener ports and daemons.\n"
            "- Verify internal firewall zoning: Ensure database and management subnets are isolated from public ingress."
        ),
    },
    {
        "id": "IR-PB-03",
        "title": "Incident Playbook: Unauthorized Sudo and Privilege Escalation Containment",
        "url": "https://hsoc.local/playbooks/ir-pb-03-privesc.md",
        "domain_tag": "authorization",
        "techniques": ["T1548.003", "T1548", "T1078"],
        "tactics": ["privilege_escalation", "defense_evasion"],
        "platforms": ["linux"],
        "text": (
            "# Playbook IR-PB-03: Unauthorized Privilege Escalation Remediation\n\n"
            "## 1. Triage & Assessment\n"
            "- Identify the executing user and whether they hold authorized administrative role in identity catalog.\n"
            "- Inspect executed command line, arguments, and parent process tree via auditd.\n\n"
            "## 2. Immediate Containment\n"
            "- Terminate unauthorized active shell sessions spawned via sudo or su (`kill -9 <pid>`).\n"
            "- Revoke user's sudo access immediately: Remove user from `/etc/sudoers` and `/etc/sudoers.d/`.\n"
            "- Suspend user login credentials pending incident review.\n\n"
            "## 3. Forensics & Eradication\n"
            "- Audit `/root/.bash_history` and `/tmp` for dropped binaries, scripts, or reverse shells.\n"
            "- Review Linux audit logs (`ausearch -m USER_CMD -ts today`) for chronological action reconstruction."
        ),
    },
    {
        "id": "IR-PB-04",
        "title": "Incident Playbook: Rogue Account Creation and Persistence Remediation",
        "url": "https://hsoc.local/playbooks/ir-pb-04-persistence.md",
        "domain_tag": "authorization",
        "techniques": ["T1136.001", "T1136"],
        "tactics": ["persistence"],
        "platforms": ["linux", "windows"],
        "text": (
            "# Playbook IR-PB-04: Rogue Account Creation & Persistence Containment\n\n"
            "## 1. Triage & Assessment\n"
            "- Compare newly created account against corporate HR and identity catalogs.\n"
            "- Check account creation timestamp and correlate with preceding authentication/privilege alerts.\n\n"
            "## 2. Immediate Containment\n"
            "- Lock and delete rogue account: `userdel -r <rogue_user>` (Linux) or `Disable-LocalUser` (Windows).\n"
            "- Invalidate all active sessions, tokens, and Kerberos tickets for the host.\n\n"
            "## 3. Persistence Eradication\n"
            "- Inspect all user home directories for rogue `~/.ssh/authorized_keys` additions.\n"
            "- Audit `/etc/cron.*`, `/var/spool/cron`, and systemd service units for unauthorized tasks.\n"
            "- On Windows, verify scheduled tasks (`schtasks /query`) and registry Run keys."
        ),
    },
    {
        "id": "IR-PB-05",
        "title": "Incident Playbook: Web Application Vulnerability Exploitation & Scanning",
        "url": "https://hsoc.local/playbooks/ir-pb-05-web-exploit.md",
        "domain_tag": "access_control",
        "techniques": ["T1595.003", "T1190"],
        "tactics": ["initial_access", "reconnaissance"],
        "platforms": ["web", "api"],
        "text": (
            "# Playbook IR-PB-05: Web Application Fuzzing and Path Exploitation Containment\n\n"
            "## 1. Triage & Assessment\n"
            "- Analyze web server access logs for targeted probes (e.g., `/.env`, `/.git`, `/wp-admin`, SQLi/SSRF payloads).\n"
            "- Review response codes: determine if requests returned 404/403 (blocked) or 200/500 (potential compromise).\n\n"
            "## 2. Containment Actions\n"
            "- Deploy WAF IP block rule targeting scanner origin IP.\n"
            "- Apply virtual patch in reverse proxy (Nginx/Apache/Cloudflare) rejecting dotfile and admin path probes.\n\n"
            "## 3. Eradication & Hardening\n"
            "- Ensure sensitive environment files (.env, config.json) are stored outside web server document root.\n"
            "- Restrict internal administrative consoles to dedicated management subnets or VPN gateways."
        ),
    },
]


def load_playbook_documents() -> list[dict[str, Any]]:
    """Return operational playbook documents."""
    documents = []
    for pb in PLAYBOOKS:
        documents.append({
            "source": f"Playbook ({pb['id']})",
            "source_type": "playbook",
            "title": pb["title"],
            "url": pb["url"],
            "version": "1.0",
            "domain_tag": pb["domain_tag"],
            "tactics": pb["tactics"],
            "techniques": pb["techniques"],
            "platforms": pb["platforms"],
            "text": pb["text"],
        })
    return documents
