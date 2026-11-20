"""
Big-4 consulting cybersecurity and incident response methodologies.

Summarised and paraphrased framework notes with authoritative source URLs
(Deloitte, EY, PwC, KPMG) - no verbatim copied text.
"""

from __future__ import annotations

from typing import Any

CONSULTING_FRAMEWORKS: list[dict[str, Any]] = [
    {
        "id": "BIG4-DELOITTE-CIRF",
        "firm": "Deloitte",
        "title": "Deloitte Cyber Incident Response Framework (CIRF) & Threat Hunting Guidelines",
        "url": "https://www.deloitte.com/global/en/services/risk-advisory/services/cyber-incident-response.html",
        "domain_tag": "incident_response",
        "techniques": ["T1046", "T1110", "T1078"],
        "tactics": ["reconnaissance", "initial_access", "lateral_movement"],
        "platforms": ["linux", "windows", "cloud", "network"],
        "text": (
            "Deloitte Cyber Incident Response Framework (CIRF) Methodology Summary.\n"
            "Source URL: https://www.deloitte.com/global/en/services/risk-advisory/services/cyber-incident-response.html\n\n"
            "Paraphrased Architecture Notes:\n"
            "- Rapid Incident Triage: Establishes a unified incident commander model to categorize operational vs systemic threat exposures. "
            "Prioritizes containment speed over exhaustive data collection when active lateral movement is observed.\n"
            "- Proactive Hypothesis-Driven Threat Hunting: Cross-examines telemetry against threat intelligence feeds, assuming the adversary "
            "already holds persistence. Scans for beaconing cadences, irregular service creations, and abnormal east-west traffic.\n"
            "- Forensic Chain of Custody & Evidence Sequestration: Mandates non-destructive volatile memory capture prior to host reboots "
            "and bit-stream disk imaging for high-criticality assets.\n"
            "- Enterprise Resilience & Root-Cause Elimination: Post-containment audits focus on identity perimeter defense, privileged account "
            "governance, and closing the initial infection vector before bringing systems back online."
        ),
    },
    {
        "id": "BIG4-EY-CTI-IR",
        "firm": "EY",
        "title": "EY Threat Intelligence-Led Incident Response & Containment Methodology",
        "url": "https://www.ey.com/en_gl/services/cybersecurity/incident-response",
        "domain_tag": "incident_response",
        "techniques": ["T1110", "T1548", "T1136"],
        "tactics": ["credential_access", "privilege_escalation", "persistence"],
        "platforms": ["linux", "windows", "cloud"],
        "text": (
            "EY Cyber Threat Intelligence-Led Incident Response Methodology Summary.\n"
            "Source URL: https://www.ey.com/en_gl/services/cybersecurity/incident-response\n\n"
            "Paraphrased Architecture Notes:\n"
            "- Intelligence Integration: Combines MITRE ATT&CK tactic mapping with external adversary profile indicators to anticipate "
            "the next phase of an active attack campaign rather than reacting solely to localized alarms.\n"
            "- Tiered Containment Strategy: Deploys containment measures across micro-segmented network boundaries. Separates infected tenant "
            "environments using dynamic firewall policies while preserving operational continuity for unaffected business divisions.\n"
            "- Identity-First Remediation: Assumes compromised credentials represent the primary vector for persistent re-entry. "
            "Enforces coordinated enterprise-wide credential resets, token invalidation, and session termination across federated identity providers.\n"
            "- Executive Incident Governance: Aligns technical containment milestones with regulatory reporting timelines (e.g. SEC, GDPR, NIS2) "
            "to ensure compliance obligations are met during active handling."
        ),
    },
    {
        "id": "BIG4-PWC-IR-FORENSICS",
        "firm": "PwC",
        "title": "PwC Incident Management, Digital Forensics & Crisis Remediation Framework",
        "url": "https://www.pwc.com/gx/en/services/consulting/cybersecurity-privacy/incident-response.html",
        "domain_tag": "incident_response",
        "techniques": ["T1078", "T1136", "T1486"],
        "tactics": ["persistence", "impact", "exfiltration"],
        "platforms": ["linux", "windows", "network"],
        "text": (
            "PwC Incident Management and Digital Forensics Framework Summary.\n"
            "Source URL: https://www.pwc.com/gx/en/services/consulting/cybersecurity-privacy/incident-response.html\n\n"
            "Paraphrased Architecture Notes:\n"
            "- Scalable Crisis Triage: Classifies incidents using a standardized severity matrix balancing operational downtime, data sensitivity, "
            "and legal exposure. Directly feeds technical triage findings into business risk registers.\n"
            "- Deep-Dive Forensic Reconstruction: Employs timeline analysis across multiple log fabrics (host event logs, network proxies, SIEM alerts) "
            "to identify the initial compromise timestamp ('patient zero') and map out all secondary compromised nodes.\n"
            "- Coordinated Mass Eradication: Executes containment and eradication scripts simultaneously across all identified systems "
            "to eliminate attacker footholds in a single window, preventing the adversary from pivoting or retaliating.\n"
            "- Control Validation & Remediation Verification: Validates that implemented security mitigations effectively block recurrence "
            "before reintroducing affected hosts into the enterprise production network."
        ),
    },
    {
        "id": "BIG4-KPMG-CYBER-RESPONSE",
        "firm": "KPMG",
        "title": "KPMG Cyber Response Framework & Continuous Threat Monitoring",
        "url": "https://kpmg.com/xx/en/home/services/advisory/risk-consulting/cyber-security/incident-response.html",
        "domain_tag": "incident_response",
        "techniques": ["T1046", "T1595", "T1190"],
        "tactics": ["reconnaissance", "initial_access", "discovery"],
        "platforms": ["network", "web", "cloud"],
        "text": (
            "KPMG Cyber Response Framework Summary.\n"
            "Source URL: https://kpmg.com/xx/en/home/services/advisory/risk-consulting/cyber-security/incident-response.html\n\n"
            "Paraphrased Architecture Notes:\n"
            "- Continuous Defense Monitoring & Signal Correlation: Advocates continuous correlation of perimeter sensor logs and host telemetry. "
            "Treats low-severity signals (such as port sweeps and repeated login errors) as early warning precursors to multi-stage intrusions.\n"
            "- Threat Modeling & Attack Path Analysis: Employs threat path graphs to model likely attacker advancement vectors from initial foothold "
            "to core database and identity assets, allowing targeted pre-emptive blocking of lateral choke points.\n"
            "- Automated Orchestration & Playbook Execution: Standardizes response actions via verified orchestration playbooks to reduce "
            "analyst mean-time-to-respond (MTTR) while retaining human authorization for disruptive isolation actions.\n"
            "- Post-Incident Resilience & Continuous Posture Enhancement: Converts incident post-mortems into quantifiable security architecture "
            "improvements, verifying that defensive rules and segmentation controls are hardened against similar threat vectors."
        ),
    },
]


def load_consulting_documents() -> list[dict[str, Any]]:
    """Return Big-4 consulting framework documents."""
    documents = []
    for cf in CONSULTING_FRAMEWORKS:
        documents.append({
            "source": f"{cf['firm']} ({cf['id']})",
            "source_type": "consulting_framework",
            "title": cf["title"],
            "url": cf["url"],
            "version": "1.0",
            "domain_tag": cf["domain_tag"],
            "tactics": cf["tactics"],
            "techniques": cf["techniques"],
            "platforms": cf["platforms"],
            "text": cf["text"],
        })
    return documents
