"""
NIST Special Publication 800-61 Revision 2:
Computer Security Incident Handling Guide knowledge source ingestion.
"""

from __future__ import annotations

from typing import Any

NIST_DOCS: list[dict[str, Any]] = [
    {
        "id": "NIST-800-61-PREP",
        "title": "NIST SP 800-61 Rev. 2: Incident Preparation & Incident Response Policy",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
        "standard": "NIST SP 800-61r2",
        "version": "Rev. 2",
        "domain_tag": "incident_response",
        "techniques": ["T1046", "T1110"],
        "tactics": ["reconnaissance", "initial_access"],
        "platforms": ["linux", "windows", "network", "cloud"],
        "text": (
            "NIST SP 800-61 Rev. 2 Phase 1: Incident Preparation.\n"
            "Summary: Preparation involves establishing and training an incident response team, acquiring necessary tools "
            "and resources, and preventing incidents by ensuring networks, systems, and applications are sufficiently secure.\n"
            "Key Directives:\n"
            "- Establish an incident response capability and clear escalation hierarchy.\n"
            "- Conduct periodic risk assessments on mission-critical assets.\n"
            "- Maintain an up-to-date asset inventory and contact information for asset owners.\n"
            "- Deploy centralized, tamper-resistant log aggregation with NTP synchronization.\n"
            "- Pre-stage digital forensics jump bags and memory acquisition tools."
        ),
    },
    {
        "id": "NIST-800-61-DETECT",
        "title": "NIST SP 800-61 Rev. 2: Detection and Analysis Phase",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
        "standard": "NIST SP 800-61r2",
        "version": "Rev. 2",
        "domain_tag": "incident_response",
        "techniques": ["T1046", "T1110", "T1548", "T1136"],
        "tactics": ["reconnaissance", "credential_access", "privilege_escalation"],
        "platforms": ["linux", "windows", "network"],
        "text": (
            "NIST SP 800-61 Rev. 2 Phase 2: Detection and Analysis.\n"
            "Summary: Organizations must be prepared to handle incidents that occur despite preventative measures. "
            "Early detection enables faster containment and mitigates business disruption.\n"
            "Core Procedures:\n"
            "- Profile baseline network traffic patterns and authentication frequencies to detect anomalies.\n"
            "- Correlate events across heterogeneous sources (network flows, host syslogs, authentication logs).\n"
            "- Maintain an evidence log documenting every action taken during investigation for chain-of-custody.\n"
            "- Perform initial severity assessment based on functional impact, information impact, and recoverability effort."
        ),
    },
    {
        "id": "NIST-800-61-CONTAIN",
        "title": "NIST SP 800-61 Rev. 2: Containment, Eradication, and Recovery Phase",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
        "standard": "NIST SP 800-61r2",
        "version": "Rev. 2",
        "domain_tag": "incident_response",
        "techniques": ["T1078", "T1136", "T1486"],
        "tactics": ["persistence", "lateral_movement", "impact"],
        "platforms": ["linux", "windows", "cloud"],
        "text": (
            "NIST SP 800-61 Rev. 2 Phase 3: Containment, Eradication, and Recovery.\n"
            "Summary: Containment prevents the incident from expanding and causing additional damage. Eradication removes components "
            "of the incident from the environment, and Recovery restores systems to normal operation.\n"
            "Execution Steps:\n"
            "- Select containment strategy (e.g., immediate network isolation, null-routing offending IPs, credential revocation).\n"
            "- Eradicate attacker persistence: delete unauthorized accounts, remove backdoor cron jobs/services, close vulnerable ports.\n"
            "- Rebuild compromised systems from trusted baseline images or restore clean backups.\n"
            "- Implement enhanced logging and continuous perimeter monitoring to ensure the threat actor does not regain foothold."
        ),
    },
    {
        "id": "NIST-800-61-POST",
        "title": "NIST SP 800-61 Rev. 2: Post-Incident Activity & Lessons Learned",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
        "standard": "NIST SP 800-61r2",
        "version": "Rev. 2",
        "domain_tag": "incident_response",
        "techniques": ["T1078", "T1595"],
        "tactics": ["initial_access", "reconnaissance"],
        "platforms": ["linux", "windows", "network"],
        "text": (
            "NIST SP 800-61 Rev. 2 Phase 4: Post-Incident Activity.\n"
            "Summary: Organizations should evolve their security posture by analyzing incidents and learning lessons.\n"
            "Action Items:\n"
            "- Hold a post-incident 'lessons learned' meeting within two weeks of incident closure.\n"
            "- Document total business downtime, root causes, detection gaps, and response bottlenecks.\n"
            "- Update detection rules and automated correlation logic to prevent recurrent intrusions.\n"
            "- Preserve evidence retention per legal and regulatory compliance guidelines."
        ),
    },
]


def load_nist_documents() -> list[dict[str, Any]]:
    """Return NIST SP 800-61 knowledge documents."""
    documents = []
    for doc in NIST_DOCS:
        documents.append({
            "source": f"{doc['standard']} ({doc['id']})",
            "source_type": "standard",
            "title": doc["title"],
            "url": doc["url"],
            "version": doc["version"],
            "domain_tag": doc["domain_tag"],
            "tactics": doc["tactics"],
            "techniques": doc["techniques"],
            "platforms": doc["platforms"],
            "text": doc["text"],
        })
    return documents
