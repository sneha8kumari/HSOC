"""
Center for Internet Security (CIS) Critical Security Controls v8
knowledge source ingestion.
"""

from __future__ import annotations

from typing import Any

CIS_DOCS: list[dict[str, Any]] = [
    {
        "id": "CIS-V8-C04",
        "title": "CIS Control 4: Secure Configuration of Enterprise Assets and Software",
        "url": "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software",
        "standard": "CIS Controls v8",
        "version": "v8",
        "domain_tag": "authorization",
        "techniques": ["T1548", "T1078"],
        "tactics": ["privilege_escalation", "defense_evasion"],
        "platforms": ["linux", "windows", "cloud"],
        "text": (
            "CIS Control 4: Secure Configuration of Enterprise Assets and Software.\n"
            "Overview: Establish and maintain the secure configuration of enterprise assets (workstations, servers, network devices) "
            "and software (operating systems and applications).\n"
            "Key Safeguards:\n"
            "- 4.1: Establish and Maintain a Secure Configuration Process.\n"
            "- 4.3: Configure Automatic Session Locking on Enterprise Assets.\n"
            "- 4.7: Manage Default Accounts on Enterprise Assets and Software (change or disable default administrative credentials).\n"
            "- 4.8: Uninstall or Disable Unnecessary Services on Enterprise Assets.\n"
            "- Sudo Hardening: Require password re-entry, forbid NOPASSWD for privileged binaries, and maintain immutable audit logs."
        ),
    },
    {
        "id": "CIS-V8-C05",
        "title": "CIS Control 5: Account Management",
        "url": "https://www.cisecurity.org/controls/account-management",
        "standard": "CIS Controls v8",
        "version": "v8",
        "domain_tag": "authentication",
        "techniques": ["T1110", "T1136", "T1078"],
        "tactics": ["credential_access", "persistence"],
        "platforms": ["linux", "windows", "cloud"],
        "text": (
            "CIS Control 5: Account Management.\n"
            "Overview: Use processes and tools to assign, manage, verify, revoke, and audit credentials and privileges for user, "
            "administrator, and service accounts for enterprise assets and software.\n"
            "Key Safeguards:\n"
            "- 5.1: Maintain an Inventory of Accounts.\n"
            "- 5.2: Use Unique Passwords and Mandate Multi-Factor Authentication (MFA).\n"
            "- 5.3: Disable Dormant and Inactive Accounts after 45 days.\n"
            "- 5.4: Restrict Administrator Privileges to Dedicated Administrative Accounts.\n"
            "- 5.5: Establish and Follow an Automated Account De-provisioning Workflow."
        ),
    },
    {
        "id": "CIS-V8-C06",
        "title": "CIS Control 6: Access Control Management",
        "url": "https://www.cisecurity.org/controls/access-control-management",
        "standard": "CIS Controls v8",
        "version": "v8",
        "domain_tag": "access_control",
        "techniques": ["T1548", "T1078", "T1021"],
        "tactics": ["privilege_escalation", "lateral_movement"],
        "platforms": ["linux", "windows", "network"],
        "text": (
            "CIS Control 6: Access Control Management.\n"
            "Overview: Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, "
            "administrator, and service accounts over network resources and data assets.\n"
            "Key Safeguards:\n"
            "- 6.1: Establish an Access Granting Process based on least privilege and need-to-know.\n"
            "- 6.2: Establish an Access Revoking Process for departing employees within 24 hours.\n"
            "- 6.3: Require MFA for Externally-Exposed and Remote Access Systems (SSH bastions, VPNs, web admin portals).\n"
            "- 6.7: Centralize Access Control via Enterprise IAM / Active Directory."
        ),
    },
    {
        "id": "CIS-V8-C17",
        "title": "CIS Control 17: Incident Response Management",
        "url": "https://www.cisecurity.org/controls/incident-response-management",
        "standard": "CIS Controls v8",
        "version": "v8",
        "domain_tag": "incident_response",
        "techniques": ["T1046", "T1110", "T1486"],
        "tactics": ["reconnaissance", "impact"],
        "platforms": ["linux", "windows", "network", "cloud"],
        "text": (
            "CIS Control 17: Incident Response Management.\n"
            "Overview: Establish a program to develop and maintain an incident response capability (e.g. policies, plans, roles, training) "
            "to quickly detect attacks and contain, eradicate, and restore systems.\n"
            "Key Safeguards:\n"
            "- 17.1: Designate Personnel to Manage Incident Handling.\n"
            "- 17.2: Establish and Maintain Contact Information for Reporting Security Incidents.\n"
            "- 17.3: Establish and Maintain an Enterprise Incident Handling Process.\n"
            "- 17.8: Conduct Post-Incident Reviews to analyze root cause and close control gaps."
        ),
    },
]


def load_cis_documents() -> list[dict[str, Any]]:
    """Return CIS Controls knowledge documents."""
    documents = []
    for doc in CIS_DOCS:
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
