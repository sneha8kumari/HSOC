"""
OWASP Top 10 (2021) and ASVS (Application Security Verification Standard v4.0.3)
knowledge source ingestion.
"""

from __future__ import annotations

from typing import Any

OWASP_DOCS: list[dict[str, Any]] = [
    {
        "id": "OWASP-2021-A01",
        "title": "OWASP Top 10:2021-A01 Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "standard": "OWASP Top 10",
        "version": "2021",
        "domain_tag": "access_control",
        "techniques": ["T1548", "T1078"],
        "tactics": ["privilege_escalation", "defense_evasion"],
        "platforms": ["web", "cloud"],
        "text": (
            "OWASP A01:2021 - Broken Access Control.\n"
            "Description: Access control enforces policy such that users cannot act outside of their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, "
            "or performing a business function outside the user's limits.\n"
            "Key Vulnerabilities: Bypassing access control checks by modifying the URL, internal application state, or the HTML page, "
            "or using a custom API attack tool; permitting viewing or editing someone else's account by providing its unique identifier (IDOR).\n"
            "Remediation & ASVS V4 Verification:\n"
            "- Enforce least privilege by default. Deny all access except for public resources.\n"
            "- Implement access control checks server-side in trusted business logic components.\n"
            "- Disable web server directory listing and ensure file metadata (e.g. .git, .env) is not present within web roots.\n"
            "- Rate limit API and controller access to minimize the harm from automated brute-forcing or scanning tools."
        ),
    },
    {
        "id": "OWASP-2021-A02",
        "title": "OWASP Top 10:2021-A02 Cryptographic Failures",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "standard": "OWASP Top 10",
        "version": "2021",
        "domain_tag": "encryption_config",
        "techniques": ["CWE-319", "T1040"],
        "tactics": ["credential_access"],
        "platforms": ["network", "web"],
        "text": (
            "OWASP A02:2021 - Cryptographic Failures (formerly Sensitive Data Exposure).\n"
            "Description: Transmitting data in clear text (HTTP, SMTP, FTP, Telnet) or using weak cryptographic protocols "
            "and outdated ciphers exposes sensitive secrets, tokens, and session identifiers to network eavesdropping.\n"
            "Remediation & ASVS V9 Verification:\n"
            "- Classify data processed, stored, or transmitted by an application. Identify sensitive data per privacy laws.\n"
            "- Encrypt all sensitive data in transit with secure TLS (TLS 1.3 or 1.2 with modern AEAD cipher suites).\n"
            "- Disable deprecated protocols including Telnet (port 23), FTP (port 21), and cleartext HTTP (port 80).\n"
            "- Enforce HTTP Strict Transport Security (HSTS) with long max-age and includeSubDomains directives."
        ),
    },
    {
        "id": "OWASP-2021-A07",
        "title": "OWASP Top 10:2021-A07 Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "standard": "OWASP Top 10",
        "version": "2021",
        "domain_tag": "authentication",
        "techniques": ["T1110", "T1110.001", "T1110.003"],
        "tactics": ["credential_access"],
        "platforms": ["web", "cloud"],
        "text": (
            "OWASP A07:2021 - Identification and Authentication Failures.\n"
            "Description: Confirmation of the user's identity, authentication, and session management is critical to protect "
            "against authentication-related attacks such as credential stuffing, brute force, and stolen session token replays.\n"
            "Remediation & ASVS V2 Verification:\n"
            "- Where possible, implement multi-factor authentication (MFA) to prevent automated credential stuffing and brute force.\n"
            "- Do not deploy with default credentials, particularly for administrator accounts.\n"
            "- Implement weak-password checks, such as testing new or changed passwords against the top 10,000 worst passwords list.\n"
            "- Align password length, complexity, and rotation requirements with NIST SP 800-63B guidelines.\n"
            "- Limit or increasingly delay failed login attempts (exponential backoff / fail2ban rate limiting)."
        ),
    },
    {
        "id": "OWASP-ASVS-V5",
        "title": "OWASP ASVS v4.0.3 Chapter 5: Validation, Sanitization and Encoding",
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "standard": "OWASP ASVS",
        "version": "4.0.3",
        "domain_tag": "access_control",
        "techniques": ["T1595", "T1190"],
        "tactics": ["initial_access"],
        "platforms": ["web", "api"],
        "text": (
            "OWASP Application Security Verification Standard (ASVS) Chapter 5.\n"
            "Scope: Input validation and output encoding architecture to prevent path traversal, code injection, and fuzzing exploits.\n"
            "Verification Requirements:\n"
            "- V5.1: Verify that input validation is enforced on a trusted service tier before processing requests.\n"
            "- V5.2: Verify that path sanitization prevents directory traversal attacks (dot-dot-slash) when accessing filesystem resources.\n"
            "- V5.3: Verify that all untrusted parameters originating from HTTP headers, URIs, and payloads are sanitized before logging or presentation.\n"
            "- V5.5: Verify that Web Application Firewall (WAF) inspects payload content-type and rejects unwhitelisted structures."
        ),
    },
]


def load_owasp_documents() -> list[dict[str, Any]]:
    """Return OWASP knowledge documents."""
    documents = []
    for doc in OWASP_DOCS:
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
