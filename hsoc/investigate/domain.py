"""
Deterministic domain classifier.

Maps rule IDs and ATT&CK technique IDs to security domains.
The LLM is NEVER used for this classification.

Primary domain = domain of the most advanced kill-chain stage.
Secondary domains = all other domains present in the incident.
"""

from __future__ import annotations

from hsoc.schema import Alert, Domain, Incident

# Deterministic rule-id → domain mapping
RULE_DOMAIN: dict[str, Domain] = {
    "R-01": Domain.authentication,
    "R-02": Domain.authentication,
    "R-03": Domain.authentication,
    "R-04": Domain.reconnaissance,
    "R-05": Domain.reconnaissance,
    "R-06": Domain.authentication,
    "R-07": Domain.authorization,
    "R-08": Domain.access_control,
    "R-09": Domain.encryption_config,
    "R-10": Domain.authorization,
}

# Kill-chain tactic ordering (lower index = earlier stage)
TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource_development",
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


def classify_domain(incident: Incident, alerts: list[Alert]) -> Incident:
    """
    Set domain and secondary_domains on an incident.

    Args:
        incident: The incident to classify.
        alerts: All alerts in the incident.

    Returns:
        The incident with domain fields set.
    """
    if not alerts:
        incident.domain = Domain.unknown
        incident.secondary_domains = []
        return incident

    all_domains = list({al.domain for al in alerts if al.domain != Domain.unknown})
    if not all_domains:
        incident.domain = Domain.unknown
        incident.secondary_domains = []
        return incident

    # Find alert with the most advanced tactic
    best_tactic_idx = -1
    primary_domain = all_domains[0]

    for al in alerts:
        tactic = (al.tactic or "").lower()
        if tactic in TACTIC_ORDER:
            idx = TACTIC_ORDER.index(tactic)
            if idx > best_tactic_idx:
                best_tactic_idx = idx
                primary_domain = al.domain

    incident.domain = primary_domain
    incident.secondary_domains = [d for d in all_domains if d != primary_domain]
    return incident
