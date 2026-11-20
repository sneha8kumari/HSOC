"""
ATT&CK technique → tactic lookup.

Built from the ATT&CK STIX JSON fetched in M4.
A small hard-coded fallback covers the techniques used by rules R-01 to R-09
so that detection works before the full index is built.
"""

from __future__ import annotations

# Hard-coded fallback for the techniques referenced by rules R-01–R-09
# and the scenario set.  This is the ONLY place ATT&CK IDs are hard-coded.
_FALLBACK: dict[str, str] = {
    "T1046": "reconnaissance",
    "T1110": "credential_access",
    "T1110.001": "credential_access",
    "T1110.003": "credential_access",
    "T1078": "initial_access",
    "T1548.003": "privilege_escalation",
    "T1098": "privilege_escalation",
    "T1595.003": "reconnaissance",
    "T1190": "initial_access",
    "T1136.001": "persistence",
    "CWE-319": "encryption_config",
}

# Full lookup is populated by build_index.py in M4
_FULL_LOOKUP: dict[str, str] = {}


def technique_to_tactic(technique_id: str) -> str | None:
    """
    Map an ATT&CK technique ID to its primary tactic.

    Checks the full index first, then falls back to the hard-coded map.

    Args:
        technique_id: ATT&CK technique ID (e.g. ``T1110.001``).

    Returns:
        Tactic string, or ``None`` if not found.
    """
    return _FULL_LOOKUP.get(technique_id) or _FALLBACK.get(technique_id)


def load_full_lookup(path: str = "data/kb/technique_tactic.json") -> None:
    """
    Populate ``_FULL_LOOKUP`` from the STIX-derived JSON.

    Args:
        path: Path to the technique->tactic JSON file.
    """
    import json
    from pathlib import Path

    file_path = Path(path)
    if file_path.exists():
        data = json.loads(file_path.read_text(encoding="utf-8"))
        for tech, tactics in data.items():
            if tactics:
                _FULL_LOOKUP[tech] = tactics[0]
