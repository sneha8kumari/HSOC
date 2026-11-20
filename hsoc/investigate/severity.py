"""
Asset-aware severity scoring.

Formula (from settings.yaml)::

    risk = round(20 * (0.4*T + 0.4*A + 1.0*C))

Where:
  T = tactic weight (2–5)
  A = max asset criticality (1–5)
  C = max fused confidence (0.0–1.0)

Bands: <40 Low · 40–59 Medium · 60–79 High · ≥80 Critical
"""

from __future__ import annotations

from hsoc.config import get_settings
from hsoc.ingest.enrich import load_asset_inventory
from hsoc.schema import Alert, Incident, Severity


def score(T: float, A: float, C: float) -> int:
    """
    Pure severity formula — testable without DB or pipeline.

    Args:
        T: Technique/tactic weight (2–5).
        A: Max asset criticality (1–5).
        C: Max fused confidence (0.0–1.0).

    Returns:
        Integer risk score.
    """
    cfg = get_settings().severity.get("formula_coeff", {})
    coeff_t = float(cfg.get("technique", 0.4))
    coeff_a = float(cfg.get("asset", 0.4))
    coeff_c = float(cfg.get("confidence", 1.0))
    scale = float(cfg.get("scale", 20))

    raw_val = scale * (coeff_t * T + coeff_a * A + coeff_c * C)
    return max(0, round(raw_val))


def band(risk_score: int) -> Severity:
    """
    Convert a numeric risk score to a named severity band.

    Args:
        risk_score: Integer from score().

    Returns:
        Severity enum value.
    """
    bands_cfg = get_settings().severity.get("bands", {})
    crit_threshold = int(bands_cfg.get("critical", 80))
    high_threshold = int(bands_cfg.get("high", 60))
    med_threshold = int(bands_cfg.get("medium", 40))

    if risk_score >= crit_threshold:
        return Severity.critical
    if risk_score >= high_threshold:
        return Severity.high
    if risk_score >= med_threshold:
        return Severity.medium
    return Severity.low


def compute_severity(incident: Incident, alerts: list[Alert]) -> Incident:
    """
    Compute risk_score, severity band and risk_rationale.

    Args:
        incident: The incident to score.
        alerts: All alerts in the incident.

    Returns:
        The incident with severity fields set.
    """
    if not alerts:
        incident.risk_score = 0
        incident.severity = Severity.low
        incident.risk_rationale = "No alerts in incident"
        return incident

    tactic_weights = get_settings().severity.get("tactic_weights", {})
    assets = load_asset_inventory()

    # 1. Compute max tactic weight T
    max_t = 2.0
    for al in alerts:
        tactic_key = (al.tactic or "").lower()
        tw = float(tactic_weights.get(tactic_key, 2.0))
        if tw > max_t:
            max_t = tw

    # 2. Compute max asset criticality A
    max_a = 1.0
    for al in alerts:
        target = al.dst_host or al.src_ip
        if target and target in assets:
            crit = float(assets[target].criticality)
            if crit > max_a:
                max_a = crit

    # 3. Compute max fused confidence C
    max_c = max(al.conf for al in alerts)

    # 4. Compute composite risk score
    risk_val = score(max_t, max_a, max_c)
    sev_band = band(risk_val)

    incident.risk_score = risk_val
    incident.severity = sev_band
    incident.risk_rationale = (
        f"Calculated risk {risk_val} (Tactic weight={max_t:.1f}, "
        f"Asset criticality={max_a:.1f}, Confidence={max_c:.2f}) -> Band {sev_band.value.upper()}"
    )

    return incident
