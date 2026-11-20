"""
Unit tests for detection window manager, rule engine, fusion, and severity scoring.
"""

from datetime import datetime, timezone

from hsoc.detect import fusion, rule_engine
from hsoc.detect.windows import WindowManager
from hsoc.investigate import correlate, severity
from hsoc.investigate.predictor import MarkovPredictor
from hsoc.schema import Alert, Domain, Event, Outcome, Severity, SourceType


def test_window_manager_sliding_time():
    wm = WindowManager()
    base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Add 3 events at t=0s, t=30s, t=90s
    for offset in [0, 30, 90]:
        ev = Event(
            ts=datetime.fromtimestamp(base_time.timestamp() + offset, tz=timezone.utc),
            source_type=SourceType.linux_auth,
            src_ip="203.0.113.5",
            action="ssh_login",
            raw=f"event at {offset}",
        )
        wm.add(ev)

    # 60s window from t=90s should include t=30s and t=90s, but NOT t=0s
    ref_time = datetime.fromtimestamp(base_time.timestamp() + 90, tz=timezone.utc)
    window = wm.get_window("src_ip", "203.0.113.5", window_seconds=60, as_of=ref_time)
    assert len(window) == 2


def test_severity_scoring_and_bands():
    # score(4, 5, 0.95) -> round(20 * (1.6 + 2.0 + 0.95)) = 91 -> Critical
    s1 = severity.score(4, 5, 0.95)
    assert s1 == 91
    assert severity.band(s1) == Severity.critical

    # score(2, 5, 0.9) -> round(20 * (0.8 + 2.0 + 0.9)) = 74 -> High
    s2 = severity.score(2, 5, 0.9)
    assert s2 == 74
    assert severity.band(s2) == Severity.high

    # score(2, 2, 0.9) -> round(20 * (0.8 + 0.8 + 0.9)) = 50 -> Medium
    s3 = severity.score(2, 2, 0.9)
    assert s3 == 50
    assert severity.band(s3) == Severity.medium

    # score(1, 1, 0.2) -> Low
    s4 = severity.score(1, 1, 0.2)
    assert severity.band(s4) == Severity.low


def test_fusion_bonus_logic():
    # Single signal without ML -> returns rule_conf
    assert fusion.fuse_alert(0.8, None) == 0.8

    # Both above 0.5 threshold -> max + 0.1 bonus
    fused = fusion.fuse_alert(0.7, 0.8)
    assert round(fused, 2) == 0.9

    # One signal below 0.5 threshold -> no bonus
    fused_no_bonus = fusion.fuse_alert(0.7, 0.4)
    assert round(fused_no_bonus, 2) == 0.7


def test_markov_predictor_laplace_smoothing():
    predictor = MarkovPredictor()
    predictor.train([
        ["reconnaissance", "credential_access", "privilege_escalation"],
        ["reconnaissance", "credential_access", "lateral_movement"],
    ])

    predictions = predictor.predict("credential_access", top_n=2)
    assert len(predictions) == 2
    # Probability should be positive and bounded by 1.0
    for p in predictions:
        assert 0.0 < p.probability <= 1.0

    # Top prediction for credential_access should be privilege_escalation or lateral_movement
    predicted_tactics = [p.tactic for p in predictions]
    assert "privilege_escalation" in predicted_tactics or "lateral_movement" in predicted_tactics
