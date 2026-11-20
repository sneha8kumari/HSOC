"""
Acceptance unit tests for Markov model Bayesian Dirichlet updates,
KL divergence drift detection, and exact registry rollback.
"""

from fastapi.testclient import TestClient

from hsoc.api.main import app
from hsoc.investigate.predictor import MarkovPredictor, ModelRegistry
from hsoc.schema import FeedbackDecision


def test_rejected_transition_probability_measurably_drops():
    predictor = MarkovPredictor()
    # Seed transition counts
    predictor.transitions["reconnaissance"]["impact"] = 5.0

    p_before = predictor.get_transition_probability("reconnaissance", "impact")

    # Apply analyst "rejected" feedback
    res = predictor.update_bayesian("reconnaissance", "impact", decision=FeedbackDecision.rejected)

    p_after = predictor.get_transition_probability("reconnaissance", "impact")

    # Acceptance check: rejected transition probability measurably drops
    assert p_after < p_before
    assert res["delta"] < 0
    assert res["p_after"] < res["p_before"]


def test_accepted_transition_probability_measurably_increases():
    predictor = MarkovPredictor()
    p_before = predictor.get_transition_probability("reconnaissance", "initial_access")

    # Apply analyst "accepted" feedback
    res = predictor.update_bayesian("reconnaissance", "initial_access", decision=FeedbackDecision.accepted)

    p_after = predictor.get_transition_probability("reconnaissance", "initial_access")

    # Acceptance check: accepted transition probability increases
    assert p_after > p_before
    assert res["delta"] > 0


def test_edited_transition_reassigns_and_updates():
    predictor = MarkovPredictor()
    predictor.transitions["reconnaissance"]["impact"] = 4.0

    p_err_before = predictor.get_transition_probability("reconnaissance", "impact")
    p_true_before = predictor.get_transition_probability("reconnaissance", "initial_access")

    # Analyst edits impact -> initial_access
    predictor.update_bayesian(
        "reconnaissance",
        "impact",
        decision=FeedbackDecision.edited,
        corrected_dst="initial_access",
    )

    p_err_after = predictor.get_transition_probability("reconnaissance", "impact")
    p_true_after = predictor.get_transition_probability("reconnaissance", "initial_access")

    assert p_err_after < p_err_before
    assert p_true_after > p_true_before


def test_rollback_restores_previous_matrix_exactly(tmp_path):
    registry_dir = tmp_path / "registry"
    registry = ModelRegistry(model_dir=str(registry_dir))

    predictor = MarkovPredictor()
    # Train predictor on standard sequence
    predictor.train([["reconnaissance", "initial_access", "execution"]])

    # Save exact baseline version 1
    v1_id = registry.save_version(predictor, description="Exact Baseline v1")
    v1_exact_dict = predictor.to_dict()

    # Mutate predictor with heavy feedback changes
    for _ in range(5):
        predictor.update_bayesian("reconnaissance", "impact", decision="accepted")
        predictor.update_bayesian("initial_access", "exfiltration", decision="accepted")

    mutated_dict = predictor.to_dict()
    assert mutated_dict != v1_exact_dict

    # Save mutated as version 2
    v2_id = registry.save_version(predictor, description="Mutated v2")
    assert v2_id == 2

    # Acceptance check: rollback to v1 restores the previous matrix EXACTLY
    restored_version = registry.rollback(predictor, version=v1_id)
    assert restored_version == 1

    restored_dict = predictor.to_dict()
    assert restored_dict == v1_exact_dict
    assert restored_dict["transitions"] == v1_exact_dict["transitions"]
    assert restored_dict["unigrams"] == v1_exact_dict["unigrams"]
    assert restored_dict["vocab"] == v1_exact_dict["vocab"]


def test_drift_detection_kl_divergence():
    predictor = MarkovPredictor()
    assert predictor.compute_kl_divergence() == 0.0

    is_drifted, kl_val, notice = predictor.check_drift()
    assert is_drifted is False
    assert "within stability boundary" in notice

    # Induce heavy divergence
    for _ in range(30):
        predictor.update_bayesian("reconnaissance", "impact", decision="accepted")

    kl_drifted = predictor.compute_kl_divergence()
    assert kl_drifted > 0.15

    is_drifted_now, kl_val_now, notice_drift = predictor.check_drift()
    assert is_drifted_now is True
    assert "NOTICE: Model drift detected" in notice_drift


def test_api_feedback_and_model_status():
    client = TestClient(app)

    # 1. Check initial status
    res = client.get("/models/markov/status")
    assert res.status_code == 200
    data = res.json()
    assert "current_version" in data
    assert "kl_divergence" in data

    # 2. Submit feedback
    payload = {
        "report_id": "rep-test-01",
        "incident_id": "inc-test-01",
        "decision": "rejected",
        "comment": "False positive transition observed",
    }
    fb_res = client.post("/feedback", json=payload)
    assert fb_res.status_code == 200
    fb_data = fb_res.json()
    assert fb_data["status"] == "success"
    assert fb_data["model_version"] >= 1
    assert "kl_divergence" in fb_data

    # 3. Test rollback route
    rb_res = client.post("/feedback/rollback?version=1")
    assert rb_res.status_code == 200
    rb_data = rb_res.json()
    assert rb_data["restored_version"] == 1
