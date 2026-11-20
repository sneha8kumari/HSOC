"""
Unit tests for the LLM Red-Team Scenario Planner and Markov Evaluator.

Verifies:
  1. S1 YAML schema validation (positive and negative cases).
  2. Trajectory generation constrained by ATT&CK graph and Markov matrix.
  3. Generation of 50+ campaigns partitioned into train/val/test splits.
  4. Automated ground-truth annotations and benign confounder distinction.
  5. Markov predictor training, test set evaluation and bootstrap confidence intervals.
"""

from pathlib import Path
import yaml
import pytest

from hsoc.investigate.predictor import MarkovPredictor
from hsoc.simulate.llm_scenarios import (
    ATTACK_GRAPH,
    RedTeamPlanner,
    evaluate_markov_on_campaigns,
    generate_campaign_dataset,
    validate_scenario_s1_schema,
)


def test_s1_schema_validation_positive_and_negative():
    # Valid scenario
    valid_scenario = {
        "id": "TEST-001",
        "name": "Test Valid Port Scan",
        "description": "Validation test for S1 schema",
        "targets": [{"host": "db-srv-01", "ip": "192.168.56.20"}],
        "techniques": ["T1046", "T1110.001"],
        "tactic": "reconnaissance",
        "steps": [
            {
                "step": 1,
                "type": "flow",
                "description": "SYN port scan",
                "src_ip": "203.0.113.15",
                "dst_ports": "80-100",
                "duration_seconds": 30,
                "label": "test_recon",
            },
            {
                "step": 2,
                "type": "auth",
                "description": "SSH brute force attempt",
                "src_ip": "203.0.113.15",
                "host": "db-srv-01",
                "user": "root",
                "attempts": 5,
                "outcome": "failure",
                "duration_seconds": 20,
                "label": "test_brute_force",
            },
        ],
    }
    is_valid, errors = validate_scenario_s1_schema(valid_scenario)
    assert is_valid is True
    assert len(errors) == 0

    # Negative 1: Missing top-level key 'targets'
    invalid_1 = dict(valid_scenario)
    del invalid_1["targets"]
    is_valid_1, errors_1 = validate_scenario_s1_schema(invalid_1)
    assert is_valid_1 is False
    assert any("targets" in e for e in errors_1)

    # Negative 2: Malformed MITRE technique ID
    invalid_2 = dict(valid_scenario)
    invalid_2["techniques"] = ["NOT_A_TECHNIQUE"]
    is_valid_2, errors_2 = validate_scenario_s1_schema(invalid_2)
    assert is_valid_2 is False
    assert any("NOT_A_TECHNIQUE" in e for e in errors_2)

    # Negative 3: Invalid step type
    invalid_3 = dict(valid_scenario)
    invalid_3["steps"] = [
        {
            "step": 1,
            "type": "unsupported_protocol",
            "description": "Invalid",
            "src_ip": "10.0.0.1",
            "duration_seconds": 10,
        }
    ]
    is_valid_3, errors_3 = validate_scenario_s1_schema(invalid_3)
    assert is_valid_3 is False
    assert any("unsupported_protocol" in e for e in errors_3)


def test_trajectory_sampling_constrained_by_attack_graph():
    planner = RedTeamPlanner()
    for _ in range(15):
        traj = planner.sample_trajectory(start_tactic="reconnaissance", length=5)
        assert len(traj) >= 3
        # Verify every transition is a valid directed edge in ATTACK_GRAPH
        for i in range(len(traj) - 1):
            src, dst = traj[i], traj[i + 1]
            allowed_next = ATTACK_GRAPH.get(src, [])
            assert dst in allowed_next, f"Illegal transition {src} -> {dst} not in ATTACK_GRAPH!"


def test_campaign_generation_with_ground_truth_and_noise():
    planner = RedTeamPlanner()
    scenario, gt = planner.generate_campaign("CMP-TEST-99", seed=123)

    # Verify scenario matches S1 schema
    is_valid, errors = validate_scenario_s1_schema(scenario)
    assert is_valid is True, f"Generated scenario failed schema: {errors}"

    # Verify ground truth records
    assert len(gt) == len(scenario["steps"])
    attack_steps = [r for r in gt if r["is_attack"]]
    assert len(attack_steps) >= 3

    # Check for presence of techniques in attack steps
    for step_gt in attack_steps:
        assert len(step_gt["techniques"]) > 0
        assert step_gt["techniques"][0].startswith("T") or step_gt["techniques"][0].startswith("CWE")


def test_campaign_dataset_generation_splits(tmp_path):
    out_dir = tmp_path / "scenarios_dataset"
    manifest = generate_campaign_dataset(
        num_campaigns=52,
        train_split=0.70,
        val_split=0.15,
        test_split=0.15,
        out_dir=str(out_dir),
        seed=100,
    )

    assert manifest["total_campaigns"] == 52
    train_count = manifest["splits"]["train"]["count"]
    val_count = manifest["splits"]["val"]["count"]
    test_count = manifest["splits"]["test"]["count"]

    assert train_count >= 35
    assert val_count >= 7
    assert test_count >= 7
    assert train_count + val_count + test_count == 52

    # Check YAML files exist and are valid
    train_files = list((out_dir / "train").glob("*.yaml"))
    assert len(train_files) == train_count
    for yf in train_files[:5]:
        content = yaml.safe_load(yf.read_text(encoding="utf-8"))
        is_valid, errs = validate_scenario_s1_schema(content)
        assert is_valid is True, f"File {yf} failed schema: {errs}"

    # Check ground truth file
    gt_file = out_dir / "ground_truth.jsonl"
    assert gt_file.exists()
    assert gt_file.stat().st_size > 0


def test_markov_evaluation_with_confidence_intervals():
    train_seqs = [
        ["reconnaissance", "initial_access", "privilege_escalation"],
        ["reconnaissance", "credential_access", "initial_access", "privilege_escalation"],
        ["initial_access", "execution", "defense_evasion", "exfiltration"],
        ["reconnaissance", "initial_access", "execution", "persistence"],
        ["reconnaissance", "initial_access", "privilege_escalation", "lateral_movement"],
    ] * 6

    test_seqs = [
        ["reconnaissance", "initial_access", "privilege_escalation"],
        ["reconnaissance", "credential_access", "initial_access"],
        ["initial_access", "execution", "defense_evasion"],
    ] * 3

    results = evaluate_markov_on_campaigns(
        train_sequences=train_seqs,
        test_sequences=test_seqs,
        num_bootstraps=200,
        ci_level=0.95,
        seed=42,
    )

    assert "top1_accuracy" in results
    assert "top3_accuracy" in results
    assert "top1_ci" in results
    assert "top3_ci" in results
    assert "perplexity" in results
    assert "perplexity_ci" in results

    # Statistical consistency of confidence intervals
    top1 = results["top1_accuracy"]
    top1_low, top1_high = results["top1_ci"]
    assert top1_low <= top1_high
    assert 0.0 <= top1 <= 1.0

    top3 = results["top3_accuracy"]
    top3_low, top3_high = results["top3_ci"]
    assert top3_low <= top3_high
    assert top3 >= top1  # Top-3 accuracy is always >= Top-1 accuracy
