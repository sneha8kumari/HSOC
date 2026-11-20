"""
Evaluation experiment: simulate 100 analyst feedback corrections on the Markov model
and measure prediction accuracy and transition probabilities before vs after.

Generates:
  - experiments/results/markov_feedback_eval.png (evolution plot)
  - experiments/results/markov_feedback_metrics.json (metrics summary)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import matplotlib.pyplot as plt

from hsoc.investigate.predictor import MarkovPredictor, ModelRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_feedback_simulation(n_steps: int = 100, out_dir: str = "experiments/results") -> dict:
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize predictor with standard baseline
    predictor = MarkovPredictor()
    registry = ModelRegistry(model_dir=str(target_dir / "models_registry"))
    registry.save_version(predictor, description="Baseline prior to simulation")

    # Define test evaluation benchmark sequences (ground truth)
    test_eval_set = [
        ("reconnaissance", "initial_access"),
        ("initial_access", "execution"),
        ("execution", "persistence"),
        ("persistence", "privilege_escalation"),
        ("privilege_escalation", "credential_access"),
        ("credential_access", "lateral_movement"),
        ("lateral_movement", "collection"),
        ("collection", "exfiltration"),
        ("exfiltration", "impact"),
    ]

    def evaluate_top1_accuracy(model: MarkovPredictor) -> float:
        correct = 0
        for src, expected_dst in test_eval_set:
            preds = model.predict(src, top_n=1)
            if preds and preds[0].tactic == expected_dst:
                correct += 1
        return correct / len(test_eval_set)

    # Artificially inject an erroneous noisy transition to simulate noise / false prediction
    # E.g. Model initially has strong false belief: reconnaissance -> impact
    predictor.transitions["reconnaissance"]["impact"] = 8.0
    predictor.unigrams["impact"] += 8.0

    acc_before = evaluate_top1_accuracy(predictor)
    p_true_before = predictor.get_transition_probability("reconnaissance", "initial_access")
    p_err_before = predictor.get_transition_probability("reconnaissance", "impact")

    logger.info(
        "Initial state before corrections: Top-1 Acc=%.2f%%, P(true: recon->initial_access)=%.4f, P(err: recon->impact)=%.4f",
        acc_before * 100,
        p_true_before,
        p_err_before,
    )

    steps_history = []
    p_true_history = [p_true_before]
    p_err_history = [p_err_before]
    kl_history = [predictor.compute_kl_divergence()]
    acc_history = [acc_before]

    # 2. Simulate 100 analyst feedback corrections
    for step in range(1, n_steps + 1):
        if step % 2 == 1:
            # Analyst rejects erroneous transition (reconnaissance -> impact)
            predictor.update_bayesian("reconnaissance", "impact", decision="rejected")
        else:
            # Analyst accepts/reinforces true transition (reconnaissance -> initial_access)
            predictor.update_bayesian("reconnaissance", "initial_access", decision="accepted")

        # Periodically reinforce other kill-chain sequences as analyst reviews legitimate incidents
        if step % 5 == 0:
            for src, dst in test_eval_set[1:4]:
                predictor.update_bayesian(src, dst, decision="accepted")

        steps_history.append(step)
        p_true_history.append(predictor.get_transition_probability("reconnaissance", "initial_access"))
        p_err_history.append(predictor.get_transition_probability("reconnaissance", "impact"))
        kl_history.append(predictor.compute_kl_divergence())
        acc_history.append(evaluate_top1_accuracy(predictor))

    acc_after = acc_history[-1]
    p_true_after = p_true_history[-1]
    p_err_after = p_err_history[-1]

    # Save final version
    final_ver = registry.save_version(predictor, description="After 100 analyst feedback corrections")

    # 3. Generate Plot
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)

    # Plot 1: Transition Probabilities (True vs Erroneous)
    ax1.plot(range(len(p_true_history)), p_true_history, color="#2563eb", linewidth=2.5, label="P(reconnaissance -> initial_access) [Ground Truth]")
    ax1.plot(range(len(p_err_history)), p_err_history, color="#dc2626", linewidth=2.5, linestyle="--", label="P(reconnaissance -> impact) [Erroneous/Rejected]")
    ax1.set_ylabel("Transition Probability", fontsize=11, fontweight="bold")
    ax1.set_title("Bayesian Markov Model Dirichlet Feedback Adaptation (100 Corrections)", fontsize=13, fontweight="bold")
    ax1.grid(True, linestyle=":", alpha=0.6)
    ax1.legend(loc="center right", frameon=True)

    # Plot 2: Top-1 Prediction Accuracy & Rolling KL Divergence
    ax2.plot(range(len(acc_history)), [a * 100 for a in acc_history], color="#16a34a", linewidth=2.5, label="Top-1 Kill-Chain Accuracy (%)")
    ax2_twin = ax2.twinx()
    ax2_twin.plot(range(len(kl_history)), kl_history, color="#9333ea", linewidth=2, linestyle="-.", label="Rolling KL Divergence D_KL(P || Q)")
    ax2_twin.axhline(0.15, color="#f97316", linestyle=":", label="Drift Notice Threshold (0.15)")
    ax2.set_xlabel("Analyst Feedback Corrections (Steps)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Accuracy (%)", fontsize=11, fontweight="bold", color="#16a34a")
    ax2_twin.set_ylabel("KL Divergence", fontsize=11, fontweight="bold", color="#9333ea")
    ax2.grid(True, linestyle=":", alpha=0.6)
    ax2.legend(loc="upper left")
    ax2_twin.legend(loc="lower right")

    plt.tight_layout()
    plot_path = target_dir / "markov_feedback_eval.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()

    metrics = {
        "simulation_steps": n_steps,
        "initial_top1_accuracy": round(acc_before, 4),
        "final_top1_accuracy": round(acc_after, 4),
        "accuracy_gain": round(acc_after - acc_before, 4),
        "p_true_initial": round(p_true_before, 4),
        "p_true_final": round(p_true_after, 4),
        "p_true_gain": round(p_true_after - p_true_before, 4),
        "p_rejected_initial": round(p_err_before, 4),
        "p_rejected_final": round(p_err_after, 4),
        "p_rejected_decay": round(p_err_before - p_err_after, 4),
        "final_kl_divergence": round(kl_history[-1], 4),
        "plot_file": str(plot_path),
        "model_registry_version": final_ver,
    }

    metrics_path = target_dir / "markov_feedback_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    logger.info("Feedback simulation complete. Metrics written to %s", metrics_path)
    return metrics


if __name__ == "__main__":
    res = run_feedback_simulation(n_steps=100)
    print("\n" + "=" * 60)
    print("MARKOV MODEL FEEDBACK SIMULATION RESULTS (100 Steps)")
    print("=" * 60)
    for k, v in res.items():
        print(f"  {k}: {v}")
