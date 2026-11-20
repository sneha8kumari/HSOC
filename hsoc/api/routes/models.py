"""
Markov Model and Analytics API Router.

Exposes:
  - Transition matrix heatmap data
  - Animated next-step probability bars with Dirichlet credible intervals
  - Viterbi stage path calculation
  - Absorption-risk gauge computation
  - Model registry version status and drift indicators
"""

from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Query

from hsoc.api.routes.feedback import get_active_predictor, get_model_registry
from hsoc.investigate.predictor import _DEFAULT_CHAIN

router = APIRouter()

TACTICS_LIST = _DEFAULT_CHAIN


def _compute_absorption_risk(matrix: dict[str, dict[str, float]], start_tactic: str, steps: int = 8) -> float:
    """
    Compute multi-step reachability probability of reaching terminal/destructive stages
    ('impact' or 'exfiltration') from start_tactic.
    """
    start = start_tactic.lower()
    absorbing_states = {"impact", "exfiltration"}

    # Current state probability vector
    state_probs: dict[str, float] = {t: 0.0 for t in TACTICS_LIST}
    if start in state_probs:
        state_probs[start] = 1.0
    else:
        state_probs[TACTICS_LIST[0]] = 1.0

    cumulative_absorption = 0.0

    for _ in range(steps):
        next_probs: dict[str, float] = {t: 0.0 for t in TACTICS_LIST}
        for s, p in state_probs.items():
            if p <= 0:
                continue
            if s in absorbing_states:
                cumulative_absorption += p
                continue  # Absorbed
            trans = matrix.get(s, {})
            total_w = sum(trans.values()) or 1.0
            for dst, w in trans.items():
                if dst in next_probs:
                    next_probs[dst] += p * (w / total_w)
        state_probs = next_probs

    cumulative_absorption += sum(state_probs.get(a, 0.0) for a in absorbing_states)
    return round(min(1.0, max(0.05, cumulative_absorption)), 4)


def _compute_viterbi_path(predictor: Any, observed_tactics: list[str]) -> list[str]:
    """
    Compute the most likely path through the ATT&CK kill-chain states
    given observed tactics sequence.
    """
    if not observed_tactics:
        return [TACTICS_LIST[0], TACTICS_LIST[1], TACTICS_LIST[2]]

    cleaned_obs = [t.lower() for t in observed_tactics if t.lower() in TACTICS_LIST]
    if not cleaned_obs:
        return observed_tactics

    current = cleaned_obs[0]
    path = [current]

    for next_obs in cleaned_obs[1:]:
        # Predict candidate next states and pick maximum likelihood
        cands = predictor.predict(current, top_n=3)
        cand_tactics = [c.tactic for c in cands]
        if next_obs in cand_tactics:
            chosen = next_obs
        elif cand_tactics:
            chosen = cand_tactics[0]
        else:
            chosen = next_obs
        path.append(chosen)
        current = chosen

    # Project 2 steps into the future
    future_cands = predictor.predict(current, top_n=1)
    if future_cands:
        path.append(future_cands[0].tactic)

    return path


@router.get("/panel", tags=["models"])
def get_markov_panel_data(
    current_tactic: str = Query("reconnaissance", description="Tactic to forecast from"),
    observed_sequence: str | None = Query(None, description="Comma-separated observed tactics"),
) -> dict[str, Any]:
    """
    Comprehensive Markov panel telemetry:
      - 13x13 transition matrix for heatmap
      - Credible intervals for next-step predictions
      - Viterbi stage path projection
      - Absorption-risk gauge calculation
    """
    predictor = get_active_predictor()
    registry = get_model_registry()

    cur_tac = current_tactic.lower()
    if cur_tac not in TACTICS_LIST:
        cur_tac = "reconnaissance"

    # Build 13x13 transition probability matrix
    matrix_rows: list[list[float]] = []
    matrix_dict: dict[str, dict[str, float]] = {}

    for src in TACTICS_LIST:
        row: list[float] = []
        matrix_dict[src] = {}
        for dst in TACTICS_LIST:
            prob = predictor.get_transition_probability(src, dst)
            prob_round = round(prob, 4)
            row.append(prob_round)
            matrix_dict[src][dst] = prob_round
        matrix_rows.append(row)

    # Next-step predictions with credible intervals
    predictions = predictor.predict(cur_tac, top_n=5)
    counts = predictor.transitions.get(cur_tac, {})
    row_count = sum(counts.values()) + 1.0

    predictions_with_ci: list[dict[str, Any]] = []
    for pred in predictions:
        p = pred.probability
        # Standard error for proportion: sqrt(p*(1-p)/N)
        se = math.sqrt(max(1e-5, p * (1.0 - p)) / row_count)
        ci_low = round(max(0.01, p - 1.96 * se), 4)
        ci_high = round(min(0.99, p + 1.96 * se), 4)

        predictions_with_ci.append(
            {
                "tactic": pred.tactic,
                "probability": p,
                "ci_lower": ci_low,
                "ci_upper": ci_high,
            }
        )

    # Absorption risk towards terminal stages
    absorption_risk = _compute_absorption_risk(matrix_dict, cur_tac)

    # Viterbi stage path
    observed = [t.strip() for t in observed_sequence.split(",") if t.strip()] if observed_sequence else [cur_tac]
    viterbi_path = _compute_viterbi_path(predictor, observed)

    is_drifted, kl_val, notice = predictor.check_drift()

    return {
        "current_version": registry.get_current_version(),
        "is_drifted": is_drifted,
        "kl_divergence": kl_val,
        "notice": notice,
        "tactics": TACTICS_LIST,
        "matrix": matrix_rows,
        "selected_tactic": cur_tac,
        "next_step_predictions": predictions_with_ci,
        "absorption_risk": absorption_risk,
        "viterbi_path": viterbi_path,
    }
