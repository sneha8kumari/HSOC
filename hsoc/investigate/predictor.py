"""
Markov-chain next-tactic predictor with Bayesian feedback updates,
rolling KL-divergence drift detection, and versioned model registry.

- Bayesian Dirichlet update:
    Analyst "accepted" reinforces observed transition (+accept_weight).
    Analyst "rejected" decays offending transition (-reject_decay, bounded by min_count).
    Analyst "edited" decays offending transition and reinforces corrected transition.
- Drift detection:
    Tracks rolling KL divergence D_KL(P || Q) against baseline.
    Raises model drift notice when D_KL > drift_kl_threshold.
- Model registry:
    Versioned snapshots (v1.json, v2.json, ...) with rollback.
"""

from __future__ import annotations

import copy
import json
import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hsoc.config import get_settings
from hsoc.schema import Feedback, FeedbackDecision, Incident, PredictedTactic

logger = logging.getLogger(__name__)

# Standard MITRE enterprise kill-chain progression baseline
_DEFAULT_CHAIN: list[str] = [
    "reconnaissance",
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


class MarkovPredictor:
    """
    First-order Markov chain over ATT&CK enterprise tactics with Dirichlet updates.

    Usage::

        p = MarkovPredictor()
        p.predict(current_tactic, top_n=3)
        p.update_bayesian("reconnaissance", "credential_access", decision="accepted")
        is_drifted, kl_val, notice = p.check_drift()
    """

    def __init__(self) -> None:
        self.transitions: dict[str, dict[str, float]] = defaultdict(dict)
        self.unigrams: dict[str, float] = defaultdict(float)
        self.vocab: set[str] = set(_DEFAULT_CHAIN)

        # Pre-seed with default chain transitions as Dirichlet prior
        for i in range(len(_DEFAULT_CHAIN) - 1):
            src, dst = _DEFAULT_CHAIN[i], _DEFAULT_CHAIN[i + 1]
            self.transitions[src][dst] = 1.0
            self.unigrams[src] = 1.0
        self.unigrams[_DEFAULT_CHAIN[-1]] = 1.0

        # Snapshot of baseline transition matrix for KL divergence calculation
        self.baseline_transitions: dict[str, dict[str, float]] = copy.deepcopy(self.transitions)

    def train(self, sequences: list[list[str]]) -> None:
        """
        Fit transition matrix from tactic sequences.

        Args:
            sequences: List of tactic sequences.
        """
        for seq in sequences:
            if not seq:
                continue
            for i in range(len(seq) - 1):
                src = seq[i].lower()
                dst = seq[i + 1].lower()
                self.vocab.add(src)
                self.vocab.add(dst)
                self.transitions[src][dst] = self.transitions[src].get(dst, 0.0) + 1.0
                self.unigrams[src] = self.unigrams.get(src, 0.0) + 1.0
            self.unigrams[seq[-1].lower()] = self.unigrams.get(seq[-1].lower(), 0.0) + 1.0
            self.vocab.add(seq[-1].lower())

        self.baseline_transitions = copy.deepcopy(self.transitions)

    def get_transition_probability(self, src: str, dst: str) -> float:
        """
        Compute P(dst | src) using Laplace smoothing.

        Args:
            src: Source tactic.
            dst: Target next tactic.

        Returns:
            Smoothed conditional probability P(dst | src).
        """
        src = (src or "").lower()
        dst = (dst or "").lower()
        alpha = float(get_settings().predictor.get("laplace_alpha", 1.0))
        V = max(len(self.vocab), 1)

        counts = self.transitions.get(src, {})
        total_transitions = sum(counts.values())
        denom = total_transitions + (alpha * V)

        val = counts.get(dst, 0.0)
        return (val + alpha) / denom

    def predict(self, current_tactic: str, top_n: int = 3) -> list[PredictedTactic]:
        """
        Predict the top-N most likely next tactics.

        Args:
            current_tactic: Current tactic observed.
            top_n: Number of predictions to return.

        Returns:
            List of PredictedTactic ordered by descending probability.
        """
        current_tactic = (current_tactic or "").lower()
        probabilities: list[tuple[str, float]] = []

        for cand in self.vocab:
            if cand == current_tactic and len(self.transitions.get(current_tactic, {})) > 0:
                continue
            prob = self.get_transition_probability(current_tactic, cand)
            probabilities.append((cand, prob))

        probabilities.sort(key=lambda x: x[1], reverse=True)
        top_items = probabilities[:top_n]
        return [PredictedTactic(tactic=t, probability=round(p, 4)) for t, p in top_items]

    def baseline_predict(self, top_n: int = 3) -> list[PredictedTactic]:
        """Most-frequent-tactic baseline."""
        total = max(sum(self.unigrams.values()), 1.0)
        items = sorted(self.unigrams.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [PredictedTactic(tactic=t, probability=round(c / total, 4)) for t, c in items]

    def update_bayesian(
        self,
        src: str,
        dst: str,
        decision: str | FeedbackDecision,
        corrected_dst: str | None = None,
    ) -> dict[str, Any]:
        """
        Perform a Bayesian Dirichlet conjugate update from analyst feedback.

        Args:
            src: Source observed tactic.
            dst: Target observed or predicted tactic.
            decision: 'accepted', 'rejected', or 'edited'.
            corrected_dst: Corrected target tactic when decision is 'edited'.

        Returns:
            Dict containing transition details and before/after probabilities.
        """
        src = src.lower()
        dst = dst.lower()
        self.vocab.add(src)
        self.vocab.add(dst)

        cfg = get_settings().predictor.get("feedback", {})
        accept_weight = float(cfg.get("accept_weight", 1.0))
        reject_decay = float(cfg.get("reject_decay", 0.5))
        min_count = float(cfg.get("min_count", 0.05))

        p_before = self.get_transition_probability(src, dst)
        decision_str = decision.value if isinstance(decision, FeedbackDecision) else str(decision).lower()

        if decision_str == "accepted":
            # Dirichlet conjugate update: add observed evidence
            self.transitions[src][dst] = self.transitions[src].get(dst, 0.0) + accept_weight
            self.unigrams[dst] = self.unigrams.get(dst, 0.0) + accept_weight

        elif decision_str == "rejected":
            # Decay offending transition counts
            current_count = self.transitions[src].get(dst, 0.0)
            new_count = max(min_count, current_count - reject_decay)
            self.transitions[src][dst] = new_count

        elif decision_str == "edited":
            # Penalize rejected transition
            current_count = self.transitions[src].get(dst, 0.0)
            self.transitions[src][dst] = max(min_count, current_count - reject_decay)

            # Re-assign to corrected tactic
            if corrected_dst:
                corrected_dst = corrected_dst.lower()
                self.vocab.add(corrected_dst)
                self.transitions[src][corrected_dst] = (
                    self.transitions[src].get(corrected_dst, 0.0) + accept_weight
                )
                self.unigrams[corrected_dst] = self.unigrams.get(corrected_dst, 0.0) + accept_weight

        p_after = self.get_transition_probability(src, dst)
        logger.info(
            "Bayesian Markov update: %s -> %s [%s] P(before)=%.4f -> P(after)=%.4f",
            src,
            dst,
            decision_str,
            p_before,
            p_after,
        )

        return {
            "src": src,
            "dst": dst,
            "decision": decision_str,
            "p_before": round(p_before, 4),
            "p_after": round(p_after, 4),
            "delta": round(p_after - p_before, 4),
        }

    def compute_kl_divergence(
        self,
        baseline: dict[str, dict[str, float]] | None = None,
        reduction: str = "max",
    ) -> float:
        """
        Compute rolling Kullback-Leibler (KL) divergence between current model P and baseline Q.

        By default, uses reduction='max' (maximum state transition divergence):
            D_KL_max(P || Q) = max_{i in V} sum_{j in V} P(j|i) * ln(P(j|i) / Q(j|i))
        This ensures localized tactic drift in any kill-chain stage triggers detection,
        rather than being diluted by un-perturbed states.
        """
        if baseline is None:
            baseline = self.baseline_transitions

        alpha = float(get_settings().predictor.get("laplace_alpha", 1.0))
        V = max(len(self.vocab), 1)

        kl_per_state = []
        for state in self.vocab:
            # Current P(· | state)
            counts_p = self.transitions.get(state, {})
            denom_p = sum(counts_p.values()) + (alpha * V)

            # Baseline Q(· | state)
            counts_q = baseline.get(state, {})
            denom_q = sum(counts_q.values()) + (alpha * V)

            kl_state = 0.0
            for cand in self.vocab:
                p_val = (counts_p.get(cand, 0.0) + alpha) / denom_p
                q_val = (counts_q.get(cand, 0.0) + alpha) / denom_q

                if p_val > 0 and q_val > 0:
                    kl_state += p_val * math.log(p_val / q_val)

            kl_per_state.append(max(0.0, kl_state))

        if reduction == "mean":
            return round(sum(kl_per_state) / V, 4)
        return round(max(kl_per_state) if kl_per_state else 0.0, 4)

    def check_drift(self) -> tuple[bool, float, str]:
        """
        Check whether the Markov model has experienced drift relative to baseline.

        Returns:
            (is_drifted: bool, kl_divergence: float, notice: str)
        """
        threshold = float(get_settings().predictor.get("feedback", {}).get("drift_kl_threshold", 0.15))
        kl_div = self.compute_kl_divergence()
        is_drifted = kl_div > threshold

        if is_drifted:
            notice = (
                f"NOTICE: Model drift detected! Rolling KL divergence ({kl_div:.4f}) "
                f"exceeds configured threshold ({threshold:.4f}). Consider retraining or registry rollback."
            )
        else:
            notice = f"Model within stability boundary (KL divergence: {kl_div:.4f} <= {threshold:.4f})."

        return is_drifted, kl_div, notice

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete model state."""
        return {
            "vocab": sorted(self.vocab),
            "transitions": {src: dict(dsts) for src, dsts in self.transitions.items()},
            "unigrams": dict(self.unigrams),
            "baseline_transitions": {src: dict(dsts) for src, dsts in self.baseline_transitions.items()},
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        """Restore exact model state."""
        self.vocab = set(data.get("vocab", _DEFAULT_CHAIN))
        self.transitions = defaultdict(dict, {src: dict(dsts) for src, dsts in data.get("transitions", {}).items()})
        self.unigrams = defaultdict(float, {k: float(v) for k, v in data.get("unigrams", {}).items()})
        self.baseline_transitions = defaultdict(
            dict, {src: dict(dsts) for src, dsts in data.get("baseline_transitions", {}).items()}
        )


class ModelRegistry:
    """
    Versioned model registry for Markov models with atomic snapshot saving and exact rollback.
    """

    def __init__(self, model_dir: str | Path | None = None) -> None:
        if model_dir is None:
            model_dir = get_settings().predictor.get("model_dir", "data/models/markov")
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.model_dir / "manifest.json"
        self._ensure_manifest()

    def _ensure_manifest(self) -> None:
        if not self.manifest_path.exists():
            manifest_data = {"current_version": 0, "versions": []}
            self.manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    def _read_manifest(self) -> dict[str, Any]:
        self._ensure_manifest()
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def save_version(self, predictor: MarkovPredictor, description: str = "") -> int:
        """
        Save a new version of the MarkovPredictor.

        Args:
            predictor: Active MarkovPredictor instance.
            description: Change summary.

        Returns:
            The newly created version number.
        """
        manifest = self._read_manifest()
        next_ver = int(manifest.get("current_version", 0)) + 1

        is_drifted, kl_val, _ = predictor.check_drift()
        model_payload = {
            "version": next_ver,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": description or f"Version {next_ver} update",
            "kl_divergence": kl_val,
            "is_drifted": is_drifted,
            "state": predictor.to_dict(),
        }

        model_file = self.model_dir / f"v{next_ver}.json"
        model_file.write_text(json.dumps(model_payload, indent=2), encoding="utf-8")

        manifest["current_version"] = next_ver
        manifest["versions"].append(
            {
                "version": next_ver,
                "timestamp": model_payload["timestamp"],
                "description": model_payload["description"],
                "kl_divergence": kl_val,
                "file": f"v{next_ver}.json",
            }
        )
        self._write_manifest(manifest)
        logger.info("Saved Markov model version %d to %s", next_ver, model_file)
        return next_ver

    def rollback(self, predictor: MarkovPredictor, version: int | None = None) -> int:
        """
        Roll back the predictor to a previous version.

        Args:
            predictor: The predictor instance whose state will be overwritten.
            version: Target version number (defaults to current_version - 1).

        Returns:
            The version rolled back to.
        """
        manifest = self._read_manifest()
        curr_ver = int(manifest.get("current_version", 0))

        if version is None:
            target_ver = curr_ver - 1
        else:
            target_ver = version

        if target_ver < 1:
            raise ValueError(f"Cannot rollback to version {target_ver}. Minimum version is 1.")

        model_file = self.model_dir / f"v{target_ver}.json"
        if not model_file.exists():
            raise FileNotFoundError(f"Model version file {model_file} not found in registry.")

        payload = json.loads(model_file.read_text(encoding="utf-8"))
        predictor.from_dict(payload["state"])

        manifest["current_version"] = target_ver
        manifest["versions"].append(
            {
                "version": target_ver,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": f"Rollback to v{target_ver} from v{curr_ver}",
                "kl_divergence": payload.get("kl_divergence", 0.0),
                "file": f"v{target_ver}.json",
                "action": "rollback",
            }
        )
        self._write_manifest(manifest)
        logger.info("Rolled back Markov predictor to version %d", target_ver)
        return target_ver

    def get_current_version(self) -> int:
        """Return the current active model version."""
        return int(self._read_manifest().get("current_version", 0))

    def list_versions(self) -> list[dict[str, Any]]:
        """List all registered version records."""
        return self._read_manifest().get("versions", [])
