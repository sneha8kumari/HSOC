"""
ForecasterAgent: Calls the Markov engine as a tool and narrates attack-chain trajectories.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from hsoc.config import get_settings
from hsoc.genai.agents.context import IncidentContext
from hsoc.genai.agents.tools import ToolDispatcher
from hsoc.schema import PredictedTactic

logger = logging.getLogger(__name__)


class ForecasterAgent:
    """Tool-calls Markov transition model and synthesizes kill-chain narrative."""

    def __init__(self, name: str = "ForecasterAgent") -> None:
        self.name = name

    def execute(self, context: IncidentContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        incident = context.incident

        current_tactic = incident.domain.value if incident.domain.value != "unknown" else (
            incident.tactics[-1] if incident.tactics else "reconnaissance"
        )
        top_n = int(get_settings().predictor.get("top_n", 3))

        # 1. Call Markov engine as a TOOL
        t_start = time.perf_counter()
        tool_res = ToolDispatcher.call("predict_markov_trajectory", current_tactic=current_tactic, top_n=top_n)
        t_markov = round((time.perf_counter() - t_start) * 1000, 2)

        tool_calls = [{
            "tool": "predict_markov_trajectory",
            "args": {"current_tactic": current_tactic, "top_n": top_n},
            "latency_ms": t_markov,
            "predictions_count": len(tool_res.get("predictions", [])),
        }]

        raw_preds = tool_res.get("predictions", [])
        predicted_items = [
            PredictedTactic(tactic=p["tactic"], probability=p["probability"])
            for p in raw_preds
        ]

        # 2. Formulate kill-chain trajectory narrative
        tech_history = " -> ".join(incident.techniques) if incident.techniques else "current stage"
        tactic_history = " -> ".join(incident.tactics) if incident.tactics else current_tactic

        pred_clauses = [f"{p['tactic']} (p={p['probability']:.2f})" for p in raw_preds]
        pred_str = ", followed by ".join(pred_clauses) if pred_clauses else "no clear progression"

        narration = (
            f"Given observed sequence [{tech_history}] across tactics [{tactic_history}], "
            f"the Markov chain predicts the next attacker progression to be {pred_str}."
        )

        forecast_data = {
            "current_tactic": current_tactic,
            "predictions": raw_preds,
            "predicted_objects": predicted_items,
            "narration": narration,
            "out_of_order": incident.out_of_order_stage,
        }

        context.forecast_data = forecast_data
        latency_ms = (time.perf_counter() - t0) * 1000

        context.add_trace(
            agent_name=self.name,
            state="FORECAST",
            inputs={"current_tactic": current_tactic, "techniques": incident.techniques},
            tool_calls=tool_calls,
            output_message=narration,
            latency_ms=latency_ms,
            tokens=85,
        )

        context.send_message(
            sender=self.name,
            recipient="RemediationAgent",
            message_type="FORECAST_COMPLETE",
            payload=forecast_data,
        )

        return forecast_data
