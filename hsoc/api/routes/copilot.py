"""
Incident Copilot, What-If Simulation, Counterfactuals & Ticket Export Router.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from hsoc.db import IncidentORM, get_db
from hsoc.genai.copilot import get_copilot_engine

router = APIRouter()


class ChatRequest(BaseModel):
    query: str | None = Field(default=None, description="Natural-language question about the incident")
    question: str | None = Field(default=None, description="Alternative field name for question")
    stream: bool = Field(default=True, description="Whether to stream tokens via SSE")

    @property
    def effective_query(self) -> str:
        return (self.query or self.question or "").strip()


class WhatIfRequest(BaseModel):
    forced_state: str = Field(
        description="Hypothetical attacker progression (e.g. 'attacker obtains sudo', 'domain admin', 'lateral movement')"
    )


@router.post("/{incident_id}/copilot/chat", tags=["copilot"])
async def chat_with_copilot(
    incident_id: str,
    req: ChatRequest,
    db: Session = Depends(get_db),
) -> Any:
    """
    Copilot Q&A endpoint: Natural-language Q&A over an incident.
    Answers strictly cite alert IDs and event IDs.
    Supports real-time SSE token streaming when stream=True.
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    engine = get_copilot_engine()
    query_text = req.effective_query or "Summarize this incident and key findings"

    if req.stream:
        return StreamingResponse(
            engine.stream_answer(query=query_text, incident_id=incident_id, db=db),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Non-streaming JSON response
    ans = engine.answer_question(query=query_text, incident_id=incident_id, db=db)
    return ans.to_dict()


@router.post("/{incident_id}/copilot/what-if", tags=["copilot"])
def what_if_analysis(
    incident_id: str,
    req: WhatIfRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    What-If Engine: User forces a state (e.g. 'attacker obtains domain admin');
    the Markov chain re-forecasts and the LLM explains the changed risk and recommended containment.
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    engine = get_copilot_engine()
    return engine.run_what_if(incident_id=incident_id, forced_state=req.forced_state, db=db)


@router.get("/{incident_id}/copilot/counterfactual", tags=["copilot"])
def counterfactual_analysis(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Counterfactual Explanation: Computes deterministic sensitivity boundaries
    ('severity would drop from High to Medium if asset criticality were <= 3').
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    engine = get_copilot_engine()
    return engine.run_counterfactual(incident_id=incident_id, db=db)


@router.get("/{incident_id}/copilot/export/{format_type}", tags=["copilot"])
def export_incident_report(
    incident_id: str,
    format_type: str,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Auto-generated formats:
      - executive_summary
      - technical_report
      - jira
      - servicenow
    """
    inc = db.query(IncidentORM).filter(IncidentORM.incident_id == incident_id).first()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    valid_formats = {"executive_summary", "technical_report", "jira", "servicenow"}
    if format_type.lower() not in valid_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid export format '{format_type}'. Must be one of: {sorted(list(valid_formats))}",
        )

    engine = get_copilot_engine()
    return engine.generate_export(incident_id=incident_id, format_type=format_type.lower(), db=db)
