"""
Report validator: enforces JSON schema and semantic safety rules.

Checks:
  1. JSON is valid against report_schema.json.
  2. Every source field references a chunk_id from the retrieval set.
  3. Force-sets needs_approval=true for disruptive remediation verbs.

Returns (valid: bool, errors: list[str]).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from hsoc.genai.action_guardrail import get_action_guardrail

_SCHEMA_PATH = Path(__file__).parent / "report_schema.json"


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate(
    report_json: dict,
    retrieved_chunk_ids: set[str],
) -> tuple[bool, list[str]]:
    """
    Validate a raw LLM JSON output against schema and safety guardrails.

    Args:
        report_json: Parsed JSON dict from the LLM.
        retrieved_chunk_ids: Set of chunk IDs returned by the retriever.

    Returns:
        (valid, errors) — errors is empty on success.
    """
    errors: list[str] = []
    schema = _load_schema()

    # 1. JSON Schema validation
    core_keys = {
        "incident_id",
        "severity",
        "summary",
        "evidence",
        "attack_mapping",
        "domain",
        "predicted_next",
        "remediation",
        "uncertainty",
    }
    payload_to_validate = {k: v for k, v in report_json.items() if k in core_keys}

    try:
        jsonschema.validate(instance=payload_to_validate, schema=schema)
    except jsonschema.ValidationError as exc:
        errors.append(f"JSON schema validation failed: {exc.message}")

    # 2. Citation check for remediation steps
    remediation_steps = report_json.get("remediation", [])
    for idx, step in enumerate(remediation_steps):
        if isinstance(step, dict):
            source = step.get("source", "")
            if retrieved_chunk_ids and source and source not in retrieved_chunk_ids:
                errors.append(
                    f"Remediation step {idx+1} cites unauthorized chunk '{source}' not in retrieval context."
                )

            # 3. Force-set needs_approval for disruptive verbs
            step_text = str(step.get("step", ""))
            if get_action_guardrail().is_disruptive(step_text):
                step["needs_approval"] = True

    return (len(errors) == 0, errors)
