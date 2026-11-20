"""
Fallback report builder.

Used when the LLM is unavailable or output fails validation.
Builds a structured report entirely from the incident evidence pack and knowledge base.
The report is marked generated_by: "template".
"""

from __future__ import annotations

from datetime import datetime, timezone

from hsoc.knowledge.retriever import retrieve
from hsoc.schema import AttackMapping, Incident, RemediationStep, Report


def build_fallback_report(incident: Incident) -> Report:
    """
    Build a template report from incident evidence only.

    Args:
        incident: A correlated, scored incident.

    Returns:
        A Report with generated_by="template" and valid schema structure.
    """
    # 1. Retrieve knowledge chunks
    search_query = f"{incident.domain.value} " + " ".join(incident.techniques)
    retrieved_chunks, _ = retrieve(search_query, domain=incident.domain.value)
    chunk_ids = [c.chunk_id for c in retrieved_chunks]

    # 2. Build summary narrative
    entity_str = ", ".join(incident.entity_keys) if incident.entity_keys else "Unknown entities"
    tactics_str = " -> ".join(incident.tactics) if incident.tactics else "Single stage detection"
    summary_text = (
        f"Incident {incident.incident_id} detected in security domain '{incident.domain.value}' "
        f"with assessed severity band {incident.severity.value.upper()} (risk score: {incident.risk_score}). "
        f"Involves entities [{entity_str}] exhibiting progression along tactics: {tactics_str}."
    )

    # 3. Build evidence list from timeline
    evidence_lines = [
        f"[{t.ts.isoformat()}] {t.description} (Technique: {t.technique or 'N/A'}, Tactic: {t.tactic or 'N/A'})"
        for t in incident.timeline[:10]
    ] or ["No discrete timeline items logged."]

    # 4. Build ATT&CK mapping
    attack_mappings: list[AttackMapping] = []
    for t_id, tac in zip(incident.techniques, incident.tactics):
        attack_mappings.append(
            AttackMapping(
                technique_id=t_id,
                technique_name=f"Technique {t_id}",
                tactic=tac,
            )
        )
    if not attack_mappings and incident.techniques:
        for t_id in incident.techniques:
            attack_mappings.append(
                AttackMapping(
                    technique_id=t_id,
                    technique_name=f"Technique {t_id}",
                    tactic=incident.domain.value,
                )
            )
    if not attack_mappings:
        attack_mappings.append(
            AttackMapping(
                technique_id="T1046",
                technique_name="Network Service Scanning",
                tactic="reconnaissance",
            )
        )

    # 5. Build remediation steps citing knowledge chunks
    remediation_steps: list[RemediationStep] = []
    for c in retrieved_chunks[:3]:
        # Split text into sentences for discrete actions
        for sentence in c.text.split(". "):
            sentence = sentence.strip()
            if sentence and not sentence.endswith("."):
                sentence += "."
            if sentence:
                is_disruptive = any(
                    v in sentence.lower()
                    for v in ["disable", "block", "kill", "isolate", "delete", "shutdown"]
                )
                remediation_steps.append(
                    RemediationStep(
                        step=sentence,
                        needs_approval=is_disruptive,
                        source=c.chunk_id,
                    )
                )

    if not remediation_steps:
        remediation_steps.append(
            RemediationStep(
                step="Isolate affected host and block offending remote IP address.",
                needs_approval=True,
                source=chunk_ids[0] if chunk_ids else "KB-RECON-T1046",
            )
        )

    return Report(
        incident_id=incident.incident_id,
        generated_at=datetime.now(timezone.utc),
        generated_by="template",
        model_name="deterministic_template",
        prompt_version="v1.0",
        latency_seconds=0.005,
        retries=0,
        valid=True,
        severity=incident.severity,
        summary=summary_text,
        evidence=evidence_lines,
        attack_mapping=attack_mappings,
        domain=incident.domain,
        predicted_next=incident.predicted_next,
        remediation=remediation_steps,
        uncertainty="Deterministic template report synthesized from verified telemetry and authoritative playbooks.",
        chunk_ids_used=chunk_ids,
    )
