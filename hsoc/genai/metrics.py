"""
Hallucination and Grounding Metrics for GenAI Reports.

Calculates key verification metrics:
  1. Citation Precision:
     Fraction of cited chunk IDs that actually exist in the retrieved context.
     Precision = valid_citations / total_citations

  2. Unsupported-Claim Rate:
     Fraction of remediation recommendations or assertions that lack valid
     source grounding.
     Unsupported-Claim Rate = unsupported_claims / total_claims

  3. Invalid-ID Rate:
     Fraction of MITRE ATT&CK techniques or CVE identifiers that do not exist
     or do not follow valid taxonomy patterns.
     Invalid-ID Rate = invalid_ids / total_ids
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from hsoc.schema import Report

# Standard MITRE ATT&CK technique pattern (e.g. T1110, T1059.001) or CWE identifier
ATTACK_TECHNIQUE_REGEX = re.compile(r"^(T\d{4}(?:\.\d{3})?|CWE-\d+)$")
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class HallucinationMetrics:
    """Quantitative hallucination and citation fidelity metrics."""

    citation_precision: float
    unsupported_claim_rate: float
    invalid_id_rate: float
    total_citations: int
    valid_citations: int
    total_claims: int
    unsupported_claims: int
    total_ids: int
    invalid_ids: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_citation_precision(
    citations: list[str],
    retrieved_chunk_ids: set[str],
) -> tuple[float, int, int]:
    """
    Compute citation precision against retrieved chunk context.

    Returns:
        (precision, valid_count, total_count)
    """
    cleaned_citations = [c.strip() for c in citations if c and c.strip()]
    total = len(cleaned_citations)
    if total == 0:
        return 1.0, 0, 0

    valid = sum(1 for c in cleaned_citations if c in retrieved_chunk_ids)
    precision = round(valid / total, 4)
    return precision, valid, total


def compute_unsupported_claim_rate(
    remediation_steps: list[dict[str, Any]],
    retrieved_chunk_ids: set[str],
) -> tuple[float, int, int]:
    """
    Compute fraction of remediation claims lacking valid source grounding.

    Returns:
        (unsupported_rate, unsupported_count, total_count)
    """
    total = len(remediation_steps)
    if total == 0:
        return 0.0, 0, 0

    unsupported = 0
    for step in remediation_steps:
        source = step.get("source", "").strip() if isinstance(step, dict) else getattr(step, "source", "").strip()
        if not source or (retrieved_chunk_ids and source not in retrieved_chunk_ids):
            unsupported += 1

    rate = round(unsupported / total, 4)
    return rate, unsupported, total


def compute_invalid_id_rate(
    technique_ids: list[str],
    valid_catalog_ids: set[str] | None = None,
) -> tuple[float, int, int]:
    """
    Compute fraction of ATT&CK or CVE identifiers that are malformed or invalid.

    Returns:
        (invalid_rate, invalid_count, total_count)
    """
    total = len(technique_ids)
    if total == 0:
        return 0.0, 0, 0

    invalid = 0
    for tid in technique_ids:
        tid_str = str(tid).strip()
        if not ATTACK_TECHNIQUE_REGEX.match(tid_str) and not CVE_REGEX.match(tid_str):
            invalid += 1
        elif valid_catalog_ids is not None and len(valid_catalog_ids) > 0:
            if tid_str not in valid_catalog_ids:
                invalid += 1

    rate = round(invalid / total, 4)
    return rate, invalid, total


def evaluate_report_hallucinations(
    report: Report | dict[str, Any],
    retrieved_chunk_ids: set[str],
    valid_catalog_ids: set[str] | None = None,
) -> HallucinationMetrics:
    """
    Evaluate all hallucination metrics for a single report.

    Args:
        report: Report model or dictionary.
        retrieved_chunk_ids: Ground truth set of chunk IDs in retrieval context.
        valid_catalog_ids: Optional set of known valid ATT&CK IDs.

    Returns:
        HallucinationMetrics dataclass.
    """
    report_dict = report.model_dump(mode="json") if isinstance(report, Report) else report

    # 1. Citations
    citations: list[str] = []
    remediation = report_dict.get("remediation", [])
    for step in remediation:
        src = step.get("source", "") if isinstance(step, dict) else getattr(step, "source", "")
        if src:
            citations.append(src)

    citation_prec, valid_cites, total_cites = compute_citation_precision(
        citations=citations,
        retrieved_chunk_ids=retrieved_chunk_ids,
    )

    # 2. Unsupported claims
    unsupported_rate, unsupp_count, total_claims = compute_unsupported_claim_rate(
        remediation_steps=remediation,
        retrieved_chunk_ids=retrieved_chunk_ids,
    )

    # 3. Invalid IDs
    proposed_ids: list[str] = []
    for mapping in report_dict.get("attack_mapping", []):
        tid = mapping.get("technique_id") if isinstance(mapping, dict) else getattr(mapping, "technique_id", "")
        if tid:
            proposed_ids.append(tid)

    for pred in report_dict.get("predicted_next", []):
        tid = pred.get("technique") if isinstance(pred, dict) else getattr(pred, "technique", "")
        if tid:
            proposed_ids.append(tid)

    invalid_rate, inv_count, total_ids = compute_invalid_id_rate(
        technique_ids=proposed_ids,
        valid_catalog_ids=valid_catalog_ids,
    )

    return HallucinationMetrics(
        citation_precision=citation_prec,
        unsupported_claim_rate=unsupported_rate,
        invalid_id_rate=invalid_rate,
        total_citations=total_cites,
        valid_citations=valid_cites,
        total_claims=total_claims,
        unsupported_claims=unsupp_count,
        total_ids=total_ids,
        invalid_ids=inv_count,
    )
