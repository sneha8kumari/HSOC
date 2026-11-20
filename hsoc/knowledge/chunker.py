"""
Document chunker for the knowledge index.

Produces stable, deterministic chunk IDs and attaches comprehensive
provenance records to every chunk.

Strategies:
  - MITRE ATT&CK techniques: one chunk per technique object.
  - Standards, playbooks & consulting frameworks: semantic / paragraph chunking (~400 tokens, 60-token overlap).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any


def _compute_stable_chunk_id(source: str, title: str, text: str, index: int) -> str:
    """Generate a deterministic, reproducible chunk ID."""
    prefix = re.sub(r"[^A-Za-z0-9_-]", "-", source.split()[0]).strip("-").upper()
    content_hash = hashlib.sha256(f"{source}|{title}|{text}|{index}".encode("utf-8")).hexdigest()[:12]
    return f"KB-{prefix}-{content_hash}"


def _estimate_tokens(text: str) -> int:
    """Rough token estimation (words * 1.3)."""
    return int(len(text.split()) * 1.3)


def chunk(document: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Chunk a document into index-ready pieces with stable IDs and provenance.

    Args:
        document: Dict with keys: ``source``, ``title``, ``url``, ``domain_tag``,
                  ``version``, ``text``, and optional ``source_type``, ``tactics``,
                  ``techniques``, ``platforms``.

    Returns:
        List of chunk dicts, each with a stable ``chunk_id`` and full ``provenance``.
    """
    source = document.get("source", "UNKNOWN")
    source_type = document.get("source_type", "standard")
    title = document.get("title", "Untitled Document")
    url = document.get("url", "")
    version = str(document.get("version", "1.0"))
    domain_tag = document.get("domain_tag", "general")
    tactics = [t.lower() for t in document.get("tactics", [])]
    techniques = document.get("techniques", [])
    platforms = [p.lower() for p in document.get("platforms", [])]
    raw_text = document.get("text", "").strip()

    if not raw_text:
        return []

    chunks_out: list[dict[str, Any]] = []

    # Strategy 1: MITRE ATT&CK technique object -> 1 atomic chunk
    if source_type == "stix" or "MITRE ATT&CK" in source:
        chunk_id = _compute_stable_chunk_id(source, title, raw_text, 0)
        chunk_checksum = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        provenance = {
            "source": source,
            "source_type": source_type,
            "title": title,
            "url": url,
            "version": version,
            "domain_tag": domain_tag,
            "tactics": tactics,
            "techniques": techniques,
            "platforms": platforms,
            "chunk_index": 0,
            "total_chunks": 1,
            "checksum": chunk_checksum,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        chunks_out.append({
            "chunk_id": chunk_id,
            "title": title,
            "text": raw_text,
            "domain_tag": domain_tag,
            "tactics": tactics,
            "techniques": techniques,
            "platforms": platforms,
            "source": source,
            "url": url,
            "provenance": provenance,
        })
        return chunks_out

    # Strategy 2: Standards, playbooks & frameworks: chunk by paragraphs or sliding window (~400 words)
    paragraphs = [p.strip() for p in raw_text.split("\n\n") if p.strip()]
    raw_chunks: list[str] = []
    current_chunk: list[str] = []
    current_len = 0

    target_tokens = 350
    for para in paragraphs:
        p_len = len(para.split())
        if current_len + p_len > target_tokens and current_chunk:
            raw_chunks.append("\n\n".join(current_chunk))
            # 60 token overlap: keep last paragraph if short
            if len(current_chunk[-1].split()) <= 60:
                current_chunk = [current_chunk[-1], para]
                current_len = len(current_chunk[0].split()) + p_len
            else:
                current_chunk = [para]
                current_len = p_len
        else:
            current_chunk.append(para)
            current_len += p_len

    if current_chunk:
        raw_chunks.append("\n\n".join(current_chunk))

    if not raw_chunks:
        raw_chunks = [raw_text]

    total_chunks = len(raw_chunks)
    for idx, c_text in enumerate(raw_chunks):
        chunk_id = _compute_stable_chunk_id(source, title, c_text, idx)
        checksum = hashlib.sha256(c_text.encode("utf-8")).hexdigest()
        chunk_title = f"{title} (Part {idx + 1}/{total_chunks})" if total_chunks > 1 else title
        provenance = {
            "source": source,
            "source_type": source_type,
            "title": chunk_title,
            "url": url,
            "version": version,
            "domain_tag": domain_tag,
            "tactics": tactics,
            "techniques": techniques,
            "platforms": platforms,
            "chunk_index": idx,
            "total_chunks": total_chunks,
            "checksum": checksum,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        chunks_out.append({
            "chunk_id": chunk_id,
            "title": chunk_title,
            "text": c_text,
            "domain_tag": domain_tag,
            "tactics": tactics,
            "techniques": techniques,
            "platforms": platforms,
            "source": source,
            "url": url,
            "provenance": provenance,
        })

    return chunks_out
