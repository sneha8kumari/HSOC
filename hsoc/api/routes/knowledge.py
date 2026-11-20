"""
Knowledge Base API router for chunk lookups and provenance audits.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()

_KB_CHUNKS_PATH = Path(__file__).parent.parent.parent.parent / "data" / "kb" / "chunks.json"


@lru_cache(maxsize=1)
def _load_chunks_cache() -> dict[str, dict[str, Any]]:
    if not _KB_CHUNKS_PATH.exists():
        return {}
    try:
        data = json.loads(_KB_CHUNKS_PATH.read_text(encoding="utf-8"))
        return {item["chunk_id"]: item for item in data if "chunk_id" in item}
    except Exception:
        return {}


@router.get("/chunks/{chunk_id}", tags=["knowledge"])
def get_knowledge_chunk(chunk_id: str) -> dict[str, Any]:
    """Retrieve full knowledge chunk text, source, url, and provenance for clickable citations."""
    chunks = _load_chunks_cache()
    if chunk_id not in chunks:
        # Check case-insensitive match
        matched = next((c for cid, c in chunks.items() if cid.lower() == chunk_id.lower()), None)
        if not matched:
            raise HTTPException(status_code=404, detail=f"Knowledge chunk '{chunk_id}' not found.")
        return matched

    return chunks[chunk_id]


@router.get("/search", tags=["knowledge"])
def search_knowledge(q: str = Query(..., min_length=2)) -> list[dict[str, Any]]:
    """Search knowledge base chunks by query string."""
    chunks = _load_chunks_cache()
    query_lower = q.lower()
    results = []

    for chunk in chunks.values():
        title = chunk.get("title", "").lower()
        text = chunk.get("text", "").lower()
        techniques = [t.lower() for t in chunk.get("techniques", [])]

        if query_lower in title or query_lower in text or any(query_lower in t for t in techniques):
            results.append(
                {
                    "chunk_id": chunk.get("chunk_id"),
                    "title": chunk.get("title"),
                    "source": chunk.get("source"),
                    "url": chunk.get("url"),
                    "domain_tag": chunk.get("domain_tag"),
                    "techniques": chunk.get("techniques", []),
                    "snippet": chunk.get("text", "")[:280] + "...",
                }
            )
            if len(results) >= 20:
                break

    return results
