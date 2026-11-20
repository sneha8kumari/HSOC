"""
Knowledge index builder.

Fetches all sources (MITRE ATT&CK STIX, OWASP Top 10/ASVS, NIST 800-61,
CIS Controls, Playbooks, and Big-4 Consulting Methodologies), chunks them,
embeds with sentence-transformers and builds:
  - data/kb/chunks.json          (all chunks with full provenance)
  - data/kb/metadata.jsonl       (one JSON line per chunk)
  - data/kb/faiss_index.bin      (faiss.IndexFlatIP on normalized vectors)
  - data/kb/embeddings.npy       (raw normalized numpy vectors)
  - data/kb/bm25_index.pkl       (serialized BM25Okapi state)
  - data/kb/manifest.json        (corpus version + checksums)
  - data/kb/technique_tactic.json (technique_id -> tactics map)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import pickle
import re
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

from hsoc.config import get_settings
from hsoc.knowledge.chunker import chunk
from hsoc.knowledge.sources.cis_controls import load_cis_documents
from hsoc.knowledge.sources.consulting_frameworks import load_consulting_documents
from hsoc.knowledge.sources.mitre_attack import load_attack_stix_documents
from hsoc.knowledge.sources.nist_800_61 import load_nist_documents
from hsoc.knowledge.sources.owasp import load_owasp_documents
from hsoc.knowledge.sources.playbooks import load_playbook_documents

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> list[str]:
    """Simple alphanumeric tokenizer for BM25."""
    return re.findall(r"\w+", text.lower())


def fetch_all_documents() -> list[dict[str, Any]]:
    """Gather all raw documents from source ingestors."""
    docs = []
    docs.extend(load_attack_stix_documents())
    docs.extend(load_owasp_documents())
    docs.extend(load_nist_documents())
    docs.extend(load_cis_documents())
    docs.extend(load_playbook_documents())
    docs.extend(load_consulting_documents())
    logger.info("Loaded %d documents from 6 knowledge sources", len(docs))
    return docs


def build_index(kb_dir: str = "data/kb") -> dict[str, Any]:
    """
    Chunk all documents, build FAISS and BM25 indices, and write manifest.

    Args:
        kb_dir: Target directory to store index artifacts.

    Returns:
        Summary dict of built corpus metrics.
    """
    target_dir = Path(kb_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Gather documents and chunk
    documents = fetch_all_documents()
    all_chunks: list[dict[str, Any]] = []
    technique_tactic_map: dict[str, list[str]] = {}

    for doc in documents:
        doc_chunks = chunk(doc)
        all_chunks.extend(doc_chunks)

        # Update technique -> tactics mapping
        for tech in doc.get("techniques", []):
            if tech not in technique_tactic_map:
                technique_tactic_map[tech] = []
            for tac in doc.get("tactics", []):
                if tac not in technique_tactic_map[tech]:
                    technique_tactic_map[tech].append(tac)

    logger.info("Generated %d chunks with stable IDs and provenance", len(all_chunks))

    # 2. Write chunks.json and metadata.jsonl
    chunks_path = target_dir / "chunks.json"
    chunks_path.write_text(json.dumps(all_chunks, indent=2), encoding="utf-8")

    jsonl_path = target_dir / "metadata.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for chk in all_chunks:
            f.write(json.dumps(chk) + "\n")

    # Write technique_tactic.json
    tt_path = target_dir / "technique_tactic.json"
    tt_path.write_text(json.dumps(technique_tactic_map, indent=2), encoding="utf-8")

    # 3. Dense embeddings with SentenceTransformer
    model_name = get_settings().rag.get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2")
    logger.info("Generating dense embeddings using model: %s", model_name)
    model = SentenceTransformer(model_name)

    texts_to_embed = [
        f"{c['title']}\n{c['text']}\nTechniques: {' '.join(c.get('techniques', []))}\nTactics: {' '.join(c.get('tactics', []))}"
        for c in all_chunks
    ]
    embeddings = model.encode(texts_to_embed, batch_size=32, show_progress_bar=False, normalize_embeddings=True)
    embeddings = np.ascontiguousarray(embeddings, dtype=np.float32)

    # Save raw embeddings
    npy_path = target_dir / "embeddings.npy"
    np.save(str(npy_path), embeddings)

    # Build FAISS IndexFlatIP (Inner Product on normalized vectors = Cosine Similarity)
    dim = embeddings.shape[1]
    faiss_index = faiss.IndexFlatIP(dim)
    faiss_index.add(embeddings)

    faiss_path = target_dir / "faiss_index.bin"
    faiss.write_index(faiss_index, str(faiss_path))
    logger.info("FAISS index built and saved to %s (dim=%d, total=%d)", faiss_path, dim, faiss_index.ntotal)

    # 4. Sparse BM25 Index
    tokenized_corpus = [_tokenize(t) for t in texts_to_embed]
    bm25 = BM25Okapi(tokenized_corpus)

    bm25_data = {
        "bm25": bm25,
        "tokenized_corpus": tokenized_corpus,
        "chunk_ids": [c["chunk_id"] for c in all_chunks],
    }
    bm25_path = target_dir / "bm25_index.pkl"
    with open(bm25_path, "wb") as f:
        pickle.dump(bm25_data, f)
    logger.info("BM25 index built and saved to %s", bm25_path)

    # 5. Build and write manifest.json
    manifest = {
        "version": "1.0.0",
        "total_chunks": len(all_chunks),
        "embedding_model": model_name,
        "embedding_dim": dim,
        "sources": sorted(list({c["source"] for c in all_chunks})),
        "platforms": sorted(list({p for c in all_chunks for p in c.get("platforms", [])})),
        "tactics": sorted(list({t for c in all_chunks for t in c.get("tactics", [])})),
        "checksums": {
            "chunks_json": hashlib.sha256(chunks_path.read_bytes()).hexdigest(),
            "faiss_index": hashlib.sha256(faiss_path.read_bytes()).hexdigest(),
            "bm25_index": hashlib.sha256(bm25_path.read_bytes()).hexdigest(),
        },
    }
    manifest_path = target_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Knowledge index build complete. Manifest: %s", manifest_path)

    return manifest


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(description="Build H-SOC knowledge base index")
    ap.add_argument("--kb-dir", default="data/kb", help="Path to knowledge directory")
    args = ap.parse_args()
    res = build_index(kb_dir=args.kb_dir)
    print("Build summary:")
    print(json.dumps(res, indent=2))
