"""
RAG hybrid retriever for H-SOC.

Combines:
  1. Dense vector search via FAISS (IndexFlatIP on sentence-transformer embeddings).
  2. Sparse keyword search via BM25 (rank-bm25).
  3. Reciprocal Rank Fusion (RRF) combining dense and sparse candidate rankings.
  4. Cross-encoder reranking (ms-marco-MiniLM-L-6-v2).
  5. Metadata filtering by tactic, technique, and platform.
  6. Markov-aware proactive retrieval: retrieves mitigations for the current attack stage
     PLUS mitigations for the top-3 predicted next tactics from the Markov model.
"""

from __future__ import annotations

import json
import logging
import pickle
import re
from pathlib import Path
from typing import Any

try:
    import faiss
except Exception:
    faiss = None
import numpy as np

from hsoc.config import get_settings
from hsoc.investigate.predictor import MarkovPredictor

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> list[str]:
    """Tokenize text for BM25 matching."""
    return re.findall(r"\w+", text.lower())


class RetrievalResult:
    """Single retrieved knowledge chunk with score metadata and provenance."""

    def __init__(
        self,
        chunk_id: str,
        source: str,
        title: str,
        url: str,
        domain_tag: str,
        text: str,
        embed_score: float = 0.0,
        bm25_score: float = 0.0,
        rrf_score: float = 0.0,
        rerank_score: float | None = None,
        provenance: dict[str, Any] | None = None,
        stage: str = "current",  # "current" or "predicted"
        predicted_tactic: str | None = None,
        predicted_prob: float | None = None,
        techniques: list[str] | None = None,
        tactics: list[str] | None = None,
        platforms: list[str] | None = None,
    ) -> None:
        self.chunk_id = chunk_id
        self.source = source
        self.title = title
        self.url = url
        self.domain_tag = domain_tag
        self.text = text
        self.embed_score = embed_score
        self.bm25_score = bm25_score
        self.rrf_score = rrf_score
        self.rerank_score = rerank_score if rerank_score is not None else embed_score
        self.provenance = provenance or {}
        self.stage = stage
        self.predicted_tactic = predicted_tactic
        self.predicted_prob = predicted_prob
        self.techniques = techniques or []
        self.tactics = tactics or []
        self.platforms = platforms or []

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "chunk_id": self.chunk_id,
            "source": self.source,
            "title": self.title,
            "url": self.url,
            "domain_tag": self.domain_tag,
            "text": self.text,
            "embed_score": round(self.embed_score, 4),
            "bm25_score": round(self.bm25_score, 4),
            "rrf_score": round(self.rrf_score, 6),
            "rerank_score": round(self.rerank_score, 4),
            "stage": self.stage,
            "predicted_tactic": self.predicted_tactic,
            "predicted_prob": self.predicted_prob,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "platforms": self.platforms,
            "provenance": self.provenance,
        }


class HybridRetriever:
    """
    Hybrid RAG Retriever orchestrating FAISS, BM25, RRF, Cross-Encoder,
    metadata filtering, and Markov-aware attack-chain expansion.
    """

    _instance: HybridRetriever | None = None

    def __init__(self, kb_dir: str | Path = "data/kb") -> None:
        self.kb_dir = Path(kb_dir)
        self.chunks: list[dict[str, Any]] = []
        self.chunk_by_id: dict[str, dict[str, Any]] = {}
        self.faiss_index: faiss.Index | None = None
        self.bm25: Any | None = None
        self._embed_model: Any | None = None
        self._cross_encoder: Any | None = None
        self._load_indices()

    @classmethod
    def get_instance(cls, kb_dir: str | Path = "data/kb") -> HybridRetriever:
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls(kb_dir=kb_dir)
        return cls._instance

    def _load_indices(self) -> None:
        """Load pre-built chunks, FAISS index, and BM25 index from disk."""
        chunks_file = self.kb_dir / "chunks.json"
        if not chunks_file.exists():
            logger.warning("Knowledge chunks not found at %s. Running build_index...", chunks_file)
            from hsoc.knowledge.build_index import build_index
            build_index(kb_dir=str(self.kb_dir))

        if chunks_file.exists():
            self.chunks = json.loads(chunks_file.read_text(encoding="utf-8"))
            self.chunk_by_id = {c["chunk_id"]: c for c in self.chunks}
            logger.info("Loaded %d knowledge chunks into retriever memory", len(self.chunks))

        # FAISS Index
        faiss_file = self.kb_dir / "faiss_index.bin"
        if faiss_file.exists():
            self.faiss_index = faiss.read_index(str(faiss_file))
            logger.info("Loaded FAISS index with %d vectors", self.faiss_index.ntotal)

        # BM25 Index
        bm25_file = self.kb_dir / "bm25_index.pkl"
        if bm25_file.exists():
            with open(bm25_file, "rb") as f:
                bm25_data = pickle.load(f)
                self.bm25 = bm25_data["bm25"]
            logger.info("Loaded BM25 index")

    def _get_embed_model(self) -> Any:
        """Lazy load sentence-transformer embedding model."""
        if self._embed_model is None:
            from sentence_transformers import SentenceTransformer
            model_name = get_settings().rag.get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2")
            self._embed_model = SentenceTransformer(model_name)
        return self._embed_model

    def _get_cross_encoder(self) -> Any:
        """Lazy load cross-encoder reranker model."""
        if self._cross_encoder is None:
            from sentence_transformers import CrossEncoder
            model_name = get_settings().rag.get("cross_encoder_model", "cross-encoder/ms-marco-MiniLM-L-6-v2")
            self._cross_encoder = CrossEncoder(model_name)
        return self._cross_encoder

    def _passes_filters(self, chunk_item: dict[str, Any], filters: dict[str, Any] | None) -> bool:
        """Check whether a chunk satisfies tactic, technique, and platform metadata filters."""
        if not filters:
            return True

        # Tactic filter
        req_tactic = filters.get("tactic")
        if req_tactic:
            req_tactic_clean = req_tactic.lower().replace("-", "_").replace(" ", "_")
            chunk_tactics = [t.lower().replace("-", "_").replace(" ", "_") for t in chunk_item.get("tactics", [])]
            chunk_domain = chunk_item.get("domain_tag", "").lower().replace("-", "_").replace(" ", "_")
            if req_tactic_clean not in chunk_tactics and req_tactic_clean != chunk_domain:
                return False

        # Technique filter
        req_tech = filters.get("technique")
        if req_tech:
            req_tech_clean = req_tech.upper()
            chunk_techs = [t.upper() for t in chunk_item.get("techniques", [])]
            # Match base technique (e.g. T1110 matches T1110.001)
            tech_match = any(
                req_tech_clean == ct or ct.startswith(f"{req_tech_clean}.") or req_tech_clean.startswith(f"{ct}.")
                for ct in chunk_techs
            )
            if not tech_match:
                return False

        # Platform filter
        req_plat = filters.get("platform")
        if req_plat:
            req_plat_clean = req_plat.lower()
            chunk_plats = [p.lower() for p in chunk_item.get("platforms", [])]
            if chunk_plats and req_plat_clean not in chunk_plats:
                return False

        return True

    def search_dense(
        self,
        query: str,
        top_k: int = 20,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[float, dict[str, Any]]]:
        """Dense similarity retrieval using FAISS."""
        if not self.chunks or self.faiss_index is None:
            return []

        model = self._get_embed_model()
        q_emb = model.encode([query], normalize_embeddings=True)
        q_emb = np.ascontiguousarray(q_emb, dtype=np.float32)

        # Search extra candidates to allow post-filtering
        k_search = min(len(self.chunks), top_k * 3)
        scores, indices = self.faiss_index.search(q_emb, k_search)

        results: list[tuple[float, dict[str, Any]]] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.chunks):
                continue
            chunk_item = self.chunks[idx]
            if self._passes_filters(chunk_item, filters):
                results.append((float(score), chunk_item))
                if len(results) >= top_k:
                    break

        return results

    def search_bm25(
        self,
        query: str,
        top_k: int = 20,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[float, dict[str, Any]]]:
        """Sparse lexical retrieval using BM25Okapi."""
        if not self.chunks or self.bm25 is None:
            return []

        tokens = _tokenize(query)
        if not tokens:
            return []

        doc_scores = self.bm25.get_scores(tokens)
        sorted_indices = np.argsort(doc_scores)[::-1]

        results: list[tuple[float, dict[str, Any]]] = []
        for idx in sorted_indices:
            score = doc_scores[idx]
            if score <= 0.0:
                break
            chunk_item = self.chunks[idx]
            if self._passes_filters(chunk_item, filters):
                results.append((float(score), chunk_item))
                if len(results) >= top_k:
                    break

        return results

    def search_hybrid_rrf(
        self,
        query: str,
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
        rrf_k: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Reciprocal Rank Fusion (RRF) between dense FAISS and sparse BM25 candidates:
            RRF_score(d) = 1/(k + rank_dense(d)) + 1/(k + rank_bm25(d))
        """
        if rrf_k is None:
            rrf_k = int(get_settings().rag.get("rrf_k", 60))

        dense_top_k = int(get_settings().rag.get("top_k_dense", 20))
        bm25_top_k = int(get_settings().rag.get("top_k_bm25", 20))

        dense_hits = self.search_dense(query, top_k=dense_top_k, filters=filters)
        bm25_hits = self.search_bm25(query, top_k=bm25_top_k, filters=filters)

        rrf_scores: dict[str, float] = {}
        dense_score_map: dict[str, float] = {}
        bm25_score_map: dict[str, float] = {}
        chunk_map: dict[str, dict[str, Any]] = {}

        for rank, (score, chunk_item) in enumerate(dense_hits, start=1):
            cid = chunk_item["chunk_id"]
            chunk_map[cid] = chunk_item
            dense_score_map[cid] = score
            rrf_scores[cid] = rrf_scores.get(cid, 0.0) + (1.0 / (rrf_k + rank))

        for rank, (score, chunk_item) in enumerate(bm25_hits, start=1):
            cid = chunk_item["chunk_id"]
            chunk_map[cid] = chunk_item
            bm25_score_map[cid] = score
            rrf_scores[cid] = rrf_scores.get(cid, 0.0) + (1.0 / (rrf_k + rank))

        # Sort by fused RRF score descending
        fused_items = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]

        candidates = []
        for cid, rrf_score in fused_items:
            c_data = dict(chunk_map[cid])
            c_data["rrf_score"] = rrf_score
            c_data["embed_score"] = dense_score_map.get(cid, 0.0)
            c_data["bm25_score"] = bm25_score_map.get(cid, 0.0)
            candidates.append(c_data)

        return candidates

    def search_hybrid_rerank(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[RetrievalResult]:
        """
        Full hybrid pipeline: BM25 + FAISS -> RRF fusion -> Cross-Encoder reranking.
        """
        # Retrieve candidate pool via RRF
        candidate_k = max(top_k * 2, int(get_settings().rag.get("top_k_dense", 10)))
        candidates = self.search_hybrid_rrf(query, top_k=candidate_k, filters=filters)

        if not candidates:
            return []

        # Cross-encoder reranking
        ce = self._get_cross_encoder()
        pairs = [(query, f"{c['title']} - {c['text']}") for c in candidates]
        ce_scores = ce.predict(pairs)

        for c, score in zip(candidates, ce_scores):
            # Normalize logit score to approx 0-1 sigmoid for consistency
            norm_score = float(1.0 / (1.0 + np.exp(-score)))
            c["rerank_score"] = norm_score

        # Sort descending by cross-encoder rerank score
        candidates.sort(key=lambda x: x["rerank_score"], reverse=True)

        results: list[RetrievalResult] = []
        for c in candidates[:top_k]:
            results.append(
                RetrievalResult(
                    chunk_id=c["chunk_id"],
                    source=c["source"],
                    title=c["title"],
                    url=c["url"],
                    domain_tag=c["domain_tag"],
                    text=c["text"],
                    embed_score=c.get("embed_score", 0.0),
                    bm25_score=c.get("bm25_score", 0.0),
                    rrf_score=c.get("rrf_score", 0.0),
                    rerank_score=c.get("rerank_score"),
                    provenance=c.get("provenance"),
                    techniques=c.get("techniques"),
                    tactics=c.get("tactics"),
                    platforms=c.get("platforms"),
                )
            )

        return results

    def retrieve_markov_aware(
        self,
        current_tactic: str,
        current_techniques: list[str] | None = None,
        platform: str | None = None,
        top_k_current: int = 3,
        top_k_predicted: int = 2,
    ) -> list[RetrievalResult]:
        """
        Markov-Aware Retrieval:
          Queries remediations for the CURRENT attack technique/tactic,
          plus proactive mitigations and early-warning controls for the
          TOP-3 PREDICTED NEXT tactics generated by the Markov model.
        """
        current_techniques = current_techniques or []
        filters_current: dict[str, Any] = {"tactic": current_tactic}
        if platform:
            filters_current["platform"] = platform

        current_query = f"{current_tactic} " + " ".join(current_techniques)
        current_results = self.search_hybrid_rerank(
            current_query,
            top_k=top_k_current,
            filters=filters_current,
        )
        for r in current_results:
            r.stage = "current"

        seen_chunk_ids = {r.chunk_id for r in current_results}
        final_results = list(current_results)

        # Predict next likely attack chain stages using Markov model
        predictor = MarkovPredictor()
        markov_top_n = int(get_settings().rag.get("markov_top_n", 3))
        predictions = predictor.predict(current_tactic, top_n=markov_top_n)

        for pred in predictions:
            pred_filters: dict[str, Any] = {"tactic": pred.tactic}
            if platform:
                pred_filters["platform"] = platform

            pred_query = f"proactive prevention and hardening against {pred.tactic}"
            pred_hits = self.search_hybrid_rerank(
                pred_query,
                top_k=top_k_predicted,
                filters=pred_filters,
            )
            for hit in pred_hits:
                if hit.chunk_id not in seen_chunk_ids:
                    hit.stage = "predicted"
                    hit.predicted_tactic = pred.tactic
                    hit.predicted_prob = pred.probability
                    seen_chunk_ids.add(hit.chunk_id)
                    final_results.append(hit)

        return final_results


def retrieve(
    query: str,
    domain: str | None = None,
    kb_dir: str = "data/kb",
    filters: dict[str, Any] | None = None,
    markov_expansion: bool | None = None,
) -> tuple[list[RetrievalResult], bool]:
    """
    Primary API entry point for knowledge retrieval.

    Args:
        query: Free-text search query (e.g. technique IDs, domain keywords).
        domain: Optional security domain / tactic filter.
        kb_dir: Path to knowledge directory.
        filters: Optional metadata filters dict (tactic, technique, platform).
        markov_expansion: Whether to perform Markov next-stage expansion.

    Returns:
        Tuple of (results: list[RetrievalResult], low_confidence: bool).
    """
    retriever = HybridRetriever.get_instance(kb_dir=kb_dir)
    search_filters = dict(filters or {})
    if domain and "tactic" not in search_filters:
        search_filters["tactic"] = domain

    top_k = int(get_settings().rag.get("top_k_after_rerank", 5))
    min_score = float(get_settings().rag.get("min_score", 0.3))

    results = retriever.search_hybrid_rerank(query, top_k=top_k, filters=search_filters)

    # Optional Markov next-technique expansion
    if markov_expansion is None:
        markov_expansion = bool(get_settings().rag.get("markov_expansion", True))

    if markov_expansion and domain and results:
        # Check if we should append proactive mitigations for next predicted tactics
        markov_hits = retriever.retrieve_markov_aware(
            current_tactic=domain,
            top_k_current=top_k,
            top_k_predicted=1,
        )
        seen_ids = {r.chunk_id for r in results}
        for mh in markov_hits:
            if mh.chunk_id not in seen_ids and mh.stage == "predicted":
                results.append(mh)
                seen_ids.add(mh.chunk_id)

    low_confidence = False
    if not results or (results[0].rerank_score is not None and results[0].rerank_score < min_score):
        low_confidence = True

    return results, low_confidence
