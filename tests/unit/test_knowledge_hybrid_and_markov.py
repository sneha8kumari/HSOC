"""
Unit tests for knowledge base hybrid retrieval (BM25 + FAISS RRF),
cross-encoder reranking, provenance records, and Markov-aware proactive query expansion.
"""

from __future__ import annotations

import json
from pathlib import Path

from hsoc.knowledge.chunker import chunk
from hsoc.knowledge.retriever import HybridRetriever, RetrievalResult, retrieve


def test_chunker_stable_ids_and_provenance():
    doc = {
        "source": "MITRE ATT&CK (T1046)",
        "source_type": "stix",
        "title": "MITRE ATT&CK T1046: Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "version": "14.1",
        "domain_tag": "reconnaissance",
        "tactics": ["discovery", "reconnaissance"],
        "techniques": ["T1046"],
        "platforms": ["linux", "windows", "network"],
        "text": "Port scanning and service sweep detection.",
    }

    chunks_1 = chunk(doc)
    chunks_2 = chunk(doc)

    assert len(chunks_1) == 1
    assert len(chunks_2) == 1

    # Deterministic chunk ID stability
    assert chunks_1[0]["chunk_id"] == chunks_2[0]["chunk_id"]
    assert chunks_1[0]["chunk_id"].startswith("KB-MITRE-")

    # Provenance integrity
    prov = chunks_1[0]["provenance"]
    assert prov["source"] == "MITRE ATT&CK (T1046)"
    assert prov["source_type"] == "stix"
    assert "checksum" in prov
    assert "created_at" in prov
    assert prov["techniques"] == ["T1046"]
    assert "reconnaissance" in prov["tactics"]
    assert "linux" in prov["platforms"]


def test_retriever_hybrid_and_filtering():
    retriever = HybridRetriever.get_instance()
    assert len(retriever.chunks) > 0
    assert retriever.faiss_index is not None
    assert retriever.bm25 is not None

    # 1. Search Dense
    dense_hits = retriever.search_dense("SSH brute force failed password", top_k=3)
    assert len(dense_hits) > 0
    assert any("T1110" in str(h[1].get("techniques", [])) or "IR-PB-01" in str(h[1].get("chunk_id", "")) for h in dense_hits)

    # 2. Search BM25
    bm25_hits = retriever.search_bm25("sudoers NOPASSWD privilege escalation", top_k=3)
    assert len(bm25_hits) > 0
    assert any("T1548" in str(h[1].get("techniques", [])) or "IR-PB-03" in str(h[1].get("chunk_id", "")) for h in bm25_hits)

    # 3. Hybrid RRF
    rrf_hits = retriever.search_hybrid_rrf("port scanning reconnaissance", top_k=5)
    assert len(rrf_hits) > 0
    assert "rrf_score" in rrf_hits[0]

    # 4. Metadata Filtering: platform = linux
    linux_hits = retriever.search_hybrid_rerank(
        "privilege escalation",
        top_k=5,
        filters={"platform": "linux"},
    )
    assert len(linux_hits) > 0
    for hit in linux_hits:
        assert "linux" in [p.lower() for p in hit.platforms]


def test_markov_aware_proactive_retrieval():
    retriever = HybridRetriever.get_instance()

    # Query with current tactic = reconnaissance and technique = T1046
    results = retriever.retrieve_markov_aware(
        current_tactic="reconnaissance",
        current_techniques=["T1046"],
        top_k_current=2,
        top_k_predicted=1,
    )

    assert len(results) >= 3

    # Check presence of both current remediation and proactive predicted mitigation
    stages = [r.stage for r in results]
    assert "current" in stages
    assert "predicted" in stages

    current_chunks = [r for r in results if r.stage == "current"]
    predicted_chunks = [r for r in results if r.stage == "predicted"]

    assert len(current_chunks) > 0
    assert len(predicted_chunks) > 0

    # Predicted chunks must carry predicted_tactic and Markov probability
    for p_chunk in predicted_chunks:
        assert p_chunk.predicted_tactic is not None
        assert p_chunk.predicted_prob is not None
        assert p_chunk.predicted_prob >= 0.0


def test_primary_retrieve_function_backward_compatibility():
    results, low_confidence = retrieve(
        query="network service scanning T1046",
        domain="reconnaissance",
        markov_expansion=True,
    )

    assert len(results) > 0
    assert low_confidence is False
    assert any(r.chunk_id.startswith("KB-") for r in results)
    assert any(r.stage == "current" for r in results)
    assert any(r.stage == "predicted" for r in results)
