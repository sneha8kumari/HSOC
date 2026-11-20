"""
Retrieval Benchmark: 50 hand-labelled SOC analyst queries.

Compares 4 retrieval pipelines across the knowledge base:
  1. Dense-only (FAISS IndexFlatIP)
  2. BM25-only (BM25Okapi)
  3. Hybrid (BM25 + FAISS fused via Reciprocal Rank Fusion)
  4. Hybrid + Re-rank (RRF + Cross-Encoder ms-marco-MiniLM-L-6-v2)

Metrics:
  - Recall@5
  - MRR (Mean Reciprocal Rank)
  - nDCG@5 (Normalized Discounted Cumulative Gain)
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

from hsoc.knowledge.retriever import HybridRetriever

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 50 hand-labelled queries with relevant target source tags / techniques / titles
BENCHMARK_DATASET: list[dict[str, Any]] = [
    # Category 1: Network Reconnaissance & Port Scanning (Q1-Q5)
    {"q": "How to detect and block TCP SYN vertical port scans?", "targets": ["T1046", "IR-PB-02", "M1030"]},
    {"q": "Mitigations for network service scanning on database servers", "targets": ["T1046", "IR-PB-02", "CIS-V8-C17"]},
    {"q": "Firewall rate limiting and perimeter dropping for sequential port sweeps", "targets": ["IR-PB-02", "T1046", "NIST-800-61-PREP"]},
    {"q": "Horizontal port scanning across multiple destination subnets", "targets": ["T1046", "IR-PB-02"]},
    {"q": "Network intrusion prevention rules for anomalous reconnaissance discovery", "targets": ["T1046", "M1031", "BIG4-KPMG-CYBER-RESPONSE"]},

    # Category 2: SSH & Authentication Brute Force (Q6-Q10)
    {"q": "SSH password brute force guessing remediation and fail2ban rules", "targets": ["T1110.001", "IR-PB-01", "M1036"]},
    {"q": "How to respond to repeated authentication failures on linux bastion?", "targets": ["IR-PB-01", "T1110.001", "CIS-V8-C05"]},
    {"q": "Account lockout policies and exponential delays for credential attacks", "targets": ["T1110.001", "OWASP-2021-A07", "M1036"]},
    {"q": "Terminating active SSH sessions and rotating compromised credentials", "targets": ["IR-PB-01", "T1078", "NIST-800-61-CONTAIN"]},
    {"q": "Password spraying detection across multiple distinct accounts", "targets": ["T1110.003", "OWASP-2021-A07", "CIS-V8-C05"]},

    # Category 3: Privilege Escalation & Sudo Hardening (Q11-Q15)
    {"q": "Unauthorized sudo execution by non-privileged user remediation", "targets": ["T1548.003", "IR-PB-03", "CIS-V8-C04"]},
    {"q": "How to audit /etc/sudoers and remove wildcard NOPASSWD privileges", "targets": ["T1548.003", "IR-PB-03", "M1026"]},
    {"q": "Killing unauthorized root shell spawned via sudo on workstation", "targets": ["IR-PB-03", "T1548.003"]},
    {"q": "Abuse of elevation control mechanisms and sudo caching in Linux", "targets": ["T1548.003", "CIS-V8-C04"]},
    {"q": "Linux auditd rules for monitoring USER_CMD and privilege elevation", "targets": ["IR-PB-03", "T1548.003", "NIST-800-61-DETECT"]},

    # Category 4: Persistence & Rogue Local Accounts (Q16-Q20)
    {"q": "Detection and eradication of rogue local user account creation", "targets": ["T1136.001", "IR-PB-04", "CIS-V8-C05"]},
    {"q": "How to audit unauthorized cron jobs and authorized_keys for persistence?", "targets": ["IR-PB-04", "T1136.001"]},
    {"q": "User account management and automated deprovisioning safeguards", "targets": ["CIS-V8-C05", "T1136.001", "M1018"]},
    {"q": "Immediate steps to delete unauthorized local account and lock sessions", "targets": ["IR-PB-04", "NIST-800-61-CONTAIN"]},
    {"q": "Windows Event ID 4720 rogue user account persistence investigation", "targets": ["T1136.001", "IR-PB-04"]},

    # Category 5: Web Application Attacks & Fuzzing (Q21-Q25)
    {"q": "Active wordlist scanning targeting /admin /.env and /.git paths", "targets": ["T1595.003", "IR-PB-05", "OWASP-2021-A01"]},
    {"q": "OWASP Top 10 Broken Access Control verification and prevention", "targets": ["OWASP-2021-A01", "OWASP-ASVS-V5"]},
    {"q": "Web application firewall rules to block directory traversal and fuzzing", "targets": ["IR-PB-05", "OWASP-ASVS-V5", "T1595.003"]},
    {"q": "Restricting public access to sensitive web root configuration files", "targets": ["OWASP-2021-A01", "T1595.003", "IR-PB-05"]},
    {"q": "OWASP ASVS Chapter 5 input validation and path sanitization", "targets": ["OWASP-ASVS-V5", "OWASP-2021-A01"]},

    # Category 6: Cryptographic & Cleartext Protocols (Q26-Q30)
    {"q": "Deprecation of cleartext protocols FTP port 21 and Telnet port 23", "targets": ["OWASP-2021-A02", "CWE-319", "CIS-V8-C04"]},
    {"q": "OWASP A02 Cryptographic Failures remediation and TLS enforcement", "targets": ["OWASP-2021-A02", "CWE-319"]},
    {"q": "Enforcing HTTP Strict Transport Security HSTS and modern AEAD ciphers", "targets": ["OWASP-2021-A02"]},
    {"q": "Sensitive data exposure in transit over unencrypted network channels", "targets": ["OWASP-2021-A02", "CWE-319"]},
    {"q": "CIS Control 4 guidelines for disabling legacy plaintext services", "targets": ["CIS-V8-C04", "OWASP-2021-A02"]},

    # Category 7: Lateral Movement & Execution (Q31-Q35)
    {"q": "Lateral movement detection via remote SSH sessions between internal hosts", "targets": ["T1021.004", "CIS-V8-C06", "BIG4-DELOITTE-CIRF"]},
    {"q": "Unix shell execution abuse /bin/sh and /bin/bash by service daemons", "targets": ["T1059.004", "CIS-V8-C04"]},
    {"q": "Restricting interactive shell execution and deploying AppArmor profiles", "targets": ["T1059.004", "M1038"]},
    {"q": "Segmentation of jump hosts and bastion network access controls", "targets": ["T1021.004", "CIS-V8-C06"]},
    {"q": "Auditing east-west traffic anomalies and unexpected SSH pivots", "targets": ["T1021.004", "BIG4-DELOITTE-CIRF"]},

    # Category 8: NIST SP 800-61 Incident Handling Phases (Q36-Q40)
    {"q": "NIST SP 800-61 preparation phase and central log aggregation requirements", "targets": ["NIST-800-61-PREP", "CIS-V8-C17"]},
    {"q": "NIST detection and analysis phase correlation across heterogeneous logs", "targets": ["NIST-800-61-DETECT", "BIG4-KPMG-CYBER-RESPONSE"]},
    {"q": "NIST containment eradication and recovery phase execution steps", "targets": ["NIST-800-61-CONTAIN", "BIG4-PWC-IR-FORENSICS"]},
    {"q": "Post-incident activity lessons learned and root-cause analysis NIST", "targets": ["NIST-800-61-POST", "CIS-V8-C17"]},
    {"q": "Severity classification based on functional impact and recoverability", "targets": ["NIST-800-61-DETECT", "NIST-800-61-PREP"]},

    # Category 9: CIS Controls v8 Security Practices (Q41-Q45)
    {"q": "CIS Control 4 secure configuration and session locking on enterprise assets", "targets": ["CIS-V8-C04", "T1548.003"]},
    {"q": "CIS Control 5 account management and disabling dormant accounts", "targets": ["CIS-V8-C05", "T1136.001"]},
    {"q": "CIS Control 6 access control management and mandatory MFA for remote access", "targets": ["CIS-V8-C06", "T1078"]},
    {"q": "CIS Control 17 establishing an enterprise incident handling process", "targets": ["CIS-V8-C17", "NIST-800-61-PREP"]},
    {"q": "Restricting administrative privileges to dedicated administrator accounts", "targets": ["CIS-V8-C05", "CIS-V8-C04", "T1078"]},

    # Category 10: Big-4 Incident Response Methodologies (Q46-Q50)
    {"q": "Deloitte Cyber Incident Response Framework hypothesis-driven threat hunting", "targets": ["BIG4-DELOITTE-CIRF"]},
    {"q": "EY threat intelligence-led incident response and identity-first remediation", "targets": ["BIG4-EY-CTI-IR"]},
    {"q": "PwC incident management digital forensics and coordinated mass eradication", "targets": ["BIG4-PWC-IR-FORENSICS"]},
    {"q": "KPMG cyber response framework attack path analysis and continuous monitoring", "targets": ["BIG4-KPMG-CYBER-RESPONSE"]},
    {"q": "Digital forensics evidence chain of custody and non-destructive memory capture", "targets": ["BIG4-DELOITTE-CIRF", "BIG4-PWC-IR-FORENSICS"]},
]


def is_target_match(chunk: dict[str, Any], target_keywords: list[str]) -> bool:
    """Check if retrieved chunk matches any expected target keywords."""
    chunk_text = (
        f"{chunk.get('chunk_id', '')} "
        f"{chunk.get('title', '')} "
        f"{chunk.get('source', '')} "
        f"{' '.join(chunk.get('techniques', []))} "
        f"{' '.join(chunk.get('tactics', []))} "
        f"{chunk.get('text', '')}"
    ).lower()

    for kw in target_keywords:
        if kw.lower() in chunk_text:
            return True
    return False


def evaluate_pipeline(
    retriever: HybridRetriever,
    pipeline_type: str,
    top_k: int = 5,
) -> dict[str, float]:
    """
    Run evaluation benchmark for a given retrieval pipeline:
      - 'dense_only'
      - 'bm25_only'
      - 'hybrid_rrf'
      - 'hybrid_rerank'
    """
    recalls = []
    mrrs = []
    ndcgs = []

    for item in BENCHMARK_DATASET:
        query = item["q"]
        targets = item["targets"]

        # Retrieve top candidates per pipeline
        if pipeline_type == "dense_only":
            hits = [c for _, c in retriever.search_dense(query, top_k=top_k)]
        elif pipeline_type == "bm25_only":
            hits = [c for _, c in retriever.search_bm25(query, top_k=top_k)]
        elif pipeline_type == "hybrid_rrf":
            hits = retriever.search_hybrid_rrf(query, top_k=top_k)
        elif pipeline_type == "hybrid_rerank":
            results = retriever.search_hybrid_rerank(query, top_k=top_k)
            hits = [r.to_dict() for r in results]
        else:
            raise ValueError(f"Unknown pipeline: {pipeline_type}")

        # Compute Metrics
        hits_binary = [1 if is_target_match(h, targets) else 0 for h in hits]

        # 1. Recall@5: was at least one target found in top-5?
        recall_at_k = 1.0 if any(hits_binary) else 0.0
        recalls.append(recall_at_k)

        # 2. MRR (Mean Reciprocal Rank)
        mrr_val = 0.0
        for rank, is_hit in enumerate(hits_binary, start=1):
            if is_hit:
                mrr_val = 1.0 / rank
                break
        mrrs.append(mrr_val)

        # 3. nDCG@5
        dcg = sum(rel / math.log2(idx + 2) for idx, rel in enumerate(hits_binary))
        # Ideal DCG: perfect binary retrieval at top ranks
        ideal_hits = min(sum(hits_binary), top_k)
        if ideal_hits == 0:
            # If no target was retrieved, check if targets exist
            idcg = 1.0 / math.log2(2)
        else:
            idcg = sum(1.0 / math.log2(idx + 2) for idx in range(ideal_hits))
        ndcg = dcg / idcg if idcg > 0 else 0.0
        ndcgs.append(ndcg)

    return {
        "recall_at_5": round(sum(recalls) / len(recalls), 4),
        "mrr": round(sum(mrrs) / len(mrrs), 4),
        "ndcg_at_5": round(sum(ndcgs) / len(ndcgs), 4),
    }


def run_benchmark(out_dir: str = "experiments/results") -> dict[str, Any]:
    """Execute complete retrieval benchmark on all 50 queries."""
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    retriever = HybridRetriever.get_instance()
    logger.info("Loaded HybridRetriever with %d chunks. Running 50-query benchmark...", len(retriever.chunks))

    pipelines = ["dense_only", "bm25_only", "hybrid_rrf", "hybrid_rerank"]
    results = {}

    for pipe in pipelines:
        logger.info("Evaluating pipeline: %s ...", pipe)
        metrics = evaluate_pipeline(retriever, pipe, top_k=5)
        results[pipe] = metrics
        logger.info("  %s -> Recall@5=%.4f, MRR=%.4f, nDCG@5=%.4f", pipe, metrics["recall_at_5"], metrics["mrr"], metrics["ndcg_at_5"])

    summary = {
        "dataset_size": len(BENCHMARK_DATASET),
        "top_k": 5,
        "results": results,
    }

    out_file = target_dir / "knowledge_retrieval_benchmark.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Benchmark complete. Results written to %s", out_file)
    return summary


if __name__ == "__main__":
    res = run_benchmark()
    print("\n" + "=" * 70)
    print("RETRIEVAL BENCHMARK: 50 Hand-Labelled Queries (Recall@5, MRR, nDCG@5)")
    print("=" * 70)
    print(f"{'Pipeline':<22} | {'Recall@5':<10} | {'MRR':<10} | {'nDCG@5':<10}")
    print("-" * 70)
    for pipe, m in res["results"].items():
        print(f"{pipe:<22} | {m['recall_at_5']:<10.4f} | {m['mrr']:<10.4f} | {m['ndcg_at_5']:<10.4f}")
    print("=" * 70)
