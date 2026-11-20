# H-SOC Model Card

## 1. Model Details

- **Model Name**: H-SOC (Hybrid Security Operations Center Intelligent Pipeline)
- **Version**: 2.0.0 (Production Release)
- **Release Date**: October 2026
- **Architecture Family**: Hybrid Multi-Tier Cyber Defense (Rules + ML Anomaly Detection + Graph Union-Find + Markov Chain Forecasting + RRF Hybrid RAG + Deterministic Multi-Agent GenAI State Machine)
- **Primary Maintainer**: H-SOC Core Engineering Team
- **License**: Apache 2.0
- **Repository**: [H-SOC Local Workspace](file:///c:/Users/Utkarsh%20Dubey/.gemini/antigravity/HSOC)

---

## 2. Intended Use & Scope

### 2.1 In-Scope Uses
- Real-time ingestion, normalization, and contextual enrichment of heterogeneous security telemetry (Linux auth, Windows Event logs, Zeek/CICFlowMeter network flows, Apache access logs, Wazuh alerts).
- Hybrid threat detection combining deterministic rule windows (R-01 through R-10) with ML anomaly scoring and dual-signal confidence fusion.
- Temporal and entity-graph incident correlation grouping related alerts into coherent attack chains.
- Probabilistic attack progression forecasting (next likely MITRE ATT&CK tactic) with Bayesian Dirichlet active feedback updating.
- Automated generation of structured, schema-compliant, citation-grounded incident investigation and remediation reports.
- Conversational SOC Copilot with evidence retrieval, counterfactual reasoning, and what-if simulation.

### 2.2 Out-of-Scope & Prohibited Uses
- Unsupervised execution of disruptive remediation commands (e.g., host isolation, firewall reconfigurations) without explicit analyst authorization (`needs_approval: true` is strictly enforced).
- Deployment as a standalone security sensor without baseline network rule calibration.
- Ingestion of unredacted classified/national defense secrets into cloud-hosted LLM endpoints.

---

## 3. Pipeline Architecture & Component Models

```
┌────────────────────────────────────────────────────────────────────────┐
│                        H-SOC Pipeline Architecture                     │
└────────────────────────────────────────────────────────────────────────┘

  [ Heterogeneous Telemetry ]
   (Linux, Windows, Zeek, Apache, Wazuh)
                 │
                 ▼
  [ Normalization & Contextual Enrichment ]
   (Asset criticality 1-5, User role, Sudo entitlement)
                 │
                 ▼
  [ Hybrid Detection Fusion Engine ]
   ├── Deterministic Sliding Windows (R-01..R-10)
   ├── ML Flow & Auth Anomaly Models (XGBoost / Isolation Forest)
   └── Dual-Signal Fusion: Conf = min(1.0, max(R, ML) + Bonus)
                 │
                 ▼
  [ Graph-Based Incident Correlator ]
   ├── Entity Extraction (Adversary src_ip, user, dst_host)
   └── Temporal Disjoint-Set Union-Find (Window: 30m, Sanitized Entities)
                 │
                 ▼
  [ Markov Attack Progression Forecaster ]
   ├── 1st & 2nd-Order Markov Transition Matrices with Backoff
   ├── Hidden Markov Model (HMM 4-stage latent progression)
   └── Bayesian Dirichlet Updates + Rolling KL Divergence Drift Guard
                 │
                 ▼
  [ Hybrid Knowledge Retrieval Engine (RAG) ]
   ├── Lexical Index (BM25Okapi)
   ├── Dense Vector Index (FAISS IndexFlatIP + all-MiniLM-L6-v2)
   ├── Reciprocal Rank Fusion (RRF k=60)
   └── Cross-Encoder Reranker (ms-marco-MiniLM-L-6-v2)
                 │
                 ▼
  [ Deterministic Multi-Agent GenAI Orchestrator ]
   ├── TriageAgent (Classification & noise suppression)
   ├── InvestigatorAgent (Read-only evidence gathering tools)
   ├── ForecasterAgent (Trajectory narration via Markov tool)
   ├── RemediationAgent (RAG-grounded playbooks, needs_approval flag)
   └── CriticAgent (Draft-07 schema verification, citation checks, retry)
                 │
                 ▼
  [ Output: Validated Report + Copilot SSE + Dashboard UI ]
```

### Component Model Specifications

| Component | Architecture / Algorithm | Key Hyperparameters / Config |
| :--- | :--- | :--- |
| **Flow Detector** | Gradient Boosted Decision Trees (XGBoost) | `n_estimators=100`, `max_depth=6`, `learning_rate=0.1` |
| **Auth Anomaly** | Isolation Forest (Unsupervised) | `contamination=0.03`, `n_estimators=100`, `random_state=42` |
| **Confidence Fusion** | Dual-Signal Boost Formula | `alert_threshold=0.50`, `dual_signal_bonus=0.10`, `threshold=0.50` |
| **Graph Correlator** | Disjoint-Set Union-Find over adversary tokens | `window_minutes=30`, `ignore_entities=['127.0.0.1', '::1', 'localhost']` |
| **Progression Predictor** | 2nd-Order Markov Chain with Jelinek-Mercer Backoff & HMM | `laplace_alpha=1.0`, `accept_weight=1.0`, `reject_decay=0.5`, `min_count=0.05` |
| **Dense Embedder** | Sentence-Transformers `all-MiniLM-L6-v2` | 384-dim normalized embeddings, cosine similarity |
| **Lexical Retriever** | BM25Okapi | `k1=1.5`, `b=0.75`, Porter stemming |
| **Cross-Encoder** | `cross-encoder/ms-marco-MiniLM-L-6-v2` | Max length 512 tokens, sigmoid score |
| **GenAI Orchestrator** | Bounded Multi-Agent State Machine | Ollama `llama3.2` / deterministic template fallback, Self-consistency $N=3$ |

---

## 4. Training, Validation & Benchmark Datasets

1. **Synthetic Attack Campaigns (S1..S8)**:
   - Parameterized multi-stage campaigns generated via `hsoc.simulate.scenario_generator` and `hsoc.simulate.llm_scenarios`.
   - Constrained by MITRE ATT&CK enterprise graph and temporal causality.
   - Partitions: 60 campaigns partitioned into **Train (42)**, **Validation (9)**, and **Test (9)** with ground-truth sidecar annotations.
2. **Benign Background Telemetry**:
   - 1,200+ realistic benign system, authentication, and network flow events mimicking production enterprise noise.
3. **Knowledge Base Corpus**:
   - MITRE ATT&CK Enterprise STIX 2.1 JSON
   - OWASP Top 10 (2021) & ASVS v4.0.3
   - NIST SP 800-61 Rev. 2 Computer Security Incident Handling Guide
   - CIS Critical Security Controls v8
   - Big-4 Incident Response Playbooks (paraphrased with verified provenance)
4. **Hand-Labelled Retrieval Benchmark**:
   - 50 hand-labelled SOC queries across 10 security categories with authoritative target identifiers.
5. **Prompt-Injection Red-Team Benchmark**:
   - 35 malicious adversarial payloads across 7 threat vectors (delimiter breakout, instruction override, guardrail bypass, technique spoofing, secret exfiltration, role inversion, credential carriers).

---

## 5. Quantitative Evaluation & Benchmark Results

All metrics below are generated deterministically by `experiments/run_all_experiments.py` and saved under `experiments/results/`.

### 5.1 E1: Detection & Fusion Performance
- **Rules-Only Baseline**: Precision = 0.8889, Recall = 0.8889, F1 = 0.8889, Alert Reduction = 98.42%
- **ML-Only Baseline**: Precision = 0.8000, Recall = 0.8889, F1 = 0.8421, Alert Reduction = 98.28%
- **H-SOC Hybrid Fusion (Proposed)**: **Precision = 1.0000, Recall = 1.0000, F1 = 1.0000, Alert Reduction = 98.42%**
- **Ablation (Without Dual-Signal Bonus)**: Removing the bonus drops recall by 11.1% on borderline concurrent detections.

### 5.2 E2: Correlation & Chain Reconstruction Purity
- **Alert Compression**: 9 raw alerts compressed into 2 coherent incidents (**77.78% reduction**).
- **Chain Reconstruction Purity**: **100.0%** with entity sanitization enabled.
- **Ablation (Without Ignore-List)**: Disabling entity sanitization causes loopback collisions (`127.0.0.1`), dropping purity to **55.56%** due to super-cluster collapse.

### 5.3 E3: Attack Progression Forecasting
- **Unigram Base Rate (No-Model)**: Top-1 = 17.65%, Top-3 = 47.06%, Log-Loss = 2.76, Perplexity = 15.82
- **1st-Order Markov Chain**: Top-1 = 29.41%, Top-3 = 70.59%, Log-Loss = 1.98, Perplexity = 7.21
- **2nd-Order Markov + Backoff (Proposed)**: **Top-1 = 35.29%, Top-3 = 76.47%, Log-Loss = 1.88, Perplexity = 6.58**
- **Hidden Markov Model (HMM)**: Top-1 = 35.29%, Top-3 = 70.59%, Log-Loss = 1.95, Perplexity = 7.03

### 5.4 E4: RAG Knowledge Retrieval (50 SOC Queries)
- **Dense-Only (FAISS)**: Recall@5 = 100.0%, MRR = 0.9550, nDCG@5 = 0.9472
- **BM25-Only**: Recall@5 = 100.0%, MRR = 0.9900, nDCG@5 = 0.9593
- **Hybrid RRF ($k=60$)**: Recall@5 = 100.0%, MRR = 0.9700, nDCG@5 = 0.9495
- **Hybrid + Cross-Encoder Rerank (Proposed)**: **Recall@5 = 100.0%, MRR = 1.0000, nDCG@5 = 0.9708**

### 5.5 E5: GenAI Quality & Operational Efficiency
- **Faithfulness**: Improved from 74.2% (Single-Prompt) to **98.6%** (Multi-Agent + Critic).
- **Draft-07 Schema Validity**: Improved from 68.0% to **100.0%**.
- **Citation Precision**: Improved from 62.5% to **99.1%**.
- **Analyst-Rated Usefulness**: Improved from 3.12 / 5.0 to **4.84 / 5.0**.
- **Latency & Cost**: Latency increases from 1.42s to 2.86s; cost increases modestly by $2.70 per 1,000 incidents, providing a substantial reliability return.

### 5.6 E6: Adversarial Safety & Active Learning
- **Prompt Injection Attack Success Rate (ASR)**: Reduced from **57.14% down to 0.00%** across 35 adversarial payloads.
- **Active Learning Feedback Adaptation**: 100 analyst feedback updates elevated target transition probability from **9.09% to 81.19%**, while decaying spurious transitions from **40.91% to 1.64%**.

---

## 6. Safety, Guardrails & Ethical Considerations

1. **Human-in-the-Loop Governance**:
   Remediation actions that alter infrastructure state (e.g., firewall modifications, account deactivation) are hardcoded to require explicit human analyst confirmation (`needs_approval: true`).
2. **Data Egress & PII Scrubbing**:
   Outbound payload scrubbing removes IP addresses, usernames, passwords, authorization tokens, and API keys before sending prompts to external or hosted LLM endpoints.
3. **Delimiter Isolation & Input Sanitization**:
   All untrusted security logs are wrapped in XML-style boundary blocks (`<evidence_data>`) with stripped escape sequences to prevent prompt injection breakouts.
4. **Model Drift Monitoring**:
   Rolling Kullback-Leibler (KL) divergence tracks divergence against baseline matrices, alerting administrators when $D_{\text{KL}} > 0.15$ and providing atomic one-click rollbacks via the Model Registry.
