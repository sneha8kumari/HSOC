# H-SOC 5-Minute Showcase Demo Script

This script provides an exact, minute-by-minute walkthrough for demonstrating the **Hybrid Security Operations Center (H-SOC)** platform. Designed for evaluation panels, executive leadership, and technical auditors.

---

## Demo Overview & Objectives
- **Target Duration**: 5 Minutes (300 seconds).
- **Core Narrative**: Demonstrate how H-SOC bridges rule-based precision and ML anomaly detection, compresses alert noise into coherent attack chains, forecasts adversary next moves using Markov models, and generates strictly grounded, injection-resistant incident reports with human-in-the-loop active learning.
- **Prerequisites**:
  - Python 3.10+ installed.
  - Project setup completed (`make setup`).

---

## Timeline & Step-by-Step Script

```
00:00 ── 00:45 │ Scene 1: Automated Attack Simulation & Pipeline Execution
00:45 ── 01:45 │ Scene 2: Command Center Dashboard & Live Attack Timeline
01:45 ── 02:45 │ Scene 3: Markov Attack Forecasting & What-If Counterfactuals
02:45 ── 03:45 │ Scene 4: Grounded Multi-Agent Report & Guardrail Verification
03:45 ── 05:00 │ Scene 5: Active Feedback Learning Loop & Benchmark Evaluation
```

---

### Scene 1: Automated Attack Simulation & Pipeline Execution (00:00 – 00:45)

**Objective**: Show autonomous ingestion, detection fusion, and correlation running end-to-end.

**Action**: Open a terminal in the project directory and run:
```bash
make demo
```

**Talking Points**:
> *"Welcome to H-SOC. Traditional SOCs struggle with two extremes: brittle rules that miss zero-days, and black-box ML that floods analysts with false positives. Notice what's happening right now in the terminal:*
> 1. *We simulate five multi-stage attack campaigns (S1 through S5) spanning port scanning, brute force, privilege escalation, persistence, and web exploitation.*
> 2. *Our dual-signal fusion engine evaluates incoming events against both rule windows and ML anomaly scores, reducing raw event noise by over 98%.*
> 3. *Our graph-based correlation engine groups 300+ raw telemetry events into five high-fidelity incidents with zero manual triage."*

---

### Scene 2: Command Center Dashboard & Live Attack Timeline (00:45 – 01:45)

**Objective**: Showcase the React/Vite dashboard, live attack timeline, and correlation graph.

**Action**: Run the unified demo UI:
```bash
make demo-ui
```
*The command starts the API and opens the dashboard in your default browser at `http://localhost:5173` (or `http://localhost:8000`).*

**Visual Highlights to Click & Point Out**:
1. **Live Incident Feed**: Point to the left panel showing the 5 incidents categorized by severity (Critical, High, Medium) with risk scores.
2. **Attack Timeline**: Click on Incident #1 or #3. Highlight the chronological stages. Show the **"Out-of-Order Stage"** badge:
   > *"Notice how the attacker attempted privilege escalation before establishing persistence—our chain analyzer flags this sequence anomaly immediately."*
3. **Interactive Graph**: Click the **"Attack Graph"** view. Show nodes (IPs, usernames, hostnames) and edges connecting evidence events.

---

### Scene 3: Markov Attack Forecasting & What-If Counterfactuals (01:45 – 02:45)

**Objective**: Demonstrate probabilistic kill-chain forecasting and interactive risk exploration.

**Visual Highlights to Click & Point Out**:
1. **Markov Intelligence Panel**: Click on the **"Markov Intelligence"** tab.
   - Point to the **Transition Heatmap** showing learned probabilities between MITRE ATT&CK tactics.
   - Point to the **Next Expected Tactics Bar Chart**:
     > *"Based on observed Reconnaissance and Credential Access, the Markov engine forecasts Privilege Escalation at 41% and Lateral Movement at 28% with Laplace smoothing."*
2. **Copilot & What-If Engine**: Open the **Copilot Sidecar**:
   - Ask: *"Why is this incident classified as High severity?"*
   - Observe the copilot return a response citing specific event IDs (`EV-00042`) and asset criticality weights.
   - Adjust the **What-If Slider**: Force the state to `"Attacker obtains Domain Admin"`.
   - Watch the risk score dynamically recalculate and the Markov engine re-project the path to Exfiltration.

---

### Scene 4: Grounded Multi-Agent Report & Guardrail Verification (02:45 – 03:45)

**Objective**: Prove zero hallucination, strict schema conformance, and action authorization guardrails.

**Visual Highlights to Click & Point Out**:
1. **Forensics Report Viewer**: Navigate to the **"Incident Report"** tab.
   - Show the structured executive summary, technical analysis, and ATT&CK mappings.
   - Click a citation badge (`[EV-00104]` or `[KB-CIS-V8-C04]`):
     > *"Every single claim is bi-directionally linked to a raw telemetry event or an authoritative knowledge chunk from NIST, CIS, or MITRE. Our CriticAgent rejected any ungrounded assertions during generation."*
2. **Action Guardrails**: Scroll to the **Remediation Plan**:
   - Point to disruptive actions (e.g., `Isolate host ws-01 from VLAN 10`, `Kill active root process`):
   - Notice the prominent badge: `[NEEDS ANALYST APPROVAL: TRUE]`.
   > *"The AI can recommend actions, but the system enforces an absolute guardrail: no disruptive change can execute without human sign-off."*

---

### Scene 5: Active Feedback Learning Loop & Benchmark Evaluation (03:45 – 05:00)

**Objective**: Demonstrate how human analyst feedback updates the Markov model via Bayesian Dirichlet updates, and review verified benchmark metrics (E1–E6).

**Action**: In the UI, click **"Accept Prediction"** or **"Edit Prediction"** on an incident.
Show the Bayesian feedback toast notification:
> *"The analyst correction triggers an immediate Bayesian Dirichlet conjugate update. The correct transition is reinforced ($+1.0$), erroneous transitions are decayed, and a versioned snapshot is saved to the Model Registry."*

**Wrap-Up with Master Benchmarks (Terminal or Docs)**:
Run the comprehensive benchmark evaluation:
```bash
make eval-all
```
Highlight key takeaways from [experiments/results/experiments_master_report.md](file:///c:/Users/Utkarsh%20Dubey/.gemini/antigravity/HSOC/experiments/results/experiments_master_report.md):
- **E1 (Detection)**: F1 improved from 0.82 to **0.95** with a **98.4% alert reduction**.
- **E2 (Correlation)**: **80% alert-to-incident compression** with **100% chain reconstruction purity**.
- **E3 (Forecasting)**: **78% Top-3 accuracy** with a **58.4% reduction in perplexity**.
- **E4 (RAG)**: **1.000 MRR** on 50 hand-labelled queries using hybrid cross-encoder reranking.
- **E5 (GenAI Quality)**: **100% Draft-07 schema validity** and **98.6% claim faithfulness**.
- **E6 (Safety)**: Prompt injection Attack Success Rate dropped from **57.1% to 0.0%**.

> *"Thank you. H-SOC demonstrates how deterministic state machines, hybrid ML, and active feedback create a trustworthy, autonomous SOC."*
