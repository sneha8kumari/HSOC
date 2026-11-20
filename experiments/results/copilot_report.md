# H-SOC Copilot, What-If & Counterfactual Evaluation Report

**Generated**: 2026-10-25T20:57:15.661838+00:00  
**Evaluation Scope**: 10 Scripted Natural Language Questions with Evidence Citations, Markov What-If Simulation, Deterministic Counterfactuals, and Multi-Format Ticket Exports.

---

## 1. Executive Summary

| Capability | Benchmark Target | Result | Status |
|:---|:---:|:---:|:---:|
| **Scripted Copilot Q&A** | 10 Scripted Questions with Alert Citations | **10/10 Passed (100.0%)** | **PASSED** |
| **SSE Token Streaming** | Real-time token streaming via SSE | **Enabled (`text/event-stream`)** | **PASSED** |
| **What-If Simulation** | Markov re-forecast + Risk trajectory | **Forced: privilege_escalation $\rightarrow$ Re-forecasted** | **PASSED** |
| **Counterfactual Engine** | Deterministic severity sensitivity | **Verified: High $\rightarrow$ Medium when Criticality $\le$ 2** | **PASSED** |
| **Multi-Format Exports** | Exec Summary + Tech Report + Jira + ServiceNow | **4 Formats Auto-Generated** | **PASSED** |

---

## 2. Scripted Copilot Questions & Citation Verification (10/10)

| ID | Analyst Question | Detected Intent | Grounding Citations | Status |
|:---|:---|:---|:---|:---:|
| `Q1` | Why is this incident classified as High severity? | `explain_severity` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q2` | What happens if the attacker gets sudo? | `what_if_query` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q3` | Show evidence for step 1 of remediation. | `step_evidence` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q4` | Show evidence for step 2 of remediation. | `step_evidence` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q5` | What entities and hostnames are compromised in this incident? | `entities_summary` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q6` | What alerts are associated with this incident? | `list_alerts` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q7` | What techniques did the attacker use? | `attack_techniques` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q8` | What are the recommended containment steps? | `containment_recommendations` | `ALT-BENCH-01` | **PASSED** |
| `Q9` | What evidence supports the brute force alert? | `list_alerts` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |
| `Q10` | What happens if the attacker pivots to lateral movement? | `what_if_query` | `ALT-BENCH-01, EVT-BENCH-01` | **PASSED** |


---

## 3. What-If Scenario Simulation

- **Hypothetical Progression**: *"attacker obtains domain admin privileges"*
- **Baseline Risk**: Score `78` (HIGH)
- **Projected Trajectory**: Score `82` (CRITICAL)
- **Markov Narrative**:
  > "If the attacker advances to state 'privilege_escalation', the Markov transition model predicts next likely attacker tactics: defense_evasion (14.3%), discovery (7.1%), collection (7.1%). Risk score shifts from 78 to 82 (Severity Band: CRITICAL). Immediate containment playbook [KB-MITRE-754bcfbc354a] requires isolating network segment and revoking domain credentials."

---

## 4. Deterministic Counterfactual Sensitivity

- **Current State**: HIGH
- **Verbalized Explanation**:
  > "Severity would drop from HIGH to MEDIUM if asset criticality were <= 2 (e.g. non-production tier instead of tier-1 server auth-srv-02), reducing computed risk score from 74 to 58. Calculated from alert [ALT-BENCH-01]."

---

## 5. Supported Auto-Generated Export Formats

1. **Executive Incident Summary**: High-level exposure narrative for CISOs and executive leadership.
2. **Technical Forensic Report**: Comprehensive timeline with alert evidence, MITRE ATT&CK techniques, and playbooks.
3. **Jira Issue Ticket**: Atlassian Jira markup (`h1.`, `* [ ]`) with components, priorities, and remediation checklist.
4. **ServiceNow Security Incident Record (SIR)**: ServiceNow incident fields with CI, Category, Work Notes, and Action Checklist.
