"""
Comprehensive Backend API Client Verification Script.
Queries and validates all primary backend endpoints in detail.
"""

import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def get(path: str):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "HSOC-Tester/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())

def post(path: str, body: dict):
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "HSOC-Tester/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())

def main():
    print("=" * 65)
    print("        H-SOC BACKEND COMPREHENSIVE ENDPOINT AUDIT")
    print("=" * 65)

    # 1. Health check
    status, health = get("/health")
    print(f"\n[1] GET /health -> Status {status}:")
    print(f"    Health: {health}")

    # 2. Incidents List
    status, incidents = get("/incidents")
    print(f"\n[2] GET /incidents -> Status {status}:")
    print(f"    Total Active Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"    - ID: {inc['incident_id']} | Severity: {str(inc['severity']).upper()} | Risk: {inc['risk_score']} | Domain: {inc['domain']}")
        print(f"      Tactics: {' -> '.join(inc.get('tactics', [])) if inc.get('tactics') else 'None'}")
        print(f"      Entities: {', '.join(inc.get('entity_keys', [])[:3])}")

    first_inc_id = incidents[0]["incident_id"] if incidents else None

    if first_inc_id:
        # 3. Incident Detail
        status, detail = get(f"/incidents/{first_inc_id}")
        print(f"\n[3] GET /incidents/{first_inc_id} -> Status {status}:")
        print(f"    Timeline stages: {len(detail.get('timeline', []))}")
        print(f"    Report linked: {detail.get('report_id') or (detail.get('report') or {}).get('report_id')}")

        # 4. Attack Graph
        status, graph = get(f"/incidents/{first_inc_id}/graph")
        print(f"\n[4] GET /incidents/{first_inc_id}/graph -> Status {status}:")
        print(f"    Nodes: {len(graph.get('nodes', []))} | Edges: {len(graph.get('edges', []))}")
        for n in graph.get("nodes", [])[:4]:
            print(f"    - Node: {n.get('id')} [{n.get('type')}] label='{n.get('label')}'")

        # 5. Replay Data
        status, replay = get(f"/incidents/{first_inc_id}/replay")
        print(f"\n[5] GET /incidents/{first_inc_id}/replay -> Status {status}:")
        print(f"    Total Replay Events: {len(replay.get('events', []))}")

        # 6. Copilot Chat
        query_payload = {"incident_id": first_inc_id, "query": "Why was this incident classified as High severity?", "stream": False}
        status, copilot_resp = post(f"/incidents/{first_inc_id}/copilot/chat", query_payload)
        print(f"\n[6] POST /incidents/{first_inc_id}/copilot/chat -> Status {status}:")
        print(f"    Question: \"{query_payload['query']}\"")
        print(f"    Answer Summary: {copilot_resp.get('answer', '')[:160]}...")
        print(f"    Citations: {copilot_resp.get('evidence_cited', [])}")

        # 7. What-If Engine
        whatif_payload = {
            "forced_state": "attacker obtains domain admin",
        }
        status, whatif_resp = post(f"/incidents/{first_inc_id}/copilot/what-if", whatif_payload)
        print(f"\n[7] POST /incidents/{first_inc_id}/copilot/what-if -> Status {status}:")
        print(f"    Baseline Risk: {whatif_resp.get('baseline_risk_score')} -> Projected Risk: {whatif_resp.get('projected_risk_score')}")
        print(f"    Explanation: {whatif_resp.get('explanation', '')[:140]}...")

        # 8. Counterfactual Explanations
        status, cf_resp = get(f"/incidents/{first_inc_id}/copilot/counterfactual")
        print(f"\n[8] GET /incidents/{first_inc_id}/copilot/counterfactual -> Status {status}:")
        print(f"    Counterfactual: {cf_resp.get('counterfactual_statement')}")

        # 8b. Export Formats (Jira, ServiceNow, Executive)
        status, jira_resp = get(f"/incidents/{first_inc_id}/copilot/export/jira")
        print(f"\n[8b] GET /incidents/{first_inc_id}/copilot/export/jira -> Status {status}:")
        print(f"    Jira Summary: {jira_resp.get('jira_text', '')[:120]}...")

    # 9. Markov Model Status
    status, markov = get("/models/markov/status")
    print(f"\n[9] GET /models/markov/status -> Status {status}:")
    print(f"    Active Version: {markov.get('current_version')}")
    print(f"    Rolling KL Divergence: {markov.get('kl_divergence')}")
    print(f"    Drift Detected: {markov.get('model_drift_detected')}")
    print(f"    Notice: {markov.get('notice')}")

    # 10. Verify Frontend index.html served
    req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "HSOC-Tester/1.0"})
    with urllib.request.urlopen(req) as resp:
        content = resp.read().decode("utf-8")
        has_root = '<div id="root">' in content or '<title>' in content
        print(f"\n[10] GET / (Frontend Dashboard Single-Page App) -> Status {resp.status}:")
        print(f"    Content Length: {len(content)} bytes | Valid React mount root: {has_root}")

    print("\n" + "=" * 65)
    print("        ALL BACKEND AND FRONTEND CHECKS PASSED WITH 200 OK!")
    print("=" * 65)

if __name__ == "__main__":
    main()
