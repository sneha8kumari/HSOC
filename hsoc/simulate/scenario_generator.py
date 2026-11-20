"""
Synthetic attack scenario log generator.

Writes realistic log lines and flow rows — NO real network traffic.
Scenarios S1–S8 are defined in simulate/scenarios/*.yaml and parameterised
by a seed for reproducibility.

Output files (in data/processed/synthetic/):
  - auth.log            Linux sshd/sudo format
  - wazuh_events.jsonl  Windows Security events as Wazuh-style JSON
  - apache_access.log   Apache combined log
  - flows.csv           CICFlowMeter-style CSV
  - truth.jsonl         Ground-truth sidecar (scenario_id, step, technique,
                        tactic, src, target, start_time, end_time)

Run:
    python -m hsoc.simulate.scenario_generator [--seed 42] [--scenarios S1,S2]
"""

from __future__ import annotations

import argparse
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ALL_SCENARIOS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]
_SCENARIO_DIR = Path(__file__).parent / "scenarios"


def _format_syslog_auth(
    dt: datetime, host: str, user: str, src_ip: str, outcome: str, command: str | None = None
) -> str:
    """Render a standard syslog auth.log line."""
    ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if command:
        return f"{ts_str} {host} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
    if outcome == "success":
        port = random.randint(30000, 60000)
        return f"{ts_str} {host} sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {src_ip} port {port} ssh2"
    port = random.randint(30000, 60000)
    return f"{ts_str} {host} sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {user} from {src_ip} port {port} ssh2"


def _format_apache_log(
    dt: datetime, src_ip: str, user: str | None, method: str, path: str, status: int
) -> str:
    """Render an Apache combined log line."""
    ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_str = user if user else "-"
    bytes_sent = random.randint(200, 1500) if status < 400 else random.randint(150, 400)
    return f'{src_ip} - {user_str} [{ts_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "Mozilla/5.0 (compatible; SecurityTester/1.0)"'


def _format_flow_csv(
    dt: datetime, src_ip: str, src_port: int, dst_ip: str, dst_port: int, duration: float, label: str
) -> str:
    """Render a CICFlowMeter CSV row."""
    ts_str = dt.isoformat()
    return f"{ts_str},{src_ip},{src_port},{dst_ip},{dst_port},TCP,{duration:.4f},1,0,{label}"


def generate(
    seed: int = 42,
    scenarios: list[str] | None = None,
    out_dir: str = "data/processed/synthetic",
    start_time: datetime | None = None,
) -> None:
    """
    Generate synthetic attack scenario logs.

    Args:
        seed: Random seed for reproducibility.
        scenarios: List of scenario IDs to generate (default: all).
        out_dir: Output directory for log files and truth.jsonl.
        start_time: Starting timestamp for the simulation run.
    """
    random.seed(seed)
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    if scenarios is None:
        scenarios = ALL_SCENARIOS

    curr_time = start_time or datetime.now(timezone.utc).replace(microsecond=0)

    auth_lines: list[str] = []
    apache_lines: list[str] = []
    flow_lines: list[str] = []
    wazuh_lines: list[str] = []
    truth_records: list[dict[str, Any]] = []

    # Common attacker IP pool
    attacker_ips = [f"203.0.113.{i}" for i in range(10, 50)]

    for sc_id in scenarios:
        yaml_path = _SCENARIO_DIR / f"{sc_id}_"
        matching_files = list(_SCENARIO_DIR.glob(f"{sc_id}*.yaml"))
        if not matching_files:
            logger.warning("Scenario definition for %s not found in %s", sc_id, _SCENARIO_DIR)
            continue

        with open(matching_files[0], "r", encoding="utf-8") as f:
            sc_data = yaml.safe_load(f)

        sc_num = "".join(filter(str.isdigit, sc_id)) or "1"
        default_attacker_ip = f"203.0.113.{10 + int(sc_num)}"
        sc_start = curr_time
        steps = sc_data.get("steps", [])
        techniques = sc_data.get("techniques", [])
        tactic = sc_data.get("tactic", "unknown")

        for step_idx, step in enumerate(steps, start=1):
            st_type = step.get("type")
            duration = step.get("duration_seconds", 30)
            step_label = step.get("label", sc_id)
            step_target = step.get("host") or step.get("dst_ips", ["unknown"])[0]

            raw_src = step.get("src_ip")
            step_src = default_attacker_ip if (not raw_src or raw_src == "{{attacker_ip}}") else raw_src

            truth_records.append(
                {
                    "scenario_id": sc_id,
                    "step": step_idx,
                    "type": st_type,
                    "description": step.get("description", ""),
                    "techniques": techniques,
                    "tactic": tactic,
                    "src_ip": step_src,
                    "target": step_target,
                    "start_time": curr_time.isoformat(),
                    "end_time": (curr_time + timedelta(seconds=duration)).isoformat(),
                    "label": step_label,
                }
            )

            if st_type == "flow":
                dst_ips = step.get("dst_ips") or [step.get("dst_ip", "192.168.56.20")]
                ports_spec = str(step.get("dst_ports", "80"))
                if "-" in ports_spec:
                    start_p, end_p = map(int, ports_spec.split("-"))
                    target_ports = list(range(start_p, min(end_p + 1, start_p + 35)))
                else:
                    target_ports = [int(p) for p in ports_spec.split(",") if p.isdigit()] or [80]

                for p in target_ports:
                    for d_ip in dst_ips:
                        flow_lines.append(
                            _format_flow_csv(
                                curr_time,
                                step_src,
                                random.randint(40000, 65000),
                                d_ip,
                                p,
                                0.05,
                                step_label,
                            )
                        )
                        curr_time += timedelta(seconds=1)

            elif st_type == "auth":
                host = step.get("host", "db-srv-01")
                attempts = step.get("attempts", 1)
                outcome = step.get("outcome", "failure")
                users = step.get("users") or [step.get("user", "admin")]
                command = step.get("command")

                for _ in range(attempts):
                    for u in users:
                        auth_lines.append(
                            _format_syslog_auth(
                                curr_time, host, u, step_src, outcome, command=command
                            )
                        )
                        curr_time += timedelta(seconds=2)

            elif st_type == "web":
                host = step.get("host", "legacy-srv")
                paths = step.get("paths", ["/admin"])
                count = step.get("count", 20)
                status_codes = step.get("status_codes", [401, 403])

                for _ in range(count):
                    path = random.choice(paths)
                    status = random.choice(status_codes)
                    apache_lines.append(
                        _format_apache_log(curr_time, step_src, None, "GET", path, status)
                    )
                    curr_time += timedelta(seconds=1)

            curr_time += timedelta(seconds=5)

    # Write files
    (target_dir / "auth.log").write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    (target_dir / "apache_access.log").write_text("\n".join(apache_lines) + "\n", encoding="utf-8")
    (target_dir / "flows.csv").write_text("\n".join(flow_lines) + "\n", encoding="utf-8")
    (target_dir / "wazuh_events.jsonl").write_text(
        "\n".join(wazuh_lines) + ("\n" if wazuh_lines else ""), encoding="utf-8"
    )

    with open(target_dir / "truth.jsonl", "w", encoding="utf-8") as f:
        for rec in truth_records:
            f.write(json.dumps(rec) + "\n")

    logger.info(
        "Generated synthetic scenario logs in %s: %d auth lines, %d apache lines, %d flow rows, %d truth records",
        out_dir,
        len(auth_lines),
        len(apache_lines),
        len(flow_lines),
        len(truth_records),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(description="H-SOC synthetic scenario generator")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--scenarios",
        type=str,
        default=None,
        help="Comma-separated scenario IDs, e.g. S1,S2",
    )
    ap.add_argument("--out-dir", type=str, default="data/processed/synthetic")
    args = ap.parse_args()
    sc = args.scenarios.split(",") if args.scenarios else None
    generate(seed=args.seed, scenarios=sc, out_dir=args.out_dir)
