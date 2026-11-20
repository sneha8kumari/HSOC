"""
Benign background telemetry generator.

Generates normal enterprise noise:
  - Legitimate user logins during standard working hours
  - Routine web traffic (HTTP 200/304)
  - Typical network flow packets

Appends to files in data/processed/synthetic/ to create realistic signal-to-noise ratio.
"""

from __future__ import annotations

import argparse
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_benign(
    seed: int = 1337,
    count: int = 100,
    out_dir: str = "data/processed/synthetic",
    start_time: datetime | None = None,
) -> None:
    """
    Generate benign enterprise telemetry.

    Args:
        seed: Random seed for reproducibility.
        count: Approximate number of benign events to generate.
        out_dir: Directory containing synthetic logs.
        start_time: Base timestamp for events.
    """
    random.seed(seed)
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    curr_time = start_time or datetime.now(timezone.utc).replace(microsecond=0)

    auth_lines: list[str] = []
    apache_lines: list[str] = []
    flow_lines: list[str] = []

    internal_ips = ["192.168.56.40", "192.168.56.41", "192.168.56.42"]
    normal_users = ["alice", "bob", "charlie"]
    normal_paths = ["/", "/index.html", "/dashboard", "/api/v1/status", "/assets/app.css"]

    for _ in range(count):
        # 1. Benign SSH logins
        user = random.choice(normal_users)
        src_ip = random.choice(internal_ips)
        port = random.randint(30000, 60000)
        ts_str = curr_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        auth_lines.append(
            f"{ts_str} ws-01 sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {src_ip} port {port} ssh2"
        )

        # 2. Benign web requests
        path = random.choice(normal_paths)
        ts_apache = curr_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        bytes_sent = random.randint(500, 5000)
        apache_lines.append(
            f'{src_ip} - {user} [{ts_apache}] "GET {path} HTTP/1.1" 200 {bytes_sent} "http://internal.corp" "Mozilla/5.0"'
        )

        # 3. Benign flows
        dst_port = random.choice([80, 443, 22])
        flow_lines.append(
            f"{curr_time.isoformat()},{src_ip},{port},192.168.56.20,{dst_port},TCP,1.2000,10,12,Benign"
        )

        curr_time += timedelta(seconds=random.randint(2, 10))

    # Append to existing files
    auth_file = target_dir / "auth.log"
    apache_file = target_dir / "apache_access.log"
    flows_file = target_dir / "flows.csv"

    with open(auth_file, "a", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")

    with open(apache_file, "a", encoding="utf-8") as f:
        f.write("\n".join(apache_lines) + "\n")

    with open(flows_file, "a", encoding="utf-8") as f:
        f.write("\n".join(flow_lines) + "\n")

    logger.info(
        "Appended benign traffic to %s: %d auth lines, %d web lines, %d flows",
        out_dir,
        len(auth_lines),
        len(apache_lines),
        len(flow_lines),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(description="H-SOC benign telemetry generator")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--out-dir", type=str, default="data/processed/synthetic")
    args = ap.parse_args()
    generate_benign(seed=args.seed, count=args.count, out_dir=args.out_dir)
