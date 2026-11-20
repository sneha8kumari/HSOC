"""
One-command UI Demo Runner (`make demo-ui`).

Executes the full offline demo pipeline and launches the interactive dashboard.
Works offline with Ollama (or local deterministic fallback).

Usage::

    python -m hsoc.demo_ui
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

from hsoc.db import IncidentORM, ReportORM, SessionLocal, init_db
from hsoc.detect import fusion
from hsoc.ingest import collector
from hsoc.investigate import correlate
from hsoc.simulate import benign_generator, scenario_generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def ensure_demo_data(force: bool = False) -> None:
    """Ensure S1..S5 incidents and GenAI reports are generated and persisted."""
    init_db()
    db = SessionLocal()
    try:
        inc_count = db.query(IncidentORM).count()
        rep_count = db.query(ReportORM).count()
    finally:
        db.close()

    if inc_count >= 5 and rep_count >= 5 and not force:
        logger.info("Demo database already populated with %d incidents and %d reports.", inc_count, rep_count)
        return

    logger.info("Generating synthetic attack scenarios S1..S5...")
    scenario_generator.generate(scenarios=["S1", "S2", "S3", "S4", "S5"])
    logger.info("Injecting benign background telemetry...")
    benign_generator.generate_benign()
    logger.info("Ingesting telemetry logs...")
    collector.run(mode="demo")
    logger.info("Running detection fusion pipeline...")
    fusion.run_demo()
    logger.info("Correlating incidents and synthesizing multi-agent reports...")
    correlate.run_demo(generate_reports=True)
    logger.info("Demo data generation complete!")


def ensure_dashboard_built() -> None:
    """Ensure dashboard/dist exists."""
    dashboard_dir = Path(__file__).parent.parent / "dashboard"
    dist_dir = dashboard_dir / "dist"
    if not dist_dir.exists():
        logger.info("Building React/Vite dashboard production bundle...")
        subprocess.run(["npm", "run", "build"], cwd=str(dashboard_dir), shell=True, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="H-SOC One-Command UI Demo")
    parser.add_argument("--force-data", action="store_true", help="Force regenerate demo incidents")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind dashboard server")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--dev", action="store_true", help="Launch Vite dev server on port 5173")
    args = parser.parse_args()

    # 1. Ensure incidents and reports exist
    ensure_demo_data(force=args.force_data)

    # 2. Ensure frontend is compiled
    ensure_dashboard_built()

    url = f"http://localhost:{args.port}"

    print("\n" + "=" * 65)
    print("      H-SOC HYBRID SECURITY OPERATIONS CENTER COMMAND CENTER")
    print("=" * 65)
    print(f"  * Live Incident Dashboard URL : {url}")
    print(f"  * Interactive API Docs        : {url}/docs")
    print(f"  * Replay Mode                 : Active (10x Speed Available)")
    print(f"  * GenAI Mode                  : Offline Ollama / Deterministic Fallback")
    print("=" * 65 + "\n")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import uvicorn
    from hsoc.api.main import app

    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
