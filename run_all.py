"""
H-SOC Windows & Cross-Platform Orchestrator (Equivalent to `make all`).

Executes the full pipeline without requiring GNU `make`:
  1. Setup & Environment Validation
  2. Test Suite (pytest)
  3. Attack Scenarios Simulation & Ingestion Demo
  4. Benchmark Evaluation Suite (E1–E6)
"""

import subprocess
import sys
import os

def run_step(name: str, cmd: list[str] | str, check: bool = True):
    print("\n" + "=" * 70)
    print(f"  [RUNNING] {name}")
    print("=" * 70)
    if isinstance(cmd, str):
        res = subprocess.run(cmd, shell=True)
    else:
        res = subprocess.run(cmd)
    if check and res.returncode != 0:
        print(f"\n[ERROR] Step '{name}' failed with exit code {res.returncode}")
        sys.exit(res.returncode)
    return res.returncode

def main():
    import argparse
    parser = argparse.ArgumentParser(description="H-SOC Pipeline Runner")
    parser.add_argument("--skip-tests", action="store_true", help="Skip the 69-test pytest suite")
    args = parser.parse_args()

    print("\n" + "#" * 70)
    print("  H-SOC FULL REPRODUCIBLE PIPELINE (Equivalent to `make all`)")
    print("#" * 70)

    # 1. Tests
    if not args.skip_tests:
        run_step("1/3: Running Pytest Test Suite", [sys.executable, "-m", "pytest", "tests/"])
    else:
        print("\n  [SKIPPED] 1/3: Pytest Suite skipped via --skip-tests flag.")

    # 2. Demo Pipeline
    print("\n" + "-" * 70)
    print("  2/3: Executing End-to-End Demo (Simulation -> Ingest -> Detect -> Correlate)")
    print("-" * 70)
    run_step("Simulation S1..S5", [sys.executable, "-m", "hsoc.simulate.scenario_generator", "--scenarios", "S1,S2,S3,S4,S5"])
    run_step("Benign Telemetry", [sys.executable, "-m", "hsoc.simulate.benign_generator"])
    run_step("Collector Ingestion", [sys.executable, "-m", "hsoc.ingest.collector", "--mode", "demo"])
    run_step("Detection Fusion", [sys.executable, "-m", "hsoc.detect.fusion", "--mode", "demo"])
    run_step("Correlation & Reporting", [sys.executable, "-m", "hsoc.investigate.correlate", "--mode", "print"])

    # 3. Benchmark Evaluations (E1-E6)
    print("\n" + "-" * 70)
    print("  3/3: Running Comprehensive Benchmark Experiments (E1–E6) & Ablations")
    print("-" * 70)
    run_step("Benchmark Evaluations (E1-E6)", [sys.executable, "experiments/run_all_experiments.py"])

    print("\n" + "=" * 70)
    print("  H-SOC ALL PIPELINE STAGES COMPLETED SUCCESSFULLY!")
    print("  Artifacts & plots saved to: experiments/results/")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
