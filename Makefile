# H-SOC Model — Makefile
# Cross-platform note: on Windows, run these via `python -m <target>` or use Git Bash / WSL.
# All targets below call Python directly so they work on any platform.

.PHONY: all setup test lint demo demo-ui api dashboard index train eval-all clean

PYTHON   := python
PIP      := pip
PYTEST   := pytest
UVICORN  := uvicorn
NPM      := npm

# ── All: Complete end-to-end reproducible pipeline ───────────────────────────
all: setup test demo eval-all
	@echo "======================================================================"
	@echo "  H-SOC REPRODUCIBLE PIPELINE COMPLETE: All tests, demo & E1-E6 passed!"
	@echo "======================================================================"


# ── Environment setup ────────────────────────────────────────────────────────
setup:
	@echo "[setup] Installing Python dependencies..."
	$(PIP) install -r requirements.txt
	@echo "[setup] Installing package in editable mode..."
	$(PIP) install -e .
	@echo "[setup] Creating .env from template if missing..."
	@if not exist .env copy .env.example .env
	@echo "[setup] Creating required data directories..."
	@if not exist data\raw\cicids2017 mkdir data\raw\cicids2017
	@if not exist data\raw\unsw_nb15 mkdir data\raw\unsw_nb15
	@if not exist data\raw\lanl mkdir data\raw\lanl
	@if not exist data\raw\sequences mkdir data\raw\sequences
	@if not exist data\kb\manual mkdir data\kb\manual
	@if not exist data\kb\playbooks mkdir data\kb\playbooks
	@echo "[setup] Done. Edit .env before running the API."

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	@echo "[test] Running pytest with coverage..."
	$(PYTEST) --cov=hsoc --cov-report=term-missing --cov-report=html tests/

# ── Linting ──────────────────────────────────────────────────────────────────
lint:
	@echo "[lint] Running ruff..."
	ruff check hsoc/ tests/
	@echo "[lint] Running black (check mode)..."
	black --check hsoc/ tests/

lint-fix:
	@echo "[lint-fix] Fixing with ruff + black..."
	ruff check --fix hsoc/ tests/
	black hsoc/ tests/

# ── Demo: generate synthetic data, ingest, detect, correlate ─────────────────
demo:
	@echo "[demo] Generating synthetic scenario data (S1..S5)..."
	$(PYTHON) -m hsoc.simulate.scenario_generator --scenarios S1,S2,S3,S4,S5
	@echo "[demo] Generating benign background data..."
	$(PYTHON) -m hsoc.simulate.benign_generator
	@echo "[demo] Ingesting all generated logs..."
	$(PYTHON) -m hsoc.ingest.collector --mode demo
	@echo "[demo] Running detection + correlation pipeline..."
	$(PYTHON) -m hsoc.detect.fusion --mode demo
	@echo "[demo] Correlating incidents and generating GenAI reports..."
	$(PYTHON) -m hsoc.investigate.correlate --mode print

# ── Demo UI: One-command full offline UI showcase ─────────────────────────────
demo-ui:
	@echo "[demo-ui] Launching H-SOC Command Center Dashboard (offline with Ollama/fallback)..."
	$(PYTHON) -m hsoc.demo_ui --no-browser

# ── API server ───────────────────────────────────────────────────────────────
api:
	@echo "[api] Starting FastAPI server on http://localhost:8000 ..."
	$(UVICORN) hsoc.api.main:app --reload --host 0.0.0.0 --port 8000

# ── Dashboard dev server ─────────────────────────────────────────────────────
dashboard:
	@echo "[dashboard] Starting React dashboard dev server..."
	cd dashboard && $(NPM) run dev

# ── Knowledge index build ────────────────────────────────────────────────────
index:
	@echo "[index] Fetching knowledge sources..."
	$(PYTHON) -m hsoc.knowledge.build_index --fetch
	@echo "[index] Building FAISS index..."
	$(PYTHON) -m hsoc.knowledge.build_index --build

# ── ML model training ────────────────────────────────────────────────────────
train:
	@echo "[train] Training flow detection model (XGBoost)..."
	$(PYTHON) -m hsoc.detect.train_flow
	@echo "[train] Training auth anomaly model (Isolation Forest)..."
	$(PYTHON) -m hsoc.detect.train_auth
	@echo "[train] Training Markov predictor..."
	$(PYTHON) -m hsoc.investigate.predictor --train

# ── Benchmark Evaluation Suite (E1–E6) ────────────────────────────────────────
eval-all:
	@echo "[eval-all] Running comprehensive benchmark experiments (E1-E6) & ablations..."
	$(PYTHON) experiments/run_all_experiments.py

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	@echo "[clean] Removing build artefacts..."
	rd /s /q build dist *.egg-info 2>nul || true
	rd /s /q .pytest_cache .ruff_cache 2>nul || true
	del /q .coverage 2>nul || true
	@echo "[clean] Done."
