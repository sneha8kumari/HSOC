"""
Central configuration loader.

Reads ``config/settings.yaml`` once and exposes a typed ``Settings``
object.  All thresholds, windows and weights come from here — never from
hard-coded literals in detection or scoring code.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Default config path (can be overridden via env var for tests)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"
_DEFAULT_ASSET_PATH = Path(__file__).parent.parent / "config" / "asset_inventory.csv"
_DEFAULT_USERS_PATH = Path(__file__).parent.parent / "config" / "users.csv"


class Settings:
    """
    Thin wrapper around the YAML config dict.

    Usage::

        from hsoc.config import get_settings
        cfg = get_settings()
        threshold = cfg.detection["alert_threshold"]
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    # ── Top-level sections ────────────────────────────────────────────────

    @property
    def ingest(self) -> dict[str, Any]:
        """Ingestion settings."""
        return self._data.get("ingest", {})

    @property
    def detection(self) -> dict[str, Any]:
        """Detection settings (rules, thresholds)."""
        return self._data.get("detection", {})

    @property
    def fusion(self) -> dict[str, Any]:
        """Fusion scoring settings."""
        return self._data.get("fusion", {})

    @property
    def correlation(self) -> dict[str, Any]:
        """Correlation window and ignore-list settings."""
        return self._data.get("correlation", {})

    @property
    def severity(self) -> dict[str, Any]:
        """Severity scoring settings."""
        return self._data.get("severity", {})

    @property
    def rag(self) -> dict[str, Any]:
        """RAG retrieval settings."""
        return self._data.get("rag", {})

    @property
    def predictor(self) -> dict[str, Any]:
        """Markov predictor settings."""
        return self._data.get("predictor", {})

    @property
    def genai(self) -> dict[str, Any]:
        """GenAI / LLM settings."""
        return self._data.get("genai", {})

    @property
    def auth_model(self) -> dict[str, Any]:
        """Auth anomaly model settings."""
        return self._data.get("auth_model", {})

    @property
    def simulation(self) -> dict[str, Any]:
        """Simulation and scenario generator settings."""
        return self._data.get("simulation", {})

    @property
    def streaming(self) -> dict[str, Any]:
        """Streaming real-time pipeline settings."""
        return self._data.get("streaming", {})

    @property
    def soar(self) -> dict[str, Any]:
        """SOAR automated response settings."""
        return self._data.get("soar", {})

    @property
    def assets(self) -> dict[str, Any]:
        """Asset inventory and default criticality settings."""
        return self._data.get("assets", {})

    # ── Path helpers ──────────────────────────────────────────────────────

    @property
    def asset_inventory_path(self) -> Path:
        """Path to asset_inventory.csv."""
        return Path(os.getenv("ASSET_INVENTORY_PATH", str(_DEFAULT_ASSET_PATH)))

    @property
    def users_csv_path(self) -> Path:
        """Path to users.csv."""
        return Path(os.getenv("USERS_CSV_PATH", str(_DEFAULT_USERS_PATH)))

    # ── Raw access ────────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Direct dict-style access for nested lookups."""
        return self._data.get(key, default)


@lru_cache(maxsize=1)
def get_settings(config_path: str | None = None) -> Settings:
    """
    Load and cache the YAML settings.

    Args:
        config_path: Override path for tests.  Falls back to the environment
                     variable ``HSOC_CONFIG`` and then the default location.

    Returns:
        A cached ``Settings`` instance.
    """
    path = Path(
        config_path
        or os.getenv("HSOC_CONFIG", str(_DEFAULT_CONFIG_PATH))
    )
    if not path.exists():
        raise FileNotFoundError(
            f"Settings file not found: {path}. "
            "Run 'make setup' or copy config/settings.yaml."
        )
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    return Settings(data)
