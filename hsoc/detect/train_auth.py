"""
Auth anomaly model training script (Isolation Forest).

Expected data location: ``data/raw/lanl/``
Falls back to synthetic fixture data when absent.

Run::

    python -m hsoc.detect.train_auth

Writes model artefacts to ``data/models/``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def train(data_dir: str = "data/raw/lanl", model_dir: str = "data/models") -> None:
    """
    Train the Isolation Forest auth anomaly model on benign-only windows.

    Args:
        data_dir: Directory containing LANL auth CSV files.
        model_dir: Directory to write trained model artefacts.
    """
    raise NotImplementedError("train_auth will be implemented in M2")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train()
