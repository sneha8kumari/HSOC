"""
Flow detection model training script (XGBoost + Random Forest baseline).

Expected data location: ``data/raw/cicids2017/``
Falls back to a tiny synthetic fixture when the real dataset is absent.

Run::

    python -m hsoc.detect.train_flow

Writes model artefacts to ``data/models/``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def train(data_dir: str = "data/raw/cicids2017", model_dir: str = "data/models") -> None:
    """
    Train the XGBoost flow detection model.

    Args:
        data_dir: Directory containing CICFlowMeter CSV files.
        model_dir: Directory to write trained model artefacts.
    """
    raise NotImplementedError("train_flow will be implemented in M2")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train()
