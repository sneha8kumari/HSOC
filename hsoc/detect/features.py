"""
Feature engineering for the ML flow and auth models.

Produces the feature vectors consumed by ``train_flow.py`` and
``train_auth.py``.  All feature names are stable strings (used as column
headers when saving training sets to disk).
"""

from __future__ import annotations

import pandas as pd

from hsoc.schema import Event


# Flow model features — derived from CICFlowMeter columns
FLOW_FEATURES: list[str] = []   # populated in M2

# Auth model features — per-entity aggregations
AUTH_FEATURES: list[str] = [
    "fail_count",
    "success_count",
    "fail_ratio",
    "distinct_users",
    "distinct_hosts",
    "distinct_srcs",
    "hour_of_day",
    "privileged",
    "mean_inter_arrival",
    "new_src_for_user",
]


def build_auth_features(events: list[Event]) -> pd.DataFrame:
    """
    Aggregate per-(src_ip, user) auth feature vectors.

    Args:
        events: Auth events for the feature window.

    Returns:
        DataFrame with one row per (src_ip, user) pair.
    """
    raise NotImplementedError("build_auth_features will be implemented in M2")
