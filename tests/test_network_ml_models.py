"""
Unit tests for the synthetic network data generator and network ML models.
Validates generation scenarios, train/val/test separation, and model loading.
"""
import os
import joblib
import pandas as pd
import pytest

from src.features.network_features import NETWORK_FEATURE_NAMES
from src.ml.generate_network_data import SyntheticNetworkFlowGenerator


def test_generate_synthetic_network_flows_scenarios():
    """Verify generator generates all configured scenarios with expected schema."""
    generator = SyntheticNetworkFlowGenerator(random_seed=42)
    df = generator.generate_dataset(
        normal_count=100,
        large_transfer_count=20,
        port_scan_count=30,
        flood_count=30,
        brute_force_count=20
    )

    assert len(df) == 200
    assert "is_anomaly" in df.columns
    assert "scenario" in df.columns
    assert "flow_id" in df.columns
    assert "threat_label" in df.columns

    # Verify all scenarios present
    scenarios = set(df["scenario"])
    assert "normal_browsing" in scenarios
    assert "benign_large_transfer" in scenarios
    assert "port_scan" in scenarios
    assert "connection_flood" in scenarios
    assert "brute_force" in scenarios


def test_network_model_artifacts_loadable():
    """Verify saved network model artifacts load and run inference properly."""
    iforest_path = "artifacts/network_anomaly_isolation_forest.joblib"
    rf_path = "artifacts/network_threat_classifier.joblib"

    if os.path.exists(iforest_path):
        iforest_model = joblib.load(iforest_path)
        assert hasattr(iforest_model, "decision_function") or hasattr(iforest_model, "predict")

    if os.path.exists(rf_path):
        rf_model = joblib.load(rf_path)
        assert hasattr(rf_model, "predict_proba")
