"""
Automated Test Suite for SentinelAI ML Threat Intelligence Module.
Verifies telemetry feature extraction, missing field imputation, leakage prevention,
Isolation Forest anomaly scoring, model versioning, evaluation metrics, and controlled retraining.
"""

import pytest
import os
import tempfile
import numpy as np
import pandas as pd
from ml_engine import TelemetryFeatureExtractor, MLAnomalyEngine, get_ml_engine, FEATURE_NAMES


@pytest.fixture
def temp_model_dir():
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


def test_feature_extractor_completeness():
    """Verify feature extractor normalizes all 12 engineered telemetry features."""
    extractor = TelemetryFeatureExtractor()
    sample_data = [
        {"Packets": 150, "Port": 443, "Protocol": "TCP", "Action": "Allowed", "Source IP": "192.168.1.10"},
        {"Packets": 90, "Port": 53, "Protocol": "UDP", "Action": "Allowed", "Source IP": "192.168.1.10"},
        {"Packets": 500, "Port": 22, "Protocol": "TCP", "Action": "Denied", "Source IP": "192.168.1.20"}
    ]

    X, feature_df = extractor.extract_features(sample_data)
    assert X.shape == (3, 12)
    assert list(feature_df.columns) == FEATURE_NAMES
    # Flow frequency for 192.168.1.10 should be 2, for 192.168.1.20 should be 1
    assert feature_df.loc[0, "flow_frequency"] == 2.0
    assert feature_df.loc[2, "flow_frequency"] == 1.0
    # Unique ports for 192.168.1.10 should be 2 (443 and 53)
    assert feature_df.loc[0, "unique_ports_contacted"] == 2.0


def test_feature_extractor_missing_and_malformed_handling():
    """Verify feature extractor imputes missing values and prevents crashes on corrupt data."""
    extractor = TelemetryFeatureExtractor()
    corrupt_data = [
        {"Packets": None, "Port": "invalid_port", "Source IP": None},
        {"Packets": "not_a_number", "Port": None, "Protocol": None},
        {}
    ]

    X, feature_df = extractor.extract_features(corrupt_data)
    assert X.shape == (3, 12)
    assert not np.isnan(X).any()
    assert (X[:, 0] == 0.0).all()  # Packets default to 0


def test_zero_target_leakage():
    """Verify that feature set contains no rule outputs, ground truth labels, or target classifications."""
    extractor = TelemetryFeatureExtractor()
    features = extractor.feature_names
    forbidden_terms = ["threat", "risk", "label", "target", "verdict", "mitre", "rule", "attack"]
    for feat in features:
        for term in forbidden_terms:
            assert term not in feat.lower(), f"Potential target leakage in feature: {feat}"


def test_isolation_forest_training_and_metrics(temp_model_dir):
    """Verify Isolation Forest training, baseline evaluation metrics, and artifact serialization."""
    engine = MLAnomalyEngine(model_dir=temp_model_dir)
    fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=100)

    metrics = engine.train(fixtures, version="v1.0.0", contamination=0.15)
    assert metrics["status"] == "TRAINED_SUCCESS"
    assert metrics["sample_count"] == 100
    assert metrics["inlier_count"] + metrics["outlier_count"] == 100
    assert 0.10 <= metrics["empirical_outlier_ratio"] <= 0.20
    assert os.path.exists(metrics["artifact_path"])


def test_scoring_transparency_and_disclaimer(temp_model_dir):
    """Verify continuous score, normalized confidence, and mandatory non-proof disclaimer."""
    engine = MLAnomalyEngine(model_dir=temp_model_dir)
    fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=100)
    engine.train(fixtures, version="v1.0.0")

    # Score nominal flow
    nominal_score = engine.predict_score({"Packets": 100, "Port": 443, "Protocol": "TCP", "Source IP": "192.168.1.15"})
    assert "raw_score" in nominal_score
    assert "confidence" in nominal_score
    assert 0.0 <= nominal_score["confidence"] <= 1.0
    assert "NOT proof" in nominal_score["disclaimer"]

    # Score extreme volumetric spike
    extreme_score = engine.predict_score({"Packets": 50000, "Port": 65530, "Protocol": "TCP", "Source IP": "198.51.100.99"})
    assert extreme_score["is_anomaly"] is True
    assert extreme_score["confidence"] >= 0.50


def test_controlled_retraining_validation(temp_model_dir):
    """Verify that retraining workflow rejects insufficient datasets (<10 samples)."""
    engine = MLAnomalyEngine(model_dir=temp_model_dir)
    tiny_dataset = [{"Packets": 100, "Port": 80}] * 3

    res = engine.train_controlled_pipeline(tiny_dataset, version_tag="v2.0.0")
    assert res["status"] == "VALIDATION_FAILED"
    assert "below minimum required" in res["message"]


def test_controlled_retraining_and_rollback(temp_model_dir):
    """Verify controlled retraining with holdout evaluation and ability to revert model."""
    engine = MLAnomalyEngine(model_dir=temp_model_dir)
    fixtures_v1 = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=80, random_seed=42)
    engine.train(fixtures_v1, version="v1.0.0")
    assert engine.model_version == "v1.0.0"

    # Retrain candidate v1.1.0 with holdout test set evaluation
    fixtures_v2 = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=100, random_seed=99)
    res = engine.train_controlled_pipeline(fixtures_v2, version_tag="v1.1.0", test_size=0.25)
    assert res["status"] == "VALIDATED_AND_TRAINED"
    assert res["model_version"] == "v1.1.0"
    assert res["test_sample_count"] == 25
    assert engine.model_version == "v1.1.0"

    # Revert back to v1.0.0
    revert_ok = engine.revert_model("v1.0.0")
    assert revert_ok is True
    assert engine.model_version == "v1.0.0"
