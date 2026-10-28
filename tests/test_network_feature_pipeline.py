"""
Unit tests for the Network Flow Feature Extraction pipeline (src/features/network_features.py).
Validates feature names, calculation from flow dictionary, and division-by-zero resilience.
"""
import pytest
import numpy as np
import pandas as pd
from src.features.network_features import (
    NetworkFlowFeaturePipeline,
    NETWORK_FEATURE_NAMES,
)


@pytest.fixture
def sample_flow_dict():
    """A realistic flow dictionary containing packet metrics."""
    return {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "total_packets": 10,
        "total_bytes": 4500,
        "duration": 1.5,
        "syn_count": 2,
        "ack_count": 8,
        "rst_count": 0,
        "fin_count": 1,
        "mean_packet_length": 450.0,
        "std_packet_length": 120.0,
        "flow_iat_mean": 0.15,
        "flow_iat_std": 0.05,
        "unique_dst_ports_src": 1,
        "flow_frequency_src": 2.0
    }


def test_network_feature_names_count():
    """Verify exactly 27 defensible flow-level features are defined."""
    assert len(NETWORK_FEATURE_NAMES) == 27
    pipeline = NetworkFlowFeaturePipeline()
    assert pipeline.feature_names == NETWORK_FEATURE_NAMES


def test_extract_features_single_dict(sample_flow_dict):
    """Test feature extraction on a single flow dictionary."""
    pipeline = NetworkFlowFeaturePipeline()
    X, df_features = pipeline.extract_features(sample_flow_dict)

    assert isinstance(X, np.ndarray)
    assert X.shape == (1, 27)
    assert isinstance(df_features, pd.DataFrame)
    assert df_features.shape == (1, 27)

    row = df_features.iloc[0]
    assert row["total_packets"] == 10
    assert row["total_bytes"] == 4500
    assert row["duration"] == 1.5
    assert row["packets_per_sec"] == pytest.approx(10 / 1.5, rel=1e-3)
    assert row["protocol_tcp"] == 1.0
    assert row["protocol_udp"] == 0.0
    assert row["is_admin_port"] == 1.0  # Port 443 is admin/HTTPS


def test_extract_features_zero_duration_resilience():
    """Test that zero duration does not raise ZeroDivisionError and safely defaults to 0."""
    zero_flow = {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "total_packets": 1,
        "total_bytes": 60,
        "duration": 0.0,
    }
    pipeline = NetworkFlowFeaturePipeline()
    X, df_features = pipeline.extract_features(zero_flow)

    assert not np.isnan(X).any(), "NaN values found in extracted features"
    assert not np.isinf(X).any(), "Inf values found in extracted features"
    assert np.isfinite(df_features["packets_per_sec"].iloc[0])
    assert df_features["packets_per_sec"].iloc[0] > 0.0
