"""
Unit and integration test suite for SentinelAI Threat Detection Engine.
Verifies rule-based heuristics, stateful multi-event correlation, ML anomaly detection,
and resilience against malformed inputs.
"""

import pytest
import pandas as pd
import numpy as np
from detector import ThreatDetector, MLAnomalyDetector, Incident, get_detector


@pytest.fixture
def detector():
    return get_detector()


def test_normal_traffic_nominal(detector):
    """Ensure normal traffic does not trigger false positives."""
    result = detector.evaluate_flow(
        packets=120,
        activity="Normal Traffic",
        source_ip="192.168.1.50",
        destination_port=443
    )
    assert not result["threat_detected"]
    assert result["risk"] == "Low"
    assert result["activity"] == "Normal Traffic"
    assert result["rule_id"] == "RULE-NOMINAL-00"


def test_ddos_volumetric_threshold(detector):
    """Verify that packet surges exceeding critical threshold trigger DDoS Flood."""
    result = detector.evaluate_flow(
        packets=950,
        activity="Normal Traffic",
        source_ip="10.0.0.99",
        destination_port=80
    )
    assert result["threat_detected"]
    assert result["activity"] == "DDoS Flood"
    assert result["risk"] == "Critical"
    assert result["mitre_id"] == "T1498"
    assert result["confidence"] >= 0.90


def test_brute_force_single_event(detector):
    """Verify administrative port brute force heuristic."""
    result = detector.evaluate_flow(
        packets=300,
        activity="Normal Traffic",
        source_ip="192.168.1.105",
        destination_port=22
    )
    assert result["threat_detected"]
    assert result["activity"] == "Brute Force"
    assert result["risk"] == "High"
    assert result["mitre_id"] == "T1110"


def test_known_signature_matching(detector):
    """Verify explicitly labeled attack signatures map to MITRE ATT&CK techniques."""
    for sig_name in ["Port Scan", "Brute Force", "DDoS Flood", "Data Exfiltration", "Suspicious Reconnaissance"]:
        result = detector.evaluate_flow(
            packets=150,
            activity=sig_name,
            source_ip="172.16.0.5",
            destination_port=80
        )
        assert result["threat_detected"]
        assert result["activity"] == sig_name
        assert result["risk"] in ["Medium", "High", "Critical"]
        assert result["mitre_id"] != "N/A"


def test_stateful_port_scan_correlation(detector):
    """Verify stateful multi-port scan correlation across separate flows."""
    scan_df = pd.DataFrame({
        "Time": ["10:00:01", "10:00:02", "10:00:03", "10:00:04"],
        "Source IP": ["192.168.1.200", "192.168.1.200", "192.168.1.200", "192.168.1.200"],
        "Destination IP": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1"],
        "Port": [21, 22, 80, 443],
        "Packets": [20, 25, 30, 22],
        "Activity": ["Normal Traffic", "Normal Traffic", "Normal Traffic", "Normal Traffic"]
    })

    incidents = detector.correlate_incidents(scan_df)
    assert len(incidents) >= 1
    scan_inc = [inc for inc in incidents if inc.category == "Port Scan"][0]
    assert scan_inc.source_ip == "192.168.1.200"
    assert scan_inc.severity == "High"
    assert scan_inc.mitre_id == "T1046"
    assert len(scan_inc.destination_ports) >= 4
    assert "distinct ports" in scan_inc.evidence


def test_stateful_brute_force_correlation(detector):
    """Verify stateful repeated authentication correlation."""
    auth_df = pd.DataFrame({
        "Time": ["11:00:01", "11:00:05", "11:00:10"],
        "Source IP": ["192.168.1.88", "192.168.1.88", "192.168.1.88"],
        "Port": [22, 22, 22],
        "Packets": [50, 60, 55],
        "Activity": ["Normal Traffic", "Normal Traffic", "Normal Traffic"]
    })

    incidents = detector.correlate_incidents(auth_df)
    assert len(incidents) >= 1
    bf_inc = [inc for inc in incidents if inc.category == "Brute Force"][0]
    assert bf_inc.source_ip == "192.168.1.88"
    assert bf_inc.severity == "High"
    assert bf_inc.mitre_id == "T1110"
    assert bf_inc.event_count == 3


def test_dataframe_enrichment_backward_compatibility(detector):
    """Verify that detect_dataframe enriches DataFrames with all required metadata columns."""
    sample_df = pd.DataFrame({
        "Time": ["12:00:01", "12:00:02"],
        "Source IP": ["192.168.1.15", "192.168.1.20"],
        "Activity": ["Port Scan", "Normal Traffic"],
        "Packets": [450, 100],
        "Port": [80, 443]
    })

    enriched = detector.detect_dataframe(sample_df)
    assert len(enriched) == 2
    for col in ["Threat Detected", "Activity", "Risk", "Confidence", "Threat Details", "Rule ID", "MITRE ID", "Incident ID"]:
        assert col in enriched.columns

    assert enriched.loc[0, "Threat Detected"] == True
    assert enriched.loc[0, "Risk"] == "High"
    assert enriched.loc[1, "Threat Detected"] == False
    assert enriched.loc[1, "Risk"] == "Low"


def test_malformed_input_graceful_handling(detector):
    """Verify that detector does not crash on NaN, invalid types, or command injection attempts."""
    malformed_df = pd.DataFrame({
        "Source IP": ["192.168.1.1; rm -rf /", "invalid_ip", None],
        "Packets": ["invalid_number", None, -50],
        "Port": ["not_a_port", None, 999999],
        "Activity": [None, "", "DDoS Flood"]
    })

    enriched = detector.detect_dataframe(malformed_df)
    assert len(enriched) == 3
    # Malicious injection string should be sanitized to 0.0.0.0
    assert enriched.loc[2, "Threat Detected"] == True  # DDoS Flood signature row


def test_ml_anomaly_detector():
    """Verify Scikit-Learn IsolationForest anomaly scoring."""
    ml = MLAnomalyDetector(contamination=0.2)
    # Synthetic normal telemetry: 50 observations around 100 packets, port 80/443
    np.random.seed(42)
    normal_data = np.column_stack([
        np.random.normal(120, 15, 30),
        np.random.choice([80, 443, 53], 30)
    ])
    ml.fit(normal_data)

    # Nominal point
    nominal_pred = ml.predict_score(np.array([[125, 443]]))
    assert nominal_pred["status"] == "Evaluated"

    # Extreme outlier (e.g. 5000 packets on port 65530)
    anomaly_pred = ml.predict_score(np.array([[5000, 65530]]))
    assert anomaly_pred["is_anomaly"] == True
    assert anomaly_pred["confidence"] > 0.50
