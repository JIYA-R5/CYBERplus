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


def test_scenario_1_normal_traffic_preservation(detector):
    """Verify that nominal traffic is preserved as not detected with zero false positive incidents."""
    normal_df = pd.DataFrame({
        "Time": ["10:00:01", "10:00:04", "10:00:08", "10:00:12"],
        "Source IP": ["192.168.1.10", "192.168.1.12", "192.168.1.20", "192.168.1.25"],
        "Destination IP": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.1"],
        "Port": [443, 80, 53, 443],
        "Packets": [120, 95, 45, 140],
        "Activity": ["Normal Traffic", "Normal Traffic", "Normal Traffic", "Normal Traffic"],
        "Risk": ["Low", "Low", "Low", "Low"]
    })

    enriched = detector.detect_dataframe(normal_df)
    assert len(enriched) == 4
    assert (enriched["Threat Detected"] == False).all()
    assert (enriched["Risk"] == "Low").all()
    assert (enriched["Activity"] == "Normal Traffic").all()
    assert (enriched["Incident ID"] == "-").all()

    incidents = detector.correlate_incidents(normal_df)
    assert len(incidents) == 0


def test_scenario_2_port_scan_correlation(detector):
    """Verify 14 port probe records correlate into 1 High-risk incident without spurious Brute Force alerts."""
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
    scan_df = pd.DataFrame({
        "Time": [f"11:00:{30+i:02d}" for i in range(14)],
        "Source IP": ["198.51.100.23"] * 14,
        "Destination IP": ["192.168.1.20"] * 14,
        "Port": scan_ports,
        "Packets": [1] * 14,
        "Activity": ["SIMULATED: Possible port scan - multiple destination ports"] * 14,
        "Risk": ["High"] * 14
    })

    incidents = detector.correlate_incidents(scan_df)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == "Port Scan"
    assert inc.severity == "High"
    assert inc.mitre_id == "T1046"
    assert inc.event_count == 14
    assert inc.confidence >= 0.95
    assert inc.source_ip == "198.51.100.23"
    assert inc.destination_ip == "192.168.1.20"

    # Enriched dataframe should group all 14 rows under the same Incident ID
    enriched = detector.detect_dataframe(scan_df)
    assert (enriched["Threat Detected"] == True).all()
    assert (enriched["Activity"] == "Port Scan").all()
    assert (enriched["Risk"] == "High").all()
    assert enriched["Incident ID"].nunique() == 1
    assert enriched["Incident ID"].iloc[0].startswith("INC-PORT-")


def test_scenario_3_repeated_ssh_failures(detector):
    """Verify 12 repeated SSH authentication failure records correlate into 1 Brute Force incident."""
    auth_df = pd.DataFrame({
        "Time": [f"11:01:{10+i:02d}" for i in range(12)],
        "Source IP": ["203.0.113.45"] * 12,
        "Destination IP": ["192.168.1.30"] * 12,
        "Port": [22] * 12,
        "Packets": [1] * 12,
        "Activity": ["SIMULATED: Repeated SSH authentication failures"] * 12,
        "Risk": ["Critical"] * 12
    })

    incidents = detector.correlate_incidents(auth_df)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == "Brute Force"
    assert inc.severity in ("Critical", "High")
    assert inc.mitre_id == "T1110"
    assert inc.event_count == 12
    assert inc.confidence >= 0.95
    assert inc.destination_ports == [22]

    enriched = detector.detect_dataframe(auth_df)
    assert (enriched["Threat Detected"] == True).all()
    assert (enriched["Activity"] == "Brute Force").all()
    assert (enriched["Risk"].isin(["Critical", "High"])).all()
    assert enriched["Incident ID"].nunique() == 1
    assert enriched["Incident ID"].iloc[0].startswith("INC-AUTH-")


def test_scenario_4_http_traffic_burst(detector):
    """Verify 10 simulated HTTP burst records correlate into 1 Traffic Burst incident without claiming DDoS."""
    burst_df = pd.DataFrame({
        "Time": [f"11:01:{50+i:02d}" for i in range(10)],
        "Source IP": [f"198.51.100.{100 + (i%5)*4}" for i in range(10)],
        "Destination IP": ["192.168.1.40"] * 10,
        "Port": [80] * 10,
        "Packets": [1] * 10,
        "Activity": ["SIMULATED: HTTP traffic burst to one destination"] * 10,
        "Risk": ["High"] * 10
    })

    incidents = detector.correlate_incidents(burst_df)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == "Traffic Burst"
    assert inc.category != "DDoS Flood"
    assert inc.mitre_id == "T1499"
    assert inc.event_count == 10
    assert inc.destination_ports == [80]
    assert inc.confidence >= 0.85

    enriched = detector.detect_dataframe(burst_df)
    assert (enriched["Threat Detected"] == True).all()
    assert (enriched["Activity"] == "Traffic Burst").all()
    assert enriched["Incident ID"].nunique() == 1
    assert enriched["Incident ID"].iloc[0].startswith("INC-BURST-")


def test_full_73_record_security_audit_dataset(detector):
    """End-to-end verification of the 73-record audit dataset resolving all reported discrepancies."""
    from log_parser import LogParser
    import os

    sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "sentinelai_suricata_eve_sample.json")
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    events, errors = LogParser.parse_suricata_eve(content)
    assert len(events) == 73
    assert len(errors) == 0

    df = LogParser.events_to_dataframe(events)
    assert len(df) == 73

    # Enriched DataFrame classifications
    enriched = detector.detect_dataframe(df)
    assert len(enriched) == 73

    counts_detected = enriched["Threat Detected"].value_counts()
    assert counts_detected[False] == 37  # 37 normal records classified as not detected
    assert counts_detected[True] == 36   # 36 attack records detected (14 port scan + 12 SSH + 10 burst)

    counts_act = enriched["Activity"].value_counts()
    assert counts_act["Normal Traffic"] == 37
    assert counts_act["Port Scan"] == 14
    assert counts_act["Brute Force"] == 12
    assert counts_act["Traffic Burst"] == 10

    counts_risk = enriched["Risk"].value_counts()
    assert counts_risk["Low"] == 37
    assert counts_risk["High"] == 24
    assert counts_risk["Critical"] == 12

    # Exactly 3 correlated incidents generated
    incidents = detector.correlate_incidents(df)
    assert len(incidents) == 3

    categories = [i.category for i in incidents]
    assert "Port Scan" in categories
    assert "Brute Force" in categories
    assert "Traffic Burst" in categories
    assert "DDoS Flood" not in categories


def test_malformed_and_edge_case_inputs(detector):
    """Verify handling of invalid timestamps, ports, missing values, and command injection."""
    malformed_df = pd.DataFrame({
        "Time": ["invalid_timestamp", "2026-99-99T99:99:99", None, "10:00:01"],
        "Source IP": ["192.168.1.1; cat /etc/passwd", "256.256.256.256", None, "192.168.1.50"],
        "Destination IP": ["10.0.0.1", None, "invalid_dst", "10.0.0.2"],
        "Port": ["not_a_port", 999999, -5, 443],
        "Packets": ["invalid_pkts", None, -500, 100],
        "Activity": [None, "", "Unknown Activity", "Normal Traffic"]
    })

    enriched = detector.detect_dataframe(malformed_df)
    assert len(enriched) == 4
    assert (enriched["Threat Detected"] == False).all()
    assert (enriched["Risk"] == "Low").all()
