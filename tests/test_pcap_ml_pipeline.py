"""
SentinelAI - Automated Test Suite for PCAP Ingestion, Bidirectional Flow Aggregation,
Supervised ML Training, Redis Streams, PostgreSQL Persistence, and Security Guardrails.
"""

import os
import io
import time
import struct
import tempfile
import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from pcap_engine import (
    PCAPValidator,
    PCAPValidationError,
    NativePCAPReader,
    BidirectionalFlowAggregator,
    PCAPJobManager,
    get_job_manager
)
from ml_engine import (
    FLOW_FEATURE_NAMES,
    TelemetryFeatureExtractor,
    ThreatPreprocessingPipeline,
    SupervisedThreatClassifier,
    SecurityPolicyViolationError,
    get_supervised_classifier,
    get_ml_engine
)
from detector import ThreatDetector, Incident
from database import DatabaseManager, get_db
from stream_engine import RedisStreamPublisher, get_stream_publisher
from api.index import app


# ------------------------------------------------------------------------------
# Test Fixtures & Synthetic PCAP Generators
# ------------------------------------------------------------------------------
@pytest.fixture
def client():
    return TestClient(app)


def build_synthetic_pcap_bytes():
    """Build valid little-endian microsecond PCAP bytes with TCP packets."""
    buf = io.BytesIO()
    # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    buf.write(global_hdr)

    # Packet 1: Forward SYN packet (Client 192.168.1.50:49152 -> Server 10.0.0.1:80)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" # Eth IPv4
    # IPv4 header: ver=4, ihl=5, total_length=40, id=1, flags=0, ttl=64, proto=6 (TCP)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                         bytes([192, 168, 1, 50]), bytes([10, 0, 0, 1]))
    # TCP header: src_port=49152, dst_port=80, seq=1000, ack=0, offset=5, flags=0x02 (SYN), win=64240
    tcp_hdr = struct.pack("!HHIIBBHHH", 49152, 80, 1000, 0, (5 << 4), 0x02, 64240, 0, 0)
    pkt1_data = eth_hdr + ip_hdr + tcp_hdr
    pkt1_hdr = struct.pack("<IIII", 1700000000, 100000, len(pkt1_data), len(pkt1_data))
    buf.write(pkt1_hdr)
    buf.write(pkt1_data)

    # Packet 2: Backward SYN-ACK packet (Server 10.0.0.1:80 -> Client 192.168.1.50:49152) 50ms later
    ip_hdr2 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 2, 0, 64, 6, 0,
                          bytes([10, 0, 0, 1]), bytes([192, 168, 1, 50]))
    tcp_hdr2 = struct.pack("!HHIIBBHHH", 80, 49152, 2000, 1001, (5 << 4), 0x12, 64240, 0, 0) # SYN+ACK
    pkt2_data = eth_hdr + ip_hdr2 + tcp_hdr2
    pkt2_hdr = struct.pack("<IIII", 1700000000, 150000, len(pkt2_data), len(pkt2_data))
    buf.write(pkt2_hdr)
    buf.write(pkt2_data)

    # Packet 3: Forward ACK packet (Client -> Server) 20ms later
    tcp_hdr3 = struct.pack("!HHIIBBHHH", 49152, 80, 1001, 2001, (5 << 4), 0x10, 64240, 0, 0) # ACK
    pkt3_data = eth_hdr + ip_hdr + tcp_hdr3
    pkt3_hdr = struct.pack("<IIII", 1700000000, 170000, len(pkt3_data), len(pkt3_data))
    buf.write(pkt3_hdr)
    buf.write(pkt3_data)

    return buf.getvalue()


# ------------------------------------------------------------------------------
# 1. PCAP Magic Bytes & Size Limits Verification
# ------------------------------------------------------------------------------
def test_pcap_validator_magic_bytes_and_size():
    """Verify PCAP and PCAPNG header validation and file size restrictions."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(build_synthetic_pcap_bytes())
        pcap_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        # PCAPNG Section Header Block magic 0x0A0D0D0A
        f.write(b"\x0a\x0d\x0d\x0a\x00\x00\x00\x1c\x1a\x2b\x3c\x4d" + b"\x00" * 32)
        pcapng_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00InvalidExecutableHeader")
        invalid_path = f.name

    try:
        # 1. Valid PCAP
        is_valid, fmt, msg = PCAPValidator.validate_file(pcap_path, max_size_bytes=1024 * 1024)
        assert is_valid is True
        assert fmt == "pcap"

        # 2. Valid PCAPNG
        is_valid, fmt, msg = PCAPValidator.validate_file(pcapng_path, max_size_bytes=1024 * 1024)
        assert is_valid is True
        assert fmt == "pcapng"

        # 3. Invalid magic bytes
        with pytest.raises(PCAPValidationError) as exc_info:
            PCAPValidator.validate_file(invalid_path)
        assert "Unsupported file signature" in str(exc_info.value)

        # 4. File size limit enforcement
        with pytest.raises(PCAPValidationError) as exc_info:
            PCAPValidator.validate_file(pcap_path, max_size_bytes=50)
        assert "exceeds allowed limit" in str(exc_info.value)

    finally:
        for p in (pcap_path, pcapng_path, invalid_path):
            if os.path.exists(p):
                os.remove(p)


# ------------------------------------------------------------------------------
# 2. Native Packet Parsing & Bidirectional Flow Aggregation
# ------------------------------------------------------------------------------
def test_native_pcap_parsing_and_bidirectional_aggregation():
    """Verify parsing of Ethernet/IPv4/TCP frames and bidirectional flow aggregation with IAT stats."""
    pcap_bytes = build_synthetic_pcap_bytes()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(pcap_bytes)
        tmp_path = f.name

    try:
        packets = list(NativePCAPReader.parse_pcap(tmp_path))
        assert len(packets) == 3

        # Check packet 1 attributes
        p1 = packets[0]
        assert p1.src_ip == "192.168.1.50"
        assert p1.dst_ip == "10.0.0.1"
        assert p1.src_port == 49152
        assert p1.dst_port == 80
        assert p1.protocol == "TCP"
        assert p1.tcp_flags.get("SYN") is True
        assert p1.tcp_flags.get("ACK") is False

        # Check packet 2 attributes (return flow)
        p2 = packets[1]
        assert p2.src_ip == "10.0.0.1"
        assert p2.dst_ip == "192.168.1.50"
        assert p2.tcp_flags.get("SYN") is True
        assert p2.tcp_flags.get("ACK") is True

        # Aggregate into bidirectional flows
        aggregator = BidirectionalFlowAggregator()
        for pkt in packets:
            aggregator.add_packet(pkt)

        flows = aggregator.get_flows()
        assert len(flows) == 1, "Bidirectional traffic between same endpoints must aggregate into 1 flow"

        flow = flows[0]
        assert flow.total_packets == 3
        assert flow.forward_packets == 2
        assert flow.backward_packets == 1
        assert flow.duration > 0
        assert flow.tcp_flags_seen.get("SYN", 0) >= 1
        assert flow.tcp_flags_seen.get("ACK", 0) >= 1
        assert hasattr(flow, "flow_iat_mean")
        assert flow.flow_iat_mean > 0

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_malformed_pcap_error_tolerance():
    """Verify reader gracefully tolerates truncated or corrupt packets without raising exceptions."""
    pcap_bytes = build_synthetic_pcap_bytes()
    corrupted_bytes = pcap_bytes[:len(pcap_bytes) - 15]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(corrupted_bytes)
        tmp_path = f.name

    try:
        packets = list(NativePCAPReader.parse_pcap(tmp_path))
        # Must parse initial packets without unhandled crash
        assert len(packets) >= 2
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ------------------------------------------------------------------------------
# 3. Flow Feature Extraction & Zero Target Leakage
# ------------------------------------------------------------------------------
def test_flow_feature_extraction_parity():
    """Verify extract_flow_features produces all 19 flow features without target leakage."""
    extractor = TelemetryFeatureExtractor()
    sample_flow = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 22,
        "protocol": "TCP",
        "duration": 1.25,
        "total_packets": 25,
        "total_bytes": 1600,
        "forward_packets": 15,
        "backward_packets": 10,
        "flow_iat_mean": 0.05,
        "flow_iat_std": 0.01,
        "flow_iat_max": 0.12,
        "flow_iat_min": 0.001,
        "fwd_iat_mean": 0.08,
        "bwd_iat_mean": 0.10,
        "tcp_flags_seen": {"SYN": 1, "RST": 0, "ACK": 1}
    }

    X, df = extractor.extract_flow_features([sample_flow])
    assert X.shape == (1, 19)
    assert list(df.columns) == FLOW_FEATURE_NAMES

    # Check zero target leakage
    forbidden_terms = ["threat", "risk", "label", "target", "verdict", "mitre", "rule", "attack"]
    for col in df.columns:
        for f_term in forbidden_terms:
            assert f_term not in col.lower(), f"Potential leakage detected in feature: {col}"


# ------------------------------------------------------------------------------
# 4. Supervised ML Training Pipeline on Existing Synthetic Dataset
# ------------------------------------------------------------------------------
def test_supervised_classifier_training_on_synthetic_dataset():
    """
    Train SupervisedThreatClassifier on existing sentinel_enriched_telemetry.csv.
    Verify holdout evaluation, confusion matrix, precision, recall, F1, and FPR metrics.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "sentinel_enriched_telemetry.csv")
    assert os.path.exists(csv_path), "Existing synthetic dataset must exist"

    df = pd.read_csv(csv_path)
    assert len(df) == 73
    assert "Activity" in df.columns

    with tempfile.TemporaryDirectory() as tmp_dir:
        classifier = SupervisedThreatClassifier(model_dir=tmp_dir)
        metrics = classifier.train_on_dataset(
            data=df,
            label_column="Activity",
            version_tag="v_test_eval",
            test_size=0.25,
            trained_by="Unit Test Runner",
            is_reviewed_ground_truth=True
        )

        assert metrics["status"] == "VALIDATED_AND_TRAINED"
        assert metrics["total_samples"] == 73
        assert metrics["test_sample_count"] > 0
        assert "accuracy" in metrics
        assert "f1_weighted" in metrics
        assert "confusion_matrix" in metrics
        assert "per_class_metrics" in metrics
        assert "false_positive_rate" in metrics

        # Verify confusion matrix covers all classes
        assert "classes" in metrics
        assert len(metrics["confusion_matrix"]) == len(metrics["classes"])

        # Check artifact persistence
        assert os.path.exists(metrics["artifact_path"])


# ------------------------------------------------------------------------------
# 5. Security Guardrail Enforcement (Never Train on Unreviewed Alerts)
# ------------------------------------------------------------------------------
def test_security_guardrail_blocks_unreviewed_training():
    """Verify training is rejected if ground-truth review gate is not satisfied."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    df = pd.read_csv(os.path.join(base_dir, "sentinel_enriched_telemetry.csv"))

    with tempfile.TemporaryDirectory() as tmp_dir:
        classifier = SupervisedThreatClassifier(model_dir=tmp_dir)
        with pytest.raises(SecurityPolicyViolationError) as exc_info:
            classifier.train_on_dataset(
                data=df,
                label_column="Activity",
                is_reviewed_ground_truth=False  # Unreviewed attempt
            )
        assert "Security Policy Guardrail" in str(exc_info.value)


# ------------------------------------------------------------------------------
# 6. Detection Tier Separation & Uncalibrated Anomaly Scores
# ------------------------------------------------------------------------------
def test_detector_tier_separation_and_uncalibrated_scores():
    """
    Verify evaluate_flow clearly categorizes:
    - Deterministic Rule Heuristic
    - Supervised ML Classification
    - Statistical Anomaly Deviation (score reported as raw continuous deviation, not probability)
    """
    detector = ThreatDetector()

    # Flow simulating Brute Force port 22 high packets
    brute_flow = {
        "src_ip": "192.168.1.150",
        "dst_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_port": 22,
        "protocol": "TCP",
        "total_packets": 300,
        "total_bytes": 15000,
        "duration": 0.5
    }

    result = detector.evaluate_flow(brute_flow)
    assert "detection_tier" in result
    assert "rule_id" in result
    assert "supervised_class" in result
    assert "anomaly_score" in result
    assert "is_probability" in result
    # Crucial safety requirement: anomaly scores are uncalibrated continuous values, not probabilities
    assert result["is_probability"] is False


# ------------------------------------------------------------------------------
# 7. Redis Stream & Database Event Logging
# ------------------------------------------------------------------------------
def test_stream_and_database_persistence():
    """Verify telemetry event logging and memory buffer fallback when Redis is standalone."""
    db = get_db()

    # Log event
    ev_id = db.log_telemetry_event({
        "source_ip": "192.168.1.200",
        "destination_ip": "10.0.0.1",
        "port": 80,
        "packets": 5,
        "activity": "Web Browse",
        "risk": "Low"
    })
    assert ev_id.startswith("EVT-")

    # Verify event persisted
    events = db.get_telemetry_events(limit=10)
    assert any(e["event_id"] == ev_id for e in events)

    # Check Stream Engine status
    publisher = get_stream_publisher()
    status = publisher.get_status()
    assert "events_stream" in status
    assert "alerts_stream" in status
    assert status["events_published_total"] >= 1


# ------------------------------------------------------------------------------
# 8. REST API Endpoints Verification
# ------------------------------------------------------------------------------
def test_api_dataset_overview_and_validation(client):
    """Verify /api/dataset/overview and /api/dataset/validate endpoints."""
    res = client.get("/api/dataset/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["sample_count"] == 73
    assert "Activity" in data["label_columns"]
    assert "Normal Traffic" in data["attack_categories"]

    val_res = client.post("/api/dataset/validate", json={"dataset_name": "sentinel_enriched_telemetry.csv", "min_samples": 50})
    assert val_res.status_code == 200
    assert val_res.json()["valid"] is True


def test_api_pcap_upload_and_job_flow(client):
    """Verify PCAP file upload, job status polling, and flow retrieval."""
    pcap_data = build_synthetic_pcap_bytes()
    files = {"file": ("test_capture.pcap", io.BytesIO(pcap_data), "application/vnd.tcpdump.pcap")}

    upload_res = client.post("/api/pcap/upload", files=files)
    assert upload_res.status_code == 200
    job_info = upload_res.json()
    assert "job_id" in job_info
    job_id = job_info["job_id"]

    # Poll status (wait up to 5s for worker completion)
    max_wait = 5.0
    start = time.time()
    status_data = {}
    while time.time() - start < max_wait:
        status_res = client.get(f"/api/pcap/jobs/{job_id}")
        assert status_res.status_code == 200
        status_data = status_res.json()
        if status_data.get("status") in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.1)

    assert status_data["job_id"] == job_id
    assert status_data["status"] == "COMPLETED"
    assert status_data["packet_count"] == 3
    assert status_data["flow_count"] == 1


def test_api_ml_train_guardrail(client):
    """Verify /api/ml/train rejects unreviewed training with 400 Bad Request."""
    payload = {
        "dataset": "sentinel_enriched_telemetry.csv",
        "model_type": "supervised_classifier",
        "is_reviewed_ground_truth": False
    }
    res = client.post("/api/ml/train", json=payload)
    assert res.status_code == 400
    assert "Security Policy Guardrail" in res.json()["detail"]
