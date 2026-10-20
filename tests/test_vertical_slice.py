"""
Unit & Integration Test Suite for SentinelAI Vertical Slice:
Telemetry Event -> ML/Rule Detection -> Persistent Incident -> Analyst Feedback -> Dry-Run Response -> Audit Entry
"""

import pytest
import os
import tempfile
import pandas as pd
from detector import ThreatDetector, get_detector, Incident
from ml_engine import MLAnomalyEngine
from response_engine import ResponseEngine, get_response_engine
from database import DatabaseManager


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = f.name
    db = DatabaseManager(db_path=temp_path)
    yield db
    if os.path.exists(temp_path):
        try:
            os.remove(temp_path)
        except OSError:
            pass


@pytest.fixture
def detector():
    return get_detector()


@pytest.fixture
def response_engine():
    return get_response_engine()


def test_complete_vertical_slice(detector, response_engine, temp_db):
    """
    Validate the end-to-end vertical pipeline:
    1. Telemetry Event Ingestion
    2. Hybrid Rule + ML Anomaly Scoring
    3. Persistent Threat Memory (SQLite)
    4. Analyst Ground-Truth Feedback & Lifecycle Transition
    5. Safe Dry-Run Response Recommendation
    6. Tamper-Evident Audit Trail
    """
    # --------------------------------------------------------------------------
    # Step 1 & 2: Telemetry Event Ingestion & Dual Rule/ML Evaluation
    # --------------------------------------------------------------------------
    raw_event = {
        "Source IP": "198.51.100.42",
        "Destination IP": "192.168.1.30",
        "Port": 22,
        "Packets": 320,
        "Protocol": "TCP",
        "Activity": "Brute Force",
        "Risk": "High",
        "Time": "12:00:05"
    }

    eval_result = detector.evaluate_flow(
        packets=raw_event["Packets"],
        activity=raw_event["Activity"],
        source_ip=raw_event["Source IP"],
        destination_port=raw_event["Port"],
        destination_ip=raw_event["Destination IP"],
        raw_risk=raw_event["Risk"]
    )

    # Validate Rule Result
    assert eval_result["threat_detected"] is True
    assert eval_result["activity"] == "Brute Force"
    assert eval_result["risk"] == "High"
    assert eval_result["rule_id"] == "RULE-BRUTE-FORCE-01"
    assert eval_result["mitre_id"] == "T1110"

    # Validate ML Anomaly Score separation
    assert "ml_anomaly_score" in eval_result
    assert "ml_is_anomaly" in eval_result
    assert "model_version" in eval_result
    assert "ml_disclaimer" in eval_result
    assert "NOT proof" in eval_result["ml_disclaimer"]

    # --------------------------------------------------------------------------
    # Step 3: Persistent Threat Memory (Incident Creation)
    # --------------------------------------------------------------------------
    incident_payload = {
        "incident_id": "INC-VERT-001",
        "category": eval_result["activity"],
        "source_ip": eval_result["source_ip"],
        "destination_ip": raw_event["Destination IP"],
        "destination_ports": [eval_result["destination_port"]],
        "protocols": [raw_event["Protocol"]],
        "event_count": 1,
        "total_packets": eval_result["packets"],
        "severity": eval_result["risk"],
        "confidence": eval_result["confidence"],
        "rule_id": eval_result["rule_id"],
        "mitre_id": eval_result["mitre_id"],
        "evidence": eval_result["details"],
        "recommended_action": eval_result["recommended_action"],
        "detection_method": "Rule Heuristics & ML Anomaly Scoring",
        "model_version": eval_result["model_version"],
        "ml_anomaly_score": eval_result["ml_anomaly_score"],
        "ml_is_anomaly": eval_result["ml_is_anomaly"],
        "status": "Open",
        "analyst_verdict": "Unreviewed",
        "raw_evidence": f"Flow event on port {eval_result['destination_port']} with {eval_result['packets']} packets"
    }

    saved_id = temp_db.save_incident(incident_payload)
    assert saved_id == "INC-VERT-001"

    retrieved = temp_db.get_incident_by_id("INC-VERT-001")
    assert retrieved is not None
    assert retrieved["source_ip"] == "198.51.100.42"
    assert retrieved["protocols"] == ["TCP"]
    assert retrieved["recurrence_count"] == 1
    assert retrieved["analyst_verdict"] == "Unreviewed"
    assert retrieved["model_version"] == eval_result["model_version"]

    # --------------------------------------------------------------------------
    # Step 4: Analyst Feedback Workflow (Controlled Learning)
    # --------------------------------------------------------------------------
    feedback_id = temp_db.record_analyst_feedback(
        incident_id="INC-VERT-001",
        verdict="True Positive",
        analyst_user="Lead Analyst Sarah",
        reason="Corroborated by SSH server failed auth logs.",
        model_version=eval_result["model_version"]
    )
    assert feedback_id.startswith("FB-")

    # Verify ground-truth feedback is segregated and incident updated
    updated_inc = temp_db.get_incident_by_id("INC-VERT-001")
    assert updated_inc["analyst_verdict"] == "True Positive"
    assert updated_inc["analyst_user"] == "Lead Analyst Sarah"

    feedback_entries = temp_db.get_feedback_history(incident_id="INC-VERT-001")
    assert len(feedback_entries) == 1
    assert feedback_entries[0]["verdict"] == "True Positive"
    assert feedback_entries[0]["analyst_user"] == "Lead Analyst Sarah"

    # --------------------------------------------------------------------------
    # Step 5: Safe Response Recommendation & Dry-Run Execution
    # --------------------------------------------------------------------------
    plan = response_engine.get_mitigation_plan(
        activity=updated_inc["category"],
        source_ip=updated_inc["source_ip"],
        risk=updated_inc["severity"],
        duration_minutes=60
    )
    assert plan["source_ip"] == "198.51.100.42"
    assert plan["proposed_duration_minutes"] == 60
    assert plan["is_allowlisted"] is False
    assert "Windows PowerShell" in plan["firewall_commands"]
    assert "Remove-NetFirewallRule" in plan["rollback_commands"]["Windows PowerShell"]

    # Execute Dry-Run Containment
    resp_result = response_engine.execute_response_action(
        incident_id="INC-VERT-001",
        action_type="FIREWALL_BLOCK",
        target_ip=updated_inc["source_ip"],
        dry_run=True,
        rule_type="Temporary",
        duration_minutes=60,
        operator="Lead Analyst Sarah",
        db_manager=temp_db
    )
    assert resp_result["status"] == "SUCCESS"
    assert resp_result["execution_mode"] == "dry_run"
    assert resp_result["result"] == "SIMULATED_SUCCESS"
    assert resp_result["duration_minutes"] == 60
    assert resp_result["verification_status"] == "VERIFIED_DRY_RUN"
    assert resp_result["audit_id"] is not None
    assert resp_result["block_id"] is not None

    # Verify Active Block tracking in Database
    active_blocks = temp_db.get_active_blocks()
    assert len(active_blocks) == 1
    assert active_blocks[0]["target_ip"] == "198.51.100.42"
    assert active_blocks[0]["duration_minutes"] == 60
    assert active_blocks[0]["expires_at"] is not None

    # --------------------------------------------------------------------------
    # Step 6: Tamper-Evident Audit Entry Verification
    # --------------------------------------------------------------------------
    audit_logs = temp_db.get_audit_logs()
    # Should have audit logs for Feedback and Response Action
    action_types = [a["action_type"] for a in audit_logs]
    assert "ANALYST_FEEDBACK" in action_types
    assert "FIREWALL_BLOCK" in action_types

    fw_log = [a for a in audit_logs if a["action_type"] == "FIREWALL_BLOCK"][0]
    assert fw_log["incident_id"] == "INC-VERT-001"
    assert fw_log["target_ip"] == "198.51.100.42"
    assert fw_log["execution_mode"] == "dry_run"
    assert fw_log["operator"] == "Lead Analyst Sarah"
    assert fw_log["result"] == "SIMULATED_SUCCESS"
