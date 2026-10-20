"""
Automated Test Suite for SentinelAI Persistent Threat & Incident Memory Module.
Verifies schema evolution, raw evidence retention, recurrence tracking,
sensitive log masking, and data retention policies.
"""

import pytest
import os
import tempfile
import json
from database import DatabaseManager, mask_sensitive_payload, IDENTITY_DISCLAIMER


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


def test_schema_upgrade_columns(temp_db):
    """Verify that incidents table has all new threat intelligence and memory columns."""
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(incidents)")
        cols = {row["name"] for row in cursor.fetchall()}

    expected_cols = [
        "protocols", "model_version", "ml_anomaly_score", "ml_is_anomaly",
        "recurrence_count", "analyst_verdict", "analyst_user", "analyst_reason",
        "analyst_timestamp", "response_history", "raw_evidence", "last_seen"
    ]
    for c in expected_cols:
        assert c in cols, f"Missing persistent schema column: {c}"


def test_recurrence_counter_tracking(temp_db):
    """Verify that recurrence counter increments over time for repeated IP indicators."""
    ip = "198.51.100.99"

    # First incident from this IP
    inc1_id = temp_db.save_incident({
        "incident_id": "INC-REC-1",
        "category": "Port Scan",
        "source_ip": ip,
        "severity": "High",
        "confidence": 0.88
    })
    inc1 = temp_db.get_incident_by_id(inc1_id)
    assert inc1["recurrence_count"] == 1

    # Second incident from same IP
    inc2_id = temp_db.save_incident({
        "incident_id": "INC-REC-2",
        "category": "Brute Force",
        "source_ip": ip,
        "severity": "Critical",
        "confidence": 0.95
    })
    inc2 = temp_db.get_incident_by_id(inc2_id)
    assert inc2["recurrence_count"] == 2

    # Third incident from same IP
    inc3_id = temp_db.save_incident({
        "incident_id": "INC-REC-3",
        "category": "DDoS Flood",
        "source_ip": ip,
        "severity": "Critical",
        "confidence": 0.96
    })
    inc3 = temp_db.get_incident_by_id(inc3_id)
    assert inc3["recurrence_count"] == 3


def test_sensitive_payload_masking():
    """Verify that credentials, bearer tokens, and passwords are redacted from stored raw evidence."""
    sensitive_log = {
        "event": "login_attempt",
        "user": "admin",
        "password": "SuperSecretPassword123!",
        "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz1234567890",
        "api_key": "sec_live_abcdef1234567890abcdef"
    }

    masked = mask_sensitive_payload(sensitive_log)
    assert masked["password"] == "[REDACTED]"
    assert masked["token"] == "[REDACTED]"
    assert masked["api_key"] == "[REDACTED]"
    assert masked["user"] == "admin"


def test_identity_disclaimer_compliance():
    """Verify that SentinelAI explicitly refuses to claim IP addresses prove human identity."""
    assert "NOT proof of a specific person's identity" in IDENTITY_DISCLAIMER
    assert "dynamically assigned" in IDENTITY_DISCLAIMER


def test_data_retention_purge(temp_db):
    """Verify data retention controls purge old unflagged telemetry and resolved incidents."""
    # Seed an old resolved incident and an active incident
    temp_db.save_incident({
        "incident_id": "INC-OLD-RESOLVED",
        "first_seen": "2025-01-01 10:00:00",
        "category": "Port Scan",
        "source_ip": "192.168.1.5",
        "status": "Resolved"
    })
    temp_db.save_incident({
        "incident_id": "INC-ACTIVE-CURRENT",
        "first_seen": "2026-10-19 10:00:00",
        "category": "Brute Force",
        "source_ip": "192.168.1.6",
        "status": "Open"
    })

    # Apply 30-day retention purge
    res = temp_db.apply_data_retention(retention_days=30, operator="Maintenance Bot")
    assert res["purged_incidents"] >= 1

    # Active incident must be preserved; old resolved incident should be purged
    assert temp_db.get_incident_by_id("INC-ACTIVE-CURRENT") is not None
    assert temp_db.get_incident_by_id("INC-OLD-RESOLVED") is None

    # Check audit log recorded retention action
    logs = temp_db.get_audit_logs()
    retention_logs = [l for l in logs if l["action_type"] == "DATA_RETENTION_PURGE"]
    assert len(retention_logs) == 1
    assert retention_logs[0]["operator"] == "Maintenance Bot"
