"""
Unit test suite for SentinelAI Database & Persistence Module.
Verifies SQLite schema creation, incident lifecycle transitions, audit logging,
and demo data reset.
"""

import pytest
import os
import tempfile
from database import DatabaseManager


@pytest.fixture
def temp_db():
    """Create an isolated temporary SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = f.name
    db = DatabaseManager(db_path=temp_path)
    yield db
    if os.path.exists(temp_path):
        try:
            os.remove(temp_path)
        except OSError:
            pass


def test_save_and_retrieve_incident(temp_db):
    """Verify incident insertion and retrieval."""
    incident_data = {
        "incident_id": "INC-TEST-01",
        "category": "Port Scan",
        "source_ip": "192.168.1.15",
        "destination_ip": "10.0.0.1",
        "destination_ports": [80, 443, 22],
        "event_count": 3,
        "total_packets": 300,
        "severity": "High",
        "confidence": 0.88,
        "rule_id": "RULE-PORT-SCAN-01",
        "mitre_id": "T1046",
        "evidence": "Scanned 3 ports in 10s",
        "recommended_action": "Block IP",
        "status": "Open"
    }

    inc_id = temp_db.save_incident(incident_data)
    assert inc_id == "INC-TEST-01"

    retrieved = temp_db.get_incident_by_id("INC-TEST-01")
    assert retrieved is not None
    assert retrieved["category"] == "Port Scan"
    assert retrieved["source_ip"] == "192.168.1.15"
    assert retrieved["severity"] == "High"
    assert retrieved["status"] == "Open"
    assert retrieved["destination_ports"] == [80, 443, 22]


def test_update_status_and_audit(temp_db):
    """Verify status update and automatic audit trail creation."""
    temp_db.save_incident({
        "incident_id": "INC-TEST-02",
        "category": "Brute Force",
        "source_ip": "192.168.1.88",
        "severity": "High",
        "confidence": 0.92,
        "status": "Open"
    })

    # Update status to Mitigated
    success = temp_db.update_incident_status("INC-TEST-02", "Mitigated", operator="Analyst Jane")
    assert success is True

    updated = temp_db.get_incident_by_id("INC-TEST-02")
    assert updated["status"] == "Mitigated"

    # Verify audit log was created
    audit_logs = temp_db.get_audit_logs(limit=10)
    assert len(audit_logs) >= 1
    recent_log = audit_logs[0]
    assert recent_log["incident_id"] == "INC-TEST-02"
    assert recent_log["action_type"] == "STATUS_UPDATE"
    assert recent_log["operator"] == "Analyst Jane"
    assert "Mitigated" in recent_log["details"]


def test_dry_run_audit_logging(temp_db):
    """Verify recording of defensive actions in dry-run mode."""
    log_id = temp_db.log_audit_action(
        incident_id="INC-TEST-03",
        action_type="FIREWALL_BLOCK",
        target_ip="192.168.1.99",
        execution_mode="dry_run",
        operator="SOC Automated Orchestrator",
        details="Generated PowerShell rule SentinelAI_Block_192.168.1.99",
        result="SIMULATED_SUCCESS"
    )

    assert log_id.startswith("AUD-")
    logs = temp_db.get_audit_logs()
    matching = [l for l in logs if l["log_id"] == log_id]
    assert len(matching) == 1
    assert matching[0]["execution_mode"] == "dry_run"
    assert matching[0]["result"] == "SIMULATED_SUCCESS"


def test_reset_demo_data(temp_db):
    """Verify demo data initialization."""
    temp_db.reset_demo_data()
    incidents = temp_db.get_incidents()
    assert len(incidents) == 4
    categories = [i["category"] for i in incidents]
    assert "Port Scan" in categories
    assert "Brute Force" in categories
    assert "DDoS Flood" in categories
    assert "Data Exfiltration" in categories
