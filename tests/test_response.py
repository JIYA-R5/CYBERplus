"""
Unit test suite for SentinelAI Response Engine Module.
Verifies dry-run containment safety, malicious IP rejection, audit logging,
and rollback script generation.
"""

import pytest
import os
import tempfile
from response_engine import ResponseEngine, get_response_engine, sanitize_ip
from database import DatabaseManager


@pytest.fixture
def response_engine():
    return get_response_engine()


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


def test_dry_run_execution_safety(response_engine, temp_db):
    """Verify that dry-run mode generates rules and logs audit trail without modifying OS state."""
    res = response_engine.execute_response_action(
        incident_id="INC-1001",
        action_type="FIREWALL_BLOCK",
        target_ip="192.168.1.15",
        dry_run=True,
        operator="SOC Analyst Jane",
        db_manager=temp_db
    )

    assert res["status"] == "SUCCESS"
    assert res["execution_mode"] == "dry_run"
    assert res["result"] == "SIMULATED_SUCCESS"
    assert "Windows PowerShell" in res["firewall_commands"]
    assert "Linux iptables" in res["firewall_commands"]
    assert "Remove-NetFirewallRule" in res["rollback_commands"]["Windows PowerShell"]
    assert res["audit_id"] is not None

    # Verify audit record stored in SQLite
    audit_logs = temp_db.get_audit_logs()
    assert len(audit_logs) == 1
    assert audit_logs[0]["execution_mode"] == "dry_run"
    assert audit_logs[0]["target_ip"] == "192.168.1.15"


def test_command_injection_rejection(response_engine, temp_db):
    """Verify that command injection attempts in the target IP are immediately rejected."""
    malicious_inputs = [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 | calc.exe",
        "invalid_host_name",
        "192.168.1.1 & format c: /q /y"
    ]

    for bad_ip in malicious_inputs:
        res = response_engine.execute_response_action(
            incident_id="INC-INJECT",
            action_type="FIREWALL_BLOCK",
            target_ip=bad_ip,
            dry_run=True,
            operator="Security Test",
            db_manager=temp_db
        )
        assert res["status"] == "REJECTED"
        assert res["result"] == "VALIDATION_FAILED"
        assert "Security validation failure" in res["message"]


def test_rollback_command_symmetry(response_engine):
    """Verify that rollback scripts match block rules."""
    test_ip = "192.168.1.55"
    block_cmds = response_engine.generate_firewall_commands(test_ip)
    rollback_cmds = response_engine.generate_rollback_commands(test_ip)

    assert "SentinelAI_Block_192.168.1.55" in block_cmds["Windows PowerShell"]
    assert "SentinelAI_Block_192.168.1.55" in rollback_cmds["Windows PowerShell"]
    assert "Remove-NetFirewallRule" in rollback_cmds["Windows PowerShell"]
    assert "sudo iptables -D INPUT" in rollback_cmds["Linux iptables"]
