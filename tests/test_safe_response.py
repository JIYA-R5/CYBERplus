"""
Automated Test Suite for SentinelAI Safe Response Orchestration Module.
Verifies allowlist protection, temporary duration expiry, explicit admin approvals,
permanent block safeguards, honest verification, and reversible rollback execution.
"""

import pytest
import os
import tempfile
import datetime
from response_engine import ResponseEngine, get_response_engine, is_ip_allowlisted, DEFAULT_PROTECTED_IPS
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


def test_allowlist_infrastructure_rejection(response_engine, temp_db):
    """Verify that protected gateways, DNS, and loopback IPs are strictly rejected from blocking."""
    protected_test_ips = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "8.8.8.8", "1.1.1.1"]

    for ip in protected_test_ips:
        is_prot, reason = is_ip_allowlisted(ip)
        assert is_prot is True
        assert len(reason) > 10

        res = response_engine.execute_response_action(
            incident_id="INC-ALLOW-TEST",
            action_type="FIREWALL_BLOCK",
            target_ip=ip,
            dry_run=True,
            operator="SOC Automated Engine",
            db_manager=temp_db
        )
        assert res["status"] == "REJECTED"
        assert res["result"] == "PROTECTED_ALLOWLIST_VIOLATION"
        assert "Containment rejected" in res["message"]


def test_response_recommendation_contents(response_engine):
    """Verify mitigation plan includes duration, evidence, risk, and rollback commands."""
    plan = response_engine.get_mitigation_plan(
        activity="Port Scan",
        source_ip="198.51.100.88",
        risk="High",
        duration_minutes=60
    )

    assert plan["source_ip"] == "198.51.100.88"
    assert plan["proposed_duration_minutes"] == 60
    assert plan["is_allowlisted"] is False
    assert "firewall_commands" in plan
    assert "rollback_commands" in plan
    assert "Windows PowerShell" in plan["firewall_commands"]
    assert "Linux iptables" in plan["firewall_commands"]
    assert "Remove-NetFirewallRule" in plan["rollback_commands"]["Windows PowerShell"]


def test_admin_approval_gate_for_live_execution(response_engine, temp_db):
    """Verify live firewall actions are rejected without explicit administrator approval."""
    # Attempt live execution without admin approval
    res_unapproved = response_engine.execute_response_action(
        incident_id="INC-LIVE-01",
        action_type="FIREWALL_BLOCK",
        target_ip="198.51.100.22",
        dry_run=False,
        admin_approved=False,
        operator="Junior Analyst",
        db_manager=temp_db
    )
    assert res_unapproved["status"] == "REJECTED"
    assert res_unapproved["result"] == "ADMIN_APPROVAL_REQUIRED"

    # With explicit admin approval
    res_approved = response_engine.execute_response_action(
        incident_id="INC-LIVE-01",
        action_type="FIREWALL_BLOCK",
        target_ip="198.51.100.22",
        dry_run=False,
        admin_approved=True,
        operator="SOC Admin Lead",
        db_manager=temp_db
    )
    assert res_approved["status"] == "SUCCESS"
    assert res_approved["execution_mode"] == "live"
    assert res_approved["result"] == "VERIFIED_CONTAINED"


def test_permanent_block_privilege_safeguards(response_engine, temp_db):
    """Verify permanent bans require both admin approval and written justification."""
    # Permanent ban with no justification
    res_no_just = response_engine.execute_response_action(
        incident_id="INC-PERM-01",
        action_type="FIREWALL_BLOCK",
        target_ip="198.51.100.33",
        dry_run=True,
        rule_type="Permanent",
        admin_approved=True,
        justification="",
        db_manager=temp_db
    )
    assert res_no_just["status"] == "REJECTED"
    assert res_no_just["result"] == "PRIVILEGED_JUSTIFICATION_REQUIRED"

    # Permanent ban with valid justification and approval
    res_valid_perm = response_engine.execute_response_action(
        incident_id="INC-PERM-01",
        action_type="FIREWALL_BLOCK",
        target_ip="198.51.100.33",
        dry_run=True,
        rule_type="Permanent",
        admin_approved=True,
        justification="Confirmed external C2 node verified by threat intel and recurrent probing.",
        db_manager=temp_db
    )
    assert res_valid_perm["status"] == "SUCCESS"
    assert res_valid_perm["rule_type"] == "Permanent"


def test_temporary_block_expiry_and_rollback(response_engine, temp_db):
    """Verify active blocks track expiry and watchdog executes automated expiration."""
    # Create block that is already past its expiration
    past_ts = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    block_id = temp_db.create_active_block(
        incident_id="INC-EXP-01",
        target_ip="198.51.100.44",
        rule_type="Temporary",
        duration_minutes=15,
        approval_status="Approved",
        approved_by="SOC Admin",
        verification_status="VERIFIED_DRY_RUN",
        rollback_commands={"Linux iptables": "sudo iptables -D INPUT -s 198.51.100.44 -j DROP"},
        audit_id="AUD-TEST-EXP"
    )

    # Force expiration time to past
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE active_blocks SET expires_at = ? WHERE block_id = ?", (past_ts, block_id))
        conn.commit()

    # Run watchdog expiry check
    expired_blocks = temp_db.check_and_expire_blocks()
    assert len(expired_blocks) == 1
    assert expired_blocks[0]["block_id"] == block_id
    assert expired_blocks[0]["target_ip"] == "198.51.100.44"

    # Verify status updated to Expired
    blocks = temp_db.get_active_blocks()
    matching = [b for b in blocks if b["block_id"] == block_id][0]
    assert matching["status"] == "Expired"


def test_manual_rollback_execution(temp_db):
    """Verify manual rollback transitions status to Rolled_Back and logs audit trail."""
    block_id = temp_db.create_active_block(
        incident_id="INC-ROLL-01",
        target_ip="198.51.100.77",
        rule_type="Temporary",
        duration_minutes=30,
        approval_status="Approved",
        approved_by="SOC Admin",
        verification_status="VERIFIED_DRY_RUN",
        rollback_commands={"Windows PowerShell": "Remove-NetFirewallRule -DisplayName SentinelAI_Block_198.51.100.77"}
    )

    roll_res = temp_db.rollback_block(block_id=block_id, operator="Lead Responder John")
    assert roll_res["status"] == "SUCCESS"
    assert roll_res["block_id"] == block_id

    # Verify status in database
    blocks = temp_db.get_active_blocks()
    matching = [b for b in blocks if b["block_id"] == block_id][0]
    assert matching["status"] == "Rolled_Back"

    # Verify audit log entry
    logs = temp_db.get_audit_logs()
    roll_logs = [l for l in logs if l["action_type"] == "FIREWALL_ROLLBACK"]
    assert len(roll_logs) >= 1
    assert roll_logs[0]["operator"] == "Lead Responder John"
