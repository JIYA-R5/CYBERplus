"""
Automated Test Suite for SentinelAI Intrusion Prevention System (IPS).
Tests:
- Detection rules (Port Scan, Brute-Force, DoS rates, ML anomaly corroboration)
- Firewall enforcement & OS verification (valid IP blocking, invalid IP rejection, private IP protection)
- Safety policies (self-lockout, loopback, gateways, custom allowlists)
- Duplicate block protection & cooldowns
- Automatic expiration & unblocking scheduler
- Startup recovery of offline expired rules
- API authorization & security guardrails
"""

import os
import time
import tempfile
import datetime
import pytest
from fastapi.testclient import TestClient

from database import DatabaseManager
from firewall_manager import (
    BaseFirewallAdapter,
    MockFirewallAdapter,
    validate_ip_for_containment,
    get_local_host_ips
)
from ips_engine import IPSEngine, get_ips_engine


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
def mock_firewall():
    return MockFirewallAdapter()


@pytest.fixture
def ips_engine(temp_db, mock_firewall):
    engine = IPSEngine(db=temp_db, adapter=mock_firewall)
    yield engine
    engine.stop_unblock_scheduler()


# ------------------------------------------------------------------------------
# 1. Detection & Threat Decision Rules Tests
# ------------------------------------------------------------------------------
def test_port_scan_prevention_decision(ips_engine, temp_db):
    """Port scanning pattern with confidence >= threshold triggers automatic block in AUTOMATIC mode."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC", "confidence_threshold": 0.85})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.132",
        category="Port Scan",
        severity="High",
        confidence=0.92,
        detection_reason="Probed 12 distinct ports targeting perimeter within 15s",
        ports_targeted=[22, 80, 443, 8080, 8443]
    )

    assert res["decision"] == "BLOCKED"
    assert res["status"] == "VERIFIED"
    assert res["verified"] is True
    assert res["duration_minutes"] == 15
    assert "SentinelAI_IPS_" in res["firewall_rule_id"]


def test_brute_force_prevention_decision(ips_engine, temp_db):
    """Brute force authentication surge triggers automatic block."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC", "confidence_threshold": 0.85})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.133",
        category="Brute Force",
        severity="High",
        confidence=0.89,
        detection_reason="35 failed authentication attempts against SSH port 22",
        event_count=5,
        ports_targeted=[22]
    )

    assert res["decision"] == "BLOCKED"
    assert res["status"] == "VERIFIED"


def test_dos_flood_prevention_decision(ips_engine, temp_db):
    """Volumetric DoS flood exceeding thresholds triggers automatic containment."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC", "confidence_threshold": 0.85})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.134",
        category="DDoS Flood",
        severity="Critical",
        confidence=0.95,
        detection_reason="Severe packet surge: 8500 packets exceeds critical threshold",
        event_count=8500
    )

    assert res["decision"] == "BLOCKED"
    assert res["status"] == "VERIFIED"


def test_ml_anomaly_alone_does_not_block(ips_engine, temp_db):
    """ML anomaly score alone without deterministic rule match is monitored, NOT automatically blocked."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC", "confidence_threshold": 0.85})

    # High anomaly score, but category is nominal/unverified
    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.135",
        category="Nominal Flow",
        severity="Low",
        confidence=0.60,
        detection_reason="Statistical Anomaly Deviation without known attack signature",
        ml_score=0.91
    )

    assert res["decision"] == "MONITORED"
    assert res["status"] == "MONITORED"
    # Ensure firewall was not modified
    active = temp_db.get_active_ips_blocks()
    assert not any(b["source_ip"] == "103.235.91.135" for b in active)


def test_low_confidence_threat_is_monitored_only(ips_engine, temp_db):
    """Threats below the configured confidence threshold are monitored, not blocked."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC", "confidence_threshold": 0.85})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.136",
        category="Suspicious Reconnaissance",
        severity="Medium",
        confidence=0.70,  # Below 0.85
        detection_reason="Probing legacy port 135 with 160 packets"
    )

    assert res["decision"] == "MONITORED"
    assert res["status"] == "MONITORED"


# ------------------------------------------------------------------------------
# 2. Safety & Anti-Lockout Validation Tests
# ------------------------------------------------------------------------------
def test_safety_rejects_loopback():
    """Loopback addresses (127.0.0.1, ::1) must be strictly protected."""
    is_safe_v4, _, r4 = validate_ip_for_containment("127.0.0.1")
    assert is_safe_v4 is False
    assert "Loopback" in r4

    is_safe_v6, _, r6 = validate_ip_for_containment("::1")
    assert is_safe_v6 is False
    assert "Loopback" in r6


def test_safety_rejects_host_machine_self_ips():
    """Local host interface IP addresses must be dynamically detected and protected."""
    local_ips = get_local_host_ips()
    assert len(local_ips) >= 1

    for self_ip in local_ips:
        is_safe, _, reason = validate_ip_for_containment(self_ip)
        assert is_safe is False
        assert "Self-Lockout" in reason or "Loopback" in reason or "protected" in reason.lower()


def test_safety_protects_rfc1918_private_networks_by_default():
    """RFC 1918 private subnets (10.x, 172.16.x, 192.168.x) protected unless explicitly allowed."""
    test_private = ["10.0.0.15", "172.16.5.20", "192.168.1.105"]
    for priv in test_private:
        is_safe, _, reason = validate_ip_for_containment(priv, allow_private_networks=False)
        assert is_safe is False
        assert "private network" in reason.lower()

        # If explicitly enabled, it should pass private check
        is_safe_allowed, _, _ = validate_ip_for_containment(priv, allow_private_networks=True)
        assert is_safe_allowed is True


def test_safety_protects_custom_database_allowlist(ips_engine, temp_db):
    """Custom allowlist entries (e.g. administrator CIDR 198.51.100.0/24) are strictly protected."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC"})
    temp_db.add_ips_allowlist_entry("198.51.100.0/24", "Admin Management Network")

    res = ips_engine.evaluate_threat(
        source_ip="198.51.100.55",
        category="Port Scan",
        severity="High",
        confidence=0.94,
        detection_reason="Aggressive port scan"
    )

    assert res["decision"] == "REJECTED_SAFETY"
    assert res["status"] == "REJECTED"
    assert "Allowlist" in res["message"]


def test_safety_rejects_broad_cidr_ranges():
    """Broad CIDR ranges (>1024 addresses) must be rejected to prevent wide outages."""
    is_safe, _, reason = validate_ip_for_containment("103.0.0.0/8")
    assert is_safe is False
    assert "too broad" in reason.lower()


# ------------------------------------------------------------------------------
# 3. Operating Modes Tests (MONITOR, AUTOMATIC, DISABLED)
# ------------------------------------------------------------------------------
def test_operating_mode_monitor(ips_engine, temp_db):
    """MONITOR mode evaluates threats and records in SQLite without modifying the firewall."""
    temp_db.update_ips_settings({"prevention_mode": "MONITOR"})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.140",
        category="Port Scan",
        severity="High",
        confidence=0.95,
        detection_reason="Port scan sweep"
    )

    assert res["decision"] == "MONITORED"
    assert res["status"] == "MONITORED"

    # Verify recorded in SQLite
    action = temp_db.get_ips_action_by_id(res["action_id"])
    assert action is not None
    assert action["action_status"] == "MONITORED"
    assert action["firewall_rule_id"] is None


def test_operating_mode_disabled(ips_engine, temp_db):
    """DISABLED mode rejects new prevention actions while logging state."""
    temp_db.update_ips_settings({"prevention_mode": "DISABLED"})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.141",
        category="Brute Force",
        severity="Critical",
        confidence=0.99,
        detection_reason="Targeted credential spray"
    )

    assert res["decision"] == "DISABLED"
    assert res["status"] == "DISABLED"


def test_duplicate_block_protection(ips_engine, temp_db):
    """Duplicate containment requests for an already actively blocked IP are prevented."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC"})

    # 1. Initial block
    res1 = ips_engine.evaluate_threat(
        source_ip="103.235.91.142",
        category="Port Scan",
        severity="High",
        confidence=0.92,
        detection_reason="Port scan probe"
    )
    assert res1["decision"] == "BLOCKED"

    # 2. Duplicate threat evaluated within cooldown/active state
    res2 = ips_engine.evaluate_threat(
        source_ip="103.235.91.142",
        category="Port Scan",
        severity="High",
        confidence=0.92,
        detection_reason="Port scan probe second packet"
    )
    assert res2["decision"] in ("DUPLICATE_ACTIVE_BLOCK", "ALREADY_BLOCKED")
    assert res2["action_id"] is None or res2["action_id"] == res1["action_id"]


# ------------------------------------------------------------------------------
# 4. Temporary Blocking, Expiration & Automatic Unblocking Tests
# ------------------------------------------------------------------------------
def test_automatic_unblocking_watchdog(ips_engine, temp_db, mock_firewall):
    """Expired temporary firewall rules are automatically removed and verified by the watchdog."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC"})

    # Create block
    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.143",
        category="Port Scan",
        severity="High",
        confidence=0.92,
        detection_reason="Port scan probe"
    )
    action_id = res["action_id"]
    rule_id = res["firewall_rule_id"]

    # Verify rule is currently present in mock firewall
    assert mock_firewall.verify_rule(rule_id).exists is True

    # Artificially age the expiration timestamp into the past
    past_iso = (datetime.datetime.now() - datetime.timedelta(minutes=10)).isoformat()
    with temp_db._get_connection() as conn:
        conn.execute("UPDATE ips_actions SET expires_at = ? WHERE action_id = ?", (past_iso, action_id))
        conn.commit()

    # Trigger watchdog processing
    unblocked_count = ips_engine.check_and_process_expirations()
    assert unblocked_count == 1

    # Verify rule removed from mock firewall
    assert mock_firewall.verify_rule(rule_id).exists is False

    # Verify SQLite record updated to UNBLOCKED
    updated = temp_db.get_ips_action_by_id(action_id)
    assert updated["action_status"] == "UNBLOCKED"
    assert updated["unblocked_at"] is not None


def test_startup_recovery_cleans_offline_expirations(temp_db, mock_firewall):
    """When the engine initializes, it reconciles and unblocks rules that expired during backend downtime."""
    # Seed an expired active block in SQLite
    action_id = "IPS-RECOVER-01"
    rule_id = f"SentinelAI_IPS_{action_id}_103_235_91_144"
    past_iso = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat()

    # Pre-add to mock firewall
    mock_firewall._rules[rule_id] = {"rule_name": rule_id, "target_ip": "103.235.91.144"}

    temp_db.log_ips_action({
        "action_id": action_id,
        "source_ip": "103.235.91.144",
        "detection_reason": "Historical scan",
        "threat_category": "Port Scan",
        "confidence": 0.90,
        "action_type": "BLOCK",
        "firewall_rule_id": rule_id,
        "action_status": "VERIFIED",
        "created_at": past_iso,
        "expires_at": past_iso
    })

    # Instantiate engine (triggers _reconcile_startup_blocks)
    engine = IPSEngine(db=temp_db, adapter=mock_firewall)
    engine.stop_unblock_scheduler()

    # Confirm rule was purged on startup
    assert rule_id not in mock_firewall._rules
    updated = temp_db.get_ips_action_by_id(action_id)
    assert updated["action_status"] == "UNBLOCKED"


def test_manual_unblock(ips_engine, temp_db, mock_firewall):
    """Administrators can manually unblock an active containment rule."""
    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC"})

    res = ips_engine.evaluate_threat(
        source_ip="103.235.91.145",
        category="Brute Force",
        severity="High",
        confidence=0.94,
        detection_reason="SSH brute force"
    )
    action_id = res["action_id"]

    # Manual unblock by IP
    unblock_res = ips_engine.manual_unblock("103.235.91.145", operator="Security Admin")
    assert unblock_res["success"] is True

    # Rule must be removed from firewall
    assert mock_firewall.verify_rule(res["firewall_rule_id"]).exists is False

    # Status must be UNBLOCKED
    action = temp_db.get_ips_action_by_id(action_id)
    assert action["action_status"] == "UNBLOCKED"


# ------------------------------------------------------------------------------
# 5. Firewall Failure & Rollback Handling
# ------------------------------------------------------------------------------
def test_firewall_permission_denied_handling(temp_db):
    """When OS firewall execution fails (e.g. requires administrator elevation), records FAILED status without crashing."""
    denied_adapter = MockFirewallAdapter(simulate_permission_denied=True)
    engine = IPSEngine(db=temp_db, adapter=denied_adapter)
    engine.stop_unblock_scheduler()

    temp_db.update_ips_settings({"prevention_mode": "AUTOMATIC"})

    res = engine.evaluate_threat(
        source_ip="103.235.91.146",
        category="Port Scan",
        severity="High",
        confidence=0.92,
        detection_reason="Port scan probe"
    )

    assert res["decision"] == "BLOCK_FAILED"
    assert res["status"] == "FAILED"
    assert res["verified"] is False
    assert "elevation" in res["message"].lower()

    # Verify action recorded as FAILED in SQLite
    action = temp_db.get_ips_action_by_id(res["action_id"])
    assert action["action_status"] == "FAILED"
    assert action["verified_at"] is None
    assert "elevation" in action["error_message"].lower()


# ------------------------------------------------------------------------------
# 6. REST API Endpoints & Administrative Authorization Tests
# ------------------------------------------------------------------------------
def test_api_ips_status_and_actions():
    """Verify REST API returns live status metrics and paginated activity logs."""
    from api.index import app
    client = TestClient(app)

    # 1. Status
    r_status = client.get("/api/ips/status")
    assert r_status.status_code == 200
    data = r_status.json()
    assert data["status"] == "success"
    assert "metrics" in data
    assert "prevention_mode" in data

    # 2. Actions pagination
    r_actions = client.get("/api/ips/actions?page=1&page_size=10")
    assert r_actions.status_code == 200
    adata = r_actions.json()
    assert adata["status"] == "success"
    assert isinstance(adata["items"], list)

    # 3. Allowlist
    r_allow = client.get("/api/ips/allowlist")
    assert r_allow.status_code == 200
    assert "allowlist" in r_allow.json()


def test_api_ips_mode_switching_and_validation():
    """Verify mode switching endpoint validates input modes and enforces administrator authorization."""
    from api.index import app
    client = TestClient(app)
    admin_key = os.environ.get("SENTINEL_ADMIN_KEY", "")

    # 1. Without admin key (if configured in env, must reject with 401)
    if admin_key:
        r_unauth = client.post("/api/ips/mode", json={"mode": "MONITOR"})
        assert r_unauth.status_code == 401

    headers = {"X-Sentinel-Admin-Key": admin_key} if admin_key else {}

    # 2. Authorized valid mode switch
    r_valid = client.post("/api/ips/mode", json={"mode": "MONITOR", "operator": "Test Analyst"}, headers=headers)
    assert r_valid.status_code == 200
    assert r_valid.json()["settings"]["prevention_mode"] == "MONITOR"

    # 3. Authorized invalid mode switch rejected with 400
    r_invalid = client.post("/api/ips/mode", json={"mode": "INVALID_MODE"}, headers=headers)
    assert r_invalid.status_code == 400


def test_api_ips_gemini_explanation():
    """Verify Gemini Copilot explanation endpoint provides structured analysis without execution authority."""
    from api.index import app
    client = TestClient(app)

    # Retrieve an action from database or insert one
    from database import get_db
    db = get_db()
    action_id = "IPS-TEST-EXPLAIN"
    db.log_ips_action({
        "action_id": action_id,
        "source_ip": "103.235.91.132",
        "detection_reason": "Aggressive multi-port SYN probe",
        "threat_category": "Port Scan",
        "confidence": 0.94,
        "action_type": "BLOCK",
        "firewall_rule_id": f"SentinelAI_IPS_{action_id}_103_235_91_132",
        "action_status": "VERIFIED",
        "created_at": datetime.datetime.now().isoformat()
    })

    r_exp = client.get(f"/api/ips/actions/{action_id}/explain")
    assert r_exp.status_code == 200
    data = r_exp.json()
    assert data["status"] == "success"
    assert "explanation" in data
    exp = data["explanation"]
    assert exp["source_ip"] == "103.235.91.132"
    assert "false_positive_factors" in exp
    assert "triage_recommendations" in exp
    assert "gemini_disclaimer" in exp
