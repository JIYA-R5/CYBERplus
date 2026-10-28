"""
Automated Integration Tests for SentinelAI Unified Platform and Guided Demo Pipeline.
Verifies the deterministic 10-step guided demo, Copilot query assistant,
and non-destructive response safeguards.
"""

import pytest
from app import run_guided_demo_pipeline, query_copilot_assistant, get_sensor_status_info
from database import get_db
from response_engine import is_ip_allowlisted, DEFAULT_PROTECTED_IPS

db = get_db()


def test_guided_demo_pipeline_deterministic_execution():
    """Verify that the 10-step guided demo runs end-to-end deterministically."""
    demo_res = run_guided_demo_pipeline()

    # Step 1: Bundled fixture ingestion
    assert demo_res["step_1_raw_events_count"] == 73
    assert "suricata" in demo_res["step_1_sample_name"].lower()

    # Step 2: Normalization
    df = demo_res["step_2_df"]
    assert len(df) == 73
    assert "Source IP" in df.columns
    assert "Destination IP" in df.columns
    assert "Port" in df.columns

    # Step 3: Detection & Isolation Forest ML Scoring
    assert demo_res["step_3_correlated_count"] >= 1
    assert len(demo_res["step_3_incidents"]) >= 1

    # Step 4: Primary Flagged Threat
    p_inc = demo_res["step_4_primary_incident"]
    assert p_inc is not None
    assert p_inc["category"] in ("Port Scan", "Brute Force", "Traffic Burst")
    assert p_inc["source_ip"] in ("198.51.100.23", "198.51.100.42")

    # Step 5: Chronological Related Event Timeline
    timeline = demo_res["step_5_related_events"]
    assert len(timeline) >= 1

    # Step 6: AI Threat Explanation (Gemini or Offline Fallback)
    exp = demo_res["step_6_explanation"]
    assert "summary" in exp
    assert "mechanism" in exp
    assert "threat_hypotheses" in exp

    # Step 7: Recommended Defensive Action
    rec = demo_res["step_7_recommendation"]
    assert rec["action_type"] == "FIREWALL_QUARANTINE"
    assert rec["target_ip"] == p_inc["source_ip"]
    assert rec["duration_minutes"] == 60

    # Step 8: Safe Dry-Run Quarantine (0 OS changes)
    resp = demo_res["step_8_response"]
    assert resp["status"] == "SUCCESS"
    assert resp["result"] == "SIMULATED_SUCCESS"
    assert "simulation" in resp["details"].lower() or "zero operating system modifications" in resp["details"].lower()

    # Step 9: Audit Ledger Recording
    audit = demo_res["step_9_audit"]
    assert audit["execution_mode"] == "dry_run"
    assert audit["target_ip"] == p_inc["source_ip"]

    # Step 10: Executive Summary Report
    sum_rep = demo_res["step_10_summary"]
    assert sum_rep["events_ingested"] == 73
    assert sum_rep["containment_status"] == "SIMULATED_SUCCESS"
    assert "SIMULATED / DRY RUN" in sum_rep["containment_mode"]


def test_copilot_assistant_query_grounding():
    """Verify that Copilot queries are strictly grounded in incident facts."""
    mock_incident = {
        "incident_id": "INC-TEST-COPILOT",
        "category": "Port Scan",
        "source_ip": "198.51.100.42",
        "destination_ip": "10.0.0.5",
        "destination_ports": [22, 80, 443, 8080],
        "total_packets": 240,
        "evidence": "Observed 4 port probes within 3 seconds"
    }

    # Query about ports
    ans_ports = query_copilot_assistant(mock_incident, "What ports were probed?")
    assert "198.51.100.42" in ans_ports
    assert "22" in ans_ports or "port" in ans_ports.lower()

    # Query about containment
    ans_block = query_copilot_assistant(mock_incident, "Is it safe to block this host?")
    assert "quarantine" in ans_block.lower() or "allowlist" in ans_block.lower()

    # Query about false alarm / legitimate testing
    ans_benign = query_copilot_assistant(mock_incident, "Could this be a legitimate scanner?")
    assert "scanner" in ans_benign.lower() or "internal" in ans_benign.lower()


def test_allowlist_protection_guardrails():
    """Verify that protected infrastructure IPs are never blocked in guided demo or manual containment."""
    for safe_ip in DEFAULT_PROTECTED_IPS:
        is_allowed, reason = is_ip_allowlisted(safe_ip)
        assert is_allowed is True
        assert len(reason) > 5

