"""
Automated Test Suite for SentinelAI Approachable UI/UX Redesign.
Verifies plain-English translations, 5-question structured breakdown,
honest simulation reporting, and data source tagging.
"""

import pytest
from app import (
    get_plain_english_title,
    get_plain_english_summary,
    get_plain_english_breakdown,
)
from response_engine import get_response_engine


def test_plain_english_title_mapping():
    """Verify technical SOC categories are mapped to approachable plain-English titles."""
    assert get_plain_english_title("Port Scan") == "Network Port Scanning"
    assert get_plain_english_title("Brute Force") == "Repeated Login Attempts"
    assert get_plain_english_title("Traffic Burst") == "Rapid Web Request Surge"
    assert get_plain_english_title("DDoS Surge") == "High-Volume Traffic Surge"
    assert get_plain_english_title("Data Exfiltration") == "Unusual Outbound Data Transfer"
    assert get_plain_english_title("Suspicious Reconnaissance") == "Network Reconnaissance Activity"
    # Unknown/custom category gracefully returns itself
    assert get_plain_english_title("Custom Anomaly Type") == "Custom Anomaly Type"


def test_plain_english_summary_generation():
    """Verify one-sentence summaries provide clear context without technical jargon."""
    incident = {
        "category": "Port Scan",
        "source_ip": "198.51.100.42",
        "destination_ip": "10.0.0.5",
        "destination_ports": [22, 80, 443, 8080],
        "event_count": 4
    }
    summary = get_plain_english_summary(incident)
    assert "198.51.100.42" in summary
    assert "4 different network ports" in summary
    assert "look for open services" in summary
    assert "MITRE" not in summary
    assert "SOC" not in summary


def test_5_question_structured_breakdown():
    """Verify incident details are organized into the 5 mandatory plain-English questions."""
    incident = {
        "incident_id": "INC-TEST-999",
        "category": "Brute Force",
        "source_ip": "203.0.113.15",
        "destination_ip": "10.0.0.10",
        "destination_ports": [22],
        "total_packets": 350,
        "evidence": "25 failed connection attempts in 60s",
        "recurrence_count": 3
    }
    breakdown = get_plain_english_breakdown(incident)
    assert "what_happened" in breakdown
    assert "why_matters" in breakdown
    assert "evidence_points" in breakdown
    assert "uncertainties" in breakdown
    assert "next_steps" in breakdown

    # Check content quality
    assert "203.0.113.15" in breakdown["what_happened"]
    assert "password" in breakdown["why_matters"].lower() or "unauthorized" in breakdown["why_matters"].lower()
    assert len(breakdown["evidence_points"]) > 0
    assert "automated script" in breakdown["what_happened"] or "guessing" in breakdown["what_happened"]
    assert "uncertain" in breakdown["uncertainties"][0].lower() or "verify" in breakdown["uncertainties"][0].lower() or "legitimate" in breakdown["uncertainties"][1].lower()
    assert len(breakdown["next_steps"]) >= 2


def test_live_firewall_enforcement_honesty():
    """Verify that live execution requests honestly report simulation status and never claim applied OS changes."""
    engine = get_response_engine()
    res = engine.execute_response_action(
        incident_id="INC-TEST-HONESTY",
        action_type="FIREWALL_BLOCK",
        target_ip="198.51.100.77",
        dry_run=False,
        admin_approved=True,
        operator="Security Architect"
    )

    # Must NOT claim applied host firewall changes
    assert res["status"] == "SUCCESS"
    assert res["result"] == "SIMULATION_ONLY_LIVE_NOT_IMPLEMENTED"
    assert res["verification_status"] == "SIMULATION_ONLY_UNVERIFIED"
    assert "Live firewall enforcement is not implemented; simulation only" in res["details"]
