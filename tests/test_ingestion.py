"""
Unit test suite for SentinelAI Log Ingestion and Live Telemetry Simulator.
Verifies Suricata EVE JSON parsing, generic JSON normalization, and simulation safety.
"""

import pytest
import time
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator


def test_parse_suricata_eve_valid():
    """Verify parsing of valid Suricata EVE JSON flow and alert records."""
    eve_content = """
    {"timestamp": "2026-10-15T10:00:01.000123+0000", "event_type": "flow", "src_ip": "192.168.1.10", "dest_ip": "10.0.0.1", "src_port": 54321, "dest_port": 443, "proto": "TCP", "flow": {"pkts_toserver": 60, "pkts_toclient": 80}}
    {"timestamp": "2026-10-15T10:00:05.000456+0000", "event_type": "alert", "src_ip": "192.168.1.15", "dest_ip": "10.0.0.1", "src_port": 49152, "dest_port": 80, "proto": "TCP", "alert": {"signature": "ET SCAN Suspicious Port Sweep", "severity": 1}}
    """
    events, errors = LogParser.parse_suricata_eve(eve_content)
    assert len(events) == 2
    assert len(errors) == 0

    # Flow record
    assert events[0]["Source IP"] == "192.168.1.10"
    assert events[0]["Port"] == 443
    assert events[0]["Packets"] == 140

    # Alert record
    assert events[1]["Source IP"] == "192.168.1.15"
    assert events[1]["Port"] == 80
    assert events[1]["Risk"] == "Critical"  # Severity 1 mapped to Critical
    assert "Port Sweep" in events[1]["Activity"]


def test_parse_suricata_eve_malformed_resilience():
    """Verify that corrupt JSON lines are isolated into errors without crashing."""
    corrupt_content = """
    {"timestamp": "2026-10-15T10:00:01", "event_type": "flow", "src_ip": "192.168.1.10"}
    THIS_IS_CORRUPT_JSON_DATA
    {"timestamp": "2026-10-15T10:00:02", "event_type": "flow", "src_ip": "192.168.1.20"}
    """
    events, errors = LogParser.parse_suricata_eve(corrupt_content)
    assert len(events) == 2
    assert len(errors) == 1
    assert "Malformed JSON" in errors[0]


def test_parse_generic_json_array():
    """Verify parsing of structured JSON array."""
    json_data = """
    [
        {"time": "12:00:01", "src_ip": "192.168.1.5", "dest_ip": "10.0.0.1", "port": 80, "packets": 250, "activity": "Port Scan", "risk": "High"},
        {"time": "12:00:02", "src_ip": "192.168.1.6", "dest_ip": "10.0.0.2", "port": 443, "packets": 110, "activity": "Normal Traffic", "risk": "Low"}
    ]
    """
    events, errors = LogParser.parse_generic_json(json_data)
    assert len(events) == 2
    assert len(errors) == 0
    assert events[0]["Source IP"] == "192.168.1.5"
    assert events[0]["Risk"] == "High"


def test_live_monitoring_simulator():
    """Verify that live monitoring generates correctly tagged laboratory events."""
    sim = LiveMonitoringSimulator(buffer_size=50)
    sim.start(interval_seconds=0.05)
    time.sleep(0.3)
    sim.stop()

    events = sim.get_recent_events()
    assert len(events) > 0
    for ev in events:
        assert ev["Telemetry Type"] == "SIMULATED: Lab Scenario"
        assert "Source IP" in ev
        assert "Port" in ev
        assert ev["Packets"] > 0
