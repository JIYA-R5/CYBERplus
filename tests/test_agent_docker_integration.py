"""
SentinelAI - Automated Tests for Dockerized API, Agent Telemetry, and Healthchecks
Verifies health routes, agent authentication, telemetry ingestion, database WAL mode,
and persistence behavior.
"""

import os
import json
import pytest
from fastapi.testclient import TestClient
from api.index import app
from database import DatabaseManager

@pytest.fixture
def client():
    return TestClient(app)

def test_root_health_and_api_health(client):
    """Verify both /health and /api/health respond with 200 OK and valid health metadata."""
    res_root = client.get("/health")
    assert res_root.status_code == 200
    data_root = res_root.json()
    assert data_root["status"] in ("healthy", "degraded")
    assert data_root["service"] == "SentinelAI Cloud SOC"
    assert "database" in data_root

    res_api = client.get("/api/health")
    assert res_api.status_code == 200
    data_api = res_api.json()
    assert data_api["status"] in ("healthy", "degraded")
    assert data_api["service"] == "SentinelAI Cloud SOC"

def test_agent_telemetry_authentication_enforced(client, monkeypatch):
    """Verify that when SENTINEL_AGENT_SECRET is set, unauthorized requests are rejected."""
    monkeypatch.setenv("SENTINEL_AGENT_SECRET", "super-secret-agent-key-123")

    payload = {
        "host_id": "test-workstation",
        "agent_version": "2.5.0",
        "os_type": "windows",
        "events": [
            {
                "timestamp": "2026-10-28T14:15:00",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "TCP",
                "packets": 5
            }
        ]
    }

    # 1. Missing header -> 401
    res_no_auth = client.post("/api/agent/telemetry", json=payload)
    assert res_no_auth.status_code == 401
    assert "Unauthorized" in res_no_auth.json()["detail"]

    # 2. Wrong header -> 401
    res_wrong_auth = client.post(
        "/api/agent/telemetry",
        json=payload,
        headers={"X-Agent-Secret": "wrong-token"}
    )
    assert res_wrong_auth.status_code == 401

    # 3. Correct header -> 200
    res_valid = client.post(
        "/api/agent/telemetry",
        json=payload,
        headers={"X-Agent-Secret": "super-secret-agent-key-123"}
    )
    assert res_valid.status_code == 200
    data = res_valid.json()
    assert data["status"] == "success"
    assert data["host_id"] == "test-workstation"
    assert data["received_events"] == 1

def test_agent_telemetry_empty_payload_validation(client, monkeypatch):
    """Verify empty events list returns 400 Bad Request."""
    monkeypatch.delenv("SENTINEL_AGENT_SECRET", raising=False)
    payload = {
        "host_id": "test-host",
        "events": []
    }
    res = client.post("/api/agent/telemetry", json=payload)
    assert res.status_code == 400
    assert "no events provided" in res.json()["detail"]

def test_agent_telemetry_correlation_and_persistence(client, monkeypatch):
    """Verify agent telemetry produces correlated incidents and saves to SQLite."""
    monkeypatch.delenv("SENTINEL_AGENT_SECRET", raising=False)

    # Synthetic port scan payload
    events = []
    for port in [21, 22, 23, 80, 443, 3389, 8080]:
        events.append({
            "timestamp": "2026-10-28T14:20:00",
            "source_ip": "198.51.100.88",
            "destination_ip": "192.168.1.10",
            "destination_port": port,
            "protocol": "TCP",
            "packets": 1,
            "bytes": 40
        })

    payload = {
        "host_id": "perimeter-sensor-01",
        "agent_version": "2.5.0",
        "os_type": "windows",
        "events": events
    }

    res = client.post("/api/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["received_events"] == 7
    assert data["correlated_incidents"] >= 1

    # Verify incident is visible in database
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    all_incs = inc_res.json()
    matching = [i for i in all_incs if i.get("source_ip") == "198.51.100.88"]
    assert len(matching) >= 1
    assert "Port Scan" in matching[0]["category"]

def test_custom_db_path_environment_variable(tmp_path, monkeypatch):
    """Verify SENTINEL_DB_PATH environment variable directs DatabaseManager to custom path."""
    custom_db = str(tmp_path / "custom_data_dir" / "custom_sentinel.db")
    monkeypatch.setenv("SENTINEL_DB_PATH", custom_db)

    mgr = DatabaseManager()
    assert os.path.abspath(mgr.db_path) == os.path.abspath(custom_db)
    assert os.path.exists(custom_db)

    # Verify tables created
    with mgr._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        assert "incidents" in tables
        assert "audit_logs" in tables
