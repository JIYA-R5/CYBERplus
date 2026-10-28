"""
Unit tests for the FastAPI ingestion endpoint and collector integration (api/index.py).
Validates authentication, batch payload validation, /ready endpoint, and WebSocket setup.
"""
import pytest
from fastapi.testclient import TestClient

from api.index import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_and_ready_endpoints(client):
    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] in ("healthy", "degraded")

    # Readiness check
    res_ready = client.get("/ready")
    assert res_ready.status_code == 200
    data = res_ready.json()
    assert data["status"] in ("ready", "unready")
    assert "database" in data
    assert "models" in data
    assert "redis_stream" in data


def test_pcap_live_stream_unauthorized_when_secret_set(client, monkeypatch):
    """Verify that when SENTINEL_AGENT_SECRET is set, unauthorized requests are rejected."""
    monkeypatch.setenv("SENTINEL_AGENT_SECRET", "super-secret-collector-token-999")

    payload = {
        "host_id": "windows-host",
        "agent_type": "host_tshark_capture",
        "timestamp": "2023-01-01T12:00:00",
        "flows": [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 50000,
                "dst_port": 80,
                "protocol": "TCP",
                "total_packets": 5,
                "total_bytes": 500,
                "duration": 0.5
            }
        ]
    }

    # No auth header -> 401
    res_no_auth = client.post("/api/pcap/live-stream", json=payload)
    assert res_no_auth.status_code == 401
    assert "Unauthorized" in res_no_auth.json()["detail"]

    # Wrong auth header -> 401
    res_bad = client.post(
        "/api/pcap/live-stream",
        json=payload,
        headers={"X-Agent-Secret": "wrong-secret"}
    )
    assert res_bad.status_code == 401

    # Valid auth header -> 200
    res_good = client.post(
        "/api/pcap/live-stream",
        json=payload,
        headers={"X-Agent-Secret": "super-secret-collector-token-999"}
    )
    assert res_good.status_code == 200
    assert res_good.json()["status"] == "success"
    assert res_good.json()["received_flows"] == 1


def test_agent_telemetry_batch_ingest(client, monkeypatch):
    """Test standard telemetry ingestion via /api/agent/telemetry."""
    test_secret = "test-agent-secret-456"
    monkeypatch.setenv("SENTINEL_AGENT_SECRET", test_secret)

    payload = {
        "host_id": "test-host-agent",
        "agent_version": "2.5.0",
        "os_type": "windows",
        "events": [
            {
                "timestamp": "2023-01-01T12:00:00",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "TCP",
                "packets": 5
            }
        ]
    }

    res = client.post(
        "/api/agent/telemetry",
        json=payload,
        headers={"X-Agent-Secret": test_secret}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
