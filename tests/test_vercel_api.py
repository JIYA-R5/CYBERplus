"""
SentinelAI - Automated Tests for Vercel Cloud Serverless API
Verifies FastAPI endpoints, dashboard rendering, containment actions, and sample ingestion.
"""

import pytest
from fastapi.testclient import TestClient
from api.index import app

@pytest.fixture
def client():
    return TestClient(app)

def test_vercel_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SentinelAI Cloud SOC"

def test_vercel_status_endpoint(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "defcon_level" in data
    assert "active_incidents" in data
    assert "threat_index" in data

def test_vercel_dashboard_html_rendering(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "SentinelAI" in response.text
    assert "Enterprise Threat Defense SOC" in response.text
    assert "DEFCON" in response.text

def test_vercel_sample_ingestion(client):
    response = client.get("/api/sample/suricata_73")
    assert response.status_code == 200
    data = response.json()
    assert data["total_records"] == 73
    assert len(data["correlated_incidents"]) == 3

def test_vercel_containment_action(client):
    payload = {
        "incident_id": "INC-TEST-001",
        "target_ip": "198.51.100.23",
        "action_type": "Quarantine Host"
    }
    response = client.post("/api/contain", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["result"]["status"] == "SUCCESS"
    assert data["result"]["result"] == "SIMULATED_SUCCESS"
    assert "Windows PowerShell" in data["commands"]
    assert "Linux iptables" in data["commands"]

def test_vercel_simulation_stream(client):
    response = client.get("/api/simulate")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert len(data["events"]) > 0
    assert all("SIMULATED" in e["Telemetry Type"] for e in data["events"])
