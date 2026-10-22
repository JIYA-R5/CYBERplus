"""
SentinelAI - Automated Tests for Vercel Cloud Serverless API
Verifies FastAPI endpoints, dashboard rendering, containment actions, sample ingestion,
ML threat intelligence endpoints, analyst feedback, and active blocks.
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

def test_vercel_ml_status(client):
    response = client.get("/api/ml/status")
    assert response.status_code == 200
    data = response.json()
    assert "active_model_version" in data
    assert "is_fitted" in data
    assert "metrics" in data

def test_vercel_ml_predict(client):
    payload = {
        "packets": 120,
        "port": 443,
        "source_ip": "192.168.1.50"
    }
    response = client.post("/api/ml/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_anomaly" in data
    assert "raw_score" in data
    assert "confidence" in data
    assert "NOT proof" in data.get("disclaimer", "")

def test_vercel_analyst_verdict(client):
    # Retrieve incidents first to get an existing ID
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    incs = inc_res.json()
    assert len(incs) > 0
    target_id = incs[0]["incident_id"]

    verdict_payload = {
        "verdict": "True Positive",
        "analyst_user": "Cloud SOC Analyst",
        "reason": "Corroborated by NetFlow packet counts"
    }
    resp = client.post(f"/api/incidents/{target_id}/verdict", json=verdict_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["verdict"] == "True Positive"

def test_vercel_incident_explain(client):
    inc_res = client.get("/api/incidents")
    incs = inc_res.json()
    target_id = incs[0]["incident_id"]

    resp = client.get(f"/api/incidents/{target_id}/explain")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "mechanism" in data
    assert "mitre_technique" in data
    assert "observed_facts" in data

def test_vercel_blocks_list(client):
    resp = client.get("/api/blocks")
    assert resp.status_code == 200
    data = resp.json()
    assert "active_blocks" in data
    assert "recently_expired" in data

def test_vercel_ml_retrain_and_revert(client):
    retrain_payload = {
        "synthetic_samples": 150,
        "contamination": 0.12
    }
    resp = client.post("/api/ml/retrain", json=retrain_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "new_model_version" in data
    assert "metrics" in data

    # Revert to baseline
    revert_payload = {
        "version": "isolation_forest_v1.0.0"
    }
    rev_resp = client.post("/api/ml/revert", json=revert_payload)
    assert rev_resp.status_code == 200
    rev_data = rev_resp.json()
    assert rev_data["status"] == "success"
    assert rev_data["active_model_version"] == "isolation_forest_v1.0.0"

def test_vercel_blocks_rollback(client):
    rollback_payload = {
        "block_id": "BLK-NONEXISTENT",
        "admin_user": "Cloud Admin",
        "reason": "Test rollback request"
    }
    resp = client.post("/api/blocks/rollback", json=rollback_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data

def test_vercel_retention_purge(client):
    purge_payload = {
        "retention_days": 90,
        "admin_user": "Cloud Admin"
    }
    resp = client.post("/api/retention/purge", json=purge_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "result" in data


def test_privileged_routes_admin_key_enforcement(client, monkeypatch):
    """Verify that privileged administrative endpoints enforce authentication when SENTINEL_ADMIN_KEY is set."""
    monkeypatch.setenv("SENTINEL_ADMIN_KEY", "super-secret-admin-key-789")

    # 1. Unauthenticated request to privileged endpoint should fail with 401
    unauth_resp = client.post("/api/contain", json={
        "incident_id": "INC-TEST-AUTH",
        "target_ip": "198.51.100.99",
        "action_type": "Quarantine Host"
    })
    assert unauth_resp.status_code == 401
    assert "Unauthorized: Valid X-Sentinel-Admin-Key" in unauth_resp.json()["detail"]

    # 2. Authenticated with X-Sentinel-Admin-Key header should succeed
    auth_resp = client.post(
        "/api/contain",
        json={
            "incident_id": "INC-TEST-AUTH",
            "target_ip": "198.51.100.99",
            "action_type": "Quarantine Host"
        },
        headers={"X-Sentinel-Admin-Key": "super-secret-admin-key-789"}
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["result"]["status"] == "SUCCESS"

    # 3. Authenticated with Bearer token should succeed
    bearer_resp = client.post(
        "/api/contain",
        json={
            "incident_id": "INC-TEST-AUTH",
            "target_ip": "198.51.100.99",
            "action_type": "Quarantine Host"
        },
        headers={"Authorization": "Bearer super-secret-admin-key-789"}
    )
    assert bearer_resp.status_code == 200


def test_cloud_dashboard_light_theme_and_accessible_labels(client):
    """Verify cloud dashboard renders the accessible light theme and plain-English navigation."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    # Verify core color palette and light theme tokens
    assert "#F4F7FB" in html
    assert "#172B4D" in html
    assert "#2457A7" in html
    # Verify approachable navigation and titles
    assert "Your Security Assistant" in html
    assert "Understand suspicious activity and decide what to do next" in html
    assert "Home" in html
    assert "Threats" in html
    assert "Protection" in html
    assert "Activity" in html
    # Verify XSS protection function is embedded
    assert "escapeHTML" in html
    # Verify honest simulation notices
    assert "Simulation Only" in html or "simulation only" in html.lower()


def test_containment_honest_simulation_notice(client):
    """Verify live-mode containment requests explicitly state simulation only without claiming OS rule execution."""
    payload = {
        "incident_id": "INC-HONEST-SIM",
        "target_ip": "198.51.100.55",
        "action_type": "Quarantine Host",
        "dry_run": False,
        "admin_approved": True
    }
    resp = client.post("/api/contain", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    result = data["result"]
    assert result["result"] == "SIMULATION_ONLY_LIVE_NOT_IMPLEMENTED"
    assert "Live firewall enforcement is not implemented; simulation only" in result["details"]



