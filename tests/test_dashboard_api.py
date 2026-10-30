"""
Automated unit tests for the React Dashboard backend API endpoints in api/index.py.
Verifies collector status/interfaces, metrics endpoints, events pagination, alert reviews,
host inventory, model metrics, and safe response actions.
"""
import pytest
from fastapi.testclient import TestClient
from api.index import app

@pytest.fixture
def client():
    return TestClient(app)

def test_collector_status_and_interfaces(client):
    res_status = client.get("/api/collector/status")
    assert res_status.status_code == 200
    data = res_status.json()
    assert "status" in data
    assert "packets_captured" in data

    res_ifaces = client.get("/api/collector/interfaces")
    assert res_ifaces.status_code == 200
    assert "interfaces" in res_ifaces.json()
    assert isinstance(res_ifaces.json()["interfaces"], list)

def test_collector_start_and_stop(client):
    # Start collector in simulated replay mode
    res_start = client.post("/api/collector/start", json={
        "interface": "Wi-Fi",
        "mode": "replay",
        "force": True
    })
    assert res_start.status_code == 200
    assert res_start.json()["status"] == "success"

    # Stop collector
    res_stop = client.post("/api/collector/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["status"] == "success"

def test_metrics_summary(client):
    res = client.get("/api/metrics/summary")
    assert res.status_code == 200
    data = res.json()
    assert "packets_observed" in data
    assert "packets_per_second" in data
    assert "bandwidth_mbps" in data
    assert "active_flows" in data
    assert "suspicious_events" in data
    assert "open_alerts" in data
    assert "collector_health" in data

def test_metrics_timeline_and_protocols(client):
    res_timeline = client.get("/api/metrics/timeline?range=24h")
    assert res_timeline.status_code == 200
    assert "timeline" in res_timeline.json()
    assert len(res_timeline.json()["timeline"]) > 0

    res_proto = client.get("/api/metrics/protocols")
    assert res_proto.status_code == 200
    assert "protocols" in res_proto.json()
    assert any(p["name"] == "TCP" for p in res_proto.json()["protocols"])

def test_metrics_top_talkers(client):
    res = client.get("/api/metrics/top-talkers?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "top_sources" in data
    assert "top_destinations" in data

def test_events_pagination_and_filter(client):
    res = client.get("/api/events?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert data["page"] == 1

def test_alerts_listing_and_patch(client):
    # List alerts
    res = client.get("/api/alerts?page=1&page_size=5")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data

    if data["items"]:
        first_alert = data["items"][0]
        alert_id = first_alert.get("incident_id") or first_alert.get("id")

        # Get alert detail
        res_detail = client.get(f"/api/alerts/{alert_id}")
        assert res_detail.status_code == 200
        detail_data = res_detail.json()
        assert "alert" in detail_data
        assert "explanation" in detail_data
        assert "safe_actions" in detail_data

        # Patch alert verdict
        res_patch = client.patch(f"/api/alerts/{alert_id}", json={
            "verdict": "Needs Investigation",
            "status": "Investigating",
            "reason": "Suspicious activity flagged for analyst verification"
        })
        assert res_patch.status_code == 200
        assert res_patch.json()["status"] == "success"

def test_hosts_and_host_detail(client):
    res_hosts = client.get("/api/hosts")
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert "hosts" in hosts_data

    # Test host detail for default or discovered host
    test_ip = hosts_data["hosts"][0]["ip"] if hosts_data["hosts"] else "198.51.100.88"
    res_detail = client.get(f"/api/hosts/{test_ip}")
    assert res_detail.status_code == 200
    assert res_detail.json()["ip"] == test_ip

def test_models_status_and_metrics(client):
    res_status = client.get("/api/models/status")
    assert res_status.status_code == 200
    data = res_status.json()
    assert "web_log_model" in data
    assert "network_anomaly_model" in data
    assert "network_classifier_model" in data

    res_metrics = client.get("/api/models/metrics")
    assert res_metrics.status_code == 200
    assert "web_log_benchmarks" in res_metrics.json()
    assert "network_flow_benchmarks" in res_metrics.json()

def test_safe_response_recommendations_and_execute(client):
    incidents = client.get("/api/alerts?page_size=1").json().get("items", [])
    test_id = incidents[0].get("incident_id") if incidents else "INC-DEMO-001"

    # Get recommendations
    res_rec = client.post("/api/response/recommendations", json={"incident_id": test_id})
    assert res_rec.status_code in (200, 404)

    # Execute simulated dry-run action
    res_exec = client.post("/api/response/execute", json={
        "incident_id": test_id,
        "action_type": "FIREWALL_BLOCK",
        "target_ip": "198.51.100.99",
        "dry_run": True,
        "approved": False,
        "operator": "Automated Test Runner"
    })
    assert res_exec.status_code == 200
    assert res_exec.json()["status"] == "SUCCESS"
    assert res_exec.json()["execution_mode"] == "dry_run"
