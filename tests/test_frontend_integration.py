"""
SentinelAI — Frontend Build and Integration Test Suite
Validates that:
1. React TypeScript frontend builds successfully into `frontend/dist`.
2. Static assets (CSS/JS) and index.html exist and contain valid SentinelAI bundle code.
3. FastAPI backend mounts and serves the React dashboard on `/` and handles SPA deep linking.
4. Collector and Metric API contracts adhere strictly to dashboard component expectations.
"""

import os
import pytest
from starlette.testclient import TestClient
from api.index import app, ROOT_DIR


@pytest.fixture
def client():
    return TestClient(app)


def test_frontend_dist_artifacts_exist():
    """Verify React build produced index.html and compiled asset bundles in frontend/dist."""
    dist_dir = os.path.join(ROOT_DIR, "frontend", "dist")
    index_html = os.path.join(dist_dir, "index.html")
    assets_dir = os.path.join(dist_dir, "assets")

    assert os.path.isdir(dist_dir), "frontend/dist directory does not exist. Run npm run build."
    assert os.path.isfile(index_html), "frontend/dist/index.html is missing."
    assert os.path.isdir(assets_dir), "frontend/dist/assets is missing."

    # Verify at least one compiled JS and CSS file exists
    files = os.listdir(assets_dir)
    js_files = [f for f in files if f.endswith(".js")]
    css_files = [f for f in files if f.endswith(".css")]

    assert len(js_files) >= 1, "Compiled React JavaScript bundle missing in dist/assets."
    assert len(css_files) >= 1, "Compiled Tailwind CSS bundle missing in dist/assets."

    # Verify index.html contains SentinelAI title and root mounting div
    with open(index_html, "r", encoding="utf-8") as f:
        html = f.read()
    assert "SentinelAI" in html
    assert 'id="root"' in html


def test_spa_deep_linking_routes(client):
    """Verify FastAPI returns the React SPA index.html for all 9 dashboard routes."""
    spa_routes = [
        "/overview",
        "/live-network",
        "/analytics",
        "/threats",
        "/alerts",
        "/hosts",
        "/investigation",
        "/models",
        "/settings",
    ]

    for route in spa_routes:
        # Browser client simulation (not testclient user-agent)
        resp = client.get(route, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        assert resp.status_code == 200, f"SPA route {route} failed with status {resp.status_code}"
        assert 'id="root"' in resp.text, f"SPA route {route} did not serve index.html"


def test_dashboard_api_contracts_for_react_components(client):
    """Verify backend endpoints return the exact field schemas required by the React components."""
    # 1. Summary Cards contract
    sum_res = client.get("/api/metrics/summary")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    for field in ["packets_observed", "current_pps", "incoming_bandwidth_kbps", "outgoing_bandwidth_kbps", "active_connections", "suspicious_events", "open_security_alerts", "collector_health", "data_source"]:
        assert field in sum_data, f"Missing {field} in /api/metrics/summary"

    # 2. Timeline contract
    time_res = client.get("/api/metrics/timeline?range=24h")
    assert time_res.status_code == 200
    timeline = time_res.json()["timeline"]
    assert len(timeline) > 0
    t_point = timeline[0]
    for field in ["timestamp", "pps", "incoming_bps", "outgoing_bps", "bandwidth_kbps", "suspicious_count", "rule_detections", "ml_detections"]:
        assert field in t_point, f"Missing {field} in timeline data point"

    # 3. Protocol Breakdown contract
    proto_res = client.get("/api/metrics/protocols")
    assert proto_res.status_code == 200
    protos = proto_res.json()["protocols"]
    assert len(protos) >= 3
    for p in protos:
        assert "protocol" in p and "count" in p and "percentage" in p

    # 4. Top Talkers contract
    talk_res = client.get("/api/metrics/top-talkers")
    assert talk_res.status_code == 200
    talk_data = talk_res.json()
    assert "top_sources" in talk_data and "top_destinations" in talk_data

    # 5. Model Insights separation contract
    model_res = client.get("/api/models/metrics")
    assert model_res.status_code == 200
    models = model_res.json()
    assert "web_log_model" in models
    assert "network_anomaly_model" in models
    # Verify strict provenance warning
    assert "synthetic" in models["web_log_model"]["limitations"].lower()
    assert "unsupervised" in models["network_anomaly_model"]["type"].lower()
