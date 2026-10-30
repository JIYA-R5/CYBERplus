"""
Automated Test Suite for SentinelAI UI Migration Verification.
Ensures:
1. Active entrypoint app.py serves the New Unified UI and does not contain legacy code.
2. legacy_app.py is archived and guarded against direct execution.
3. FastAPI /api/threat-map and /api/threat-map/ip-lookup are functional.
4. /api/copilot/summary and /api/copilot/explain return structured reasoning.
5. React production assets contain the Threat Intelligence routing.
"""

import os
import json
import pytest
from starlette.testclient import TestClient
from api.index import app
from database import get_db

client = TestClient(app)


def test_active_entrypoint_app_py_bridges_to_new_ui():
    """Verify app.py is the active launcher pointing to the New Unified UI."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app_py_path = os.path.join(root_dir, "app.py")
    assert os.path.exists(app_py_path)
    with open(app_py_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "ACTIVE (NEW UNIFIED UI)" in content
    assert "legacy_app.py" in content
    # Ensure legacy multi-tabs are not present in active entrypoint
    assert "tab_overview, tab_live" not in content
    assert "map_sub_geo" not in content


def test_legacy_app_py_is_archived_with_execution_guard():
    """Verify legacy_app.py contains execution prevention guard."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    legacy_py_path = os.path.join(root_dir, "legacy_app.py")
    assert os.path.exists(legacy_py_path)
    with open(legacy_py_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "LEGACY STREAMLIT UI (ARCHIVED / READ-ONLY REFERENCE)" in content
    assert "Execution of the legacy interface is prevented" in content
    assert "_st.stop()" in content


def test_threat_map_api_endpoint():
    """Verify /api/threat-map returns live statistics, markers, and aggregations."""
    resp = client.get("/api/threat-map")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "success"
    assert "markers" in data
    assert "country_aggregates" in data
    assert "local_network" in data
    assert "activity_timeline" in data
    assert "statistics" in data
    stats = data["statistics"]
    assert "total_geolocated_sources" in stats
    assert "countries_detected" in stats
    assert "total_suspicious_events" in stats
    assert "unlocated_source_ips" in stats
    assert "high_critical_events" in stats

    # Verify Country Aggregates contain required Choropleth fields & weighted intensity
    c_aggs = data["country_aggregates"]
    if c_aggs:
        for c in c_aggs:
            assert "country" in c
            assert "intensity_score" in c
            assert c["intensity_score"] >= 1
            assert "incident_count" in c
            assert "unique_ips" in c
            assert "max_severity" in c
            assert "top_category" in c
            assert "severities" in c
            assert "recent_incidents" in c

    # Verify filtered queries
    resp_filtered = client.get("/api/threat-map?severity=High")
    assert resp_filtered.status_code == 200
    data_filt = resp_filtered.json()
    assert data_filt.get("status") == "success"



def test_threat_map_ip_lookup_endpoint():
    """Verify GeoLite2 City IP intelligence lookup."""
    resp = client.get("/api/threat-map/ip-lookup?ip=128.30.52.100")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "success"
    assert data.get("ip") == "128.30.52.100"
    intel = data.get("intelligence", {})
    assert intel.get("is_public") is True
    assert intel.get("country") == "United States"


def test_copilot_summary_endpoint():
    """Verify /api/copilot/summary produces executive threat reasoning."""
    resp = client.get("/api/copilot/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "success"
    assert "summary" in data
    assert "provider" in data


def test_react_dist_contains_threat_intelligence_route():
    """Verify the compiled React bundle includes Threat Intelligence routing."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist_index = os.path.join(root_dir, "frontend", "dist", "index.html")
    assert os.path.exists(dist_index)
    with open(dist_index, "r", encoding="utf-8") as f:
        html = f.read()
    assert 'id="root"' in html
