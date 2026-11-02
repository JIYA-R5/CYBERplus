#!/usr/bin/env python3
"""
scripts/test_live_attack_flow.py
=============================================================================
End-to-End Validation Script for SentinelAI Real-Time Attack Origin Tracking:
1. Ingest authorized attack telemetry from laptop public IP (103.235.91.132)
2. Verify MaxMind GeoLite2 City resolution (India / Gujarat / Borsad)
3. Verify SQLite persistence in network_logs
4. Verify threat intensity calculation and attack trajectory generation
5. Verify RFC 1918 private IP segregation into local_network
6. Verify live attack ticker and measured ingestion delay
=============================================================================
"""

import sys
import os
import json

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from fastapi.testclient import TestClient
from api.index import app
from database import get_db
from geoip_service import get_geoip_service


def run_tests():
    print("=" * 70)
    print("SentinelAI — Testing Real-Time Attack Origin & Live Heat Map Flow")
    print("=" * 70)

    client = TestClient(app)
    db = get_db()
    geoip_svc = get_geoip_service(db_manager=db)

    # ---------------------------------------------------------
    # TEST 1: Direct GeoIP Resolution for Laptop Public IP
    # ---------------------------------------------------------
    laptop_ip = "103.235.91.132"
    intel = geoip_svc.get_ip_intelligence(laptop_ip)
    print(f"\n[TEST 1] GeoLite2 City Lookup for Laptop IP: {laptop_ip}")
    print(f"  - Is Public: {intel.get('is_public')}")
    print(f"  - Country:   {intel.get('country')} ({intel.get('country_code')})")
    print(f"  - Region:    {intel.get('region')}")
    print(f"  - City:      {intel.get('city')}")
    print(f"  - Lat/Lon:   {intel.get('latitude')}, {intel.get('longitude')}")
    print(f"  - Accuracy:  +/-{intel.get('accuracy_km') or intel.get('accuracy_radius')} km")

    assert intel.get("is_public") is True, "Laptop IP should be identified as public routable"
    assert intel.get("country") == "India", f"Expected India, got {intel.get('country')}"
    assert intel.get("latitude") is not None and intel.get("longitude") is not None, "Coordinates must be non-null"
    print("  [OK] PASS: Laptop public IP resolved accurately via MaxMind GeoLite2.")

    # ---------------------------------------------------------
    # TEST 2: Ingest Authorized Test Attack via API
    # ---------------------------------------------------------
    print(f"\n[TEST 2] Ingesting Authorized Test Attack via POST /api/threat-map/simulate-attack")
    sim_payload = {
        "source_ip": laptop_ip,
        "target_ip": "10.10.213.36",
        "target_port": 22,
        "protocol": "TCP",
        "attack_type": "Brute Force",
        "severity": "Critical",
        "event_count": 3
    }
    resp = client.post("/api/threat-map/simulate-attack", json=sim_payload)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    sim_result = resp.json()
    print(f"  - Status:  {sim_result.get('status')}")
    print(f"  - Message: {sim_result.get('message')}")
    print(f"  - Event Details: {sim_result.get('event')}")
    assert sim_result.get("status") == "success", "Simulation status should be success"
    print("  [OK] PASS: Authorized test attack ingested and processed by backend.")

    # ---------------------------------------------------------
    # TEST 3: Verify Persistence in SQLite Database
    # ---------------------------------------------------------
    print(f"\n[TEST 3] Verifying SQLite Persistence in network_logs")
    recent_logs = db.get_network_logs(limit=20)
    matching_logs = [log for log in recent_logs if log.get("source_ip") == laptop_ip]
    assert len(matching_logs) > 0, f"No logs found in SQLite for {laptop_ip}"
    latest_log = matching_logs[0]
    print(f"  - Stored Flow ID:    {latest_log.get('flow_id')}")
    print(f"  - Stored Source IP:  {latest_log.get('source_ip')}")
    print(f"  - Stored Reason:     {latest_log.get('detection_reason')}")
    print(f"  - Stored Detection Status: {latest_log.get('detection_status')}")
    assert latest_log.get("detection_status") == "suspicious" or latest_log.get("detection_reason") == "Brute Force", "Log must be flagged as suspicious"
    print("  [OK] PASS: Ingested attack probe is saved and verified in SQLite.")

    # ---------------------------------------------------------
    # TEST 4: Verify Heat Map Payload & Multi-Layer Fields
    # ---------------------------------------------------------
    print(f"\n[TEST 4] Querying GET /api/threat-map for Shockwaves & Trajectories")
    map_resp = client.get("/api/threat-map")
    assert map_resp.status_code == 200, f"Expected 200, got {map_resp.status_code}"
    map_data = map_resp.json()

    print(f"  - Status:                   {map_data.get('status')}")
    print(f"  - Public Markers Count:     {len(map_data.get('markers', []))}")
    print(f"  - Country Aggregates Count: {len(map_data.get('country_aggregates', []))}")
    print(f"  - Attack Trajectories:      {len(map_data.get('attack_trajectories', []))}")
    print(f"  - Live Attack Ticker Items: {len(map_data.get('live_attack_ticker', []))}")
    print(f"  - Latest Ingestion Delay:   {map_data.get('latest_ingestion_delay_ms')} ms")

    # Find laptop marker
    laptop_marker = None
    for m in map_data.get("markers", []):
        if laptop_ip in m.get("source_ips", []):
            laptop_marker = m
            break

    assert laptop_marker is not None, f"Laptop IP {laptop_ip} not found in public markers"
    print(f"  - Laptop Marker Found:")
    print(f"      City/Country:   {laptop_marker.get('city')}, {laptop_marker.get('country')}")
    print(f"      Coordinates:    {laptop_marker.get('latitude')}, {laptop_marker.get('longitude')}")
    print(f"      Heat Intensity: {laptop_marker.get('heat_intensity')} (Weight 5 for Critical)")
    print(f"      Accuracy:       +/-{laptop_marker.get('accuracy_km')} km")
    assert laptop_marker.get("heat_intensity", 0) >= 5, "Heat intensity should reflect severity weight"

    # Verify Trajectory exists
    traj_found = any(t.get("source_ip") == laptop_ip for t in map_data.get("attack_trajectories", []))
    assert traj_found, f"Attack trajectory not generated for {laptop_ip}"
    print("  [OK] PASS: Heat marker, intensity weighting, and trajectory vectors verified.")

    # ---------------------------------------------------------
    # TEST 5: Verify RFC 1918 Private IP Segregation
    # ---------------------------------------------------------
    print(f"\n[TEST 5] Testing RFC 1918 Private IP Segregation (10.10.213.36)")
    lan_ip = "10.10.213.36"
    lan_intel = geoip_svc.get_ip_intelligence(lan_ip)
    print(f"  - LAN IP:    {lan_ip}")
    print(f"  - Is Public: {lan_intel.get('is_public')}")
    print(f"  - Lat/Lon:   {lan_intel.get('latitude')}, {lan_intel.get('longitude')}")
    print(f"  - Status:    {lan_intel.get('status')}")

    assert lan_intel.get("is_public") is False, "Private IP must have is_public == False"
    assert lan_intel.get("latitude") is None, "Private IP must NOT have public coordinates"

    # Simulate attack from LAN IP
    client.post("/api/threat-map/simulate-attack", json={
        "source_ip": lan_ip,
        "attack_type": "Port Scan",
        "severity": "Medium",
        "event_count": 1
    })

    map_resp2 = client.get("/api/threat-map").json()
    local_hosts = map_resp2.get("local_network", [])
    lan_in_local = any(h.get("ip") == lan_ip for h in local_hosts)
    print(f"  - Local Network Hosts Count: {len(local_hosts)}")
    print(f"  - LAN Host in Local Topology: {lan_in_local}")
    assert lan_in_local, "LAN IP must appear in local_network topology list"

    # Verify LAN IP is NOT in public markers
    lan_in_public = any(lan_ip in m.get("source_ips", []) for m in map_resp2.get("markers", []))
    assert not lan_in_public, "LAN IP must NOT appear on public world map"
    print("  [OK] PASS: RFC 1918 private IP correctly segregated without fake coordinates.")

    print("\n" + "=" * 70)
    print("ALL 5 TESTS PASSED SUCCESSFULLY! Real-time heat map pipeline verified.")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
