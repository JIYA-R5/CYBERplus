"""
SentinelAI - MaxMind GeoLite2 City Integration Test Suite
Verifies the complete integration across all 9 specification tests:
TEST 1: GeoIP database file exists and can be opened
TEST 2: Public IP lookup returns accurate geographic information
TEST 3: 192.168.1.10 (RFC 1918) is rejected from geolocation
TEST 4: 127.0.0.1 (RFC 1122) is rejected from geolocation
TEST 5: Invalid IP addresses are handled gracefully
TEST 6: Missing database file behavior and graceful fallback
TEST 7: FastAPI ingestion pipeline persists GeoIP coordinates to SQLite
TEST 8: Threat map reads SQLite records and renders approximate locations
TEST 9: Service restart and database persistence durability
"""

import os
import sys
import tempfile
import pytest

from geoip_service import GeoIPService, get_geoip_service
from database import DatabaseManager
from api.index import process_and_persist_network_event


@pytest.fixture(scope="module")
def shared_db():
    """Create a temporary SQLite database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="test_sentinel_geoip_")
    os.close(fd)
    db = DatabaseManager(db_path=path)
    yield db
    try:
        os.remove(path)
    except Exception:
        pass


@pytest.fixture(scope="module")
def geoip_svc(shared_db):
    """Instantiate GeoIP service with local MaxMind database."""
    return GeoIPService(db_manager=shared_db)


def test_1_database_exists_and_can_be_opened(geoip_svc):
    """TEST 1: Check whether the GeoIP database file exists and can be opened."""
    status = geoip_svc.get_database_status()
    db_path = status["configured_path"]

    assert os.path.isfile(db_path), f"GeoLite2 database not found at {db_path}"
    assert os.path.getsize(db_path) > 10 * 1024 * 1024, "Database file is smaller than expected 10MB"
    assert status["file_exists"] is True, "Database file_exists check failed"
    assert status["reader_loaded"] is True, "Database reader failed to initialize"
    assert status["status"] == "LOADED", f"Unexpected database status: {status['status']}"


def test_2_lookup_valid_public_ip(geoip_svc):
    """TEST 2: Look up a valid public IP address and verify geographic information."""
    # Test W3C / MIT public IP address
    test_ip = "128.30.52.100"
    res = geoip_svc.get_ip_intelligence(test_ip, force_refresh=True)

    assert res["ip"] == test_ip
    assert res["status"] == "available"
    assert res["is_public"] is True
    assert res["country"] == "United States"
    assert res["region"] == "Massachusetts"
    assert res["city"] == "Newton Highlands"
    assert res["latitude"] is not None and isinstance(res["latitude"], float)
    assert res["longitude"] is not None and isinstance(res["longitude"], float)
    assert abs(res["latitude"] - 42.327) < 0.1
    assert abs(res["longitude"] - (-71.2008)) < 0.1
    assert res["accuracy_km"] is not None and isinstance(res["accuracy_km"], int)
    assert res["accuracy_radius"] is not None
    assert res["provider"] == "maxmind_geolite2_local"


def test_3_lookup_private_rfc1918(geoip_svc):
    """TEST 3: Look up 192.168.1.10 and confirm it is NOT geolocated."""
    res = geoip_svc.get_ip_intelligence("192.168.1.10")

    assert res["ip"] == "192.168.1.10"
    assert res["status"] == "private/local"
    assert res["is_public"] is False
    assert res["ip_type"] == "private"
    assert res["latitude"] is None
    assert res["longitude"] is None
    assert res["country"] is None
    assert res["city"] is None
    assert res["region"] is None
    assert res["accuracy_km"] is None


def test_4_lookup_loopback_rfc1122(geoip_svc):
    """TEST 4: Look up 127.0.0.1 and confirm it is NOT geolocated."""
    res = geoip_svc.get_ip_intelligence("127.0.0.1")

    assert res["ip"] == "127.0.0.1"
    assert res["status"] == "private/local"
    assert res["is_public"] is False
    assert res["ip_type"] == "loopback"
    assert res["latitude"] is None
    assert res["longitude"] is None
    assert res["country"] is None
    assert res["city"] is None


def test_5_lookup_invalid_ip_addresses(geoip_svc):
    """TEST 5: Test invalid IP addresses."""
    invalid_ips = ["999.999.999.999", "not-an-ip", "256.1.2.3", ""]
    for bad_ip in invalid_ips:
        res = geoip_svc.get_ip_intelligence(bad_ip)
        assert res["status"] == "lookup failed"
        assert res["is_public"] is False
        assert res["latitude"] is None
        assert res["longitude"] is None
        assert res["country"] is None


def test_6_missing_database_file_fallback():
    """TEST 6: Test what happens if the database file is missing."""
    old_db_path = os.environ.get("GEOIP_DB_PATH")
    try:
        os.environ["GEOIP_DB_PATH"] = "data/non_existent_fake_db.mmdb"
        missing_svc = GeoIPService()
        status = missing_svc.get_database_status()

        assert status["file_exists"] is False
        assert status["reader_loaded"] is False
        assert status["status"] == "MISSING_FILE"

        # Lookup should not throw exception; returns lookup failed or fallback
        res = missing_svc.get_ip_intelligence("192.168.1.1")
        assert res["status"] == "private/local"
        assert res["latitude"] is None

        # Public lookup without DB falls back gracefully
        res_pub = missing_svc.get_ip_intelligence("8.8.8.8")
        assert res_pub is not None
        assert "status" in res_pub
    finally:
        if old_db_path:
            os.environ["GEOIP_DB_PATH"] = old_db_path
        else:
            os.environ.pop("GEOIP_DB_PATH", None)


def test_7_fastapi_ingestion_saves_geoip_to_sqlite(shared_db):
    """TEST 7: Send a network event through FastAPI ingestion pipeline and verify GeoIP is saved to SQLite."""
    # Temporarily bind db in api.index to shared_db
    import api.index as api_mod
    orig_db = api_mod.db
    orig_geoip = api_mod.geoip_svc
    try:
        api_mod.db = shared_db
        api_mod.geoip_svc = GeoIPService(db_manager=shared_db)

        test_public_ip = "128.30.52.100"
        result = process_and_persist_network_event(
            src_ip=test_public_ip,
            dst_ip="10.0.0.1",
            dst_port=445,
            src_port=52341,
            protocol="TCP",
            packet_size=512,
            collector_id="test_suite_collector",
            event_type="TEST_FLOW",
            is_suspicious_override=True,
            detection_reason_override="Port Scan Test Probe"
        )

        assert result is not None
        log_id = result.get("log_id")
        assert log_id is not None, "Pipeline failed to return log_id"

        # Query SQLite network_logs table
        persisted = shared_db.get_network_log_by_id(log_id)
        assert persisted is not None, f"Log {log_id} not found in SQLite"
        assert persisted["source_ip"] == test_public_ip
        assert persisted["geoip_country"] == "United States"
        assert persisted["geoip_city"] == "Newton Highlands"
        assert persisted["latitude"] is not None and isinstance(persisted["latitude"], float)
        assert persisted["longitude"] is not None and isinstance(persisted["longitude"], float)
        assert persisted["accuracy_km"] is not None
        assert persisted["detection_status"] == "suspicious"
        assert persisted["severity"] == "High"
    finally:
        api_mod.db = orig_db
        api_mod.geoip_svc = orig_geoip


def test_8_threat_map_reads_saved_event_and_displays_location(shared_db):
    """TEST 8: Verify that the Streamlit threat map reads the saved event and displays approximate location."""
    # Query threat map data from SQLite
    tmap_data = shared_db.get_threat_map_data(
        time_range="All Time",
        severity_filter=None,
        country_filter=None,
        attack_category_filter=None
    )

    markers = tmap_data["markers"]
    stats = tmap_data["statistics"]

    assert len(markers) >= 1, "Threat map found 0 markers in SQLite"
    assert stats["total_geolocated_sources"] >= 1, "Expected at least 1 geolocated source"
    assert stats["countries_detected"] >= 1, "Expected at least 1 detected country"
    assert stats["high_critical_events"] >= 1, "Expected at least 1 high/critical event"

    # Find the marker for 128.30.52.100
    target_marker = next((m for m in markers if "128.30.52.100" in m["source_ips"]), None)
    assert target_marker is not None, "Marker for 128.30.52.100 not found on threat map"
    assert target_marker["country"] == "United States"
    assert target_marker["city"] == "Newton Highlands"
    assert abs(target_marker["latitude"] - 42.327) < 0.1
    assert abs(target_marker["longitude"] - (-71.2008)) < 0.1
    assert target_marker["max_severity"] == "High"
    assert "first_seen" in target_marker
    assert "last_seen" in target_marker
    assert target_marker["event_count"] >= 1


def test_9_restart_application_and_database_remains_accessible(shared_db):
    """TEST 9: Restart the application and confirm that the database remains accessible."""
    # Close any open connections and simulate clean restart
    fresh_db = DatabaseManager(db_path=shared_db.db_path)
    fresh_geoip = GeoIPService(db_manager=fresh_db)

    # 1. Verify GeoIP service reopens and operates normally
    status = fresh_geoip.get_database_status()
    assert status["status"] == "LOADED"
    assert status["reader_loaded"] is True

    # 2. Verify IP lookup works on restarted service
    res = fresh_geoip.get_ip_intelligence("128.30.52.100")
    assert res["status"] == "available"
    assert res["country"] == "United States"

    # 3. Verify SQLite records remain intact after restart
    logs = fresh_db.get_geolocated_suspicious_logs(time_range="all")
    assert len(logs) >= 1
    assert any(l["source_ip"] == "128.30.52.100" for l in logs)

    # Clean shutdown
    fresh_geoip.close()
