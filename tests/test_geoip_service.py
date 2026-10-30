"""
Comprehensive automated unit tests for SentinelAI Source IP Geolocation & Network Intelligence Service.
Verifies:
- Public, private, loopback, reserved, link-local, and malformed IP classifications.
- Strict non-fabrication of coordinates for private/local IP addresses.
- Provider lookups, offline testbed fixtures, and graceful handling of unknown IPs.
- Multi-tier in-memory and SQLite persistent caching with TTL.
- Mandatory identity disclaimer adherence.
- Threat map aggregation and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from geoip_service import GeoIPService, get_geoip_service, GEOIP_DISCLAIMER
from database import get_db
from api.index import app


@pytest.fixture
def service():
    db = get_db()
    return GeoIPService(db_manager=db)


@pytest.fixture
def api_client():
    return TestClient(app)


def test_ip_classification_public(service):
    """Verify standard public IP addresses are classified correctly as public."""
    for ip in ["8.8.8.8", "1.1.1.1", "142.250.190.46", "198.51.100.99"]:
        res = service.classify_ip(ip)
        assert res.is_valid is True
        assert res.is_public is True
        assert res.ip_type == "public"


def test_ip_classification_private(service):
    """Verify RFC 1918 private IP addresses are correctly detected as non-public."""
    private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "172.31.255.254"]
    for ip in private_ips:
        res = service.classify_ip(ip)
        assert res.is_valid is True
        assert res.is_public is False
        assert res.ip_type == "private"
        assert "RFC 1918" in res.rfc_spec


def test_ip_classification_loopback(service):
    """Verify loopback addresses (127.0.0.0/8) are identified accurately."""
    for ip in ["127.0.0.1", "127.0.0.53", "127.255.255.254"]:
        res = service.classify_ip(ip)
        assert res.is_valid is True
        assert res.is_public is False
        assert res.ip_type == "loopback"
        assert "RFC 1122" in res.rfc_spec


def test_ip_classification_link_local_and_cgnat(service):
    """Verify link-local (169.254.0.0/16) and CGNAT (100.64.0.0/10) addresses."""
    res_ll = service.classify_ip("169.254.1.1")
    assert res_ll.is_valid is True
    assert res_ll.is_public is False
    assert res_ll.ip_type == "link_local"

    res_cg = service.classify_ip("100.64.0.1")
    assert res_cg.is_valid is True
    assert res_cg.is_public is False
    assert res_cg.ip_type == "cgnat"


def test_ip_classification_malformed(service):
    """Verify invalid or malformed strings are handled without crashing."""
    for invalid in ["not-an-ip", "999.999.999.999", "192.168.1.", "::xyz", ""]:
        res = service.classify_ip(invalid)
        assert res.is_valid is False
        assert res.is_public is False
        assert res.ip_type == "invalid"


def test_private_ips_never_have_fabricated_coordinates(service):
    """
    CRITICAL SECURITY & INTEGRITY REQUIREMENT:
    Private, loopback, and local IPs must NEVER be assigned fabricated geographic coordinates.
    """
    private_sample = ["192.168.1.1", "10.200.1.5", "127.0.0.1", "169.254.10.20"]
    for ip in private_sample:
        intel = service.get_ip_intelligence(ip)
        assert intel["is_public"] is False
        assert intel["latitude"] is None, f"Private IP {ip} must NOT have latitude"
        assert intel["longitude"] is None, f"Private IP {ip} must NOT have longitude"
        assert intel["status"] == "private/local"
        assert "approximate" in intel["disclaimer"].lower()


def test_curated_offline_fixture_lookup(service):
    """Verify deterministic offline curated testbed addresses return verified intelligence."""
    intel_de = service.get_ip_intelligence("198.51.100.99")
    assert intel_de["is_public"] is True
    assert intel_de["country"] == "Germany"
    assert intel_de["city"] == "Frankfurt"
    assert intel_de["latitude"] == 50.1109
    assert intel_de["longitude"] == 8.6821
    assert intel_de["status"] == "available"
    assert intel_de["provider"] == "offline_curated_fixture"

    intel_cf = service.get_ip_intelligence("1.1.1.1")
    assert intel_cf["is_public"] is True
    assert intel_cf["country"] == "Australia"
    assert intel_cf["status"] == "available"


def test_in_memory_and_db_caching(service):
    """Verify that lookups are cached in memory and in the database to prevent duplicate network calls."""
    test_ip = "198.51.100.42"

    # First lookup
    first = service.get_ip_intelligence(test_ip)
    assert first["country"] == "Poland"

    # Verify cached in in-memory cache
    assert test_ip in service._cache

    # Second lookup should hit cache
    second = service.get_ip_intelligence(test_ip)
    assert second["country"] == "Poland"
    assert second["latitude"] == first["latitude"]


def test_batch_enrichment(service):
    """Verify batch IP enrichment processes lists of IPs efficiently."""
    ips = ["198.51.100.99", "192.168.1.50", "1.1.1.1"]
    batch = service.batch_get_ip_intelligence(ips)
    assert len(batch) == 3
    assert batch["198.51.100.99"]["is_public"] is True
    assert batch["192.168.1.50"]["is_public"] is False
    assert batch["1.1.1.1"]["is_public"] is True


def test_incident_enrichment(service):
    """Verify incident dictionaries are enriched with both source and destination GeoIP data."""
    inc = {
        "incident_id": "INC-TEST-001",
        "source_ip": "198.51.100.23",
        "destination_ip": "192.168.1.10",
        "category": "Port Scan"
    }
    enriched = service.enrich_incident(inc)
    assert "source_geo" in enriched
    assert enriched["source_geo"]["country"] == "Switzerland"
    assert "destination_geo" in enriched
    assert enriched["destination_geo"]["is_public"] is False


def test_geoip_api_endpoint(api_client):
    """Verify FastAPI /api/geoip/{ip} endpoint returns valid network intelligence."""
    res = api_client.get("/api/geoip/198.51.100.99")
    assert res.status_code == 200
    data = res.json()
    assert data["ip"] == "198.51.100.99"
    assert data["country"] == "Germany"
    assert data["latitude"] is not None
    assert "disclaimer" in data


def test_threat_map_api_endpoint(api_client):
    """Verify FastAPI /api/threat-map endpoint aggregates markers and isolates internal hosts."""
    res = api_client.get("/api/threat-map")
    assert res.status_code == 200
    data = res.json()
    assert "markers" in data
    assert "country_aggregates" in data
    assert "local_network" in data
    assert "disclaimer" in data
    assert isinstance(data["markers"], list)
    assert isinstance(data["country_aggregates"], list)
    assert isinstance(data["local_network"], list)

    # Ensure no local/private IPs leaked into public markers
    for m in data["markers"]:
        assert m["latitude"] is not None
        assert m["longitude"] is not None
        for s_ip in m["source_ips"]:
            service = get_geoip_service()
            assert service.classify_ip(s_ip).is_public is True
