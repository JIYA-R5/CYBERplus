"""
Unit test suite for SentinelAI ThreatExplainer Module.
Verifies Google Gemini fallback mechanisms, Pydantic schema validation,
executive summary generation, and compliance disclaimers.
"""

import pytest
import pandas as pd
from explainerAI import ThreatExplainer, ThreatExplanation, get_explainer


@pytest.fixture
def offline_explainer():
    """Returns an explainer with no API key, forcing deterministic local fallback."""
    return ThreatExplainer(api_key="")


def test_explainer_fallback_contract(offline_explainer):
    """Verify that offline explainer returns a valid ThreatExplanation dictionary."""
    explanation = offline_explainer.explain_threat(
        activity="Port Scan",
        source_ip="192.168.1.15",
        packets=450,
        risk="High",
        details="Sequential probing detected"
    )

    assert isinstance(explanation, dict)
    assert explanation["activity"] == "Port Scan"
    assert explanation["source_ip"] == "192.168.1.15"
    assert explanation["risk"] == "High"
    assert "T1046" in explanation["mitre_technique"]
    assert len(explanation["investigation_steps"]) >= 2
    assert len(explanation["containment_recommendations"]) >= 2
    assert explanation["provider"] == "local_rule_fallback"
    assert "advisory" in explanation["ai_disclaimer"].lower()


def test_all_signature_explanations(offline_explainer):
    """Verify all supported attack categories provide actionable playbooks."""
    signatures = ["Port Scan", "Brute Force", "DDoS Flood", "Data Exfiltration", "Suspicious Reconnaissance", "High Volume Anomaly"]
    for sig in signatures:
        res = offline_explainer.explain_threat(
            activity=sig,
            source_ip="10.0.0.5",
            packets=500,
            risk="High"
        )
        assert len(res["summary"]) > 20
        assert len(res["mechanism"]) > 20
        assert len(res["potential_impact"]) > 20
        assert res["mitre_technique"].startswith("T1")


def test_invalid_api_key_resilience():
    """Verify that an invalid API key does not crash the system and falls back safely."""
    explainer = ThreatExplainer(api_key="INVALID_TEST_KEY_12345")
    # explain_threat should handle any API error gracefully
    res = explainer.explain_threat(
        activity="Brute Force",
        source_ip="192.168.1.99",
        packets=380,
        risk="High"
    )
    assert isinstance(res, dict)
    assert res["activity"] == "Brute Force"
    assert "T1110" in res["mitre_technique"]
    assert res["provider"] in ["google_gemini", "local_rule_fallback"]


def test_executive_summary_nominal(offline_explainer):
    """Verify executive summary generation for nominal network conditions."""
    df_nominal = pd.DataFrame({
        "Activity": ["Normal Traffic", "Normal Traffic"],
        "Risk": ["Low", "Low"],
        "Source IP": ["192.168.1.10", "192.168.1.20"]
    })
    summary = offline_explainer.generate_executive_summary(df_nominal)
    assert "No elevated security threats were identified" in summary


def test_executive_summary_elevated(offline_explainer):
    """Verify executive summary generation when high-severity threats are present."""
    df_threat = pd.DataFrame({
        "Activity": ["Port Scan", "Normal Traffic"],
        "Risk": ["High", "Low"],
        "Source IP": ["192.168.1.15", "192.168.1.20"]
    })
    summary = offline_explainer.generate_executive_summary(df_threat)
    assert "flagged 1 high-severity alert" in summary
    assert "Port Scan" in summary
    assert "192.168.1.15" in summary


def test_api_key_loaded_from_environment(monkeypatch):
    """Verify that ThreatExplainer automatically reads GEMINI_API_KEY from the environment."""
    test_key = "test_env_key_abc_123"
    monkeypatch.setenv("GEMINI_API_KEY", test_key)
    explainer = ThreatExplainer()
    assert explainer.api_key == test_key


def test_api_key_strips_quotes_from_env(monkeypatch):
    """Verify that quotes around keys in .env files are stripped automatically."""
    monkeypatch.setenv("GEMINI_API_KEY", '"quoted_gemini_key_999"')
    explainer = ThreatExplainer()
    assert explainer.api_key == "quoted_gemini_key_999"


def test_google_api_key_fallback(monkeypatch):
    """Verify that GOOGLE_API_KEY is also recognized as a valid fallback environment variable."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "google_fallback_key_456")
    explainer = ThreatExplainer()
    assert explainer.api_key == "google_fallback_key_456"

