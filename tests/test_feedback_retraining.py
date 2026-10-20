"""
Automated Test Suite for SentinelAI Analyst Feedback & Controlled Retraining Module.
Verifies ground truth feedback recording, isolated label storage, audit trail creation,
controlled retraining validation, model version promotion, and model reversion.
"""

import pytest
import os
import tempfile
from database import DatabaseManager
from ml_engine import MLAnomalyEngine, get_ml_engine


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = f.name
    db = DatabaseManager(db_path=temp_path)
    yield db
    if os.path.exists(temp_path):
        try:
            os.remove(temp_path)
        except OSError:
            pass


@pytest.fixture
def temp_model_dir():
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


def test_analyst_feedback_isolated_storage(temp_db):
    """Verify analyst verdicts are stored in analyst_feedback separately from unverified model predictions."""
    # Seed incident with unverified model prediction
    temp_db.save_incident({
        "incident_id": "INC-FEEDBACK-01",
        "category": "Port Scan",
        "source_ip": "198.51.100.55",
        "model_version": "v1.0.0",
        "ml_anomaly_score": -0.25,
        "ml_is_anomaly": 1,
        "analyst_verdict": "Unreviewed"
    })

    # Submit true positive verdict
    fb_id = temp_db.record_analyst_feedback(
        incident_id="INC-FEEDBACK-01",
        verdict="True Positive",
        analyst_user="Senior SOC Analyst Alice",
        reason="Port 22/80/443 probing verified in firewall logs.",
        model_version="v1.0.0"
    )

    assert fb_id.startswith("FB-")

    # Check dedicated feedback table
    history = temp_db.get_feedback_history(incident_id="INC-FEEDBACK-01")
    assert len(history) == 1
    assert history[0]["feedback_id"] == fb_id
    assert history[0]["verdict"] == "True Positive"
    assert history[0]["analyst_user"] == "Senior SOC Analyst Alice"
    assert history[0]["model_version"] == "v1.0.0"

    # Check incident was updated
    inc = temp_db.get_incident_by_id("INC-FEEDBACK-01")
    assert inc["analyst_verdict"] == "True Positive"
    assert inc["analyst_user"] == "Senior SOC Analyst Alice"


def test_all_verdict_types_supported(temp_db):
    """Verify support for True Positive, False Positive, Benign, and Unresolved verdicts."""
    verdicts = ["True Positive", "False Positive", "Benign", "Unresolved"]

    for idx, v in enumerate(verdicts, 1):
        inc_id = f"INC-V-{idx}"
        temp_db.save_incident({
            "incident_id": inc_id,
            "category": "Traffic Burst",
            "source_ip": f"192.168.1.{10+idx}",
            "status": "Open"
        })
        fb_id = temp_db.record_analyst_feedback(
            incident_id=inc_id,
            verdict=v,
            analyst_user=f"Analyst {idx}",
            reason=f"Tested verdict {v}"
        )
        assert fb_id.startswith("FB-")
        inc = temp_db.get_incident_by_id(inc_id)
        assert inc["analyst_verdict"] == v


def test_invalid_verdict_rejection(temp_db):
    """Verify that invalid verdicts are rejected."""
    temp_db.save_incident({"incident_id": "INC-BAD-V", "category": "Port Scan", "source_ip": "1.2.3.4"})
    with pytest.raises(ValueError, match="Invalid verdict"):
        temp_db.record_analyst_feedback(
            incident_id="INC-BAD-V",
            verdict="INVALID_VERDICT_STRING",
            analyst_user="Hacker",
            reason="Invalid"
        )


def test_controlled_retraining_model_registry(temp_db, temp_model_dir):
    """Verify controlled retraining, model registry persistence, and rollback."""
    engine = MLAnomalyEngine(model_dir=temp_model_dir)

    # Initial training of v1.0.0
    fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=60)
    v1_metrics = engine.train(fixtures, version="v1.0.0")

    mod1_id = temp_db.register_model(
        version="v1.0.0",
        algorithm="IsolationForest",
        sample_count=60,
        metrics=v1_metrics,
        artifact_path=v1_metrics["artifact_path"],
        trained_by="Initial Training",
        set_active=True
    )
    assert mod1_id.startswith("MOD-")

    # Controlled retrain to candidate v1.1.0
    fixtures_new = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=80, random_seed=101)
    v2_res = engine.train_controlled_pipeline(
        training_data=fixtures_new,
        version_tag="v1.1.0",
        test_size=0.25,
        trained_by="SOC ML Lead"
    )

    mod2_id = temp_db.register_model(
        version="v1.1.0",
        algorithm="IsolationForest",
        sample_count=v2_res["total_samples"],
        metrics=v2_res,
        artifact_path=v2_res["artifact_path"],
        trained_by="SOC ML Lead",
        set_active=True
    )

    # Verify active model in registry is v1.1.0
    active = temp_db.get_active_model()
    assert active["version"] == "v1.1.0"

    # Revert active model back to v1.0.0
    revert_db = temp_db.set_active_model_version("v1.0.0")
    assert revert_db is True

    active_after = temp_db.get_active_model()
    assert active_after["version"] == "v1.0.0"
