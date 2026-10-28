"""
Unit tests for the dataset audit module (src/ml/audit_dataset.py).
Validates schema checks, North Korea anomaly flagging, and reporting.
"""
import os
import pandas as pd
import pytest

from src.ml.audit_dataset import DatasetAuditor


@pytest.fixture
def sample_csv(tmp_path):
    """Create a temporary dataset with known characteristics including North Korea."""
    csv_file = tmp_path / "test_cyber_data.csv"
    df = pd.DataFrame({
        "Timestamp": ["2023-01-01 00:00:00", "2023-01-01 00:01:00", "2023-01-01 00:02:00"],
        "IP_Address": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        "Request_Type": ["GET", "POST", "DELETE"],
        "Status_Code": [200, 404, 500],
        "Anomaly_Flag": [0, 0, 1],
        "User_Agent": ["Chrome", "Firefox", "Bot"],
        "Session_ID": [1001, 1002, 1003],
        "Location": ["USA", "Germany", "North Korea"]
    })
    df.to_csv(csv_file, index=False)
    return str(csv_file)


def test_expected_columns():
    """Verify expected schema columns list."""
    expected = [
        "Timestamp", "IP_Address", "Request_Type", "Status_Code",
        "Anomaly_Flag", "User_Agent", "Session_ID", "Location"
    ]
    assert DatasetAuditor.EXPECTED_COLUMNS == expected


def test_auditor_on_sample(sample_csv, tmp_path):
    """Test full audit run on controlled sample."""
    out_dir = str(tmp_path / "reports")
    auditor = DatasetAuditor(dataset_path=sample_csv, output_dir=out_dir)
    metrics = auditor.audit()

    assert metrics["normal_count"] == 2
    assert metrics["anomaly_count"] == 1
    assert metrics["north_korea_total"] == 1
    assert metrics["north_korea_rate"] == 1.0  # 100% anomaly rate for North Korea
    assert os.path.isfile(os.path.join(out_dir, "dataset_audit.txt"))


def test_auditor_actual_dataset_if_present():
    """If advanced_cybersecurity_data.csv exists, verify reported metrics match reality."""
    dataset_path = "data/advanced_cybersecurity_data.csv"
    if os.path.isfile(dataset_path):
        auditor = DatasetAuditor(dataset_path=dataset_path, output_dir="reports")
        metrics = auditor.audit()

        assert metrics["normal_count"] == 9510
        assert metrics["anomaly_count"] == 490
        assert metrics["north_korea_total"] == 10
        assert metrics["north_korea_rate"] == 1.0  # Exactly 100% anomaly rate verified
