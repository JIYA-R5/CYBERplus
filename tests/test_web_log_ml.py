"""
Unit tests for the baseline web-log ML training module (src/ml/train_baseline.py).
Validates feature exclusion, GroupShuffleSplit without session leakage, and preprocessor construction.
"""
import os
import pandas as pd
import pytest

from src.ml.train_baseline import BaselineModelTrainer


@pytest.fixture
def sample_web_log_df():
    """Create a dataframe with repeated sessions to test split isolation."""
    rows = []
    # 5 sessions, each with 10 records
    for s_id in range(100, 105):
        for i in range(10):
            rows.append({
                "Timestamp": f"2023-01-01 00:{i:02d}:00",
                "IP_Address": f"10.0.0.{s_id}",
                "Request_Type": "GET" if i % 2 == 0 else "POST",
                "Status_Code": 200 if i < 8 else 500,
                "Anomaly_Flag": 1 if i == 9 else 0,
                "User_Agent": "Chrome" if i % 3 == 0 else "Firefox",
                "Session_ID": s_id,
                "Location": "USA" if s_id % 2 == 0 else "Germany"
            })
    return pd.DataFrame(rows)


def test_feature_selection_and_exclusion():
    """Ensure baseline features only use Request_Type, Status_Code, User_Agent."""
    assert BaselineModelTrainer.FEATURE_COLUMNS == ["Request_Type", "Status_Code", "User_Agent"]
    assert BaselineModelTrainer.TARGET_COLUMN == "Anomaly_Flag"
    assert BaselineModelTrainer.GROUP_COLUMN == "Session_ID"

    # Verify identifiers and locations are excluded
    excluded = ["IP_Address", "Session_ID", "Timestamp", "Location"]
    for col in excluded:
        assert col not in BaselineModelTrainer.FEATURE_COLUMNS


def test_group_session_split_no_leakage(sample_web_log_df, tmp_path):
    """Test that records from the same session never leak across train/val/test splits."""
    csv_file = tmp_path / "web_log_sample.csv"
    sample_web_log_df.to_csv(csv_file, index=False)

    trainer = BaselineModelTrainer(dataset_path=str(csv_file), output_dir=str(tmp_path))
    train_df, val_df, test_df = trainer.create_group_splits(
        sample_web_log_df,
        train_ratio=0.6,
        val_ratio=0.2,
        random_state=42
    )

    train_sessions = set(train_df["Session_ID"])
    val_sessions = set(val_df["Session_ID"])
    test_sessions = set(test_df["Session_ID"])

    # Zero intersection between splits
    assert len(train_sessions.intersection(val_sessions)) == 0, "Train and Val share sessions!"
    assert len(train_sessions.intersection(test_sessions)) == 0, "Train and Test share sessions!"
    assert len(val_sessions.intersection(test_sessions)) == 0, "Val and Test share sessions!"

    # Total sessions preserved
    assert len(train_sessions) + len(val_sessions) + len(test_sessions) == sample_web_log_df["Session_ID"].nunique()


def test_chronological_splits(sample_web_log_df, tmp_path):
    """Test time-ordered splits."""
    csv_file = tmp_path / "web_log_sample.csv"
    sample_web_log_df.to_csv(csv_file, index=False)

    trainer = BaselineModelTrainer(dataset_path=str(csv_file), output_dir=str(tmp_path))
    train_df, val_df, test_df = trainer.create_chronological_splits(
        sample_web_log_df,
        train_ratio=0.6,
        val_ratio=0.2
    )

    assert len(train_df) + len(val_df) + len(test_df) == len(sample_web_log_df)
    # Confirm train timestamps precede test timestamps
    assert train_df["Timestamp"].iloc[0] <= test_df["Timestamp"].iloc[-1]


def test_preprocessor_construction(sample_web_log_df, tmp_path):
    """Verify ColumnTransformer fits categorical features."""
    trainer = BaselineModelTrainer(dataset_path="dummy.csv", output_dir=str(tmp_path))
    preprocessor = trainer._build_preprocessor()

    X = sample_web_log_df[BaselineModelTrainer.FEATURE_COLUMNS]
    X_trans = preprocessor.fit_transform(X)
    assert X_trans.shape[0] == len(sample_web_log_df)
    assert X_trans.shape[1] >= len(BaselineModelTrainer.FEATURE_COLUMNS)
