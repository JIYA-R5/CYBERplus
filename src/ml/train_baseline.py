"""
SentinelAI - Web-Log Baseline Model Training and Evaluation Pipeline
Trains, tunes, and validates baseline ML models (Logistic Regression, Decision Tree,
Random Forest) on application/web-log telemetry features.
Guarantees session-level group split isolation to prevent data leakage.
Excludes high-cardinality IDs and geographic shortcuts.
"""

import os
import sys
import json
import hashlib
import argparse
import datetime
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
import pandas as pd
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    precision_recall_curve
)


class BaselineModelTrainer:
    """
    Trains and benchmarks baseline web-log anomaly classification models.
    """

    FEATURE_COLUMNS = ["Request_Type", "Status_Code", "User_Agent"]
    TARGET_COLUMN = "Anomaly_Flag"
    GROUP_COLUMN = "Session_ID"
    TIMESTAMP_COLUMN = "Timestamp"

    def __init__(
        self,
        dataset_path: str = "data/advanced_cybersecurity_data.csv",
        output_dir: str = "reports",
        artifacts_dir: str = "artifacts",
        default_threshold: float = 0.50
    ):
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.artifacts_dir = artifacts_dir
        self.default_threshold = default_threshold

        self.df: Optional[pd.DataFrame] = None
        self.dataset_fingerprint: str = ""
        self.models: Dict[str, Any] = {}
        self.comparison_results: List[Dict[str, Any]] = []
        self.best_model_name: str = ""
        self.best_pipeline: Optional[Pipeline] = None
        self.best_threshold: float = default_threshold

    def _compute_dataset_fingerprint(self) -> str:
        """Calculates SHA256 checksum of raw dataset file."""
        hasher = hashlib.sha256()
        with open(self.dataset_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def load_and_validate(self) -> pd.DataFrame:
        """Loads dataset and validates required columns, target values, and groups."""
        if not os.path.isfile(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found at {self.dataset_path}")

        self.dataset_fingerprint = self._compute_dataset_fingerprint()
        df = pd.read_csv(self.dataset_path)

        # Validate required columns
        for col in self.FEATURE_COLUMNS:
            if col not in df.columns:
                raise ValueError(f"Required feature column '{col}' missing from dataset.")

        if self.TARGET_COLUMN not in df.columns:
            raise ValueError(f"Target column '{self.TARGET_COLUMN}' missing from dataset.")

        if self.GROUP_COLUMN not in df.columns:
            raise ValueError(f"Group column '{self.GROUP_COLUMN}' missing from dataset.")

        # Validate target labels (binary 0 or 1)
        valid_targets = {0, 1}
        actual_targets = set(df[self.TARGET_COLUMN].dropna().unique())
        if not actual_targets.issubset(valid_targets):
            raise ValueError(f"Target contains invalid classes: {actual_targets}. Expected subset of {valid_targets}.")

        positives = int(df[self.TARGET_COLUMN].sum())
        if positives == 0:
            raise ValueError("Dataset contains zero anomalous positive samples; evaluation is impossible.")

        self.df = df
        print(f"[DataLoader] Loaded {len(df):,} records (SHA256: {self.dataset_fingerprint[:12]}...)")
        print(f"[DataLoader] Features: {self.FEATURE_COLUMNS}")
        print(f"[DataLoader] Target: {self.TARGET_COLUMN} ({positives} anomalies, {positives/len(df):.2%})")
        return df

    def create_group_splits(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Creates train, validation, and test splits grouped by Session_ID.
        Ensures strict session isolation: no session appears in more than one split.
        """
        gss = GroupShuffleSplit(n_splits=1, train_size=train_ratio, random_state=random_state)
        train_idx, temp_idx = next(gss.split(df, groups=df[self.GROUP_COLUMN]))

        train_df = df.iloc[train_idx].copy()
        temp_df = df.iloc[temp_idx].copy()

        # Split remaining temp into validation and test (50/50 of remaining 30% -> 15% each)
        relative_val_size = val_ratio / (1.0 - train_ratio)
        gss_val = GroupShuffleSplit(n_splits=1, train_size=relative_val_size, random_state=random_state)
        val_idx, test_idx = next(gss_val.split(temp_df, groups=temp_df[self.GROUP_COLUMN]))

        val_df = temp_df.iloc[val_idx].copy()
        test_df = temp_df.iloc[test_idx].copy()

        # Sanity verify zero session leakage
        train_sessions = set(train_df[self.GROUP_COLUMN])
        val_sessions = set(val_df[self.GROUP_COLUMN])
        test_sessions = set(test_df[self.GROUP_COLUMN])

        leak_train_val = train_sessions.intersection(val_sessions)
        leak_train_test = train_sessions.intersection(test_sessions)
        leak_val_test = val_sessions.intersection(test_sessions)

        if leak_train_val or leak_train_test or leak_val_test:
            raise RuntimeError("CRITICAL ERROR: Session_ID leaked across split boundaries!")

        # Verify class distribution in each split
        for name, s_df in [("Train", train_df), ("Validation", val_df), ("Test", test_df)]:
            pos = int(s_df[self.TARGET_COLUMN].sum())
            neg = len(s_df) - pos
            if pos == 0 or neg == 0:
                raise RuntimeError(f"Invalid split distribution: {name} split has only one class (pos={pos}, neg={neg})!")

        print("\n[Splits] Session Group Split (Leakage-Free):")
        print(f"  - Train      : {len(train_df):>5} records ({train_df[self.TARGET_COLUMN].sum():>3} anomalies, {train_df[self.TARGET_COLUMN].mean():.2%}) | {len(train_sessions):>4} sessions")
        print(f"  - Validation : {len(val_df):>5} records ({val_df[self.TARGET_COLUMN].sum():>3} anomalies, {val_df[self.TARGET_COLUMN].mean():.2%}) | {len(val_sessions):>4} sessions")
        print(f"  - Test       : {len(test_df):>5} records ({test_df[self.TARGET_COLUMN].sum():>3} anomalies, {test_df[self.TARGET_COLUMN].mean():.2%}) | {len(test_sessions):>4} sessions")

        return train_df, val_df, test_df

    def create_chronological_splits(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Creates time-ordered splits to evaluate forward-looking performance on future events.
        """
        sorted_df = df.copy()
        if self.TIMESTAMP_COLUMN in sorted_df.columns:
            sorted_df["_dt"] = pd.to_datetime(sorted_df[self.TIMESTAMP_COLUMN])
            sorted_df = sorted_df.sort_values(by="_dt").reset_index(drop=True)
            sorted_df = sorted_df.drop(columns=["_dt"])

        n = len(sorted_df)
        n_train = int(n * train_ratio)
        n_val = int(n * (train_ratio + val_ratio))

        train_df = sorted_df.iloc[:n_train].copy()
        val_df = sorted_df.iloc[n_train:n_val].copy()
        test_df = sorted_df.iloc[n_val:].copy()

        print("\n[Splits] Chronological Split (Temporal Out-of-Time):")
        print(f"  - Train (Historical) : {len(train_df):>5} records ({train_df[self.TARGET_COLUMN].sum():>3} anomalies, {train_df[self.TARGET_COLUMN].mean():.2%})")
        print(f"  - Val   (Intermediate): {len(val_df):>5} records ({val_df[self.TARGET_COLUMN].sum():>3} anomalies, {val_df[self.TARGET_COLUMN].mean():.2%})")
        print(f"  - Test  (Future)      : {len(test_df):>5} records ({test_df[self.TARGET_COLUMN].sum():>3} anomalies, {test_df[self.TARGET_COLUMN].mean():.2%})")

        return train_df, val_df, test_df

    def _build_preprocessor(self) -> ColumnTransformer:
        """
        Constructs preprocessing transformer fitted strictly on training data.
        Performs missing value imputation and one-hot encoding for categorical features.
        """
        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
        ])

        preprocessor = ColumnTransformer(
            transformers=[
                ("categorical", cat_pipeline, self.FEATURE_COLUMNS)
            ],
            remainder="drop"
        )
        return preprocessor

    def train_and_compare(self) -> pd.DataFrame:
        """
        Executes end-to-end training and comparative validation of baseline candidate models.
        Selects best model strictly based on validation partition performance.
        Evaluates best model on held-out test partition.
        """
        if self.df is None:
            self.load_and_validate()

        df = self.df
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.artifacts_dir, exist_ok=True)

        # 1. Create session-grouped splits
        train_df, val_df, test_df = self.create_group_splits(df)

        X_train, y_train = train_df[self.FEATURE_COLUMNS], train_df[self.TARGET_COLUMN]
        X_val, y_val = val_df[self.FEATURE_COLUMNS], val_df[self.TARGET_COLUMN]
        X_test, y_test = test_df[self.FEATURE_COLUMNS], test_df[self.TARGET_COLUMN]

        # 2. Define baseline candidate models
        candidate_estimators = {
            "Logistic Regression": LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                random_state=42
            ),
            "Decision Tree": DecisionTreeClassifier(
                class_weight="balanced",
                max_depth=5,
                min_samples_split=20,
                random_state=42
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                max_depth=6,
                min_samples_leaf=10,
                random_state=42
            )
        }

        print("\n" + "=" * 80)
        print("FITTING PREPROCESSING AND MODELS (TRAIN PARTITION ONLY)")
        print("=" * 80)

        pipelines: Dict[str, Pipeline] = {}
        val_evaluations: Dict[str, Dict[str, Any]] = {}

        for name, estimator in candidate_estimators.items():
            preprocessor = self._build_preprocessor()
            pipe = Pipeline([
                ("preprocessor", preprocessor),
                ("classifier", estimator)
            ])

            # FIT ONLY ON TRAINING SET
            pipe.fit(X_train, y_train)
            pipelines[name] = pipe

            # EVALUATE ON VALIDATION SET
            y_val_prob = pipe.predict_proba(X_val)[:, 1] if hasattr(pipe, "predict_proba") else pipe.predict(X_val)
            y_val_pred = (y_val_prob >= self.default_threshold).astype(int)

            metrics = self._calculate_metrics(y_val, y_val_pred, y_val_prob)
            metrics["model_name"] = name
            metrics["split"] = "validation"
            metrics["threshold"] = self.default_threshold
            val_evaluations[name] = metrics

            print(f"[{name}] Validation Metrics (Threshold={self.default_threshold}):")
            print(f"  Precision: {metrics['precision']:.4f} | Recall: {metrics['recall']:.4f} | F1: {metrics['f1']:.4f} | FPR: {metrics['fpr']:.4f}")

        # 3. Model Selection: Best Model Chosen EXCLUSIVELY on Validation F1
        # (Tie-breaker: Precision, then lowest FPR)
        best_name = max(
            val_evaluations.keys(),
            key=lambda k: (val_evaluations[k]["f1"], val_evaluations[k]["precision"], -val_evaluations[k]["fpr"])
        )
        self.best_model_name = best_name
        self.best_pipeline = pipelines[best_name]

        print("\n" + "=" * 80)
        print(f"MODEL SELECTION RESULT: '{best_name}' selected based on validation performance.")
        print("=" * 80)

        # 4. Threshold tuning on Validation Partition for Best Model
        best_pipe = self.best_pipeline
        y_val_prob = best_pipe.predict_proba(X_val)[:, 1]

        threshold_sweep = self._sweep_decision_thresholds(y_val, y_val_prob)
        best_threshold_entry = max(threshold_sweep, key=lambda x: (x["f1"], x["precision"]))
        self.best_threshold = best_threshold_entry["threshold"]

        print(f"[Threshold Tuning] Swept thresholds for '{best_name}' on validation set.")
        print(f"  Default Threshold: {self.default_threshold} -> F1: {val_evaluations[best_name]['f1']:.4f}, Recall: {val_evaluations[best_name]['recall']:.4f}, FPR: {val_evaluations[best_name]['fpr']:.4f}")
        print(f"  Optimal Threshold: {self.best_threshold} -> F1: {best_threshold_entry['f1']:.4f}, Recall: {best_threshold_entry['recall']:.4f}, FPR: {best_threshold_entry['fpr']:.4f}")

        # 5. Untouched Final Test Set Evaluation for Best Model
        print("\n" + "=" * 80)
        print(f"FINAL UNTOUCHED TEST SET EVALUATION ('{best_name}')")
        print("=" * 80)

        y_test_prob = best_pipe.predict_proba(X_test)[:, 1]
        y_test_pred = (y_test_prob >= self.best_threshold).astype(int)
        test_metrics = self._calculate_metrics(y_test, y_test_pred, y_test_prob)
        test_metrics["model_name"] = best_name
        test_metrics["split"] = "test_held_out"
        test_metrics["threshold"] = self.best_threshold

        print(f"Test Partition Evaluation (Threshold={self.best_threshold}):")
        print(f"  Accuracy : {test_metrics['accuracy']:.4f}")
        print(f"  Precision: {test_metrics['precision']:.4f}")
        print(f"  Recall   : {test_metrics['recall']:.4f}")
        print(f"  F1-Score : {test_metrics['f1']:.4f}")
        print(f"  FPR      : {test_metrics['fpr']:.4f}")
        print(f"  ROC-AUC  : {test_metrics['roc_auc']:.4f}")
        print(f"\nConfusion Matrix:\n{np.array(test_metrics['confusion_matrix'])}")
        print(f"\nClassification Report:\n{classification_report(y_test, y_test_pred, digits=4)}")

        # 6. Chronological (Temporal Out-of-Time) Evaluation
        train_chrono, val_chrono, test_chrono = self.create_chronological_splits(df)
        X_train_c, y_train_c = train_chrono[self.FEATURE_COLUMNS], train_chrono[self.TARGET_COLUMN]
        X_test_c, y_test_c = test_chrono[self.FEATURE_COLUMNS], test_chrono[self.TARGET_COLUMN]

        chrono_pipe = Pipeline([
            ("preprocessor", self._build_preprocessor()),
            ("classifier", candidate_estimators[best_name])
        ])
        chrono_pipe.fit(X_train_c, y_train_c)
        y_chrono_prob = chrono_pipe.predict_proba(X_test_c)[:, 1]
        y_chrono_pred = (y_chrono_prob >= self.best_threshold).astype(int)
        chrono_metrics = self._calculate_metrics(y_test_c, y_chrono_pred, y_chrono_prob)
        chrono_metrics["model_name"] = f"{best_name} (Chronological)"
        chrono_metrics["split"] = "chronological_future_test"
        chrono_metrics["threshold"] = self.best_threshold

        print(f"\n[Chronological Evaluation] Performance on Future Time Records:")
        print(f"  Precision: {chrono_metrics['precision']:.4f} | Recall: {chrono_metrics['recall']:.4f} | F1: {chrono_metrics['f1']:.4f} | FPR: {chrono_metrics['fpr']:.4f}")

        # 7. Compile Comparison Table and Save
        comparison_records = []
        for name, m in val_evaluations.items():
            comparison_records.append({
                "Model": name,
                "Evaluation_Split": "Validation (Session-Grouped)",
                "Threshold": m["threshold"],
                "Accuracy": m["accuracy"],
                "Precision": m["precision"],
                "Recall": m["recall"],
                "F1_Score": m["f1"],
                "False_Positive_Rate": m["fpr"],
                "ROC_AUC": m["roc_auc"],
                "TP": m["tp"],
                "FP": m["fp"],
                "TN": m["tn"],
                "FN": m["fn"],
                "Selected_Best": (name == best_name)
            })

        comparison_records.append({
            "Model": best_name,
            "Evaluation_Split": "Final Test (Session-Grouped)",
            "Threshold": test_metrics["threshold"],
            "Accuracy": test_metrics["accuracy"],
            "Precision": test_metrics["precision"],
            "Recall": test_metrics["recall"],
            "F1_Score": test_metrics["f1"],
            "False_Positive_Rate": test_metrics["fpr"],
            "ROC_AUC": test_metrics["roc_auc"],
            "TP": test_metrics["tp"],
            "FP": test_metrics["fp"],
            "TN": test_metrics["tn"],
            "FN": test_metrics["fn"],
            "Selected_Best": True
        })

        comparison_records.append({
            "Model": f"{best_name} (Temporal)",
            "Evaluation_Split": "Future Out-Of-Time Test",
            "Threshold": chrono_metrics["threshold"],
            "Accuracy": chrono_metrics["accuracy"],
            "Precision": chrono_metrics["precision"],
            "Recall": chrono_metrics["recall"],
            "F1_Score": chrono_metrics["f1"],
            "False_Positive_Rate": chrono_metrics["fpr"],
            "ROC_AUC": chrono_metrics["roc_auc"],
            "TP": chrono_metrics["tp"],
            "FP": chrono_metrics["fp"],
            "TN": chrono_metrics["tn"],
            "FN": chrono_metrics["fn"],
            "Selected_Best": False
        })

        comp_df = pd.DataFrame(comparison_records)
        comparison_csv_path = os.path.join(self.output_dir, "model_comparison.csv")
        comp_df.to_csv(comparison_csv_path, index=False)
        print(f"\n[Saved] Model comparison table saved to: {comparison_csv_path}")

        # 8. Save Serialized Model Artifact & Metadata
        model_artifact_path = os.path.join(self.artifacts_dir, "web_log_model.joblib")
        metadata_path = os.path.join(self.artifacts_dir, "web_log_model_metadata.json")

        joblib.dump(best_pipe, model_artifact_path)
        print(f"[Saved] Selected model pipeline saved to: {model_artifact_path}")

        metadata = {
            "model_version": "web_log_v1.0.0",
            "model_task": "web_log_anomaly_detector",
            "selected_algorithm": best_name,
            "feature_schema": self.FEATURE_COLUMNS,
            "excluded_features": ["IP_Address", "Session_ID", "Timestamp", "Location"],
            "exclusion_rationale": "Identifiers (IP_Address, Session_ID) cause memorization leakage; Timestamp creates trivial temporal shortcuts; Location introduces synthetic geographic bias (North Korea 100% anomaly heuristic).",
            "training_date": datetime.datetime.now().isoformat(),
            "dataset_fingerprint_sha256": self.dataset_fingerprint,
            "decision_threshold": self.best_threshold,
            "validation_results": val_evaluations[best_name],
            "held_out_test_results": test_metrics,
            "chronological_test_results": chrono_metrics,
            "threshold_tradeoff_sweep": threshold_sweep,
            "disclaimer": "This model detects anomalous application/web-log patterns (HTTP verb, status code, user agent). It does not inspect packet-level or flow-level network measurements."
        }

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        print(f"[Saved] Model metadata saved to: {metadata_path}")

        return comp_df

    def _sweep_decision_thresholds(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        thresholds: Optional[List[float]] = None
    ) -> List[Dict[str, Any]]:
        """Sweeps decision thresholds to evaluate Precision, Recall, F1, and FPR trade-offs."""
        if thresholds is None:
            thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

        sweep = []
        for t in thresholds:
            pred = (y_prob >= t).astype(int)
            m = self._calculate_metrics(y_true, pred, y_prob)
            sweep.append({
                "threshold": t,
                "precision": m["precision"],
                "recall": m["recall"],
                "f1": m["f1"],
                "fpr": m["fpr"]
            })
        return sweep

    def _calculate_metrics(
        self,
        y_true: pd.Series,
        y_pred: np.ndarray,
        y_prob: np.ndarray
    ) -> Dict[str, Any]:
        """Calculates standardized classification metrics and confusion matrix."""
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        try:
            auc = roc_auc_score(y_true, y_prob)
        except Exception:
            auc = 0.5

        return {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
            "roc_auc": round(float(auc), 4),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "confusion_matrix": cm.tolist()
        }


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Baseline Model Trainer")
    parser.add_argument(
        "--dataset",
        default=os.environ.get(
            "DATASET_PATH",
            "data/advanced_cybersecurity_data.csv"
            if os.path.isfile("data/advanced_cybersecurity_data.csv")
            else "C:/Users/Asus/Downloads/advanced_cybersecurity_data.csv"
        ),
        help="Path to CSV dataset"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save model comparison table"
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Directory to save serialized model and metadata"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help="Default decision threshold"
    )
    args = parser.parse_args()

    trainer = BaselineModelTrainer(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        artifacts_dir=args.artifacts_dir,
        default_threshold=args.threshold
    )
    trainer.train_and_compare()


if __name__ == "__main__":
    main()
