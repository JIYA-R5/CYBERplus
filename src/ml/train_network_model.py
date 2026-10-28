"""
SentinelAI - Network Anomaly & Threat Detection Model Training Pipeline
Trains and evaluates:
1. Unsupervised Anomaly Detection: Scikit-Learn IsolationForest with calibrated decision threshold
2. Supervised Benchmark: RandomForestClassifier & LogisticRegression
Extracts features using src.features.network_features.
Evaluates scenario-by-scenario breakdown and saves standalone artifacts and metadata.
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

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.features.network_features import get_network_pipeline, NETWORK_FEATURE_NAMES


class NetworkModelTrainer:
    """
    Trains unsupervised and supervised network models on flow telemetry.
    """

    def __init__(
        self,
        dataset_path: str = "data/synthetic_network_flows.csv",
        output_dir: str = "reports",
        artifacts_dir: str = "artifacts"
    ):
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.artifacts_dir = artifacts_dir
        self.feature_pipeline = get_network_pipeline()
        self.df: Optional[pd.DataFrame] = None
        self.dataset_fingerprint: str = ""

    def _compute_fingerprint(self) -> str:
        hasher = hashlib.sha256()
        with open(self.dataset_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def load_data(self) -> pd.DataFrame:
        if not os.path.isfile(self.dataset_path):
            raise FileNotFoundError(f"Synthetic network flow dataset not found at {self.dataset_path}")

        self.dataset_fingerprint = self._compute_fingerprint()
        self.df = pd.read_csv(self.dataset_path)
        print(f"[NetworkTrainer] Loaded {len(self.df):,} flow records (SHA256: {self.dataset_fingerprint[:12]}...)")
        print(f"[NetworkTrainer] Scenarios: {self.df['scenario'].value_counts().to_dict()}")
        return self.df

    def create_splits(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Stratifies split across operational scenarios so that each split contains
        representative proportions of normal browsing, benign transfers, port scans,
        floods, and brute force attempts.
        """
        train_dfs = []
        val_dfs = []
        test_dfs = []

        for scenario, group in df.groupby("scenario"):
            group = group.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
            n = len(group)
            n_tr = int(n * train_ratio)
            n_va = int(n * (train_ratio + val_ratio))

            train_dfs.append(group.iloc[:n_tr])
            val_dfs.append(group.iloc[n_tr:n_va])
            test_dfs.append(group.iloc[n_va:])

        train_df = pd.concat(train_dfs, ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
        val_df = pd.concat(val_dfs, ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
        test_df = pd.concat(test_dfs, ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)

        print("\n[Splits] Stratified Scenario Split:")
        print(f"  - Train      : {len(train_df):>5} flows ({train_df['is_anomaly'].sum():>4} anomalies, {train_df['is_anomaly'].mean():.2%})")
        print(f"  - Validation : {len(val_df):>5} flows ({val_df['is_anomaly'].sum():>4} anomalies, {val_df['is_anomaly'].mean():.2%})")
        print(f"  - Test       : {len(test_df):>5} flows ({test_df['is_anomaly'].sum():>4} anomalies, {test_df['is_anomaly'].mean():.2%})")

        return train_df, val_df, test_df

    def train_and_evaluate(self) -> Dict[str, Any]:
        """Runs feature extraction, fits models, evaluates metrics and scenarios."""
        if self.df is None:
            self.load_data()

        df = self.df
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.artifacts_dir, exist_ok=True)

        train_df, val_df, test_df = self.create_splits(df)

        # Extract features using dedicated NetworkFlowFeaturePipeline
        X_train, _ = self.feature_pipeline.extract_features(train_df)
        X_val, _ = self.feature_pipeline.extract_features(val_df)
        X_test, _ = self.feature_pipeline.extract_features(test_df)

        y_train = train_df["is_anomaly"].to_numpy(dtype=int)
        y_val = val_df["is_anomaly"].to_numpy(dtype=int)
        y_test = test_df["is_anomaly"].to_numpy(dtype=int)

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_val_scaled = scaler.transform(X_val)
        X_test_scaled = scaler.transform(X_test)

        print("\n" + "=" * 80)
        print("1. UNSUPERVISED BASELINE: ISOLATION FOREST")
        print("=" * 80)

        # Fit Isolation Forest strictly on train data
        contamination_est = float(np.mean(y_train))
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=contamination_est,
            random_state=42,
            n_jobs=-1
        )
        iso_forest.fit(X_train_scaled)

        # Decision function: lower score = more anomalous
        # Negative anomaly score where higher score = more anomalous
        val_anomaly_scores = -iso_forest.decision_function(X_val_scaled)
        test_anomaly_scores = -iso_forest.decision_function(X_test_scaled)

        # Tune threshold on validation set to maximize F1
        threshold_candidates = np.percentile(val_anomaly_scores, np.linspace(50, 95, 20))
        best_iso_f1 = -1.0
        best_iso_thresh = 0.0

        for thresh in threshold_candidates:
            pred = (val_anomaly_scores >= thresh).astype(int)
            f1 = f1_score(y_val, pred, zero_division=0)
            if f1 > best_iso_f1:
                best_iso_f1 = f1
                best_iso_thresh = thresh

        # Evaluate Isolation Forest on untouched Test Set
        y_test_pred_iso = (test_anomaly_scores >= best_iso_thresh).astype(int)
        iso_metrics = self._evaluate_predictions(y_test, y_test_pred_iso, test_anomaly_scores)

        print(f"Isolation Forest (Optimal Threshold={best_iso_thresh:.4f}):")
        print(f"  Test Accuracy : {iso_metrics['accuracy']:.4f}")
        print(f"  Test Precision: {iso_metrics['precision']:.4f}")
        print(f"  Test Recall   : {iso_metrics['recall']:.4f}")
        print(f"  Test F1-Score : {iso_metrics['f1']:.4f}")
        print(f"  Test FPR      : {iso_metrics['fpr']:.4f}")
        print(f"  ROC-AUC       : {iso_metrics['roc_auc']:.4f}")

        print("\n" + "=" * 80)
        print("2. SUPERVISED BENCHMARK: RANDOM FOREST & LOGISTIC REGRESSION")
        print("=" * 80)

        supervised_models = {
            "Supervised Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=8,
                class_weight="balanced",
                random_state=42
            ),
            "Supervised Logistic Regression": LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                random_state=42
            )
        }

        sup_results = {}
        for name, clf in supervised_models.items():
            clf.fit(X_train_scaled, y_train)
            prob_test = clf.predict_proba(X_test_scaled)[:, 1]
            pred_test = (prob_test >= 0.5).astype(int)

            metrics = self._evaluate_predictions(y_test, pred_test, prob_test)
            sup_results[name] = {"clf": clf, "metrics": metrics, "preds": pred_test}
            print(f"[{name}]:")
            print(f"  Precision: {metrics['precision']:.4f} | Recall: {metrics['recall']:.4f} | F1: {metrics['f1']:.4f} | FPR: {metrics['fpr']:.4f} | ROC-AUC: {metrics['roc_auc']:.4f}")

        # 3. Scenario-by-Scenario Breakdown on Held-Out Test Set
        test_eval_df = test_df.copy()
        test_eval_df["iso_pred"] = y_test_pred_iso
        test_eval_df["rf_pred"] = sup_results["Supervised Random Forest"]["preds"]

        scenario_breakdown = []
        for scn, grp in test_eval_df.groupby("scenario"):
            tot = len(grp)
            is_anom_ground = grp["is_anomaly"].iloc[0]
            iso_detected = grp["iso_pred"].sum()
            rf_detected = grp["rf_pred"].sum()

            scenario_breakdown.append({
                "Scenario": scn,
                "Ground_Truth": "Malicious" if is_anom_ground == 1 else "Benign",
                "Total_Test_Samples": tot,
                "Isolation_Forest_Detections": int(iso_detected),
                "Isolation_Forest_Rate": round(float(iso_detected / tot), 4),
                "Random_Forest_Detections": int(rf_detected),
                "Random_Forest_Rate": round(float(rf_detected / tot), 4),
            })

        scenario_df = pd.DataFrame(scenario_breakdown)
        print("\n[Scenario Breakdown on Held-Out Test Set]:")
        print(scenario_df.to_string(index=False))

        # 4. Save comparison CSV
        comp_records = [{
            "Model": "Isolation Forest (Unsupervised)",
            "Model_Type": "Unsupervised Anomaly Detection",
            "Threshold": round(float(best_iso_thresh), 4),
            "Accuracy": iso_metrics["accuracy"],
            "Precision": iso_metrics["precision"],
            "Recall": iso_metrics["recall"],
            "F1_Score": iso_metrics["f1"],
            "False_Positive_Rate": iso_metrics["fpr"],
            "ROC_AUC": iso_metrics["roc_auc"],
            "TP": iso_metrics["tp"],
            "FP": iso_metrics["fp"],
            "TN": iso_metrics["tn"],
            "FN": iso_metrics["fn"],
        }]

        for name, data in sup_results.items():
            m = data["metrics"]
            comp_records.append({
                "Model": name,
                "Model_Type": "Supervised Classifier",
                "Threshold": 0.50,
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
            })

        comp_df = pd.DataFrame(comp_records)
        comp_path = os.path.join(self.output_dir, "network_model_comparison.csv")
        comp_df.to_csv(comp_path, index=False)
        print(f"\n[Saved] Network model comparison table saved to: {comp_path}")

        # 5. Save Artifacts: Full pipelines (Feature Scaler + Model)
        iso_pipeline = Pipeline([
            ("scaler", scaler),
            ("model", iso_forest)
        ])
        rf_pipeline = Pipeline([
            ("scaler", scaler),
            ("model", sup_results["Supervised Random Forest"]["clf"])
        ])

        iso_artifact_path = os.path.join(self.artifacts_dir, "network_anomaly_isolation_forest.joblib")
        rf_artifact_path = os.path.join(self.artifacts_dir, "network_threat_classifier.joblib")
        meta_artifact_path = os.path.join(self.artifacts_dir, "network_model_metadata.json")

        joblib.dump(iso_pipeline, iso_artifact_path)
        joblib.dump(rf_pipeline, rf_artifact_path)

        metadata = {
            "model_version": "network_flow_v1.0.0",
            "model_task": "network_flow_anomaly_detector",
            "feature_schema": NETWORK_FEATURE_NAMES,
            "training_date": datetime.datetime.now().isoformat(),
            "dataset_path": self.dataset_path,
            "dataset_fingerprint_sha256": self.dataset_fingerprint,
            "isolation_forest_optimal_threshold": float(best_iso_thresh),
            "isolation_forest_metrics": iso_metrics,
            "supervised_rf_metrics": sup_results["Supervised Random Forest"]["metrics"],
            "scenario_evaluation": scenario_breakdown,
            "synthetic_limitations": (
                "Trained on controlled synthetic network flow distributions. "
                "Synthetic flows provide verified ground truth for port scans, connection floods, and brute force, "
                "but may not encapsulate all subtle, encrypted, or zero-day protocol anomalies in diverse enterprise environments."
            )
        }

        with open(meta_artifact_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"[Saved] Network Isolation Forest saved to: {iso_artifact_path}")
        print(f"[Saved] Network Random Forest saved to: {rf_artifact_path}")
        print(f"[Saved] Network Model Metadata saved to: {meta_artifact_path}")

        return metadata

    def _evaluate_predictions(self, y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> Dict[str, Any]:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        try:
            auc = roc_auc_score(y_true, scores)
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
    parser = argparse.ArgumentParser(description="SentinelAI Network Flow Model Trainer")
    parser.add_argument("--dataset", default="data/synthetic_network_flows.csv", help="Path to synthetic network flow CSV")
    parser.add_argument("--output-dir", default="reports", help="Directory to save model comparison table")
    parser.add_argument("--artifacts-dir", default="artifacts", help="Directory to save serialized model and metadata")
    args = parser.parse_args()

    trainer = NetworkModelTrainer(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        artifacts_dir=args.artifacts_dir
    )
    trainer.train_and_evaluate()


if __name__ == "__main__":
    main()
