"""
SentinelAI - Machine Learning Threat Intelligence Module
Provides statistical anomaly detection using Scikit-Learn IsolationForest,
repeatable training pipelines, feature extraction with zero data leakage,
model versioning, evaluation metrics, and transparent scoring.
"""

import os
import json
import datetime
from typing import Dict, Any, List, Optional, Union, Tuple
import numpy as np
import pandas as pd
import joblib

FEATURE_NAMES = [
    "packets",
    "port",
    "flow_frequency",
    "unique_ports_contacted",
    "mean_packets_per_flow",
    "is_privileged_port",
    "is_admin_port",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "outcome_allowed",
    "outcome_blocked",
]

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")


class TelemetryFeatureExtractor:
    """
    Transforms raw network flow and alert telemetry into normalized numerical features.
    Guarantees robust imputation of missing fields and strictly prevents data leakage
    by excluding target labels, rule heuristics, or downstream classifications.
    """

    def __init__(self):
        self.feature_names = list(FEATURE_NAMES)

    def extract_features(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]
    ) -> Tuple[np.ndarray, pd.DataFrame]:
        """
        Extract numerical feature vectors from DataFrame, list of records, or single dict.
        Returns:
            X: 2D numpy array of shape (N, len(FEATURE_NAMES))
            feature_df: DataFrame containing the normalized features
        """
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data) if data else pd.DataFrame(columns=["Packets", "Port"])
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            df = pd.DataFrame()

        if df.empty:
            empty_df = pd.DataFrame(columns=self.feature_names)
            return np.empty((0, len(self.feature_names))), empty_df

        # Column normalization
        col_map = {str(c).lower().replace(" ", "_"): c for c in df.columns}
        src_col = col_map.get("source_ip", col_map.get("src_ip", col_map.get("ip", "Source IP")))
        port_col = col_map.get("port", col_map.get("destination_port", col_map.get("dest_port", "Port")))
        pkt_col = col_map.get("packets", col_map.get("pkts", col_map.get("packet_count", "Packets")))
        proto_col = col_map.get("proto", col_map.get("protocol", "Protocol"))
        action_col = col_map.get("action", col_map.get("status", col_map.get("outcome", "Action")))

        # 1. Packet Count
        if pkt_col in df.columns:
            packets_series = pd.to_numeric(df[pkt_col], errors="coerce").fillna(0.0).clip(lower=0.0)
        else:
            packets_series = pd.Series(0.0, index=df.index)

        # 2. Port & Port Categories
        if port_col in df.columns:
            port_series = pd.to_numeric(df[port_col], errors="coerce").fillna(0.0).clip(lower=0.0, upper=65535.0)
        else:
            port_series = pd.Series(0.0, index=df.index)

        is_privileged = (port_series > 0) & (port_series < 1024)
        admin_ports = {21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080}
        is_admin = port_series.isin(admin_ports)

        # 3. Aggregations per Source IP (Frequency & Port Diversity)
        if src_col in df.columns:
            src_series = df[src_col].astype(str).fillna("0.0.0.0")
            # Flow frequency per source IP
            src_freq_map = src_series.value_counts().to_dict()
            flow_freq = src_series.map(src_freq_map).fillna(1.0).astype(float)

            # Unique ports per source IP
            temp_df = pd.DataFrame({"src": src_series, "port": port_series})
            unique_ports_map = temp_df.groupby("src")["port"].nunique().to_dict()
            unique_ports = src_series.map(unique_ports_map).fillna(1.0).astype(float)

            # Mean packets per source IP
            temp_df["pkts"] = packets_series
            mean_pkts_map = temp_df.groupby("src")["pkts"].mean().to_dict()
            mean_pkts = src_series.map(mean_pkts_map).fillna(packets_series).astype(float)
        else:
            flow_freq = pd.Series(1.0, index=df.index)
            unique_ports = pd.Series(1.0, index=df.index)
            mean_pkts = packets_series.copy()

        # 4. Protocol One-Hot Encoding
        if proto_col in df.columns:
            proto_clean = df[proto_col].astype(str).str.upper().fillna("UNKNOWN")
            proto_tcp = (proto_clean.str.contains("TCP")).astype(float)
            proto_udp = (proto_clean.str.contains("UDP")).astype(float)
            proto_icmp = (proto_clean.str.contains("ICMP")).astype(float)
        else:
            # Default to TCP if port indicates standard TCP, or zero
            proto_tcp = pd.Series(1.0, index=df.index)
            proto_udp = pd.Series(0.0, index=df.index)
            proto_icmp = pd.Series(0.0, index=df.index)

        # 5. Connection Outcome Encoding
        if action_col in df.columns:
            act_clean = df[action_col].astype(str).str.lower().fillna("allowed")
            outcome_allowed = (act_clean.isin(["allowed", "allow", "pass", "200", "ok"])).astype(float)
            outcome_blocked = (act_clean.isin(["blocked", "block", "drop", "deny", "rejected"])).astype(float)
        else:
            outcome_allowed = pd.Series(1.0, index=df.index)
            outcome_blocked = pd.Series(0.0, index=df.index)

        # Assemble feature DataFrame
        feature_df = pd.DataFrame({
            "packets": packets_series.astype(float),
            "port": port_series.astype(float),
            "flow_frequency": flow_freq.astype(float),
            "unique_ports_contacted": unique_ports.astype(float),
            "mean_packets_per_flow": mean_pkts.astype(float),
            "is_privileged_port": is_privileged.astype(float),
            "is_admin_port": is_admin.astype(float),
            "proto_tcp": proto_tcp.astype(float),
            "proto_udp": proto_udp.astype(float),
            "proto_icmp": proto_icmp.astype(float),
            "outcome_allowed": outcome_allowed.astype(float),
            "outcome_blocked": outcome_blocked.astype(float),
        }, index=df.index)

        # Ensure exact column order and fill any remaining NaNs
        feature_df = feature_df[self.feature_names].fillna(0.0)
        X = feature_df.values.astype(np.float64)

        return X, feature_df


class MLAnomalyEngine:
    """
    Enterprise-grade ML Anomaly Engine managing IsolationForest model lifecycles,
    versioned serialization, evaluation metrics, and score transparency.
    """

    def __init__(
        self,
        model_version: str = "v1.0.0",
        contamination: float = 0.15,
        random_state: int = 42,
        model_dir: Optional[str] = None
    ):
        self.model_version = model_version
        self.contamination = contamination
        self.random_state = random_state
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        self.model = None
        self.is_fitted = False
        self.extractor = TelemetryFeatureExtractor()
        self.metrics: Dict[str, Any] = {}

        os.makedirs(self.model_dir, exist_ok=True)
        self._load_active_or_default()

    def _get_model_path(self, version: str) -> str:
        clean_v = version.replace("isolation_forest_", "")
        return os.path.join(self.model_dir, f"isolation_forest_{clean_v}.joblib")

    def _get_meta_path(self, version: str) -> str:
        clean_v = version.replace("isolation_forest_", "")
        return os.path.join(self.model_dir, f"isolation_forest_{clean_v}_meta.json")

    def _load_active_or_default(self):
        """Attempt to load default model version if file exists on disk."""
        target_path = self._get_model_path(self.model_version)
        if os.path.exists(target_path):
            try:
                self.model = joblib.load(target_path)
                self.is_fitted = True
                meta_path = self._get_meta_path(self.model_version)
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.metrics = json.load(f)
            except Exception:
                self.is_fitted = False
                self.model = None

    def train(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], np.ndarray],
        version: Optional[str] = None,
        contamination: Optional[float] = None,
        trained_by: str = "SOC ML Pipeline"
    ) -> Dict[str, Any]:
        """
        Train IsolationForest on normalized telemetry features.
        Calculates baseline distribution metrics and persists versioned artifacts.
        """
        from sklearn.ensemble import IsolationForest

        use_version = version or self.model_version
        use_contam = contamination if contamination is not None else self.contamination

        if isinstance(data, np.ndarray):
            X = data.astype(np.float64)
            feature_df = pd.DataFrame(X, columns=FEATURE_NAMES[:X.shape[1]])
        else:
            X, feature_df = self.extractor.extract_features(data)

        if len(X) < 4:
            return {
                "status": "ERROR",
                "message": f"Insufficient observations to train reliably ({len(X)} provided, minimum 4 required).",
                "sample_count": len(X)
            }

        model = IsolationForest(
            contamination=use_contam,
            random_state=self.random_state,
            n_estimators=100
        )
        model.fit(X)

        # Baseline evaluation metrics
        preds = model.predict(X)  # -1 anomaly, 1 inlier
        scores = model.decision_function(X)

        inlier_count = int(np.sum(preds == 1))
        outlier_count = int(np.sum(preds == -1))
        outlier_ratio = round(outlier_count / len(preds), 4)

        metrics = {
            "model_version": use_version,
            "algorithm": "IsolationForest",
            "contamination_parameter": use_contam,
            "trained_at": datetime.datetime.now().isoformat(),
            "trained_by": trained_by,
            "sample_count": int(len(X)),
            "features_used": self.extractor.feature_names[:X.shape[1]],
            "inlier_count": inlier_count,
            "outlier_count": outlier_count,
            "empirical_outlier_ratio": outlier_ratio,
            "score_mean": round(float(np.mean(scores)), 4),
            "score_std": round(float(np.std(scores)), 4),
            "score_min": round(float(np.min(scores)), 4),
            "score_max": round(float(np.max(scores)), 4),
        }

        # Save model and metadata artifacts
        model_path = self._get_model_path(use_version)
        meta_path = self._get_meta_path(use_version)

        joblib.dump(model, model_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        self.model = model
        self.model_version = use_version
        self.contamination = use_contam
        self.is_fitted = True
        self.metrics = metrics

        metrics["status"] = "TRAINED_SUCCESS"
        metrics["artifact_path"] = model_path
        return metrics

    def predict_score(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any], np.ndarray]
    ) -> Dict[str, Any]:
        """
        Predict whether telemetry is anomalous and return continuous score,
        normalized confidence, and transparent feature context.
        """
        if not self.is_fitted or self.model is None:
            return {
                "is_anomaly": False,
                "raw_score": 0.0,
                "confidence": 0.0,
                "status": "Model uncalibrated",
                "model_version": self.model_version,
                "disclaimer": "Notice: Statistical anomaly score measures deviation from baseline traffic and is NOT proof of an attack or malicious compromise."
            }

        if isinstance(data, np.ndarray):
            X = data.astype(np.float64)
            if X.ndim == 1:
                X = X.reshape(1, -1)
        else:
            X, _ = self.extractor.extract_features(data)

        if len(X) == 0:
            return {
                "is_anomaly": False,
                "raw_score": 0.0,
                "confidence": 0.0,
                "status": "Empty input",
                "model_version": self.model_version
            }

        # Predict for first row / primary record
        pred = self.model.predict(X[0:1])[0]  # -1 for anomaly, 1 for inlier
        raw_score = float(self.model.decision_function(X[0:1])[0])

        # Normalized anomaly confidence: higher means more anomalous (0.0 to 1.0)
        # Decision function: inliers > 0, anomalies < 0.
        norm_conf = round(max(0.0, min(1.0, 0.5 - (raw_score * 2.0))), 2)

        return {
            "is_anomaly": bool(pred == -1),
            "raw_score": round(raw_score, 4),
            "confidence": norm_conf,
            "status": "Evaluated",
            "model_version": self.model_version,
            "disclaimer": (
                "Notice: Anomaly score reflects statistical deviation from learned traffic baselines. "
                "Anomalous score is NOT proof of an attack or malicious compromise."
            )
        }

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich a traffic DataFrame with ML anomaly predictions, continuous scores, and confidence.
        """
        if df.empty or not self.is_fitted or self.model is None:
            df_res = df.copy()
            df_res["ML_Anomaly"] = False
            df_res["ML_Anomaly_Score"] = 0.0
            df_res["ML_Confidence"] = 0.0
            df_res["ML_Model_Version"] = self.model_version
            return df_res

        X, _ = self.extractor.extract_features(df)
        preds = self.model.predict(X)
        scores = self.model.decision_function(X)
        confidences = np.clip(0.5 - (scores * 2.0), 0.0, 1.0).round(2)

        df_res = df.copy()
        df_res["ML_Anomaly"] = (preds == -1)
        df_res["ML_Anomaly_Score"] = np.round(scores, 4)
        df_res["ML_Confidence"] = confidences
        df_res["ML_Model_Version"] = self.model_version
        return df_res

    def revert_model(self, target_version: str) -> bool:
        """
        Revert active model to a previously registered version.
        """
        target_path = self._get_model_path(target_version)
        if not os.path.exists(target_path):
            return False

        try:
            self.model = joblib.load(target_path)
            self.model_version = target_version
            self.is_fitted = True
            meta_path = self._get_meta_path(target_version)
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            return True
        except Exception:
            return False

    def validate_dataset(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]]],
        min_samples: int = 10
    ) -> Dict[str, Any]:
        """
        Validate candidate retraining dataset before initiating training.
        Prevents training on empty or statistically inadequate data.
        """
        if isinstance(data, list):
            df = pd.DataFrame(data) if data else pd.DataFrame()
        elif isinstance(data, pd.DataFrame):
            df = data
        else:
            return {"valid": False, "reason": "Unsupported data format", "sample_count": 0}

        if len(df) < min_samples:
            return {
                "valid": False,
                "reason": f"Sample count ({len(df)}) below minimum required ({min_samples}) to prevent overfitting.",
                "sample_count": len(df)
            }
        return {"valid": True, "sample_count": len(df), "reason": "Dataset validated successfully."}

    def train_controlled_pipeline(
        self,
        training_data: Union[pd.DataFrame, List[Dict[str, Any]]],
        version_tag: Optional[str] = None,
        test_size: float = 0.25,
        trained_by: str = "SOC Admin",
        contamination: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Execute controlled retraining workflow:
        1. Validate dataset
        2. Perform train/test split to prevent data leakage and evaluate on unseen holdout
        3. Train candidate Isolation Forest
        4. Calculate evaluation metrics on holdout test set
        5. Persist versioned artifacts
        6. Return candidate model evaluation summary
        """
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import IsolationForest

        val_res = self.validate_dataset(training_data, min_samples=10)
        if not val_res["valid"]:
            return {
                "status": "VALIDATION_FAILED",
                "message": val_res["reason"],
                "sample_count": val_res["sample_count"]
            }

        if isinstance(training_data, list):
            df = pd.DataFrame(training_data)
        else:
            df = training_data.copy()

        X, _ = self.extractor.extract_features(df)
        use_contam = contamination if contamination is not None else self.contamination

        # Determine version tag (e.g. v1.1.0 or custom)
        if not version_tag:
            curr_v = self.model_version.lstrip("v")
            try:
                parts = [int(p) for p in curr_v.split(".")]
                parts[-1] += 1
                new_v = "v" + ".".join(str(p) for p in parts)
            except Exception:
                new_v = f"v{datetime.datetime.now().strftime('%Y%m%d%H%M')}"
        else:
            new_v = version_tag

        # Train / test split to evaluate on unseen holdout
        X_train, X_test = train_test_split(X, test_size=test_size, random_state=self.random_state)

        candidate_model = IsolationForest(
            contamination=use_contam,
            random_state=self.random_state,
            n_estimators=100
        )
        candidate_model.fit(X_train)

        # Test set evaluation
        test_preds = candidate_model.predict(X_test)
        test_scores = candidate_model.decision_function(X_test)
        outlier_count = int(np.sum(test_preds == -1))
        inlier_count = int(np.sum(test_preds == 1))
        empirical_contam = round(outlier_count / len(test_preds), 4)

        metrics = {
            "model_version": new_v,
            "algorithm": "IsolationForest",
            "contamination_parameter": use_contam,
            "trained_at": datetime.datetime.now().isoformat(),
            "trained_by": trained_by,
            "train_sample_count": len(X_train),
            "test_sample_count": len(X_test),
            "total_samples": len(X),
            "test_inlier_count": inlier_count,
            "test_outlier_count": outlier_count,
            "test_empirical_outlier_ratio": empirical_contam,
            "test_score_mean": round(float(np.mean(test_scores)), 4),
            "test_score_std": round(float(np.std(test_scores)), 4),
            "features_used": self.extractor.feature_names[:X.shape[1]],
            "status": "VALIDATED_AND_TRAINED"
        }

        # Save candidate model artifact
        model_path = self._get_model_path(new_v)
        meta_path = self._get_meta_path(new_v)
        joblib.dump(candidate_model, model_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        # Promote candidate to active
        self.model = candidate_model
        self.model_version = new_v
        self.contamination = use_contam
        self.is_fitted = True
        self.metrics = metrics

        metrics["artifact_path"] = model_path
        return metrics

    @staticmethod
    def generate_synthetic_lab_fixtures(n_samples: int = 200, random_seed: int = 42) -> pd.DataFrame:
        """
        Generate explicitly labeled synthetic network telemetry fixtures for repeatable lab training.
        Clearly labeled with `[SYNTHETIC LAB FIXTURE]` metadata.
        """
        np.random.seed(random_seed)
        records = []
        n_normal = int(n_samples * 0.80)
        n_anom = n_samples - n_normal

        # 1. Synthetic Normal Enterprise Telemetry
        normal_ports = [80, 443, 53, 123]
        for i in range(n_normal):
            src_num = np.random.randint(10, 50)
            p = int(np.random.choice(normal_ports))
            pkts = int(np.random.normal(110, 25))
            pkts = max(15, pkts)
            records.append({
                "Time": f"10:{i//60:02d}:{i%60:02d}",
                "Source IP": f"192.168.1.{src_num}",
                "Destination IP": "10.0.0.1",
                "Port": p,
                "Packets": pkts,
                "Protocol": "UDP" if p in [53, 123] else "TCP",
                "Action": "Allowed",
                "Activity": "Normal Traffic",
                "Risk": "Low",
                "Label": 0,
                "Fixture_Type": "[SYNTHETIC LAB FIXTURE: Nominal Enterprise Baseline]"
            })

        # 2. Synthetic Anomalous Scenarios (Port Probes, High Volume Spikes, Brute Force)
        for j in range(n_anom):
            scenario = j % 3
            if scenario == 0:
                # Port Probing pattern
                p = int(np.random.choice([21, 23, 135, 139, 445, 1433, 3306, 3389, 8080]))
                pkts = int(np.random.randint(10, 40))
                src = "198.51.100.77"
                act = "Port Scan"
                risk = "High"
            elif scenario == 1:
                # Volumetric Spike
                p = 80
                pkts = int(np.random.randint(900, 2500))
                src = f"192.168.1.{np.random.randint(90, 99)}"
                act = "DDoS Flood"
                risk = "Critical"
            else:
                # Repeated SSH / RDP probe
                p = 22
                pkts = int(np.random.randint(280, 500))
                src = "203.0.113.45"
                act = "Brute Force"
                risk = "High"

            records.append({
                "Time": f"11:{j//60:02d}:{j%60:02d}",
                "Source IP": src,
                "Destination IP": "10.0.0.1",
                "Port": p,
                "Packets": pkts,
                "Protocol": "TCP",
                "Action": "Denied" if scenario != 1 else "Allowed",
                "Activity": act,
                "Risk": risk,
                "Label": 1,
                "Fixture_Type": f"[SYNTHETIC LAB FIXTURE: Attack Simulation - {act}]"
            })

        df = pd.DataFrame(records)
        return df


# Compatibility class preserving existing MLAnomalyDetector interface
class MLAnomalyDetector:
    """
    Backwards-compatibility adapter ensuring zero breaking changes for existing tests.
    """

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.engine = MLAnomalyEngine(contamination=contamination, random_state=random_state)
        self.model = None
        self.is_fitted = False

    def fit(self, features: np.ndarray) -> "MLAnomalyDetector":
        self.engine.train(features, contamination=self.contamination)
        self.model = self.engine.model
        self.is_fitted = self.engine.is_fitted
        return self

    def predict_score(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        return self.engine.predict_score(feature_vector)


_global_ml_engine = None

def get_ml_engine() -> MLAnomalyEngine:
    global _global_ml_engine
    if _global_ml_engine is None:
        _global_ml_engine = MLAnomalyEngine()
    return _global_ml_engine
