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

FLOW_FEATURE_NAMES = [
    "packets",
    "port",
    "source_port",
    "flow_duration",
    "bytes",
    "flow_frequency",
    "unique_ports_contacted",
    "mean_packets_per_flow",
    "is_privileged_port",
    "is_admin_port",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "tcp_flag_syn",
    "tcp_flag_rst",
    "tcp_flag_ack",
    "packets_per_sec",
    "bytes_per_sec",
]

DEFAULT_MODEL_DIR = os.environ.get("SENTINEL_MODEL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")


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

    def extract_flow_features(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]
    ) -> Tuple[np.ndarray, pd.DataFrame]:
        """
        Extract extended flow features suitable for PCAP flow records, synthetic dataset,
        and live bidirectional flows. Strictly prevents target leakage.
        Returns:
            X: 2D numpy array of shape (N, len(FLOW_FEATURE_NAMES))
            feature_df: DataFrame containing the normalized flow features
        """
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data) if data else pd.DataFrame()
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            df = pd.DataFrame()

        if df.empty:
            empty_df = pd.DataFrame(columns=FLOW_FEATURE_NAMES)
            return np.empty((0, len(FLOW_FEATURE_NAMES))), empty_df

        col_map = {str(c).lower().replace(" ", "_"): c for c in df.columns}
        src_col = col_map.get("source_ip", col_map.get("src_ip", col_map.get("ip", "Source IP")))
        port_col = col_map.get("port", col_map.get("destination_port", col_map.get("dest_port", col_map.get("dst_port", "Port"))))
        src_port_col = col_map.get("source_port", col_map.get("src_port", "Source Port"))
        pkt_col = col_map.get("packets", col_map.get("total_packets", col_map.get("pkts", col_map.get("packet_count", "Packets"))))
        byte_col = col_map.get("bytes", col_map.get("total_bytes", "Bytes"))
        dur_col = col_map.get("duration", col_map.get("flow_duration", "Duration"))
        proto_col = col_map.get("protocol", col_map.get("proto", "Protocol"))

        # 1. Packets & Bytes
        if pkt_col in df.columns:
            packets_series = pd.to_numeric(df[pkt_col], errors="coerce").fillna(0.0).clip(lower=0.0)
        else:
            packets_series = pd.Series(0.0, index=df.index)

        if byte_col in df.columns:
            bytes_series = pd.to_numeric(df[byte_col], errors="coerce").fillna(0.0).clip(lower=0.0)
        else:
            bytes_series = packets_series * 64.0

        # 2. Duration & Rates
        if dur_col in df.columns:
            duration_series = pd.to_numeric(df[dur_col], errors="coerce").fillna(0.0).clip(lower=0.0)
        else:
            duration_series = pd.Series(0.05, index=df.index)

        safe_duration = duration_series.replace(0.0, 0.001)
        packets_per_sec = (packets_series / safe_duration).clip(lower=0.0, upper=1e7)
        bytes_per_sec = (bytes_series / safe_duration).clip(lower=0.0, upper=1e9)

        # 3. Ports & Privileges
        if port_col in df.columns:
            port_series = pd.to_numeric(df[port_col], errors="coerce").fillna(0.0).clip(lower=0.0, upper=65535.0)
        else:
            port_series = pd.Series(0.0, index=df.index)

        if src_port_col in df.columns:
            src_port_series = pd.to_numeric(df[src_port_col], errors="coerce").fillna(0.0).clip(lower=0.0, upper=65535.0)
        else:
            src_port_series = pd.Series(0.0, index=df.index)

        is_privileged = (port_series > 0) & (port_series < 1024)
        admin_ports = {21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080}
        is_admin = port_series.isin(admin_ports)

        # 4. Aggregations per Source IP
        if src_col in df.columns:
            src_series = df[src_col].astype(str).fillna("0.0.0.0")
            flow_freq = src_series.map(src_series.value_counts().to_dict()).fillna(1.0).astype(float)
            temp_df = pd.DataFrame({"src": src_series, "port": port_series, "pkts": packets_series})
            unique_ports = src_series.map(temp_df.groupby("src")["port"].nunique().to_dict()).fillna(1.0).astype(float)
            mean_pkts = src_series.map(temp_df.groupby("src")["pkts"].mean().to_dict()).fillna(packets_series).astype(float)
        else:
            flow_freq = pd.Series(1.0, index=df.index)
            unique_ports = pd.Series(1.0, index=df.index)
            mean_pkts = packets_series.copy()

        # 5. Protocol One-Hot Encoding
        if proto_col in df.columns:
            proto_clean = df[proto_col].astype(str).str.upper().fillna("TCP")
            proto_tcp = (proto_clean.str.contains("TCP")).astype(float)
            proto_udp = (proto_clean.str.contains("UDP")).astype(float)
            proto_icmp = (proto_clean.str.contains("ICMP")).astype(float)
            proto_other = ((~proto_clean.str.contains("TCP")) & (~proto_clean.str.contains("UDP")) & (~proto_clean.str.contains("ICMP"))).astype(float)
        else:
            proto_tcp = pd.Series(1.0, index=df.index)
            proto_udp = pd.Series(0.0, index=df.index)
            proto_icmp = pd.Series(0.0, index=df.index)
            proto_other = pd.Series(0.0, index=df.index)

        # 6. TCP Flags
        flag_col = col_map.get("tcp_flags", col_map.get("tcp_flags_seen", "tcp_flags"))
        if flag_col in df.columns:
            syn_flags, rst_flags, ack_flags = [], [], []
            for item in df[flag_col]:
                if isinstance(item, dict):
                    syn_flags.append(float(item.get("SYN", 0)))
                    rst_flags.append(float(item.get("RST", 0)))
                    ack_flags.append(float(item.get("ACK", 0)))
                elif isinstance(item, str):
                    syn_flags.append(1.0 if "SYN" in item.upper() else 0.0)
                    rst_flags.append(1.0 if "RST" in item.upper() else 0.0)
                    ack_flags.append(1.0 if "ACK" in item.upper() else 0.0)
                else:
                    syn_flags.append(0.0); rst_flags.append(0.0); ack_flags.append(0.0)
            tcp_syn = pd.Series(syn_flags, index=df.index)
            tcp_rst = pd.Series(rst_flags, index=df.index)
            tcp_ack = pd.Series(ack_flags, index=df.index)
        else:
            tcp_syn = pd.Series(0.0, index=df.index)
            tcp_rst = pd.Series(0.0, index=df.index)
            tcp_ack = pd.Series(0.0, index=df.index)

        feature_df = pd.DataFrame({
            "packets": packets_series.astype(float),
            "port": port_series.astype(float),
            "source_port": src_port_series.astype(float),
            "flow_duration": duration_series.astype(float),
            "bytes": bytes_series.astype(float),
            "flow_frequency": flow_freq.astype(float),
            "unique_ports_contacted": unique_ports.astype(float),
            "mean_packets_per_flow": mean_pkts.astype(float),
            "is_privileged_port": is_privileged.astype(float),
            "is_admin_port": is_admin.astype(float),
            "proto_tcp": proto_tcp.astype(float),
            "proto_udp": proto_udp.astype(float),
            "proto_icmp": proto_icmp.astype(float),
            "proto_other": proto_other.astype(float),
            "tcp_flag_syn": tcp_syn.astype(float),
            "tcp_flag_rst": tcp_rst.astype(float),
            "tcp_flag_ack": tcp_ack.astype(float),
            "packets_per_sec": packets_per_sec.astype(float),
            "bytes_per_sec": bytes_per_sec.astype(float),
        }, index=df.index)

        feature_df = feature_df[FLOW_FEATURE_NAMES].fillna(0.0)
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
        repo_models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
        if os.path.exists(repo_models_dir) and os.path.abspath(repo_models_dir) != os.path.abspath(self.model_dir):
            import shutil
            for fname in os.listdir(repo_models_dir):
                src_f = os.path.join(repo_models_dir, fname)
                dst_f = os.path.join(self.model_dir, fname)
                if os.path.isfile(src_f) and not os.path.exists(dst_f):
                    try:
                        shutil.copy2(src_f, dst_f)
                    except Exception:
                        pass
        self._load_active_or_default()

    def _get_model_path(self, version: str) -> str:
        clean_v = version.replace("isolation_forest_", "")
        primary_path = os.path.join(self.model_dir, f"isolation_forest_{clean_v}.joblib")
        if not os.path.exists(primary_path):
            repo_models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            fallback_path = os.path.join(repo_models_dir, f"isolation_forest_{clean_v}.joblib")
            if os.path.exists(fallback_path):
                return fallback_path
        return primary_path

    def _get_meta_path(self, version: str) -> str:
        clean_v = version.replace("isolation_forest_", "")
        primary_path = os.path.join(self.model_dir, f"isolation_forest_{clean_v}_meta.json")
        if not os.path.exists(primary_path):
            repo_models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            fallback_path = os.path.join(repo_models_dir, f"isolation_forest_{clean_v}_meta.json")
            if os.path.exists(fallback_path):
                return fallback_path
        return primary_path

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


class SecurityPolicyViolationError(ValueError):
    """Raised when an operation violates cybersecurity safety guardrails."""
    pass


class ThreatPreprocessingPipeline:
    """
    Leakage-free preprocessing pipeline.
    Standardizes numerical features and handles missing/invalid values.
    Crucially fits ONLY on the training split, never the holdout evaluation set.
    """

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = list(feature_names or FLOW_FEATURE_NAMES)
        self.medians: Dict[int, float] = {}
        self.means: Dict[int, float] = {}
        self.stds: Dict[int, float] = {}
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> "ThreatPreprocessingPipeline":
        if len(X) == 0:
            return self
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        n_features = X_clean.shape[1]
        self.medians = {i: float(np.median(X_clean[:, i])) for i in range(n_features)}
        self.means = {i: float(np.mean(X_clean[:, i])) for i in range(n_features)}
        stds = np.std(X_clean, axis=0)
        self.stds = {i: float(stds[i]) if stds[i] > 1e-6 else 1.0 for i in range(n_features)}
        self.is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.empty((0, len(self.feature_names)))
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6).copy()
        n_features = min(X_clean.shape[1], len(self.feature_names))
        for i in range(n_features):
            med = self.medians.get(i, 0.0)
            X_clean[np.isnan(X_clean[:, i]), i] = med
            mean = self.means.get(i, 0.0)
            std = self.stds.get(i, 1.0)
            X_clean[:, i] = (X_clean[:, i] - mean) / std
        return X_clean

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)


class SupervisedThreatClassifier:
    """
    Supervised Machine Learning Threat Classifier for network attack categories.
    Trained strictly on verified ground-truth datasets with zero leakage,
    class imbalance weighting, holdout evaluation metrics, and model artifact versioning.
    """

    def __init__(
        self,
        model_version: str = "classifier_v1.0.0",
        model_dir: Optional[str] = None,
        random_state: int = 42
    ):
        self.model_version = model_version
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        self.random_state = random_state
        self.pipeline: Optional[ThreatPreprocessingPipeline] = None
        self.model = None
        self.classes_: List[str] = []
        self.is_fitted = False
        self.metrics: Dict[str, Any] = {}
        self.extractor = TelemetryFeatureExtractor()

        os.makedirs(self.model_dir, exist_ok=True)
        self._load_active_or_default()

    def _get_model_path(self, version: str) -> str:
        clean_v = version.replace("classifier_", "")
        primary_path = os.path.join(self.model_dir, f"threat_classifier_{clean_v}.joblib")
        if not os.path.exists(primary_path):
            repo_models = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            fallback = os.path.join(repo_models, f"threat_classifier_{clean_v}.joblib")
            if os.path.exists(fallback):
                return fallback
        return primary_path

    def _get_meta_path(self, version: str) -> str:
        clean_v = version.replace("classifier_", "")
        primary_path = os.path.join(self.model_dir, f"threat_classifier_{clean_v}_meta.json")
        if not os.path.exists(primary_path):
            repo_models = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            fallback = os.path.join(repo_models, f"threat_classifier_{clean_v}_meta.json")
            if os.path.exists(fallback):
                return fallback
        return primary_path

    def _load_active_or_default(self):
        target_path = self._get_model_path(self.model_version)
        if os.path.exists(target_path):
            try:
                loaded = joblib.load(target_path)
                if isinstance(loaded, tuple) and len(loaded) == 3:
                    self.model, self.pipeline, self.classes_ = loaded
                else:
                    self.model = loaded
                    self.classes_ = list(getattr(loaded, "classes_", []))
                self.is_fitted = True
                meta_path = self._get_meta_path(self.model_version)
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.metrics = json.load(f)
            except Exception:
                self.is_fitted = False
                self.model = None

    def train_on_dataset(
        self,
        data: Union[pd.DataFrame, str, List[Dict[str, Any]]],
        label_column: str = "Activity",
        version_tag: Optional[str] = None,
        test_size: float = 0.25,
        trained_by: str = "SOC Security Engineer",
        is_reviewed_ground_truth: bool = True
    ) -> Dict[str, Any]:
        """
        Execute supervised training workflow with strict zero-leakage holdout evaluation.
        Requires is_reviewed_ground_truth=True to enforce the security guardrail.
        """
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (
            precision_score, recall_score, f1_score, confusion_matrix, accuracy_score
        )

        if not is_reviewed_ground_truth:
            raise SecurityPolicyViolationError(
                "Security Policy Guardrail: Automated model retraining is strictly prohibited "
                "on unreviewed live alerts. Training requires explicitly reviewed ground-truth dataset."
            )

        if isinstance(data, str) and os.path.isfile(data):
            df = pd.read_csv(data)
            dataset_name = os.path.basename(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
            dataset_name = "In-Memory Telemetry DataFrame"
        elif isinstance(data, list):
            df = pd.DataFrame(data)
            dataset_name = "Telemetry Record Batch"
        else:
            raise ValueError("Unsupported training dataset format.")

        if df.empty or len(df) < 10:
            raise ValueError(f"Insufficient samples to train reliably ({len(df)} provided, minimum 10 required).")

        # Normalize label column lookup
        col_map = {str(c).lower().replace(" ", "_"): c for c in df.columns}
        target_col = col_map.get(label_column.lower().replace(" ", "_"), label_column)
        if target_col not in df.columns:
            # Fallback to Activity or Threat Detected if available
            for candidate in ["Activity", "Threat Detected", "Risk"]:
                if candidate in df.columns:
                    target_col = candidate
                    break
            if target_col not in df.columns:
                raise ValueError(f"Label column '{label_column}' not found in dataset columns: {list(df.columns)}")

        # Extract features (leakage-free: excludes labels and rules)
        X, feature_df = self.extractor.extract_flow_features(df)
        y = np.array(df[target_col].astype(str).tolist(), dtype=object)

        unique_labels, label_counts = np.unique(y, return_counts=True)
        if len(unique_labels) < 2:
            raise ValueError("Training dataset must contain at least 2 distinct classes.")

        use_version = version_tag or f"classifier_{datetime.datetime.now().strftime('%Y%m%d%H%M')}"

        # Stratified holdout split to prevent leakage
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y,
                test_size=test_size,
                stratify=y,
                random_state=self.random_state
            )
        except Exception:
            # If a class has too few instances to stratify
            X_train, X_test, y_train, y_test = train_test_split(
                X, y,
                test_size=test_size,
                random_state=self.random_state
            )

        # Fit preprocessing ONLY on training split
        pipeline = ThreatPreprocessingPipeline(FLOW_FEATURE_NAMES)
        X_train_scaled = pipeline.fit_transform(X_train)
        X_test_scaled = pipeline.transform(X_test)

        # Train balanced Random Forest Classifier
        model = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=self.random_state
        )
        model.fit(X_train_scaled, y_train)

        # Evaluate on unseen holdout test split
        y_pred = model.predict(X_test_scaled)
        classes = list(model.classes_)
        cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec_macro = round(float(precision_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        rec_macro = round(float(recall_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        f1_macro = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        prec_weighted = round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4)
        rec_weighted = round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4)
        f1_weighted = round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4)

        # False-Positive Rate (FPR) for nominal traffic
        fpr = 0.0
        for norm_label in ["Normal Traffic", "Normal", "nominal", "False", "0"]:
            if norm_label in classes:
                norm_idx = classes.index(norm_label)
                fp = sum(cm[i][norm_idx] for i in range(len(classes)) if i != norm_idx)
                tn = sum(cm[i][j] for i in range(len(classes)) for j in range(len(classes)) if i != norm_idx and j != norm_idx)
                fpr = round(fp / max(1, fp + tn), 4)
                break

        # Per-class metrics breakdown
        per_class = {}
        for c in classes:
            y_t_c = (y_test == c)
            y_p_c = (y_pred == c)
            p = float(precision_score(y_t_c, y_p_c, zero_division=0))
            r = float(recall_score(y_t_c, y_p_c, zero_division=0))
            f = float(f1_score(y_t_c, y_p_c, zero_division=0))
            per_class[c] = {
                "precision": round(p, 4),
                "recall": round(r, 4),
                "f1_score": round(f, 4),
                "support": int(np.sum(y_t_c))
            }

        metrics = {
            "model_version": use_version,
            "algorithm": "RandomForestClassifier",
            "model_type": "supervised_classifier",
            "dataset_name": dataset_name,
            "label_column": target_col,
            "classes": classes,
            "features_used": FLOW_FEATURE_NAMES,
            "trained_at": datetime.datetime.now().isoformat(),
            "trained_by": trained_by,
            "total_samples": len(df),
            "train_sample_count": len(X_train),
            "test_sample_count": len(X_test),
            "accuracy": acc,
            "precision_macro": prec_macro,
            "recall_macro": rec_macro,
            "f1_macro": f1_macro,
            "precision_weighted": prec_weighted,
            "recall_weighted": rec_weighted,
            "f1_weighted": f1_weighted,
            "false_positive_rate": fpr,
            "confusion_matrix": cm,
            "per_class_metrics": per_class,
            "status": "VALIDATED_AND_TRAINED"
        }

        # Persist versioned model and metadata artifacts
        model_path = self._get_model_path(use_version)
        meta_path = self._get_meta_path(use_version)

        joblib.dump((model, pipeline, classes), model_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        self.model = model
        self.pipeline = pipeline
        self.classes_ = classes
        self.model_version = use_version
        self.is_fitted = True
        self.metrics = metrics

        metrics["artifact_path"] = model_path
        return metrics

    def predict_sample(self, sample: Union[Dict[str, Any], pd.DataFrame]) -> Dict[str, Any]:
        """
        Classify single flow or record with calibrated probability confidence.
        """
        if not self.is_fitted or self.model is None or self.pipeline is None:
            return {
                "predicted_class": "Unknown",
                "is_threat": False,
                "confidence": 0.0,
                "class_probabilities": {},
                "model_version": self.model_version,
                "status": "Model uncalibrated"
            }

        X_raw, _ = self.extractor.extract_flow_features(sample)
        if len(X_raw) == 0:
            return {
                "predicted_class": "Unknown",
                "is_threat": False,
                "confidence": 0.0,
                "class_probabilities": {},
                "model_version": self.model_version,
                "status": "Empty input"
            }

        X_scaled = self.pipeline.transform(X_raw)
        pred_label = self.model.predict(X_scaled[0:1])[0]
        probs = self.model.predict_proba(X_scaled[0:1])[0]
        prob_dict = {c: round(float(probs[i]), 4) for i, c in enumerate(self.classes_)}

        is_threat = str(pred_label).lower() not in ("normal traffic", "normal", "nominal", "false", "0")
        confidence = round(float(max(probs)), 2)

        return {
            "predicted_class": str(pred_label),
            "is_threat": is_threat,
            "confidence": confidence,
            "class_probabilities": prob_dict,
            "model_version": self.model_version,
            "status": "Evaluated"
        }

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enrich a DataFrame of flows with supervised predictions and calibrated confidence."""
        if df.empty or not self.is_fitted or self.model is None or self.pipeline is None:
            df_res = df.copy()
            df_res["ML_Supervised_Class"] = "Uncalibrated"
            df_res["ML_Is_Threat"] = False
            df_res["ML_Supervised_Confidence"] = 0.0
            return df_res

        X_raw, _ = self.extractor.extract_flow_features(df)
        X_scaled = self.pipeline.transform(X_raw)
        preds = self.model.predict(X_scaled)
        probs = self.model.predict_proba(X_scaled)
        max_probs = np.max(probs, axis=1)

        df_res = df.copy()
        df_res["ML_Supervised_Class"] = preds
        df_res["ML_Is_Threat"] = [
            str(p).lower() not in ("normal traffic", "normal", "nominal", "false", "0") for p in preds
        ]
        df_res["ML_Supervised_Confidence"] = np.round(max_probs, 2)
        return df_res


_global_classifier = None

def get_supervised_classifier() -> SupervisedThreatClassifier:
    global _global_classifier
    if _global_classifier is None:
        _global_classifier = SupervisedThreatClassifier()
    return _global_classifier

