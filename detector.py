"""
SentinelAI - Network Threat Detector Module
Advanced multi-tier threat detection combining behavioral heuristics, stateful temporal
correlation, known attack signatures, and optional machine learning anomaly scoring.
"""

from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Union
import datetime
import uuid
import numpy as np
import pandas as pd
from response_engine import sanitize_ip


@dataclass
class Incident:
    """
    Structured security incident entity adhering to professional SOC data contracts.
    """
    incident_id: str
    category: str
    source_ip: str
    destination_ip: str
    destination_ports: List[int]
    first_seen: str
    last_seen: str
    event_count: int
    total_packets: int
    severity: str          # Critical, High, Medium, Low
    confidence: float      # 0.0 - 1.0
    rule_id: str
    mitre_id: str
    evidence: str
    recommended_action: str
    detection_method: str = "Heuristic Rule"
    status: str = "Open"   # Open, Investigating, Mitigated, Resolved, False Positive

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MLAnomalyDetector:
    """
    Transparent Machine Learning Anomaly Detector using Scikit-Learn IsolationForest.
    Clearly distinguishes machine learning anomaly scores from deterministic rule-based logic.
    """

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.is_fitted = False

    def fit(self, features: np.ndarray) -> "MLAnomalyDetector":
        """
        Train IsolationForest on normalized traffic features.
        """
        from sklearn.ensemble import IsolationForest
        if len(features) < 4:
            # Need minimum observations to train reliably
            return self

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state
        )
        self.model.fit(features)
        self.is_fitted = True
        return self

    def predict_score(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Predict whether a flow is an anomaly and return the continuous anomaly score.
        Negative scores indicate anomalous deviation.
        """
        if not self.is_fitted or self.model is None:
            return {"is_anomaly": False, "score": 0.0, "status": "Model uncalibrated"}

        prediction = self.model.predict(feature_vector)[0]  # -1 for anomaly, 1 for inlier
        raw_score = float(self.model.decision_function(feature_vector)[0])
        # Normalize score into a 0.0 - 1.0 anomaly confidence
        normalized_confidence = round(max(0.0, min(1.0, 0.5 - raw_score)), 2)

        return {
            "is_anomaly": bool(prediction == -1),
            "raw_score": round(raw_score, 4),
            "confidence": normalized_confidence,
            "status": "Evaluated"
        }


class ThreatDetector:
    """
    Defensive network threat detection engine implementing stateful temporal correlation,
    volumetric anomaly detection, port scan heuristics, and brute-force tracking.
    """

    def __init__(
        self,
        high_packet_threshold: int = 350,
        critical_packet_threshold: int = 800,
        port_scan_threshold: int = 3,
        brute_force_threshold: int = 3,
        time_window_seconds: int = 60,
        known_signatures: Optional[Dict[str, Dict]] = None
    ):
        self.high_packet_threshold = high_packet_threshold
        self.critical_packet_threshold = critical_packet_threshold
        self.port_scan_threshold = port_scan_threshold
        self.brute_force_threshold = brute_force_threshold
        self.time_window_seconds = time_window_seconds

        self.known_signatures = known_signatures or {
            "Port Scan": {
                "description": "Sequential or multi-port connection probing pattern",
                "risk": "High",
                "mitre_id": "T1046",
                "default_confidence": 0.88,
                "rule_id": "RULE-PORT-SCAN-01",
                "action": "Isolate source host and enforce border ACL drop."
            },
            "Brute Force": {
                "description": "High-frequency repeated authentication requests on administrative service",
                "risk": "High",
                "mitre_id": "T1110",
                "default_confidence": 0.92,
                "rule_id": "RULE-BRUTE-FORCE-01",
                "action": "Drop active sessions, lock targeted account, and enforce IP block."
            },
            "DDoS Flood": {
                "description": "Abnormal volume spike overwhelming link capacity",
                "risk": "Critical",
                "mitre_id": "T1498",
                "default_confidence": 0.95,
                "rule_id": "RULE-DDOS-01",
                "action": "Activate upstream DDoS mitigation and rate-limiting scrubbers."
            },
            "Data Exfiltration": {
                "description": "Abnormal outbound volume transfer indicating potential data theft",
                "risk": "High",
                "mitre_id": "T1048",
                "default_confidence": 0.86,
                "rule_id": "RULE-EXFIL-01",
                "action": "Quarantine host, dump memory for forensics, and sever egress route."
            },
            "Suspicious Reconnaissance": {
                "description": "Host sweep or irregular ICMP/SNMP probe sequence",
                "risk": "Medium",
                "mitre_id": "T1595",
                "default_confidence": 0.75,
                "rule_id": "RULE-RECON-01",
                "action": "Review internal subnet ACLs and restrict sweeping."
            },
            "High Volume Anomaly": {
                "description": "Packet rate significantly deviates from operational baseline",
                "risk": "Medium",
                "mitre_id": "T1499",
                "default_confidence": 0.78,
                "rule_id": "RULE-VOLUME-01",
                "action": "Inspect active sockets and verify scheduled tasks."
            }
        }

        # Initialize optional machine learning classifier
        self.ml_detector = MLAnomalyDetector()

    def evaluate_flow(
        self,
        packets: int,
        activity: str,
        source_ip: str,
        destination_port: Optional[int] = None,
        destination_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an individual network traffic flow for anomalies.
        Provides robust fallbacks for missing or malformed inputs.
        """
        safe_ip = sanitize_ip(source_ip)
        safe_packets = max(0, int(packets)) if isinstance(packets, (int, float)) and not np.isnan(packets) else 0
        safe_port = int(destination_port) if destination_port is not None and not pd.isna(destination_port) else None

        threat_detected = False
        threat_name = activity or "Normal Traffic"
        risk_level = "Low"
        confidence = 0.50
        rule_id = "RULE-NOMINAL-00"
        mitre_id = "N/A"
        details = "Traffic behavior within nominal operating bounds."
        action = "Normal monitoring."

        # 1. Direct signature lookup if explicitly supplied
        if threat_name in self.known_signatures and threat_name != "Normal Traffic":
            threat_detected = True
            threat_info = self.known_signatures[threat_name]
            risk_level = threat_info["risk"]
            confidence = threat_info["default_confidence"]
            details = threat_info["description"]
            rule_id = threat_info["rule_id"]
            mitre_id = threat_info["mitre_id"]
            action = threat_info["action"]

        # 2. Volumetric DDoS check
        elif safe_packets >= self.critical_packet_threshold:
            threat_detected = True
            threat_name = "DDoS Flood"
            risk_level = "Critical"
            confidence = 0.94
            rule_id = "RULE-DDOS-01"
            mitre_id = "T1498"
            details = f"Severe volumetric surge: {safe_packets} packets exceeds critical threshold ({self.critical_packet_threshold})."
            action = self.known_signatures["DDoS Flood"]["action"]

        # 3. High Volume Anomaly check
        elif safe_packets >= self.high_packet_threshold:
            threat_detected = True
            threat_name = "High Volume Anomaly"
            risk_level = "High"
            confidence = 0.82
            rule_id = "RULE-VOLUME-01"
            mitre_id = "T1499"
            details = f"Traffic surge exceeds nominal threshold: {safe_packets} packets (threshold {self.high_packet_threshold})."
            action = self.known_signatures["High Volume Anomaly"]["action"]

        # 4. Port-specific administrative authentication heuristics
        if safe_port in [22, 3389, 445] and safe_packets > 250 and threat_name == "Normal Traffic":
            threat_detected = True
            threat_name = "Brute Force"
            risk_level = "High"
            confidence = 0.89
            rule_id = "RULE-BRUTE-FORCE-01"
            mitre_id = "T1110"
            details = f"High-packet density ({safe_packets} packets) directed at sensitive administrative port {safe_port}."
            action = self.known_signatures["Brute Force"]["action"]

        # 5. Suspicious port inspection
        elif safe_port in [135, 137, 139, 161] and safe_packets > 150 and not threat_detected:
            threat_detected = True
            threat_name = "Suspicious Reconnaissance"
            risk_level = "Medium"
            confidence = 0.72
            rule_id = "RULE-RECON-01"
            mitre_id = "T1595"
            details = f"Probing detected on legacy discovery port {safe_port} with {safe_packets} packets."
            action = self.known_signatures["Suspicious Reconnaissance"]["action"]

        return {
            "threat_detected": threat_detected,
            "activity": threat_name,
            "risk": risk_level,
            "confidence": round(confidence, 2),
            "details": details,
            "rule_id": rule_id,
            "mitre_id": mitre_id,
            "recommended_action": action,
            "source_ip": safe_ip,
            "destination_port": safe_port,
            "packets": safe_packets,
        }

    def correlate_incidents(self, df: pd.DataFrame) -> List[Incident]:
        """
        Perform stateful multi-event temporal correlation across the dataset.
        Identifies distributed port scanning, repeated brute-force authentication,
        and targeted DDoS attacks that span multiple flows.
        """
        if df.empty:
            return []

        incidents: List[Incident] = []
        df_clean = df.copy()

        # Normalize column names
        col_map = {c.lower().replace(" ", "_"): c for c in df_clean.columns}
        src_col = col_map.get("source_ip", "Source IP")
        dst_col = col_map.get("destination_ip", "Destination IP")
        port_col = col_map.get("port", col_map.get("destination_port", "Port"))
        pkt_col = col_map.get("packets", "Packets")
        time_col = col_map.get("time", col_map.get("timestamp", "Time"))
        act_col = col_map.get("activity", "Activity")

        # Group by Source IP to detect multi-event behaviors
        if src_col in df_clean.columns:
            for source_ip, group in df_clean.groupby(src_col):
                safe_src = sanitize_ip(str(source_ip))
                flow_count = len(group)
                ports = [int(p) for p in group[port_col].dropna().unique() if str(p).isdigit()] if port_col in group.columns else []
                total_pkts = int(group[pkt_col].sum()) if pkt_col in group.columns else 0
                first_ts = str(group[time_col].iloc[0]) if time_col in group.columns else "N/A"
                last_ts = str(group[time_col].iloc[-1]) if time_col in group.columns else "N/A"
                dest_ip = str(group[dst_col].iloc[0]) if dst_col in group.columns else "Target Perimeter"

                # 1. Multi-port scan correlation
                if len(ports) >= self.port_scan_threshold:
                    ports_sampled = sorted(ports)[:8]
                    incidents.append(Incident(
                        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                        category="Port Scan",
                        source_ip=safe_src,
                        destination_ip=dest_ip,
                        destination_ports=ports_sampled,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=flow_count,
                        total_packets=total_pkts,
                        severity="High",
                        confidence=min(0.98, round(0.85 + (len(ports) * 0.02), 2)),
                        rule_id="RULE-PORT-SCAN-CORRELATED",
                        mitre_id="T1046",
                        evidence=(
                            f"Host contacted {len(ports)} distinct ports {ports_sampled} across "
                            f"{flow_count} connection attempts (threshold: {self.port_scan_threshold})."
                        ),
                        recommended_action="Block source IP at edge firewall and verify external perimeter ACL.",
                        detection_method="Stateful Port Diversity Correlation"
                    ))

                # 2. Repeated Brute-Force authentication correlation
                auth_ports = [p for p in ports if p in [22, 3389, 445, 21, 23, 8080]]
                if auth_ports and flow_count >= self.brute_force_threshold:
                    incidents.append(Incident(
                        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                        category="Brute Force",
                        source_ip=safe_src,
                        destination_ip=dest_ip,
                        destination_ports=auth_ports,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=flow_count,
                        total_packets=total_pkts,
                        severity="High",
                        confidence=min(0.99, round(0.88 + (flow_count * 0.02), 2)),
                        rule_id="RULE-BRUTE-FORCE-CORRELATED",
                        mitre_id="T1110",
                        evidence=(
                            f"Host executed {flow_count} repeated connection attempts against administrative "
                            f"port(s) {auth_ports} exceeding threshold ({self.brute_force_threshold})."
                        ),
                        recommended_action="Immediately quarantine host IP and verify MFA status on targeted service.",
                        detection_method="Stateful Authentication Threshold Correlation"
                    ))

                # 3. Aggregated Volumetric DDoS Surge
                if total_pkts >= self.critical_packet_threshold:
                    incidents.append(Incident(
                        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                        category="DDoS Flood",
                        source_ip=safe_src,
                        destination_ip=dest_ip,
                        destination_ports=ports[:3],
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=flow_count,
                        total_packets=total_pkts,
                        severity="Critical",
                        confidence=0.96,
                        rule_id="RULE-DDOS-CORRELATED",
                        mitre_id="T1498",
                        evidence=(
                            f"Volumetric surge: Aggregated {total_pkts} packets over {flow_count} flows "
                            f"exceeds critical DDoS capacity limit ({self.critical_packet_threshold})."
                        ),
                        recommended_action="Engage upstream DDoS scrubbing and activate rate-limiting filters.",
                        detection_method="Volumetric Threshold Correlation"
                    ))

        return incidents

    def detect_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich a traffic DataFrame with automated threat detection flags, risk ratings,
        MITRE technique IDs, and incident correlation metadata.
        Maintains 100% backwards compatibility with SentinelAI dashboard components.
        """
        if df.empty:
            return df.copy()

        df_processed = df.copy()
        threat_flags = []
        activities = []
        risks = []
        confidences = []
        descriptions = []
        rule_ids = []
        mitre_ids = []
        incident_ids = []

        # Check if multiple ports exist per IP to inform single-flow evaluation
        col_map = {c.lower().replace(" ", "_"): c for c in df_processed.columns}
        src_col = col_map.get("source_ip", "Source IP")
        port_col = col_map.get("port", col_map.get("destination_port", "Port"))

        distinct_ports_by_ip = {}
        if src_col in df_processed.columns and port_col in df_processed.columns:
            for ip, grp in df_processed.groupby(src_col):
                valid_ports = grp[port_col].dropna().unique()
                distinct_ports_by_ip[ip] = len(valid_ports)

        for idx, row in df_processed.iterrows():
            # Robust extraction of packets
            raw_pkt = row.get("Packets", row.get("packets", 0))
            try:
                packets = int(float(raw_pkt)) if pd.notna(raw_pkt) else 0
            except (ValueError, TypeError):
                packets = 0

            raw_activity = str(row.get("Activity", row.get("activity", "Normal Traffic")))
            source_ip = str(row.get("Source IP", row.get("source_ip", "0.0.0.0")))

            raw_port = row.get("Port", row.get("port", None))
            try:
                port = int(float(raw_port)) if pd.notna(raw_port) else None
            except (ValueError, TypeError):
                port = None

            eval_result = self.evaluate_flow(
                packets=packets,
                activity=raw_activity,
                source_ip=source_ip,
                destination_port=port
            )

            # Check if multi-port correlation upgrades this flow
            ip_port_diversity = distinct_ports_by_ip.get(source_ip, 1)
            if ip_port_diversity >= self.port_scan_threshold and not eval_result["threat_detected"]:
                eval_result["threat_detected"] = True
                eval_result["activity"] = "Port Scan"
                eval_result["risk"] = "High"
                eval_result["confidence"] = 0.90
                eval_result["rule_id"] = "RULE-PORT-SCAN-01"
                eval_result["mitre_id"] = "T1046"
                eval_result["details"] = f"Host probed {ip_port_diversity} distinct ports across session."

            threat_flags.append(eval_result["threat_detected"])
            activities.append(eval_result["activity"])
            risks.append(eval_result["risk"])
            confidences.append(eval_result["confidence"])
            descriptions.append(eval_result["details"])
            rule_ids.append(eval_result["rule_id"])
            mitre_ids.append(eval_result["mitre_id"])
            incident_ids.append(f"INC-{idx+1:04d}")

        df_processed["Threat Detected"] = threat_flags
        df_processed["Activity"] = activities
        df_processed["Risk"] = risks
        df_processed["Confidence"] = confidences
        df_processed["Threat Details"] = descriptions
        df_processed["Rule ID"] = rule_ids
        df_processed["MITRE ID"] = mitre_ids
        df_processed["Incident ID"] = incident_ids

        return df_processed


# Helper factory function
def get_detector() -> ThreatDetector:
    return ThreatDetector()