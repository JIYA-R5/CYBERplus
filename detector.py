#detect suspicious activity 
"""
SentinelAI - Network Threat Detector Module
Detects suspicious activities and security threats from network traffic data.
"""

from typing import Dict, List, Optional
import pandas as pd


class ThreatDetector:
    """
    Threat detection engine using heuristic rules and behavioral traffic profiling.
    """

    def __init__(
        self,
        high_packet_threshold: int = 350,
        critical_packet_threshold: int = 800,
        known_signatures: Optional[Dict[str, Dict]] = None
    ):
        self.high_packet_threshold = high_packet_threshold
        self.critical_packet_threshold = critical_packet_threshold
        self.known_signatures = known_signatures or {
            "Port Scan": {
                "description": "Sequential or multi-port connection probing pattern",
                "risk": "High",
                "mitre_id": "T1046",
                "default_confidence": 0.88,
            },
            "Brute Force": {
                "description": "High-frequency repeated authentication or protocol requests",
                "risk": "High",
                "mitre_id": "T1110",
                "default_confidence": 0.92,
            },
            "DDoS Flood": {
                "description": "Abnormal volume spike overwhelming link capacity",
                "risk": "Critical",
                "mitre_id": "T1498",
                "default_confidence": 0.95,
            },
            "Data Exfiltration": {
                "description": "Abnormal outbound volume transfer indicating potential data leak",
                "risk": "High",
                "mitre_id": "T1048",
                "default_confidence": 0.85,
            },
            "Suspicious Reconnaissance": {
                "description": "Host sweep or irregular ICMP/SNMP probe sequence",
                "risk": "Medium",
                "mitre_id": "T1595",
                "default_confidence": 0.75,
            },
        }

    def evaluate_flow(
        self,
        packets: int,
        activity: str,
        source_ip: str,
        destination_port: Optional[int] = None
    ) -> Dict[str, any]:
        """
        Evaluate an individual network traffic flow for anomalies.
        """
        threat_detected = False
        threat_name = activity
        risk_level = "Low"
        confidence = 0.50
        details = "Traffic behavior within nominal operating bounds."

        # Check known signature matching
        if activity in self.known_signatures:
            threat_detected = True
            threat_info = self.known_signatures[activity]
            risk_level = threat_info["risk"]
            confidence = threat_info["default_confidence"]
            details = threat_info["description"]
        elif packets >= self.critical_packet_threshold:
            threat_detected = True
            threat_name = "DDoS Flood"
            risk_level = "Critical"
            confidence = 0.94
            details = f"Severe volumetric surge detected ({packets} packets exceeds threshold {self.critical_packet_threshold})."
        elif packets >= self.high_packet_threshold:
            threat_detected = True
            threat_name = "High Volume Anomaly"
            risk_level = "High"
            confidence = 0.82
            details = f"Traffic surge exceeds nominal threshold ({packets} packets)."

        # Port-specific heuristics if port is supplied
        if destination_port in [22, 3389, 445] and packets > 250 and threat_name == "Normal Traffic":
            threat_detected = True
            threat_name = "Brute Force"
            risk_level = "High"
            confidence = 0.89
            details = f"High-packet density observed against administrative port {destination_port}."

        return {
            "threat_detected": threat_detected,
            "activity": threat_name,
            "risk": risk_level,
            "confidence": confidence,
            "details": details,
            "source_ip": source_ip,
            "packets": packets,
        }

    def detect_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrich a traffic DataFrame with automated threat detection flags and risk ratings.
        """
        if df.empty:
            return df.copy()

        df_processed = df.copy()
        threat_flags = []
        activities = []
        risks = []
        confidences = []
        descriptions = []

        for _, row in df_processed.iterrows():
            packets = int(row.get("Packets", 0))
            raw_activity = str(row.get("Activity", "Normal Traffic"))
            source_ip = str(row.get("Source IP", "0.0.0.0"))
            port = int(row["Port"]) if "Port" in row and pd.notna(row["Port"]) else None

            eval_result = self.evaluate_flow(
                packets=packets,
                activity=raw_activity,
                source_ip=source_ip,
                destination_port=port
            )

            threat_flags.append(eval_result["threat_detected"])
            activities.append(eval_result["activity"])
            risks.append(eval_result["risk"])
            confidences.append(eval_result["confidence"])
            descriptions.append(eval_result["details"])

        df_processed["Threat Detected"] = threat_flags
        df_processed["Activity"] = activities
        df_processed["Risk"] = risks
        df_processed["Confidence"] = confidences
        df_processed["Threat Details"] = descriptions

        return df_processed


# Helper factory function
def get_detector() -> ThreatDetector:
    return ThreatDetector()