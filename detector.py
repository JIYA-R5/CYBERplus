"""
SentinelAI - Network Threat Detector Module
Advanced multi-tier threat detection combining behavioral heuristics, stateful temporal
correlation, known attack signatures, and optional machine learning anomaly scoring.
"""

from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Union
import os
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
    supporting_events: List[int] = field(default_factory=list)

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
        self._fallback_means = None
        self._fallback_stds = None

    def fit(self, features: np.ndarray) -> "MLAnomalyDetector":
        """
        Train IsolationForest on normalized traffic features, or fallback to statistical
        standard-deviation profiling if scikit-learn is not present in runtime environment.
        """
        if len(features) < 4:
            # Need minimum observations to train reliably
            return self

        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state
            )
            self.model.fit(features)
            self.is_fitted = True
        except ImportError:
            # Lightweight statistical fallback (pure numpy, zero external dependencies)
            features_arr = np.asarray(features, dtype=float)
            self._fallback_means = np.mean(features_arr, axis=0)
            self._fallback_stds = np.std(features_arr, axis=0)
            self._fallback_stds[self._fallback_stds == 0] = 1.0
            self.model = "statistical_fallback"
            self.is_fitted = True

        return self

    def predict_score(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Predict whether a flow is an anomaly and return the continuous anomaly score.
        Negative scores indicate anomalous deviation.
        """
        if not self.is_fitted or self.model is None:
            return {"is_anomaly": False, "score": 0.0, "status": "Model uncalibrated"}

        if self.model == "statistical_fallback":
            vec = np.asarray(feature_vector, dtype=float).flatten()
            z_scores = np.abs((vec - self._fallback_means) / self._fallback_stds)
            max_z = float(np.max(z_scores))
            # Standard anomaly threshold is z > 2.5
            is_anomaly = bool(max_z > 2.5)
            raw_score = round(max(-1.0, 0.5 - (max_z / 4.0)), 4)
            normalized_confidence = round(max(0.0, min(1.0, max_z / 4.0)), 2)
            return {
                "is_anomaly": is_anomaly,
                "raw_score": raw_score,
                "confidence": normalized_confidence,
                "status": "Evaluated"
            }

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
    volumetric anomaly detection, port scan heuristics, brute-force tracking,
    and unusual traffic burst detection.
    """

    def __init__(
        self,
        high_packet_threshold: Optional[int] = None,
        critical_packet_threshold: Optional[int] = None,
        port_scan_threshold: Optional[int] = None,
        brute_force_threshold: Optional[int] = None,
        burst_flow_threshold: Optional[int] = None,
        time_window_seconds: Optional[int] = None,
        known_signatures: Optional[Dict[str, Dict]] = None
    ):
        self.high_packet_threshold = high_packet_threshold if high_packet_threshold is not None else int(os.getenv("HIGH_PACKET_THRESHOLD", "350"))
        self.critical_packet_threshold = critical_packet_threshold if critical_packet_threshold is not None else int(os.getenv("CRITICAL_PACKET_THRESHOLD", "800"))
        self.port_scan_threshold = port_scan_threshold if port_scan_threshold is not None else int(os.getenv("PORT_SCAN_THRESHOLD", "3"))
        self.brute_force_threshold = brute_force_threshold if brute_force_threshold is not None else int(os.getenv("BRUTE_FORCE_THRESHOLD", "3"))
        self.burst_flow_threshold = burst_flow_threshold if burst_flow_threshold is not None else int(os.getenv("BURST_FLOW_THRESHOLD", "5"))
        self.time_window_seconds = time_window_seconds if time_window_seconds is not None else int(os.getenv("TIME_WINDOW_SECONDS", "60"))

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
            "Traffic Burst": {
                "description": "Unusual burst of traffic flows or requests directed to an endpoint service",
                "risk": "High",
                "mitre_id": "T1499",
                "default_confidence": 0.85,
                "rule_id": "RULE-BURST-01",
                "action": "Inspect web server logs, monitor connection rates, and apply rate-limiting."
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

    def match_signature(self, activity: Optional[str]) -> Optional[str]:
        """
        Normalize and map raw activity strings or Suricata alert signatures to canonical attack categories.
        Returns None for nominal/normal traffic.
        """
        if not activity or not isinstance(activity, str):
            return None
        act_clean = activity.strip()
        if act_clean in self.known_signatures:
            return act_clean

        act_lower = act_clean.lower()
        if "normal traffic" in act_lower or act_lower == "nominal":
            return None

        if "port scan" in act_lower or "port sweep" in act_lower or "service discovery" in act_lower:
            return "Port Scan"
        if ("ssh" in act_lower and "auth" in act_lower) or "brute force" in act_lower or "authentication failure" in act_lower or "privilege gain" in act_lower:
            return "Brute Force"
        if "traffic burst" in act_lower or "burst to one destination" in act_lower or "request burst" in act_lower:
            return "Traffic Burst"
        if "ddos" in act_lower or "packet flood" in act_lower or "syn flood" in act_lower:
            return "DDoS Flood"
        if "exfiltration" in act_lower or "data theft" in act_lower:
            return "Data Exfiltration"
        if "reconnaissance" in act_lower or "host sweep" in act_lower or "icmp sweep" in act_lower:
            return "Suspicious Reconnaissance"
        if "volume anomaly" in act_lower or "volume surge" in act_lower:
            return "High Volume Anomaly"

        return None

    @staticmethod
    def parse_timestamp(ts: Any) -> Optional[datetime.datetime]:
        """
        Robustly parse ISO 8601 timestamps, standard datetime strings, and epoch numbers.
        Returns datetime object, or None if invalid.
        """
        if ts is None or pd.isna(ts):
            return None
        if isinstance(ts, datetime.datetime):
            return ts
        s = str(ts).strip()
        if not s or s.lower() in ("n/a", "none", "null", ""):
            return None
        try:
            if len(s) > 5 and s[-5] in ("+", "-") and s[-3] != ":":
                s_iso = s[:-2] + ":" + s[-2:]
            else:
                s_iso = s
            return datetime.datetime.fromisoformat(s_iso.replace("Z", "+00:00"))
        except Exception:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%H:%M:%S", "%H:%M:%S.%f"):
            try:
                parsed = datetime.datetime.strptime(s, fmt)
                if fmt.startswith("%H"):
                    parsed = parsed.replace(year=2026, month=1, day=1)
                return parsed
            except Exception:
                pass
        return None

    def evaluate_flow(
        self,
        packets: int,
        activity: str,
        source_ip: str,
        destination_port: Optional[int] = None,
        destination_ip: Optional[str] = None,
        raw_risk: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an individual network traffic flow for anomalies.
        Provides robust fallbacks for missing or malformed inputs.
        """
        safe_ip = sanitize_ip(source_ip)
        try:
            safe_packets = max(0, int(float(packets))) if packets is not None and not pd.isna(packets) else 0
        except (ValueError, TypeError):
            safe_packets = 0

        try:
            safe_port = int(float(destination_port)) if destination_port is not None and not pd.isna(destination_port) else None
            safe_port = safe_port if safe_port and 1 <= safe_port <= 65535 else None
        except (ValueError, TypeError):
            safe_port = None

        threat_detected = False
        threat_name = "Normal Traffic"
        risk_level = "Low"
        confidence = 0.50
        rule_id = "RULE-NOMINAL-00"
        mitre_id = "N/A"
        details = "Traffic behavior within nominal operating bounds."
        action = "Normal monitoring."

        canonical_sig = self.match_signature(activity)

        # 1. Direct signature lookup or canonical match
        if canonical_sig and canonical_sig in self.known_signatures:
            threat_detected = True
            threat_name = canonical_sig
            threat_info = self.known_signatures[canonical_sig]
            risk_level = threat_info["risk"]
            if raw_risk in ("Critical", "High") and risk_level not in ("Critical",):
                risk_level = raw_risk
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
        elif safe_port in [22, 3389, 445] and safe_packets > 250:
            threat_detected = True
            threat_name = "Brute Force"
            risk_level = "High"
            confidence = 0.89
            rule_id = "RULE-BRUTE-FORCE-01"
            mitre_id = "T1110"
            details = f"High-packet density ({safe_packets} packets) directed at sensitive administrative port {safe_port}."
            action = self.known_signatures["Brute Force"]["action"]

        # 5. Suspicious port inspection
        elif safe_port in [135, 137, 139, 161] and safe_packets > 150:
            threat_detected = True
            threat_name = "Suspicious Reconnaissance"
            risk_level = "Medium"
            confidence = 0.72
            rule_id = "RULE-RECON-01"
            mitre_id = "T1595"
            details = f"Probing detected on legacy discovery port {safe_port} with {safe_packets} packets."
            action = self.known_signatures["Suspicious Reconnaissance"]["action"]

        # 6. Fallback for explicit alert objects with high raw risk that didn't match known signatures
        elif raw_risk in ("Critical", "High") and activity and activity.lower() not in ("normal traffic", "nominal", ""):
            threat_detected = True
            threat_name = activity
            risk_level = raw_risk
            confidence = 0.80
            rule_id = "RULE-ALERT-01"
            mitre_id = "T1000"
            details = f"Security alert event observed: {activity}"
            action = "Inspect security alert details and monitor host."

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
        unusual traffic bursts, and targeted DDoS attacks that span multiple flows.
        Correlates related events into unified incident entities with supporting event linkages.
        """
        if df.empty:
            return []

        incidents: List[Incident] = []
        df_clean = df.copy()

        # Normalize column names
        col_map = {c.lower().replace(" ", "_"): c for c in df_clean.columns}
        src_col = col_map.get("source_ip", col_map.get("src_ip", "Source IP"))
        dst_col = col_map.get("destination_ip", col_map.get("dest_ip", "Destination IP"))
        port_col = col_map.get("port", col_map.get("destination_port", col_map.get("dest_port", "Port")))
        pkt_col = col_map.get("packets", col_map.get("pkts", "Packets"))
        time_col = col_map.get("time", col_map.get("timestamp", "Time"))
        act_col = col_map.get("activity", col_map.get("signature", "Activity"))
        risk_col = col_map.get("risk", col_map.get("severity", "Risk"))

        records = []
        for idx, row in df_clean.iterrows():
            raw_src = str(row.get(src_col, "0.0.0.0")) if src_col in row else "0.0.0.0"
            safe_src = sanitize_ip(raw_src)

            raw_dst = str(row.get(dst_col, "Target Perimeter")) if dst_col in row else "Target Perimeter"
            safe_dst = sanitize_ip(raw_dst) if raw_dst and raw_dst != "Target Perimeter" else raw_dst

            raw_port = row.get(port_col) if port_col in row else None
            try:
                p = int(float(raw_port)) if pd.notna(raw_port) else None
                p = p if p and 1 <= p <= 65535 else None
            except (ValueError, TypeError):
                p = None

            raw_pkts = row.get(pkt_col, 0) if pkt_col in row else 0
            try:
                pkts = max(0, int(float(raw_pkts))) if pd.notna(raw_pkts) else 0
            except (ValueError, TypeError):
                pkts = 0

            raw_act = str(row.get(act_col, "Normal Traffic")) if act_col in row else "Normal Traffic"
            raw_risk = str(row.get(risk_col, "Low")) if risk_col in row else "Low"
            ts_str = str(row.get(time_col, "N/A")) if time_col in row else "N/A"
            ts_dt = self.parse_timestamp(ts_str)

            records.append({
                "idx": idx,
                "src_ip": safe_src,
                "dst_ip": safe_dst,
                "port": p,
                "packets": pkts,
                "activity": raw_act,
                "canonical": self.match_signature(raw_act),
                "risk": raw_risk,
                "ts_str": ts_str,
                "ts_dt": ts_dt
            })

        claimed_events = set()

        # ----------------------------------------------------------------------
        # 1. Multi-Port Scan Correlation (Group by source_ip, destination_ip)
        # ----------------------------------------------------------------------
        from collections import defaultdict
        src_dst_groups = defaultdict(list)
        for r in records:
            src_dst_groups[(r["src_ip"], r["dst_ip"])].append(r)

        for (src, dst), group in src_dst_groups.items():
            valid_ports = sorted(list(set(r["port"] for r in group if r["port"] is not None)))
            if len(valid_ports) >= self.port_scan_threshold:
                probe_rows = [r["idx"] for r in group]
                first_ts = group[0]["ts_str"]
                last_ts = group[-1]["ts_str"]
                total_pkts = sum(r["packets"] for r in group)

                duration_str = ""
                if group[0]["ts_dt"] and group[-1]["ts_dt"]:
                    diff_sec = abs(int((group[-1]["ts_dt"] - group[0]["ts_dt"]).total_seconds()))
                    duration_str = f" within {diff_sec}s"

                conf = min(0.99, round(0.85 + (len(valid_ports) - self.port_scan_threshold) * 0.02 + 0.04, 2))
                inc_id = f"INC-PORT-{uuid.uuid4().hex[:6].upper()}"

                incidents.append(Incident(
                    incident_id=inc_id,
                    category="Port Scan",
                    source_ip=src,
                    destination_ip=dst,
                    destination_ports=valid_ports[:8],
                    first_seen=first_ts,
                    last_seen=last_ts,
                    event_count=len(probe_rows),
                    total_packets=total_pkts,
                    severity="High",
                    confidence=conf,
                    rule_id="RULE-PORT-SCAN-CORRELATED",
                    mitre_id="T1046",
                    evidence=(
                        f"Host {src} probed {len(valid_ports)} distinct ports {valid_ports[:8]} targeting "
                        f"{dst} across {len(probe_rows)} attempts{duration_str} (threshold: {self.port_scan_threshold})."
                    ),
                    recommended_action="Block source IP at edge firewall and verify external perimeter ACL.",
                    detection_method="Stateful Port Diversity Correlation",
                    supporting_events=probe_rows
                ))
                claimed_events.update(probe_rows)

        # ----------------------------------------------------------------------
        # 2. Repeated Authentication Failures / Brute Force (Port-Specific)
        # ----------------------------------------------------------------------
        auth_target_ports = [22, 3389, 445, 21, 23, 8080]
        for (src, dst), group in src_dst_groups.items():
            unclaimed = [r for r in group if r["idx"] not in claimed_events]
            port_subgroups = defaultdict(list)
            for r in unclaimed:
                if r["port"] in auth_target_ports or r["canonical"] == "Brute Force":
                    port_key = r["port"] if r["port"] is not None else 22
                    port_subgroups[port_key].append(r)

            for auth_p, p_rows in port_subgroups.items():
                if len(p_rows) >= self.brute_force_threshold:
                    auth_indices = [r["idx"] for r in p_rows]
                    first_ts = p_rows[0]["ts_str"]
                    last_ts = p_rows[-1]["ts_str"]
                    total_pkts = sum(r["packets"] for r in p_rows)

                    duration_str = ""
                    if p_rows[0]["ts_dt"] and p_rows[-1]["ts_dt"]:
                        diff_sec = abs(int((p_rows[-1]["ts_dt"] - p_rows[0]["ts_dt"]).total_seconds()))
                        duration_str = f" within {diff_sec}s"

                    conf = min(0.99, round(0.85 + (len(p_rows) - self.brute_force_threshold) * 0.02 + 0.04, 2))
                    sev = "Critical" if any(r["risk"] == "Critical" for r in p_rows) or len(p_rows) >= 10 else "High"
                    inc_id = f"INC-AUTH-{uuid.uuid4().hex[:6].upper()}"

                    incidents.append(Incident(
                        incident_id=inc_id,
                        category="Brute Force",
                        source_ip=src,
                        destination_ip=dst,
                        destination_ports=[auth_p],
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=len(auth_indices),
                        total_packets=total_pkts,
                        severity=sev,
                        confidence=conf,
                        rule_id="RULE-BRUTE-FORCE-CORRELATED",
                        mitre_id="T1110",
                        evidence=(
                            f"Host {src} executed {len(auth_indices)} repeated authentication attempts/failures "
                            f"against port {auth_p} on {dst}{duration_str} (threshold: {self.brute_force_threshold})."
                        ),
                        recommended_action="Immediately quarantine host IP and verify MFA status on targeted service.",
                        detection_method="Stateful Authentication Threshold Correlation",
                        supporting_events=auth_indices
                    ))
                    claimed_events.update(auth_indices)

        # ----------------------------------------------------------------------
        # 3. Unusual Traffic Burst Correlation (Group by destination_ip, port)
        # ----------------------------------------------------------------------
        dst_port_groups = defaultdict(list)
        for r in records:
            if r["idx"] not in claimed_events:
                dst_port_groups[(r["dst_ip"], r["port"])].append(r)

        for (dst, p), group in dst_port_groups.items():
            burst_alerts = [
                r for r in group
                if r["canonical"] in ("Traffic Burst", "High Volume Anomaly") or "burst" in r["activity"].lower()
            ]
            if len(burst_alerts) >= 3 or (len(group) >= self.burst_flow_threshold and burst_alerts):
                burst_indices = [r["idx"] for r in burst_alerts]
                src_ips = list(set(r["src_ip"] for r in burst_alerts))
                rep_src = src_ips[0] if len(src_ips) == 1 else "Distributed Sources"
                first_ts = burst_alerts[0]["ts_str"]
                last_ts = burst_alerts[-1]["ts_str"]
                total_pkts = sum(r["packets"] for r in burst_alerts)

                duration_str = ""
                if burst_alerts[0]["ts_dt"] and burst_alerts[-1]["ts_dt"]:
                    diff_sec = abs(int((burst_alerts[-1]["ts_dt"] - burst_alerts[0]["ts_dt"]).total_seconds()))
                    duration_str = f" within {diff_sec}s"

                conf = min(0.95, round(0.80 + (len(burst_indices) - self.burst_flow_threshold) * 0.02 + 0.05, 2))
                sev = "High" if any(r["risk"] in ("High", "Critical") for r in burst_alerts) else "Medium"
                inc_id = f"INC-BURST-{uuid.uuid4().hex[:6].upper()}"

                incidents.append(Incident(
                    incident_id=inc_id,
                    category="Traffic Burst",
                    source_ip=rep_src,
                    destination_ip=dst,
                    destination_ports=[p] if p else [80],
                    first_seen=first_ts,
                    last_seen=last_ts,
                    event_count=len(burst_indices),
                    total_packets=total_pkts,
                    severity=sev,
                    confidence=conf,
                    rule_id="RULE-BURST-CORRELATED",
                    mitre_id="T1499",
                    evidence=(
                        f"Unusual traffic burst: {len(burst_indices)} burst alert events directed to "
                        f"{dst}:{p}{duration_str} (threshold: {self.burst_flow_threshold})."
                    ),
                    recommended_action="Inspect application connection rates and apply reverse proxy rate-limiting.",
                    detection_method="Traffic Burst Correlation",
                    supporting_events=burst_indices
                ))
                claimed_events.update(burst_indices)

        # ----------------------------------------------------------------------
        # 4. Aggregated Volumetric Surge Correlation
        # ----------------------------------------------------------------------
        for (src, dst), group in src_dst_groups.items():
            unclaimed = [r for r in group if r["idx"] not in claimed_events]
            if not unclaimed:
                continue
            total_pkts = sum(r["packets"] for r in unclaimed)
            if total_pkts >= self.critical_packet_threshold:
                surge_indices = [r["idx"] for r in unclaimed]
                first_ts = unclaimed[0]["ts_str"]
                last_ts = unclaimed[-1]["ts_str"]
                ports = sorted(list(set(r["port"] for r in unclaimed if r["port"] is not None)))
                inc_id = f"INC-DDOS-{uuid.uuid4().hex[:6].upper()}"

                incidents.append(Incident(
                    incident_id=inc_id,
                    category="DDoS Flood",
                    source_ip=src,
                    destination_ip=dst,
                    destination_ports=ports[:3],
                    first_seen=first_ts,
                    last_seen=last_ts,
                    event_count=len(surge_indices),
                    total_packets=total_pkts,
                    severity="Critical",
                    confidence=0.96,
                    rule_id="RULE-DDOS-CORRELATED",
                    mitre_id="T1498",
                    evidence=(
                        f"Volumetric surge: Aggregated {total_pkts} packets over {len(surge_indices)} flows "
                        f"exceeds critical capacity limit ({self.critical_packet_threshold})."
                    ),
                    recommended_action="Engage upstream DDoS scrubbing and activate rate-limiting filters.",
                    detection_method="Volumetric Threshold Correlation",
                    supporting_events=surge_indices
                ))
                claimed_events.update(surge_indices)

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

        # Run multi-event correlation first to group related events
        correlated_incs = self.correlate_incidents(df_processed)
        event_to_incident: Dict[int, Incident] = {}
        for inc in correlated_incs:
            for ev_idx in inc.supporting_events:
                event_to_incident[ev_idx] = inc

        threat_flags = []
        activities = []
        risks = []
        confidences = []
        descriptions = []
        rule_ids = []
        mitre_ids = []
        incident_ids = []

        col_map = {c.lower().replace(" ", "_"): c for c in df_processed.columns}
        src_col = col_map.get("source_ip", col_map.get("src_ip", "Source IP"))
        dst_col = col_map.get("destination_ip", col_map.get("dest_ip", "Destination IP"))
        port_col = col_map.get("port", col_map.get("destination_port", col_map.get("dest_port", "Port")))
        pkt_col = col_map.get("packets", col_map.get("pkts", "Packets"))
        act_col = col_map.get("activity", col_map.get("signature", "Activity"))
        risk_col = col_map.get("risk", col_map.get("severity", "Risk"))

        for idx, row in df_processed.iterrows():
            # If row was claimed by a correlated incident, inherit its metadata
            if idx in event_to_incident:
                matched_inc = event_to_incident[idx]
                threat_flags.append(True)
                activities.append(matched_inc.category)
                risks.append(matched_inc.severity)
                confidences.append(matched_inc.confidence)
                descriptions.append(matched_inc.evidence)
                rule_ids.append(matched_inc.rule_id)
                mitre_ids.append(matched_inc.mitre_id)
                incident_ids.append(matched_inc.incident_id)
                continue

            # Otherwise, evaluate row individually
            raw_pkt = row.get(pkt_col, 0) if pkt_col in row else 0
            try:
                packets = int(float(raw_pkt)) if pd.notna(raw_pkt) else 0
            except (ValueError, TypeError):
                packets = 0

            raw_activity = str(row.get(act_col, "Normal Traffic")) if act_col in row else "Normal Traffic"
            source_ip = str(row.get(src_col, "0.0.0.0")) if src_col in row else "0.0.0.0"
            dest_ip = str(row.get(dst_col, "Target Perimeter")) if dst_col in row else "Target Perimeter"
            raw_risk = str(row.get(risk_col, "Low")) if risk_col in row else "Low"

            raw_port = row.get(port_col) if port_col in row else None
            try:
                port = int(float(raw_port)) if pd.notna(raw_port) else None
                port = port if port and 1 <= port <= 65535 else None
            except (ValueError, TypeError):
                port = None

            eval_result = self.evaluate_flow(
                packets=packets,
                activity=raw_activity,
                source_ip=source_ip,
                destination_port=port,
                destination_ip=dest_ip,
                raw_risk=raw_risk
            )

            threat_flags.append(eval_result["threat_detected"])
            activities.append(eval_result["activity"])
            risks.append(eval_result["risk"])
            confidences.append(eval_result["confidence"])
            descriptions.append(eval_result["details"])
            rule_ids.append(eval_result["rule_id"])
            mitre_ids.append(eval_result["mitre_id"])
            incident_ids.append(f"INC-{idx+1:04d}" if eval_result["threat_detected"] else "-")

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