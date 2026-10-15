#genrtae  explaination - detected threats 
"""
SentinelAI - ExplainerAI Module
Generates intelligent, context-aware cybersecurity threat explanations,
impact assessments, and MITRE ATT&CK mappings for detected network anomalies.
"""

from typing import Dict, Any, List, Optional
import pandas as pd


class ThreatExplainer:
    """
    Intelligent explanation engine translating raw telemetry and rule alerts
    into actionable security intelligence and root cause summaries.
    """

    def __init__(self):
        self.threat_knowledge_base = {
            "Port Scan": {
                "summary": (
                    "Sequential or distributed probing of listening TCP/UDP ports. "
                    "The source is actively mapping open services and network topology "
                    "in preparation for exploitation."
                ),
                "mechanism": (
                    "The source host sends SYN packets across a wide port range to discover "
                    "vulnerable daemons or perimeter openings."
                ),
                "potential_impact": (
                    "Service discovery, reconnaissance of perimeter defenses, identification "
                    "of unpatched or outdated software."
                ),
                "mitre_technique": "T1046 - Network Service Discovery",
                "recommended_focus": "Check if the IP belongs to internal vulnerability scanners; if external, block at firewall perimeter."
            },
            "Brute Force": {
                "summary": (
                    "High-frequency credential guessing or protocol authentication flood. "
                    "Targeted attempts to gain unauthorized shell or account access."
                ),
                "mechanism": (
                    "Automated dictionary or credential stuffing attack targeting administrative "
                    "ports (SSH: 22, RDP: 3389, SMB: 445, or web login forms)."
                ),
                "potential_impact": (
                    "Account takeover, unauthorized lateral movement, credential theft, and persistent compromise."
                ),
                "mitre_technique": "T1110 - Brute Force",
                "recommended_focus": "Examine failed authentication audit logs and enforce account lockout / MFA rules."
            },
            "DDoS Flood": {
                "summary": (
                    "Abnormal surge in network packets exceeding nominal link capacity. "
                    "Potential Distributed Denial of Service (DDoS) or SYN/UDP volumetric flood."
                ),
                "mechanism": (
                    "Saturation of upstream ingress bandwidth and exhaustion of socket state tables."
                ),
                "potential_impact": (
                    "Service outage, degraded network latency, loss of critical business availability."
                ),
                "mitre_technique": "T1498 - Network Denial of Service",
                "recommended_focus": "Activate upstream DDoS mitigation scrubbing and apply rate-limiting ACLs."
            },
            "Data Exfiltration": {
                "summary": (
                    "Atypical high-volume outbound data flow directed towards an external destination. "
                    "Indicates unauthorized bulk extraction of sensitive files."
                ),
                "mechanism": (
                    "Transmission of compressed archives, database dumps, or sensitive assets via encrypted or covert protocols."
                ),
                "potential_impact": (
                    "Intellectual property loss, regulatory non-compliance, data breach."
                ),
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
                "recommended_focus": "Identify destination endpoint ownership, inspect payload hashes, and isolate host."
            },
            "Suspicious Reconnaissance": {
                "summary": (
                    "Unusual host sweep or ICMP discovery attempting to identify live devices."
                ),
                "mechanism": (
                    "Sending ping sweeps or ARP requests across internal subnets to enumerate responsive endpoints."
                ),
                "potential_impact": (
                    "Discovery of internal network topology and vulnerable subnets."
                ),
                "mitre_technique": "T1595 - Active Scanning",
                "recommended_focus": "Review subnet isolation policies and restrict ICMP/internal sweeping."
            },
            "High Volume Anomaly": {
                "summary": (
                    "Packet transmission rates significantly deviate from standard baseline telemetry."
                ),
                "mechanism": (
                    "Sudden burst of traffic flows exceeding moving average baseline by more than 2 standard deviations."
                ),
                "potential_impact": (
                    "Capacity degradation or early-stage attack staging."
                ),
                "mitre_technique": "T1499 - Endpoint Denial of Service",
                "recommended_focus": "Cross-reference with scheduled cron jobs, backup tasks, or verify if malicious."
            }
        }

    def explain_threat(
        self,
        activity: str,
        source_ip: str,
        packets: int,
        risk: str = "High",
        details: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate detailed, human-readable threat explanation with technical indicators and MITRE mapping.
        """
        kb_entry = self.threat_knowledge_base.get(activity, {
            "summary": f"Detected anomalous traffic classified as '{activity}'. Requires analyst verification.",
            "mechanism": "Unusual flow pattern detected by heuristic baseline analysis.",
            "potential_impact": "Potential security exposure depending on destination service.",
            "mitre_technique": "T1071 - Application Layer Protocol",
            "recommended_focus": "Inspect packet headers and inspect destination endpoints."
        })

        color_map = {
            "Low": "#10B981",       # Green
            "Medium": "#F59E0B",    # Amber
            "High": "#EF4444",      # Red
            "Critical": "#7F1D1D"   # Dark Red / Crimson
        }

        return {
            "activity": activity,
            "source_ip": source_ip,
            "packets": packets,
            "risk": risk,
            "severity_color": color_map.get(risk, "#EF4444"),
            "summary": kb_entry["summary"],
            "mechanism": kb_entry["mechanism"],
            "potential_impact": kb_entry["potential_impact"],
            "mitre_technique": kb_entry["mitre_technique"],
            "recommended_focus": kb_entry["recommended_focus"],
            "custom_details": details or "",
            "investigation_prompt": (
                f"Verify traffic originating from host {source_ip} transferring {packets} packets. "
                f"Evaluate if this represents legitimate administrative activity or malicious {activity}."
            )
        }

    def generate_executive_summary(self, df: pd.DataFrame) -> str:
        """
        Produce a high-level executive cybersecurity summary paragraph.
        """
        if df.empty:
            return "No network telemetry recorded during this monitoring period. Systems appear quiescent."

        total = len(df)
        high_risks = df[df["Risk"].isin(["High", "Critical"])] if "Risk" in df.columns else pd.DataFrame()
        high_count = len(high_risks)

        if high_count == 0:
            return (
                f"SentinelAI monitored {total} network transactions with nominal operational characteristics. "
                "No elevated security threats were identified; all observed flows remain within acceptable baseline tolerance."
            )

        top_threat = high_risks["Activity"].value_counts().index[0] if "Activity" in high_risks.columns else "Anomalous Traffic"
        suspicious_ips = high_risks["Source IP"].unique().tolist() if "Source IP" in high_risks.columns else []
        ip_str = ", ".join(suspicious_ips[:3])

        return (
            f"SentinelAI flagged {high_count} high-severity alert(s) across {total} monitored flows. "
            f"The primary threat identified is '{top_threat}', primarily originating from host(s): {ip_str}. "
            "Immediate containment and log correlation are strongly advised to prevent lateral expansion or credential compromise."
        )


# Helper factory function
def get_explainer() -> ThreatExplainer:
    return ThreatExplainer()