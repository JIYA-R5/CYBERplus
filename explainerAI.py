"""
SentinelAI - ExplainerAI Module
Provides context-aware cybersecurity threat explanations, MITRE ATT&CK mapping,
and forensic investigation checklists using Google Gemini with deterministic local fallbacks.
"""

from typing import Dict, Any, List, Optional, Union
import os
import json
import logging
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load local environment variables from .env if available
load_dotenv()

logger = logging.getLogger("SentinelAI.Explainer")


class ThreatExplanation(BaseModel):
    """
    Validated Pydantic data contract for AI and local rule-based threat explanations.
    """
    activity: str = Field(description="Identified threat or activity name")
    source_ip: str = Field(description="Originating source IP address")
    packets: int = Field(default=0, description="Observed packet count")
    risk: str = Field(default="High", description="Severity risk level")
    severity_color: str = Field(default="#EF4444", description="Hex color indicator")
    summary: str = Field(description="Executive-level summary of the incident")
    mechanism: str = Field(description="Technical mechanism of how the attack operates")
    potential_impact: str = Field(description="Potential security risk and business impact")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID and name")
    recommended_focus: str = Field(description="Priority investigation focus for SOC analysts")
    investigation_steps: List[str] = Field(default_factory=list, description="Actionable forensic investigation steps")
    containment_recommendations: List[str] = Field(default_factory=list, description="Defensive containment suggestions")
    custom_details: str = Field(default="", description="Contextual evidence or runtime notes")
    investigation_prompt: str = Field(default="", description="Guided prompt for deeper SOC triage")
    provider: str = Field(default="local_rule_fallback", description="Explanation provider: 'google_gemini' or 'local_rule_fallback'")
    ai_disclaimer: str = Field(
        default="Advisory notice: AI-generated explanations are guidance recommendations and must be verified by a human security analyst.",
        description="Mandatory compliance disclaimer"
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ThreatExplainer:
    """
    Hybrid cybersecurity explanation engine combining live Google Gemini GenAI
    with an offline, deterministic local knowledge base.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_client = None
        self.is_gemini_active = False

        # Attempt to initialize official google.genai client if API key is present
        if self.api_key and self.api_key != "your_gemini_api_key_here":
            try:
                from google import genai
                self.gemini_client = genai.Client(api_key=self.api_key)
                self.is_gemini_active = True
                logger.info("Google Gemini GenAI client initialized successfully.")
            except Exception as e:
                logger.warning(f"Could not initialize Google GenAI client: {e}. Defaulting to deterministic fallback.")
                self.is_gemini_active = False

        # Deterministic local knowledge base
        self.threat_knowledge_base = {
            "Port Scan": {
                "summary": (
                    "Sequential or distributed probing of listening TCP/UDP ports. "
                    "The source host is actively enumerating open services, daemons, and perimeter openings "
                    "in preparation for targeted exploitation."
                ),
                "mechanism": (
                    "The source transmits SYN/connect probes across a range of port numbers, "
                    "recording SYN-ACK or RST responses to construct a service map."
                ),
                "potential_impact": (
                    "Service discovery, reconnaissance of perimeter defenses, identification of unpatched services."
                ),
                "mitre_technique": "T1046 - Network Service Discovery",
                "recommended_focus": "Check if source IP belongs to authorized internal scanners; if external, block at boundary firewall.",
                "investigation_steps": [
                    "Verify firewall logs to identify total count of unique destination ports targeted.",
                    "Check whether internal honeypots or sensitive management ports (22, 3389, 445) were touched.",
                    "Determine whether the source IP is listed in external Threat Intelligence feeds (AbuseIPDB, AlienVault OTX).",
                    "Verify if any targeted port responded with an established connection (SYN-ACK)."
                ],
                "containment_recommendations": [
                    "Apply temporary border firewall drop for source IP.",
                    "Close or restrict exposed non-essential perimeter ports.",
                    "Ensure IDS/IPS signature drop rules are active."
                ]
            },
            "Brute Force": {
                "summary": (
                    "High-frequency credential guessing or protocol authentication flood. "
                    "Targeted attempts to gain unauthorized shell, console, or account access."
                ),
                "mechanism": (
                    "Automated dictionary or credential stuffing attack targeting administrative "
                    "ports (SSH: 22, RDP: 3389, SMB: 445, or web login endpoints)."
                ),
                "potential_impact": (
                    "Account takeover, unauthorized lateral movement, credential theft, and persistent endpoint compromise."
                ),
                "mitre_technique": "T1110 - Brute Force",
                "recommended_focus": "Examine failed authentication audit logs and enforce account lockout / MFA rules.",
                "investigation_steps": [
                    "Examine server security event logs (Windows Event ID 4625 / Linux /var/log/auth.log).",
                    "Identify specific usernames targeted (e.g. admin, root, administrator, user).",
                    "Confirm whether any successful login (Windows Event ID 4624 / Accepted password) occurred from this IP.",
                    "Inspect concurrent connections from the same subnet."
                ],
                "containment_recommendations": [
                    "Immediately terminate any active sessions originating from the source IP.",
                    "Trigger mandatory credential resets for all targeted user accounts.",
                    "Enforce Multi-Factor Authentication (MFA) and adaptive IP lockout."
                ]
            },
            "DDoS Flood": {
                "summary": (
                    "Abnormal surge in network packets exceeding nominal link capacity. "
                    "Volumetric Distributed Denial of Service (DDoS) or SYN/UDP link saturation."
                ),
                "mechanism": (
                    "Saturation of upstream ingress bandwidth and socket state exhaustion "
                    "through rapid transmission of spoofed or high-rate packet sequences."
                ),
                "potential_impact": (
                    "Service outage, degraded network latency, loss of critical business availability."
                ),
                "mitre_technique": "T1498 - Network Denial of Service",
                "recommended_focus": "Activate upstream DDoS mitigation scrubbing and apply rate-limiting ACLs.",
                "investigation_steps": [
                    "Inspect packet protocol distribution (TCP SYN, UDP amplification, ICMP).",
                    "Correlate ingress interface saturation metrics with edge routing telemetry.",
                    "Verify whether source IP addresses are spoofed or originate from an identifiable botnet cluster.",
                    "Check server resource metrics (CPU, RAM, connection pool limits)."
                ],
                "containment_recommendations": [
                    "Engage cloud scrubbing center / upstream provider DDoS protection.",
                    "Deploy border rate-limiting and SYN-proxy defense.",
                    "Drop malformed or unrequested UDP/ICMP packets at perimeter router."
                ]
            },
            "Data Exfiltration": {
                "summary": (
                    "Atypical high-volume outbound data flow directed towards an external destination. "
                    "Indicates unauthorized bulk extraction of sensitive files or database archives."
                ),
                "mechanism": (
                    "Transmission of compressed archives or sensitive telemetry via encrypted, non-standard, or covert channels."
                ),
                "potential_impact": (
                    "Loss of intellectual property, breach of customer records, regulatory non-compliance."
                ),
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
                "recommended_focus": "Identify destination endpoint ownership, inspect payload hashes, and isolate host.",
                "investigation_steps": [
                    "Identify exact destination IP, domain name, and geographical jurisdiction.",
                    "Correlate timestamp with local endpoint file-access audit logs.",
                    "Determine outbound volume transferred (megabytes/gigabytes).",
                    "Capture memory dump of the source workstation for digital forensics."
                ],
                "containment_recommendations": [
                    "Sever network connectivity for the affected endpoint immediately.",
                    "Revoke user credentials, active VPN sessions, and cloud access keys.",
                    "Preserve disk and volatile RAM images for forensic analysis."
                ]
            },
            "Suspicious Reconnaissance": {
                "summary": (
                    "Unusual host sweep or discovery attempting to identify live devices and subnet topology."
                ),
                "mechanism": (
                    "Transmitting ICMP echo requests, ARP sweeps, or SNMP probes across internal subnets."
                ),
                "potential_impact": (
                    "Internal network architecture mapping and identification of high-value internal assets."
                ),
                "mitre_technique": "T1595 - Active Scanning",
                "recommended_focus": "Review subnet isolation policies and restrict ICMP/internal sweeping.",
                "investigation_steps": [
                    "Verify if source host is part of IT administrative inventory.",
                    "Determine scope of IP range scanned within the local network.",
                    "Check for subsequent connection attempts on discovered live hosts."
                ],
                "containment_recommendations": [
                    "Restrict inter-VLAN reconnaissance traffic.",
                    "Enable internal switch port security and dynamic ARP inspection."
                ]
            },
            "High Volume Anomaly": {
                "summary": (
                    "Packet transmission rates significantly deviate from standard operational baseline."
                ),
                "mechanism": (
                    "Sudden surge of traffic flows exceeding moving baseline by multiple standard deviations."
                ),
                "potential_impact": (
                    "Capacity degradation, staging of malicious payload delivery, or misconfigured software sync."
                ),
                "mitre_technique": "T1499 - Endpoint Denial of Service",
                "recommended_focus": "Cross-reference with scheduled cron jobs, backup tasks, or verify if malicious.",
                "investigation_steps": [
                    "Inspect running system services and active network sockets (`netstat -ano`).",
                    "Determine if legitimate bulk backup or operating system updates are executing.",
                    "Review destination ports and protocols utilized."
                ],
                "containment_recommendations": [
                    "Apply bandwidth rate-limiting on offending host.",
                    "Schedule heavy administrative jobs during off-peak hours."
                ]
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
        Generate detailed threat explanation. If Google Gemini is available, uses the live LLM;
        otherwise seamlessly falls back to the deterministic knowledge base.
        Returns a dictionary adhering to the SentinelAI frontend contract.
        """
        color_map = {
            "Low": "#10B981",       # Green
            "Medium": "#F59E0B",    # Amber
            "High": "#EF4444",      # Red
            "Critical": "#7F1D1D"   # Dark Red / Crimson
        }
        severity_color = color_map.get(risk, "#EF4444")

        # Attempt live Google Gemini explanation if client is available
        if self.is_gemini_active and self.gemini_client is not None:
            try:
                gemini_result = self._call_gemini_explainer(activity, source_ip, packets, risk, details)
                if gemini_result:
                    return gemini_result.to_dict()
            except Exception as e:
                logger.warning(f"Gemini API call failed: {e}. Falling back to deterministic local knowledge base.")

        # Deterministic Local Fallback
        kb_entry = self.threat_knowledge_base.get(activity, {
            "summary": f"Detected anomalous traffic activity classified as '{activity}'. Requires analyst verification.",
            "mechanism": "Unusual network flow pattern detected by heuristic baseline analysis.",
            "potential_impact": "Potential security exposure depending on destination service.",
            "mitre_technique": "T1071 - Application Layer Protocol",
            "recommended_focus": "Inspect packet headers and destination endpoints.",
            "investigation_steps": [
                "Inspect source host network socket connections.",
                "Correlate event with host process activity logs."
            ],
            "containment_recommendations": [
                "Monitor source host traffic.",
                "Apply rate limiting if traffic continues to rise."
            ]
        })

        explanation = ThreatExplanation(
            activity=activity,
            source_ip=source_ip,
            packets=packets,
            risk=risk,
            severity_color=severity_color,
            summary=kb_entry["summary"],
            mechanism=kb_entry["mechanism"],
            potential_impact=kb_entry["potential_impact"],
            mitre_technique=kb_entry["mitre_technique"],
            recommended_focus=kb_entry["recommended_focus"],
            investigation_steps=kb_entry.get("investigation_steps", []),
            containment_recommendations=kb_entry.get("containment_recommendations", []),
            custom_details=details or "",
            investigation_prompt=(
                f"Verify traffic originating from host {source_ip} transferring {packets} packets. "
                f"Evaluate if this represents legitimate administrative activity or malicious {activity}."
            ),
            provider="local_rule_fallback",
            ai_disclaimer="Deterministic rule-based advisory (Local Fallback Mode). Recommended for operational verification."
        )

        return explanation.to_dict()

    def _call_gemini_explainer(
        self,
        activity: str,
        source_ip: str,
        packets: int,
        risk: str,
        details: Optional[str]
    ) -> Optional[ThreatExplanation]:
        """
        Query Google Gemini with a constrained prompt and parse structured JSON output.
        """
        prompt = (
            f"You are SentinelAI, an expert SOC cybersecurity analyst. "
            f"Analyze this detected security incident and return ONLY a valid JSON object matching the schema:\n"
            f"- Incident Activity: {activity}\n"
            f"- Source IP: {source_ip}\n"
            f"- Packet Volume: {packets}\n"
            f"- Severity Risk: {risk}\n"
            f"- Detection Details: {details or 'Heuristic rule match'}\n\n"
            f"Required JSON structure:\n"
            f"{{\n"
            f'  "summary": "1-2 sentence executive briefing",\n'
            f'  "mechanism": "technical explanation of the attack method",\n'
            f'  "potential_impact": "business and security consequence",\n'
            f'  "mitre_technique": "MITRE ATT&CK ID - Technique Name",\n'
            f'  "recommended_focus": "key area for SOC analyst triage",\n'
            f'  "investigation_steps": ["step 1", "step 2", "step 3"],\n'
            f'  "containment_recommendations": ["action 1", "action 2"]\n'
            f"}}\n"
            f"Return ONLY raw JSON without markdown codeblocks."
        )

        response = self.gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        if not response or not response.text:
            return None

        # Clean JSON text
        raw_text = response.text.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

        data = json.loads(raw_text)

        color_map = {"Low": "#10B981", "Medium": "#F59E0B", "High": "#EF4444", "Critical": "#7F1D1D"}

        return ThreatExplanation(
            activity=activity,
            source_ip=source_ip,
            packets=packets,
            risk=risk,
            severity_color=color_map.get(risk, "#EF4444"),
            summary=data.get("summary", ""),
            mechanism=data.get("mechanism", ""),
            potential_impact=data.get("potential_impact", ""),
            mitre_technique=data.get("mitre_technique", "T1071"),
            recommended_focus=data.get("recommended_focus", ""),
            investigation_steps=data.get("investigation_steps", []),
            containment_recommendations=data.get("containment_recommendations", []),
            custom_details=details or "",
            investigation_prompt=f"Triage incident {activity} from host {source_ip}.",
            provider="google_gemini",
            ai_disclaimer="Generated by Google Gemini AI Copilot. Validate before executing disruptive containment."
        )

    def generate_executive_summary(self, df) -> str:
        """
        Produce a high-level executive cybersecurity summary paragraph.
        """
        if df.empty:
            return "No network telemetry recorded during this monitoring period. Systems appear quiescent."

        total = len(df)
        high_risks = df[df["Risk"].isin(["High", "Critical"])] if "Risk" in df.columns else None
        high_count = len(high_risks) if high_risks is not None else 0

        if high_count == 0:
            return (
                f"SentinelAI monitored {total} network transactions with nominal operational characteristics. "
                "No elevated security threats were identified; all observed flows remain within acceptable baseline tolerance."
            )

        top_threat = high_risks["Activity"].value_counts().index[0] if "Activity" in high_risks.columns else "Anomalous Traffic"
        suspicious_ips = high_risks["Source IP"].unique().tolist() if "Source IP" in high_risks.columns else []
        ip_str = ", ".join(str(ip) for ip in suspicious_ips[:3])

        return (
            f"SentinelAI flagged {high_count} high-severity alert(s) across {total} monitored flows. "
            f"The primary threat identified is '{top_threat}', primarily originating from host(s): {ip_str}. "
            "Immediate containment and log correlation are strongly advised to prevent lateral expansion or credential compromise."
        )


# Helper factory function
def get_explainer() -> ThreatExplainer:
    return ThreatExplainer()