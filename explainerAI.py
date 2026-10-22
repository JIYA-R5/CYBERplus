"""
SentinelAI - ExplainerAI Module
Provides context-aware cybersecurity threat explanations, MITRE ATT&CK mapping,
forensic investigation checklists, and incident summaries using Google Gemini
with deterministic local fallbacks and strict AI safety guardrails.
"""

from typing import Dict, Any, List, Optional, Union
import os
import json
import logging
from pydantic import BaseModel, Field
from dotenv import load_dotenv, dotenv_values

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def reload_environment():
    """Load credentials from .env and .env.local without requiring website input."""
    # Check .env first, then .env.local for overrides
    for env_name in [".env", ".env.local"]:
        env_file = os.path.join(BASE_DIR, env_name)
        if os.path.isfile(env_file):
            try:
                vals = dotenv_values(env_file)
                for k, v in vals.items():
                    if v and str(v).strip() and str(v).strip() not in ["your_gemini_api_key_here"]:
                        os.environ[k] = str(v).strip()
            except Exception:
                pass
    load_dotenv()

# Initial load from environment files
reload_environment()

logger = logging.getLogger("SentinelAI.Explainer")


class ThreatExplanation(BaseModel):
    """
    Validated Pydantic data contract for AI and local rule-based threat explanations.
    Strictly distinguishes observed facts, model predictions, and attack hypotheses.
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

    # Clear segregation of evidence, predictions, and hypotheses
    observed_facts: Dict[str, Any] = Field(default_factory=dict, description="Verified observed network indicators and raw telemetry")
    model_predictions: Dict[str, Any] = Field(default_factory=dict, description="Machine learning anomaly score and confidence ratings")
    threat_hypotheses: str = Field(default="", description="Plausible attack scenarios vs benign administrative explanations")

    provider: str = Field(default="local_rule_fallback", description="Explanation provider: 'google_gemini' or 'local_rule_fallback'")
    ai_disclaimer: str = Field(
        default="Advisory notice: AI-generated explanations are guidance recommendations and must be verified by a human security analyst.",
        description="Mandatory compliance disclaimer"
    )
    ai_safety_notice: str = Field(
        default="Safety Guardrail: AI outputs are advisory hypotheses for analyst consideration. AI cannot classify an IP as malicious or trigger automated firewall containment.",
        description="Response safety constraint"
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ThreatExplainer:
    """
    Hybrid cybersecurity explanation engine combining live Google Gemini GenAI
    with an offline, deterministic local knowledge base.
    """

    def __init__(self, api_key: Optional[str] = None):
        reload_environment()
        raw_key = api_key if api_key is not None else (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "")
        self.api_key = raw_key.strip().strip("'\"")
        self.gemini_client = None
        self.is_gemini_active = False

        self._initialize_client()

    def _initialize_client(self):
        """Attempt to initialize official google.genai client if API key is present."""
        if self.api_key and self.api_key not in ["your_gemini_api_key_here", "INVALID_TEST_KEY_12345", ""]:
            try:
                from google import genai
                self.gemini_client = genai.Client(api_key=self.api_key)
                self.is_gemini_active = True
                logger.info("Google Gemini GenAI client initialized successfully from environment.")
            except Exception as e:
                logger.warning(f"Could not initialize Google GenAI client: {e}. Defaulting to deterministic fallback.")
                self.is_gemini_active = False
        else:
            self.gemini_client = None
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
                    "Determine if traffic source is spoofed or distributed across multiple subnets.",
                    "Engage cloud scrubbers or upstream ISP upstream mitigation filters."
                ],
                "containment_recommendations": [
                    "Activate upstream DDoS scrubbing policies.",
                    "Deploy rate-limiting and boundary ACL drops.",
                    "Route non-critical services to failover infrastructure."
                ]
            },
            "Data Exfiltration": {
                "summary": (
                    "Abnormal outbound data volume transfer indicating possible intellectual property or sensitive database theft."
                ),
                "mechanism": (
                    "Staging and transferring compressed archives or database dumps over encrypted egress channels (HTTPS, DNS tunneling, SFTP)."
                ),
                "potential_impact": (
                    "Confidential data loss, regulatory non-compliance fines (GDPR/HIPAA), loss of competitive advantage."
                ),
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
                "recommended_focus": "Isolate the compromised internal host and capture memory dumps for digital forensics.",
                "investigation_steps": [
                    "Check endpoint proxy logs for large POST/PUT requests to unfamiliar external domains.",
                    "Inspect process execution tree on source machine around the time of the transfer.",
                    "Verify file integrity and database access logs for unusual export queries."
                ],
                "containment_recommendations": [
                    "Sever network egress connectivity for the host immediately.",
                    "Revoke host credentials and API tokens.",
                    "Preserve disk and volatile memory artifacts for legal chain-of-custody."
                ]
            },
            "Suspicious Reconnaissance": {
                "summary": (
                    "Low-frequency host discovery, ping sweeps, or irregular SNMP/ICMP queries across internal network segments."
                ),
                "mechanism": (
                    "Probing of subnet address spaces to locate active endpoints, routers, and peripheral appliances."
                ),
                "potential_impact": (
                    "Internal network architecture mapping facilitating subsequent lateral movement."
                ),
                "mitre_technique": "T1595 - Active Scanning",
                "recommended_focus": "Verify if the source IP belongs to an authorized internal IT asset scanner or unauthorized host.",
                "investigation_steps": [
                    "Check vulnerability scanner schedule with IT infrastructure team.",
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
            },
            "Traffic Burst": {
                "summary": (
                    "Unusual concentration of request flows directed toward an application service endpoint. "
                    "Indicates an automated request spike, scraping, or micro-burst testing service limits."
                ),
                "mechanism": (
                    "Rapid transmission of HTTP/application requests to a single destination port within a tight time window, "
                    "exceeding normal baseline without saturating network link bandwidth."
                ),
                "potential_impact": (
                    "Degraded web application responsiveness, backend database queue saturation, or HTTP thread pool exhaustion."
                ),
                "mitre_technique": "T1499 - Endpoint Denial of Service: Application or Service Exhaustion",
                "recommended_focus": "Inspect web server access logs (HTTP status codes, User-Agent, URI paths) and evaluate rate-limiting rules.",
                "investigation_steps": [
                    "Examine web application access logs for targeted URI endpoints (e.g. login, search, API routes).",
                    "Check client User-Agent strings and TLS fingerprinting for automated headless tools or scripts.",
                    "Verify if source IPs belong to a distributed proxy pool or single autonomous system.",
                    "Review server application metrics (worker process CPU, memory, request response latency)."
                ],
                "containment_recommendations": [
                    "Deploy HTTP rate-limiting / throttling at reverse proxy or WAF layer.",
                    "Activate CAPTCHA challenges or challenge-response verification for aggressive endpoints.",
                    "Apply temporary IP connection limits in firewall / load balancer configuration."
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
            observed_facts={
                "source_ip": source_ip,
                "packet_volume": packets,
                "activity": activity,
                "risk": risk
            },
            model_predictions={
                "detection_engine": "Deterministic Heuristics / Knowledge Base",
                "risk_rating": risk
            },
            threat_hypotheses=(
                f"Plausible Hypothesis: Potential {activity} targeting internal network assets. "
                "Alternative Hypothesis: Legitimate administrative maintenance or heavy backup job."
            ),
            provider="local_rule_fallback",
            ai_disclaimer="Deterministic rule-based advisory (Local Fallback Mode). Recommended for operational verification."
        )

        return explanation.to_dict()

    def explain_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Explain a stored incident entity using actual stored evidence and historical telemetry.
        Strictly segregates observed facts, ML model predictions, and attack hypotheses.
        """
        activity = incident.get("category", "Unknown Threat")
        source_ip = incident.get("source_ip", "0.0.0.0")
        packets = int(incident.get("total_packets", 0))
        risk = incident.get("severity", "High")
        details = incident.get("evidence", "")

        # Incorporate rich stored incident context
        observed_facts = {
            "incident_id": incident.get("incident_id"),
            "source_ip": source_ip,
            "destination_ip": incident.get("destination_ip"),
            "destination_ports": incident.get("destination_ports", []),
            "protocols": incident.get("protocols", ["TCP"]),
            "event_count": incident.get("event_count", 1),
            "total_packets": packets,
            "first_seen": incident.get("first_seen") or incident.get("timestamp"),
            "last_seen": incident.get("last_seen"),
            "recurrence_count": incident.get("recurrence_count", 1),
            "raw_evidence": incident.get("raw_evidence") or details
        }

        model_predictions = {
            "model_version": incident.get("model_version", "v1.0.0"),
            "ml_anomaly_score": incident.get("ml_anomaly_score", 0.0),
            "ml_is_anomaly": bool(incident.get("ml_is_anomaly", False)),
            "rule_id": incident.get("rule_id", "N/A"),
            "mitre_id": incident.get("mitre_id", "N/A"),
            "confidence": incident.get("confidence", 0.85)
        }

        if self.is_gemini_active and self.gemini_client is not None:
            try:
                prompt = (
                    f"You are SentinelAI Threat Intelligence Copilot. Explain this stored incident evidence:\n"
                    f"Observed Facts: {json.dumps(observed_facts)}\n"
                    f"Model Predictions: {json.dumps(model_predictions)}\n"
                    f"Requirements:\n"
                    f"1. Clearly separate OBSERVED FACTS, MODEL PREDICTIONS, and ATTACK HYPOTHESES.\n"
                    f"2. Never claim an IP address proves a person's identity.\n"
                    f"3. Do not make autonomous blocking decisions.\n"
                    f"Return ONLY valid JSON matching the schema:\n"
                    f"{{\n"
                    f'  "summary": "1-2 sentence executive briefing",\n'
                    f'  "mechanism": "technical explanation of attack mechanism",\n'
                    f'  "potential_impact": "business risk",\n'
                    f'  "mitre_technique": "Txxxx - Name",\n'
                    f'  "recommended_focus": "forensic focus",\n'
                    f'  "threat_hypotheses": "attack hypothesis vs benign alternative",\n'
                    f'  "investigation_steps": ["step 1", "step 2", "step 3"],\n'
                    f'  "containment_recommendations": ["step 1", "step 2"]\n'
                    f"}}"
                )
                response = self.gemini_client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
                if response and response.text:
                    raw_text = response.text.strip()
                    if raw_text.startswith("```json"):
                        raw_text = raw_text[7:]
                    if raw_text.startswith("```"):
                        raw_text = raw_text[3:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
                    data = json.loads(raw_text.strip())

                    color_map = {"Low": "#10B981", "Medium": "#F59E0B", "High": "#EF4444", "Critical": "#7F1D1D"}
                    exp = ThreatExplanation(
                        activity=activity,
                        source_ip=source_ip,
                        packets=packets,
                        risk=risk,
                        severity_color=color_map.get(risk, "#EF4444"),
                        summary=data.get("summary", ""),
                        mechanism=data.get("mechanism", ""),
                        potential_impact=data.get("potential_impact", ""),
                        mitre_technique=data.get("mitre_technique", incident.get("mitre_id", "T1071")),
                        recommended_focus=data.get("recommended_focus", ""),
                        threat_hypotheses=data.get("threat_hypotheses", ""),
                        investigation_steps=data.get("investigation_steps", []),
                        containment_recommendations=data.get("containment_recommendations", []),
                        custom_details=details,
                        observed_facts=observed_facts,
                        model_predictions=model_predictions,
                        provider="google_gemini",
                        ai_disclaimer="Generated by Google Gemini AI Copilot based on stored evidence. Requires human analyst validation."
                    )
                    return exp.to_dict()
            except Exception as e:
                logger.warning(f"Gemini incident explanation failed: {e}. Falling back to deterministic knowledge base.")

        # Fallback explanation enriched with actual incident memory
        res = self.explain_threat(activity, source_ip, packets, risk, details)
        res["observed_facts"] = observed_facts
        res["model_predictions"] = model_predictions
        res["threat_hypotheses"] = (
            f"Malicious Hypothesis: Host {source_ip} is conducting unauthorized {activity} against {incident.get('destination_ip')}.\n"
            f"Benign Hypothesis: Legitimate system maintenance or administrative scanning tool."
        )
        return res

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
            observed_facts={"source_ip": source_ip, "packet_volume": packets, "activity": activity, "risk": risk},
            model_predictions={"detection_engine": "Google Gemini Copilot", "risk": risk},
            threat_hypotheses=f"Hypothesis: Active {activity} probe. Validate against server logs.",
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
_global_explainer = None

def get_explainer() -> ThreatExplainer:
    global _global_explainer
    if _global_explainer is None:
        _global_explainer = ThreatExplainer()
    elif not _global_explainer.is_gemini_active:
        # Check if user added key to .env/.env.local while app is running
        reload_environment()
        new_key = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip().strip("'\"")
        if new_key and new_key not in ["your_gemini_api_key_here", "INVALID_TEST_KEY_12345", ""]:
            _global_explainer.api_key = new_key
            _global_explainer._initialize_client()
    return _global_explainer