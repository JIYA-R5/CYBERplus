#recommend contorlled mitigation actions 
"""
SentinelAI - Response Engine Module
Generates automated and controlled mitigation recommendations, firewall rules,
and incident response containment workflows.
"""

from typing import Dict, Any, List, Optional
import datetime


class ResponseEngine:
    """
    Automated and analyst-assisted security response orchestrator.
    Generates tailored remediation plans and platform-specific firewall commands.
    """

    def __init__(self):
        self.action_playbooks = {
            "Port Scan": {
                "priority": "P2 - High",
                "actions": [
                    "Isolate source host or apply temporary border firewall block.",
                    "Review external perimeter ports to confirm closed/filtered state.",
                    "Audit IDS/IPS signatures and confirm signature drop rules are active.",
                ],
                "recommended_policy": "Drop and blacklist IP for 120 minutes."
            },
            "Brute Force": {
                "priority": "P1 - Critical",
                "actions": [
                    "Immediately drop active sessions and blacklist source IP.",
                    "Trigger password reset for accounts targeted in the authentication flow.",
                    "Verify Multi-Factor Authentication (MFA) enforcement on destination endpoints.",
                    "Check authentication logs for any successful login (Status 200 / Event 4624) from source IP.",
                ],
                "recommended_policy": "Immediate quarantine and mandatory credential audit."
            },
            "DDoS Flood": {
                "priority": "P1 - Critical",
                "actions": [
                    "Engage upstream ISP / Cloud Scrubbing Center (Cloudflare, AWS Shield, Akamai).",
                    "Apply rate-limiting and SYN-proxy on border edge routers.",
                    "Drop spoofed / malformed packets at boundary ingress.",
                ],
                "recommended_policy": "Activate upstream DDoS mitigation policy and BGP blackholing if necessary."
            },
            "Data Exfiltration": {
                "priority": "P1 - Critical",
                "actions": [
                    "Sever network connectivity for the affected endpoint immediately.",
                    "Capture physical/virtual volatile memory (RAM) dump for digital forensics.",
                    "Identify compromised data assets and initiate regulatory breach protocol.",
                ],
                "recommended_policy": "Network host isolation and immediate forensics preservation."
            },
            "High Volume Anomaly": {
                "priority": "P3 - Medium",
                "actions": [
                    "Inspect network socket states (`netstat -ano` / `ss -tulpn`).",
                    "Verify whether scheduled backup, sync, or deployment processes are running.",
                    "Observe traffic pattern for continuous volumetric growth.",
                ],
                "recommended_policy": "Monitor and rate-limit flow."
            }
        }

    def generate_firewall_commands(self, source_ip: str, rule_name: str = "SentinelAI_Block") -> Dict[str, str]:
        """
        Generate copy-pasteable firewall commands across major operating systems and network appliances.
        """
        return {
            "Linux iptables": f"sudo iptables -I INPUT -s {source_ip} -j DROP",
            "Linux ufw": f"sudo ufw insert 1 deny from {source_ip} to any",
            "Windows PowerShell": (
                f"New-NetFirewallRule -DisplayName \"{rule_name}_{source_ip}\" "
                f"-Direction Inbound -Action Block -RemoteAddress \"{source_ip}\""
            ),
            "Cisco IOS ACL": f"access-list 100 deny ip host {source_ip} any\naccess-list 100 permit ip any any",
        }

    def get_mitigation_plan(
        self,
        activity: str,
        source_ip: str,
        risk: str = "High"
    ) -> Dict[str, Any]:
        """
        Produce a full mitigation plan tailored to the detected security threat.
        """
        playbook = self.action_playbooks.get(activity, {
            "priority": "P3 - Medium",
            "actions": [
                f"Monitor network flows from host {source_ip}.",
                "Inspect related system logs for unusual behavior.",
            ],
            "recommended_policy": "Standard monitoring and analyst review."
        })

        firewall_cmds = self.generate_firewall_commands(source_ip)

        return {
            "source_ip": source_ip,
            "activity": activity,
            "risk": risk,
            "priority": playbook["priority"],
            "recommended_policy": playbook["recommended_policy"],
            "action_steps": playbook["actions"],
            "firewall_commands": firewall_cmds,
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


# Helper factory function
def get_response_engine() -> ResponseEngine:
    return ResponseEngine()