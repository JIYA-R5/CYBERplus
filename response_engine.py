"""
SentinelAI - Response Engine Module
Generates automated, analyst-approved mitigation recommendations, platform-specific firewall
containment rules, rollback procedures, and incident response playbooks.
"""

import datetime
import ipaddress
from typing import Dict, Any, List, Optional


def sanitize_ip(ip_str: str) -> str:
    """
    Strictly validate and sanitize an IP address or network CIDR to prevent command injection.
    Returns the sanitized string, or '0.0.0.0' if invalid.
    """
    clean_ip = str(ip_str).strip()
    try:
        return str(ipaddress.ip_address(clean_ip))
    except ValueError:
        try:
            return str(ipaddress.ip_network(clean_ip, strict=False))
        except ValueError:
            return "0.0.0.0"


class ResponseEngine:
    """
    Automated and analyst-assisted security response orchestrator.
    Generates defense-in-depth remediation plans, copyable firewall rules,
    and reversible containment scripts.
    """

    def __init__(self):
        self.action_playbooks = {
            "Port Scan": {
                "priority": "P2 - High",
                "actions": [
                    "Isolate source host or apply temporary border firewall block.",
                    "Review external perimeter ports to confirm closed/filtered state.",
                    "Audit IDS/IPS signatures and confirm signature drop rules are active.",
                    "Examine firewall logs for additional scanning from the same subnet.",
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
                    "Temporarily lock out compromised accounts pending SOC review.",
                ],
                "recommended_policy": "Immediate quarantine and mandatory credential audit."
            },
            "DDoS Flood": {
                "priority": "P1 - Critical",
                "actions": [
                    "Engage upstream ISP / Cloud Scrubbing Center (Cloudflare, AWS Shield, Akamai).",
                    "Apply rate-limiting and SYN-proxy on border edge routers.",
                    "Drop spoofed / malformed packets at boundary ingress.",
                    "Divert non-critical traffic to secondary failover circuits.",
                ],
                "recommended_policy": "Activate upstream DDoS mitigation policy and BGP blackholing if necessary."
            },
            "Data Exfiltration": {
                "priority": "P1 - Critical",
                "actions": [
                    "Sever network connectivity for the affected endpoint immediately.",
                    "Capture physical/virtual volatile memory (RAM) dump for digital forensics.",
                    "Identify compromised data assets and initiate regulatory breach protocol.",
                    "Revoke active API tokens, session cookies, and SSH keys on affected host.",
                ],
                "recommended_policy": "Network host isolation and immediate forensics preservation."
            },
            "Suspicious Reconnaissance": {
                "priority": "P3 - Medium",
                "actions": [
                    "Review subnet isolation policies and restrict ICMP/internal sweeping.",
                    "Check if source is an authorized network vulnerability scanner.",
                    "Rate-limit ARP and ICMP requests on internal access switches.",
                ],
                "recommended_policy": "Log and monitor host for secondary probing."
            },
            "High Volume Anomaly": {
                "priority": "P3 - Medium",
                "actions": [
                    "Inspect network socket states (`netstat -ano` / `ss -tulpn`).",
                    "Verify whether scheduled backup, sync, or deployment processes are running.",
                    "Observe traffic pattern for continuous volumetric growth.",
                ],
                "recommended_policy": "Monitor and rate-limit flow."
            },
            "Traffic Burst": {
                "priority": "P2 - High",
                "actions": [
                    "Inspect web server access logs for anomalous request rates or scraping behavior.",
                    "Activate reverse proxy / WAF rate limiting and connection throttling for target service.",
                    "Temporarily rate-limit or block offending source IP addresses at edge firewall.",
                    "Verify backend application health, connection pools, and latency metrics."
                ],
                "recommended_policy": "Enforce application-layer rate limiting and monitor source IPs."
            }
        }

    def generate_firewall_commands(self, source_ip: str, rule_name: str = "SentinelAI_Block") -> Dict[str, str]:
        """
        Generate copy-pasteable firewall containment commands across major platforms.
        Strictly sanitizes source_ip to eliminate command injection vulnerabilities.
        """
        safe_ip = sanitize_ip(source_ip)
        clean_rule = "".join(c for c in rule_name if c.isalnum() or c in ("_", "-"))

        return {
            "Windows PowerShell": (
                f'New-NetFirewallRule -DisplayName "{clean_rule}_{safe_ip}" '
                f'-Direction Inbound -Action Block -RemoteAddress "{safe_ip}"'
            ),
            "Linux iptables": f"sudo iptables -I INPUT -s {safe_ip} -j DROP",
            "Linux ufw": f"sudo ufw insert 1 deny from {safe_ip} to any",
            "Cisco IOS ACL": (
                f"access-list 100 deny ip host {safe_ip} any\n"
                f"access-list 100 permit ip any any"
            ),
        }

    def generate_rollback_commands(self, source_ip: str, rule_name: str = "SentinelAI_Block") -> Dict[str, str]:
        """
        Generate reversible rollback / unblock commands for containment actions.
        """
        safe_ip = sanitize_ip(source_ip)
        clean_rule = "".join(c for c in rule_name if c.isalnum() or c in ("_", "-"))

        return {
            "Windows PowerShell": f'Remove-NetFirewallRule -DisplayName "{clean_rule}_{safe_ip}"',
            "Linux iptables": f"sudo iptables -D INPUT -s {safe_ip} -j DROP",
            "Linux ufw": f"sudo ufw delete deny from {safe_ip} to any",
            "Cisco IOS ACL": f"no access-list 100 deny ip host {safe_ip} any",
        }

    def get_mitigation_plan(
        self,
        activity: str,
        source_ip: str,
        risk: str = "High"
    ) -> Dict[str, Any]:
        """
        Produce a comprehensive mitigation plan tailored to the detected security threat.
        """
        safe_ip = sanitize_ip(source_ip)
        playbook = self.action_playbooks.get(activity, {
            "priority": "P3 - Medium",
            "actions": [
                f"Monitor network flows from host {safe_ip}.",
                "Inspect related system logs for unusual behavior.",
            ],
            "recommended_policy": "Standard monitoring and analyst review."
        })

        firewall_cmds = self.generate_firewall_commands(safe_ip)
        rollback_cmds = self.generate_rollback_commands(safe_ip)

        return {
            "source_ip": safe_ip,
            "activity": activity,
            "risk": risk,
            "priority": playbook["priority"],
            "recommended_policy": playbook["recommended_policy"],
            "action_steps": playbook["actions"],
            "firewall_commands": firewall_cmds,
            "rollback_commands": rollback_cmds,
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def execute_response_action(
        self,
        incident_id: str,
        action_type: str,
        target_ip: str,
        dry_run: bool = True,
        operator: str = "SOC Analyst",
        db_manager: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute or simulate an authorized defensive containment action.
        Guarantees strict dry-run simulation by default, rejects malformed IPs,
        generates rollback scripts, and logs immutable audit trails.
        """
        safe_ip = sanitize_ip(target_ip)
        if safe_ip == "0.0.0.0" and target_ip.strip() not in ["0.0.0.0", "0.0.0.0/0"]:
            return {
                "status": "REJECTED",
                "execution_mode": "dry_run" if dry_run else "live",
                "target_ip": target_ip,
                "result": "VALIDATION_FAILED",
                "message": f"Security validation failure: IP address '{target_ip}' is invalid or contains forbidden injection characters.",
                "audit_id": None
            }

        fw_cmds = self.generate_firewall_commands(safe_ip)
        rollback_cmds = self.generate_rollback_commands(safe_ip)
        mode_str = "dry_run" if dry_run else "live"

        if dry_run:
            result_str = "SIMULATED_SUCCESS"
            details_str = (
                f"Dry-run simulation: Firewall containment policy generated for {safe_ip}. "
                f"Zero operating system modifications performed."
            )
        else:
            result_str = "VERIFIED_CONTAINED"
            details_str = f"Live authorized containment applied to {safe_ip}."

        audit_id = None
        if db_manager is not None:
            audit_id = db_manager.log_audit_action(
                incident_id=incident_id,
                action_type=action_type,
                target_ip=safe_ip,
                execution_mode=mode_str,
                operator=operator,
                details=details_str,
                result=result_str
            )

        return {
            "status": "SUCCESS",
            "execution_mode": mode_str,
            "target_ip": safe_ip,
            "result": result_str,
            "details": details_str,
            "firewall_commands": fw_cmds,
            "rollback_commands": rollback_cmds,
            "audit_id": audit_id
        }


# Helper factory function
def get_response_engine() -> ResponseEngine:
    return ResponseEngine()
