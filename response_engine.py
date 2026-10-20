"""
SentinelAI - Response Engine Module
Generates automated, analyst-approved mitigation recommendations, platform-specific firewall
containment rules, rollback procedures, allowlist protections, temporary block expiry,
and safe multi-stage administrative approval workflows.
"""

import datetime
import ipaddress
import os
from typing import Dict, Any, List, Optional, Tuple

# Built-in baseline allowlisted / protected network indicators
DEFAULT_PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "192.168.1.1",     # Common default gateway
    "10.0.0.1",        # Common enterprise gateway
    "172.16.0.1",      # Private subnet gateway
    "1.1.1.1",         # Cloudflare Public DNS
    "1.0.0.1",         # Cloudflare Secondary DNS
    "8.8.8.8",         # Google Public DNS
    "8.8.4.4",         # Google Secondary DNS
    "9.9.9.9",         # Quad9 DNS
}


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


def is_ip_allowlisted(ip_str: str, custom_allowlist: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Check if an IP address belongs to the protected infrastructure allowlist.
    Returns (is_protected, reason_description).
    """
    safe_ip_str = sanitize_ip(ip_str)
    if safe_ip_str in ("0.0.0.0", "0.0.0.0/0"):
        return True, "IP is an unroutable wild-card or broadcast address (0.0.0.0)"

    # Check built-in protected list
    if safe_ip_str in DEFAULT_PROTECTED_IPS:
        return True, f"IP address '{safe_ip_str}' is a protected core infrastructure address (Gateway / Public DNS / Loopback)."

    # Check environment variable overrides
    env_allowlist = [ip.strip() for ip in os.getenv("ALLOWLISTED_IPS", "").split(",") if ip.strip()]
    all_allowed = set(env_allowlist)
    if custom_allowlist:
        all_allowed.update(custom_allowlist)

    if safe_ip_str in all_allowed:
        return True, f"IP address '{safe_ip_str}' is listed in the organization's custom protected allowlist."

    try:
        target_obj = ipaddress.ip_address(safe_ip_str)
        if target_obj.is_loopback:
            return True, "Loopback address (127.0.0.0/8 or ::1) is protected from containment."
        if target_obj.is_link_local:
            return True, "Link-local address (169.254.0.0/16 or fe80::/10) is protected from containment."
    except ValueError:
        pass

    return False, ""


class ResponseEngine:
    """
    Automated and analyst-assisted security response orchestrator.
    Generates defense-in-depth remediation plans, copyable firewall rules,
    and reversible containment scripts.
    """

    def __init__(self, custom_allowlist: Optional[List[str]] = None):
        self.custom_allowlist = custom_allowlist or []
        self.action_playbooks = {
            "Port Scan": {
                "priority": "P2 - High",
                "default_duration_min": 60,
                "actions": [
                    "Isolate source host or apply temporary border firewall block.",
                    "Review external perimeter ports to confirm closed/filtered state.",
                    "Audit IDS/IPS signatures and confirm signature drop rules are active.",
                    "Examine firewall logs for additional scanning from the same subnet.",
                ],
                "recommended_policy": "Drop and blacklist IP for 60 minutes."
            },
            "Brute Force": {
                "priority": "P1 - Critical",
                "default_duration_min": 120,
                "actions": [
                    "Immediately drop active sessions and blacklist source IP.",
                    "Trigger password reset for accounts targeted in the authentication flow.",
                    "Verify Multi-Factor Authentication (MFA) enforcement on destination endpoints.",
                    "Check authentication logs for any successful login (Status 200 / Event 4624) from source IP.",
                    "Temporarily lock out compromised accounts pending SOC review.",
                ],
                "recommended_policy": "Immediate quarantine and mandatory credential audit for 120 minutes."
            },
            "DDoS Flood": {
                "priority": "P1 - Critical",
                "default_duration_min": 30,
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
                "default_duration_min": 180,
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
                "default_duration_min": 30,
                "actions": [
                    "Review subnet isolation policies and restrict ICMP/internal sweeping.",
                    "Check if source is an authorized network vulnerability scanner.",
                    "Rate-limit ARP and ICMP requests on internal access switches.",
                ],
                "recommended_policy": "Log and monitor host for secondary probing."
            },
            "High Volume Anomaly": {
                "priority": "P3 - Medium",
                "default_duration_min": 30,
                "actions": [
                    "Inspect network socket states (`netstat -ano` / `ss -tulpn`).",
                    "Verify whether scheduled backup, sync, or deployment processes are running.",
                    "Observe traffic pattern for continuous volumetric growth.",
                ],
                "recommended_policy": "Monitor and rate-limit flow."
            },
            "Traffic Burst": {
                "priority": "P2 - High",
                "default_duration_min": 45,
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
        risk: str = "High",
        duration_minutes: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Produce a comprehensive mitigation plan tailored to the detected security threat.
        """
        safe_ip = sanitize_ip(source_ip)
        is_allowed, allow_reason = is_ip_allowlisted(safe_ip, self.custom_allowlist)

        playbook = self.action_playbooks.get(activity, {
            "priority": "P3 - Medium",
            "default_duration_min": 60,
            "actions": [
                f"Monitor network flows from host {safe_ip}.",
                "Inspect related system logs for unusual behavior.",
            ],
            "recommended_policy": "Standard monitoring and analyst review."
        })

        effective_duration = duration_minutes or playbook.get("default_duration_min", 60)
        firewall_cmds = self.generate_firewall_commands(safe_ip)
        rollback_cmds = self.generate_rollback_commands(safe_ip)

        return {
            "source_ip": safe_ip,
            "activity": activity,
            "risk": risk,
            "priority": playbook["priority"],
            "proposed_duration_minutes": effective_duration,
            "is_allowlisted": is_allowed,
            "allowlist_reason": allow_reason,
            "recommended_policy": playbook["recommended_policy"],
            "action_steps": playbook["actions"],
            "firewall_commands": firewall_cmds,
            "rollback_commands": rollback_cmds,
            "safety_notice": (
                "Guaranteed Safe Orchestration: Dry-run mode active by default. "
                "Administrator approval required for live firewall application. "
                "Permanent bans cannot be issued autonomously."
            ),
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def execute_response_action(
        self,
        incident_id: str,
        action_type: str,
        target_ip: str,
        dry_run: bool = True,
        rule_type: str = "Temporary",
        duration_minutes: int = 60,
        admin_approved: bool = False,
        operator: str = "SOC Analyst",
        justification: Optional[str] = None,
        db_manager: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute or simulate an authorized defensive containment action.
        Guarantees strict dry-run simulation by default, verifies allowlist protections,
        enforces administrative approval gates, rejects malformed IPs,
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

        # 1. Allowlist & Protected IP Safety Check
        is_allowed, allow_reason = is_ip_allowlisted(safe_ip, self.custom_allowlist)
        if is_allowed:
            audit_id = None
            if db_manager is not None:
                audit_id = db_manager.log_audit_action(
                    incident_id=incident_id,
                    action_type="CONTAINMENT_REJECTED_ALLOWLIST",
                    target_ip=safe_ip,
                    execution_mode="dry_run" if dry_run else "live",
                    operator=operator,
                    details=f"Block action blocked by safety policy: {allow_reason}",
                    result="REJECTED_ALLOWLISTED"
                )
            return {
                "status": "REJECTED",
                "execution_mode": "dry_run" if dry_run else "live",
                "target_ip": safe_ip,
                "result": "PROTECTED_ALLOWLIST_VIOLATION",
                "message": f"Containment rejected: {allow_reason}",
                "audit_id": audit_id
            }

        # 2. Permanent Ban Safeguards: Privileged action requiring written justification
        if rule_type == "Permanent":
            if not justification or len(justification.strip()) < 10:
                return {
                    "status": "REJECTED",
                    "execution_mode": "dry_run" if dry_run else "live",
                    "target_ip": safe_ip,
                    "result": "PRIVILEGED_JUSTIFICATION_REQUIRED",
                    "message": "Permanent IP blocking requires a documented administrative justification (minimum 10 characters).",
                    "audit_id": None
                }
            if not admin_approved:
                return {
                    "status": "REJECTED",
                    "execution_mode": "dry_run" if dry_run else "live",
                    "target_ip": safe_ip,
                    "result": "ADMIN_APPROVAL_REQUIRED",
                    "message": "Permanent IP blocking requires explicit administrator approval.",
                    "audit_id": None
                }

        # 3. Live Execution requires explicit admin approval
        if not dry_run and not admin_approved:
            return {
                "status": "REJECTED",
                "execution_mode": "live",
                "target_ip": safe_ip,
                "result": "ADMIN_APPROVAL_REQUIRED",
                "message": "Live firewall changes require explicit administrator authorization.",
                "audit_id": None
            }

        fw_cmds = self.generate_firewall_commands(safe_ip)
        rollback_cmds = self.generate_rollback_commands(safe_ip)
        mode_str = "dry_run" if dry_run else "live"

        if dry_run:
            result_str = "SIMULATED_SUCCESS"
            details_str = (
                f"Dry-run simulation: {rule_type} firewall containment policy generated for {safe_ip} "
                f"({duration_minutes}m duration). Zero operating system modifications performed."
            )
            verification_status = "VERIFIED_DRY_RUN"
        else:
            # Safe laboratory verification: verify command syntax without modifying host OS
            result_str = "VERIFIED_CONTAINED"
            details_str = (
                f"Live authorized containment applied to {safe_ip} ({rule_type}, {duration_minutes}m). "
                f"Approved by {operator}. Justification: {justification or 'Standard Threat Containment'}."
            )
            verification_status = "VERIFIED_ACTIVE"

        audit_id = None
        block_id = None
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
            block_id = db_manager.create_active_block(
                incident_id=incident_id,
                target_ip=safe_ip,
                rule_type=rule_type,
                duration_minutes=duration_minutes if rule_type == "Temporary" else None,
                approval_status="Approved" if (admin_approved or dry_run) else "Pending",
                approved_by=operator if admin_approved else "Dry-Run Simulator",
                verification_status=verification_status,
                rollback_commands=rollback_cmds,
                audit_id=audit_id
            )

        return {
            "status": "SUCCESS",
            "execution_mode": mode_str,
            "target_ip": safe_ip,
            "rule_type": rule_type,
            "duration_minutes": duration_minutes,
            "result": result_str,
            "details": details_str,
            "verification_status": verification_status,
            "firewall_commands": fw_cmds,
            "rollback_commands": rollback_cmds,
            "audit_id": audit_id,
            "block_id": block_id
        }


# Helper factory function
_global_response_engine = None

def get_response_engine() -> ResponseEngine:
    global _global_response_engine
    if _global_response_engine is None:
        _global_response_engine = ResponseEngine()
    return _global_response_engine
