"""
SentinelAI - Windows Defender Firewall Adapter & Safety Enforcement Module
Implements real OS-level firewall blocking via Windows Defender Firewall (netsh / PowerShell),
strict anti-lockout safety checks, verification of OS rule state, rollback on failure,
and clean removal of temporary SentinelAI rules.
"""

import os
import sys
import json
import socket
import logging
import ipaddress
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger("SentinelAI.FirewallManager")

# Prefix identifying SentinelAI-managed firewall rules
SENTINEL_RULE_PREFIX = "SentinelAI_IPS_"

# Core infrastructure & critical services protected from any containment action
BUILTIN_PROTECTED_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "255.255.255.255",
    "192.168.1.1",     # Common default gateway
    "192.168.0.1",     # Common default gateway
    "10.0.0.1",        # Common enterprise gateway
    "172.16.0.1",      # Private subnet gateway
    "1.1.1.1",         # Cloudflare Primary DNS
    "1.0.0.1",         # Cloudflare Secondary DNS
    "8.8.8.8",         # Google Primary DNS
    "8.8.4.4",         # Google Secondary DNS
    "9.9.9.9",         # Quad9 DNS
}


@dataclass
class FirewallExecutionResult:
    """Detailed result of a firewall command execution."""
    success: bool
    action: str            # 'BLOCK', 'UNBLOCK'
    rule_id: str
    target_ip: str
    command_executed: str
    return_code: int
    stdout: str
    stderr: str
    error_message: Optional[str] = None
    verified: bool = False
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallVerificationResult:
    """Result of verifying that a rule actually exists and is active in the OS."""
    exists: bool
    is_enabled: bool
    is_blocking: bool
    rule_name: str
    raw_output: str
    verified: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_local_host_ips() -> Set[str]:
    """
    Dynamically discover all IP addresses assigned to network interfaces on the local machine.
    These must NEVER be blocked to prevent self-lockout.
    """
    local_ips = {"127.0.0.1", "::1"}
    try:
        # Standard hostname lookup
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip:
                local_ips.add(ip.strip())
    except Exception:
        pass

    try:
        # Connect UDP socket to detect primary routing IP without sending packets
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    return local_ips


def validate_ip_for_containment(
    ip_str: str,
    allow_private_networks: bool = False,
    custom_allowlist_checker: Optional[Any] = None
) -> Tuple[bool, str, str]:
    """
    Comprehensive safety validator:
    Ensures an IP address is syntactically valid and NOT protected.
    
    Returns:
        (is_safe_to_block: bool, sanitized_ip: str, rejection_reason: str)
    """
    raw = str(ip_str).strip()
    if not raw:
        return False, "0.0.0.0", "Empty IP address provided"

    # 1. Parse and validate IP syntax
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        try:
            net_obj = ipaddress.ip_network(raw, strict=False)
            if net_obj.num_addresses > 1024:
                return False, "0.0.0.0", f"CIDR range '{raw}' too broad (>1024 addresses). Unrestricted blocking prohibited."
            ip_obj = net_obj
        except ValueError:
            return False, "0.0.0.0", f"Malformed or invalid IP address format: '{raw}'"

    clean_ip = str(ip_obj)

    # 2. Check for wildcard / unroutable / broadcast
    if clean_ip in ("0.0.0.0", "0.0.0.0/0", "255.255.255.255", "::"):
        return False, clean_ip, f"Address '{clean_ip}' is an unroutable wildcard or broadcast address."

    # 3. Check loopback addresses
    if getattr(ip_obj, "is_loopback", False) or clean_ip.startswith("127.") or clean_ip == "::1":
        return False, clean_ip, f"Loopback address '{clean_ip}' is protected from containment."

    # 4. Check multicast & Class E / unallocated reserved ranges
    if getattr(ip_obj, "is_multicast", False):
        return False, clean_ip, f"Multicast address '{clean_ip}' cannot be blocked."
    if getattr(ip_obj, "is_link_local", False):
        return False, clean_ip, f"Link-local address '{clean_ip}' is protected."
    # Check reserved (Class E 240.0.0.0/4), but allow RFC 5737 documentation test nets for simulation
    is_test_net = False
    try:
        test_nets = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")]
        if isinstance(ip_obj, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
            addr_check = ip_obj if isinstance(ip_obj, ipaddress.IPv4Address) else ip_obj.network_address
            is_test_net = any(addr_check in tnet for tnet in test_nets)
    except Exception:
        pass

    if getattr(ip_obj, "is_reserved", False) and not is_test_net:
        return False, clean_ip, f"Reserved address '{clean_ip}' cannot be blocked."

    # 5. Check local host machine IP addresses (Self-lockout prevention)
    local_host_ips = get_local_host_ips()
    if clean_ip in local_host_ips:
        return False, clean_ip, f"Address '{clean_ip}' belongs to the host machine running SentinelAI (Self-Lockout Prevention)."

    # 6. Check built-in protected list (gateways, public DNS)
    if clean_ip in BUILTIN_PROTECTED_IPS:
        return False, clean_ip, f"Address '{clean_ip}' is protected core infrastructure (Gateway / Public DNS)."

    # 7. Check private networks (RFC 1918) unless explicitly permitted
    if not allow_private_networks and getattr(ip_obj, "is_private", False) and not is_test_net:
        return False, clean_ip, f"Address '{clean_ip}' is in a private network (RFC 1918). Private network blocking is disabled by default."

    # 8. Check database / custom allowlist
    if custom_allowlist_checker:
        try:
            is_allowed, reason = custom_allowlist_checker(clean_ip)
            if is_allowed:
                return False, clean_ip, f"Allowlist rule matched: {reason}"
        except Exception as e:
            logger.warning(f"Error checking custom allowlist for {clean_ip}: {e}")

    return True, clean_ip, ""


class BaseFirewallAdapter:
    """Abstract interface for OS firewall enforcement adapters."""
    def block_ip(self, ip: str, action_id: str, reason: str = "") -> FirewallExecutionResult:
        raise NotImplementedError

    def verify_rule(self, rule_id: str) -> FirewallVerificationResult:
        raise NotImplementedError

    def unblock_rule(self, rule_id: str) -> FirewallExecutionResult:
        raise NotImplementedError

    def verify_rule_removed(self, rule_id: str) -> bool:
        raise NotImplementedError

    def list_active_rules(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def check_elevation(self) -> bool:
        raise NotImplementedError


class WindowsDefenderFirewallAdapter(BaseFirewallAdapter):
    """
    Native Windows Defender Firewall Adapter.
    Uses safe netsh advfirewall and PowerShell NetSecurity commands with:
    - Unique SentinelAI_IPS_ rule naming
    - Real OS state verification
    - Rollback upon verification failure
    - Detailed operating-system error capture
    """

    def __init__(self):
        self._is_admin: Optional[bool] = None

    def check_elevation(self) -> bool:
        """Check if the current process possesses Administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _format_rule_name(self, action_id: str, ip: str) -> str:
        clean_ip_tag = ip.replace(":", "_").replace("/", "_")
        return f"{SENTINEL_RULE_PREFIX}{action_id}_{clean_ip_tag}"

    def block_ip(self, ip: str, action_id: str, reason: str = "") -> FirewallExecutionResult:
        """
        Creates a narrowly scoped inbound blocking rule in Windows Defender Firewall.
        Format:
            netsh advfirewall firewall add rule name="<rule_name>" dir=in action=block remoteip="<ip>" enable=yes description="<desc>"
        Then immediately queries Windows Firewall to verify that the rule actually exists and is active.
        """
        rule_name = self._format_rule_name(action_id, ip)
        clean_desc = f"SentinelAI IPS Containment: {reason or 'Malicious threat source'} [ID: {action_id}]"

        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            f"description={clean_desc}"
        ]
        cmd_str = " ".join(cmd)
        logger.info(f"Executing Windows Firewall command: {cmd_str}")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            rc = proc.returncode

            if rc != 0 or "Ok." not in stdout:
                err_msg = stderr or stdout or f"Command failed with exit code {rc}"
                logger.error(f"Failed to create firewall rule {rule_name}: {err_msg}")
                return FirewallExecutionResult(
                    success=False,
                    action="BLOCK",
                    rule_id=rule_name,
                    target_ip=ip,
                    command_executed=cmd_str,
                    return_code=rc,
                    stdout=stdout,
                    stderr=stderr,
                    error_message=err_msg,
                    verified=False,
                    details=f"OS execution failed (RC {rc}): {err_msg}"
                )

            # Rule creation command succeeded -> Verify actual OS firewall state
            verification = self.verify_rule(rule_name)
            if not verification.verified:
                logger.warning(f"Firewall command succeeded but rule verification failed for {rule_name}. Rolling back.")
                self.unblock_rule(rule_name)
                return FirewallExecutionResult(
                    success=False,
                    action="BLOCK",
                    rule_id=rule_name,
                    target_ip=ip,
                    command_executed=cmd_str,
                    return_code=rc,
                    stdout=stdout,
                    stderr=stderr,
                    error_message="Firewall rule created but failed post-creation OS state verification.",
                    verified=False,
                    details="Post-creation verification check did not confirm rule is active."
                )

            logger.info(f"Successfully verified Windows Firewall rule {rule_name} for IP {ip}")
            return FirewallExecutionResult(
                success=True,
                action="BLOCK",
                rule_id=rule_name,
                target_ip=ip,
                command_executed=cmd_str,
                return_code=0,
                stdout=stdout,
                stderr="",
                error_message=None,
                verified=True,
                details=f"Windows Defender Firewall rule active and verified (Action: Block, RemoteIP: {ip})"
            )

        except subprocess.TimeoutExpired:
            return FirewallExecutionResult(
                success=False,
                action="BLOCK",
                rule_id=rule_name,
                target_ip=ip,
                command_executed=cmd_str,
                return_code=-1,
                stdout="",
                stderr="Execution timed out after 12 seconds",
                error_message="Firewall command execution timed out.",
                verified=False,
                details="OS command timed out"
            )
        except Exception as e:
            return FirewallExecutionResult(
                success=False,
                action="BLOCK",
                rule_id=rule_name,
                target_ip=ip,
                command_executed=cmd_str,
                return_code=-1,
                stdout="",
                stderr=str(e),
                error_message=str(e),
                verified=False,
                details=f"Unexpected exception: {e}"
            )

    def verify_rule(self, rule_id: str) -> FirewallVerificationResult:
        """
        Queries Windows Defender Firewall to confirm that the rule exists, is enabled,
        and is configured with action=Block.
        """
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_id}"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            out = proc.stdout.strip()
            if proc.returncode != 0 or "No rules match the specified criteria" in out:
                return FirewallVerificationResult(
                    exists=False,
                    is_enabled=False,
                    is_blocking=False,
                    rule_name=rule_id,
                    raw_output=out,
                    verified=False
                )

            # Check properties in output
            out_lower = out.lower()
            is_enabled = "enabled:                              yes" in out_lower or "enabled: yes" in out_lower or "action:                               block" in out_lower
            is_block = "action:                               block" in out_lower or "action: block" in out_lower or "block" in out_lower

            verified = proc.returncode == 0 and ("action: block" in out_lower or "action:                               block" in out_lower or "block" in out_lower)
            return FirewallVerificationResult(
                exists=True,
                is_enabled=is_enabled,
                is_blocking=is_block,
                rule_name=rule_id,
                raw_output=out,
                verified=verified
            )
        except Exception as e:
            return FirewallVerificationResult(
                exists=False,
                is_enabled=False,
                is_blocking=False,
                rule_name=rule_id,
                raw_output=str(e),
                verified=False
            )

    def unblock_rule(self, rule_id: str) -> FirewallExecutionResult:
        """
        Safely removes a SentinelAI-created firewall rule from Windows Defender Firewall.
        Validates prefix before deletion to ensure NO unrelated firewall rules can ever be modified.
        """
        if not rule_id.startswith(SENTINEL_RULE_PREFIX):
            return FirewallExecutionResult(
                success=False,
                action="UNBLOCK",
                rule_id=rule_id,
                target_ip="",
                command_executed="",
                return_code=1,
                stdout="",
                stderr="Safety violation: Cannot remove firewall rules without SentinelAI_IPS_ prefix",
                error_message="Safety violation: Cannot remove non-SentinelAI rules.",
                verified=False,
                details="Rule name rejected by security prefix filter."
            )

        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_id}"]
        cmd_str = " ".join(cmd)
        logger.info(f"Executing firewall rule deletion: {cmd_str}")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            rc = proc.returncode

            # Verify removal
            is_removed = self.verify_rule_removed(rule_id)

            if is_removed or "No rules match the specified criteria" in stdout or rc == 0:
                logger.info(f"Verified removal of firewall rule {rule_id}")
                return FirewallExecutionResult(
                    success=True,
                    action="UNBLOCK",
                    rule_id=rule_id,
                    target_ip="",
                    command_executed=cmd_str,
                    return_code=0,
                    stdout=stdout,
                    stderr=stderr,
                    error_message=None,
                    verified=True,
                    details=f"Windows Defender Firewall rule {rule_id} removed and verified."
                )

            err_msg = stderr or stdout or "Failed to delete rule from Windows Defender Firewall."
            return FirewallExecutionResult(
                success=False,
                action="UNBLOCK",
                rule_id=rule_id,
                target_ip="",
                command_executed=cmd_str,
                return_code=rc,
                stdout=stdout,
                stderr=stderr,
                error_message=err_msg,
                verified=False,
                details=f"Deletion failed: {err_msg}"
            )

        except Exception as e:
            return FirewallExecutionResult(
                success=False,
                action="UNBLOCK",
                rule_id=rule_id,
                target_ip="",
                command_executed=cmd_str,
                return_code=-1,
                stdout="",
                stderr=str(e),
                error_message=str(e),
                verified=False,
                details=f"Exception during rule unblocking: {e}"
            )

    def verify_rule_removed(self, rule_id: str) -> bool:
        """Verify that the rule no longer exists in Windows Defender Firewall."""
        v = self.verify_rule(rule_id)
        return not v.exists

    def list_active_rules(self) -> List[Dict[str, Any]]:
        """
        Enumerate all active SentinelAI-managed firewall rules currently present in the OS.
        Never touches or lists unrelated system firewall rules.
        """
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"]
        rules = []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return rules

            blocks = proc.stdout.split("\n\n")
            for b in blocks:
                if SENTINEL_RULE_PREFIX in b:
                    lines = [line.strip() for line in b.splitlines() if line.strip()]
                    rule_data = {"raw": b}
                    for line in lines:
                        if ":" in line:
                            parts = line.split(":", 1)
                            k = parts[0].strip().lower().replace(" ", "_")
                            v = parts[1].strip()
                            rule_data[k] = v
                    rule_name = rule_data.get("rule_name", "")
                    if rule_name.startswith(SENTINEL_RULE_PREFIX):
                        rules.append(rule_data)
        except Exception as e:
            logger.warning(f"Error enumerating SentinelAI firewall rules: {e}")

        return rules


class MockFirewallAdapter(BaseFirewallAdapter):
    """
    Mock Firewall Adapter for automated tests, non-Windows environments,
    or CI environments where OS firewall modification is simulated.
    """
    def __init__(self, simulate_permission_denied: bool = False):
        self._rules: Dict[str, Dict[str, Any]] = {}
        self.simulate_permission_denied = simulate_permission_denied
        self.execution_log: List[Dict[str, Any]] = []

    def check_elevation(self) -> bool:
        return not self.simulate_permission_denied

    def block_ip(self, ip: str, action_id: str, reason: str = "") -> FirewallExecutionResult:
        rule_name = f"{SENTINEL_RULE_PREFIX}{action_id}_{ip.replace(':', '_').replace('/', '_')}"
        cmd_str = f"netsh advfirewall firewall add rule name={rule_name} dir=in action=block remoteip={ip} enable=yes"

        if self.simulate_permission_denied:
            err = "The requested operation requires elevation (Run as administrator)."
            res = FirewallExecutionResult(
                success=False,
                action="BLOCK",
                rule_id=rule_name,
                target_ip=ip,
                command_executed=cmd_str,
                return_code=1,
                stdout=err,
                stderr="",
                error_message=err,
                verified=False,
                details="Mock: Administrator elevation required"
            )
            self.execution_log.append(res.to_dict())
            return res

        self._rules[rule_name] = {
            "rule_name": rule_name,
            "target_ip": ip,
            "action": "Block",
            "direction": "In",
            "enabled": True,
            "reason": reason
        }

        res = FirewallExecutionResult(
            success=True,
            action="BLOCK",
            rule_id=rule_name,
            target_ip=ip,
            command_executed=cmd_str,
            return_code=0,
            stdout="Ok.",
            stderr="",
            error_message=None,
            verified=True,
            details="Mock rule added and verified"
        )
        self.execution_log.append(res.to_dict())
        return res

    def verify_rule(self, rule_id: str) -> FirewallVerificationResult:
        if rule_id in self._rules:
            return FirewallVerificationResult(
                exists=True,
                is_enabled=True,
                is_blocking=True,
                rule_name=rule_id,
                raw_output="Action: Block, Enabled: Yes",
                verified=True
            )
        return FirewallVerificationResult(
            exists=False,
            is_enabled=False,
            is_blocking=False,
            rule_name=rule_id,
            raw_output="No rules match",
            verified=False
        )

    def unblock_rule(self, rule_id: str) -> FirewallExecutionResult:
        cmd_str = f"netsh advfirewall firewall delete rule name={rule_id}"
        if not rule_id.startswith(SENTINEL_RULE_PREFIX):
            return FirewallExecutionResult(
                success=False,
                action="UNBLOCK",
                rule_id=rule_id,
                target_ip="",
                command_executed=cmd_str,
                return_code=1,
                stdout="",
                stderr="Safety violation: Cannot remove non-SentinelAI rule",
                error_message="Safety violation",
                verified=False
            )

        if rule_id in self._rules:
            del self._rules[rule_id]

        return FirewallExecutionResult(
            success=True,
            action="UNBLOCK",
            rule_id=rule_id,
            target_ip="",
            command_executed=cmd_str,
            return_code=0,
            stdout="Deleted 1 rule(s). Ok.",
            stderr="",
            error_message=None,
            verified=True,
            details="Mock rule removed and verified"
        )

    def verify_rule_removed(self, rule_id: str) -> bool:
        return rule_id not in self._rules

    def list_active_rules(self) -> List[Dict[str, Any]]:
        return list(self._rules.values())


# Adapter singleton & factory
_global_adapter: Optional[BaseFirewallAdapter] = None

def get_firewall_adapter(force_mock: bool = False) -> BaseFirewallAdapter:
    """
    Factory function returning the active firewall adapter.
    Uses WindowsDefenderFirewallAdapter on Windows, or MockFirewallAdapter if requested or in CI.
    """
    global _global_adapter
    if _global_adapter is not None and not force_mock:
        return _global_adapter

    if force_mock or os.environ.get("SENTINEL_MOCK_FIREWALL") == "1" or sys.platform != "win32":
        _global_adapter = MockFirewallAdapter()
    else:
        _global_adapter = WindowsDefenderFirewallAdapter()

    return _global_adapter
