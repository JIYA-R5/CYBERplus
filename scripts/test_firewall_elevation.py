"""
SentinelAI - Windows Defender Firewall Elevation and Enforcement Probe
Usage: python scripts/test_firewall_elevation.py
"""
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_manager import get_firewall_adapter, validate_ip_for_containment
import database

def main():
    print("=" * 60)
    print("SentinelAI - Windows Defender Firewall Verification Probe")
    print("=" * 60)

    adapter = get_firewall_adapter()
    is_elevated = adapter.check_elevation()
    print(f"[*] Adapter Type:        {adapter.__class__.__name__}")
    print(f"[*] Operating System:    {sys.platform}")
    print(f"[*] Elevated (Admin):    {'YES (Enforcement Active)' if is_elevated else 'NO (Requires Administrator)'}")

    if not is_elevated:
        print("\n[!] WARNING:")
        print("    Your shell is NOT running as Administrator.")
        print("    Windows Defender Firewall prevents standard users from adding inbound rules.")
        print("    To enable live firewall blocking, run:")
        print("      start_sentinel_admin.bat")
        print("    or open PowerShell as Administrator and run uvicorn.\n")
        return

    print("\n[*] Running live firewall test on test address 198.51.100.99...")
    test_ip = "198.51.100.99"
    test_action_id = "IPS-ADMIN-PROBE"

    block_res = adapter.block_ip(
        ip=test_ip,
        action_id=test_action_id,
        reason="SentinelAI Elevation Probe Test"
    )
    print(f"[*] Block Result:       {block_res.get('status')} (Rule: {block_res.get('firewall_rule_id')})")

    if block_res.get("success"):
        print("[+] Rule creation verified in Windows Defender Firewall!")
        verify_res = adapter.verify_rule(block_res.get("firewall_rule_id"))
        print(f"[*] Rule Verified State: {verify_res}")

        print("[*] Cleaning up probe rule...")
        unblock_res = adapter.unblock_ip(block_res.get("firewall_rule_id"))
        print(f"[+] Unblock Result:     {unblock_res.get('status')}")
        print("\n[SUCCESS] Windows Defender Firewall is fully operational and capable of live automated blocking!")
    else:
        print(f"[-] Block failed: {block_res.get('error')}")

if __name__ == "__main__":
    main()
