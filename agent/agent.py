"""
SentinelAI - Endpoint Telemetry Collector Agent
Collects real native endpoint network telemetry on Windows/Linux or generates
synthetic telemetry streams for Docker container environments, transmitting authenticated
events to the SentinelAI API backend.
"""

import os
import sys
import time
import json
import socket
import platform
import argparse
import datetime
import subprocess
from typing import Dict, Any, List, Optional
import urllib.request
import urllib.error

# Ensure UTF-8 output encoding across platforms
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def get_default_host_id() -> str:
    """Generate friendly hostname identifier."""
    return socket.gethostname() or "sentinel-endpoint"


def collect_native_connections() -> List[Dict[str, Any]]:
    """
    Collect active local TCP/UDP socket endpoints and connections safely.
    Runs without requiring administrator/root kernel drivers.
    """
    events = []
    now_iso = datetime.datetime.now().isoformat()
    system_name = platform.system().lower()

    if system_name == "windows":
        try:
            # Run netstat -ano safely to get established and listening endpoints
            out = subprocess.check_output(
                ["netstat", "-ano"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            lines = out.splitlines()
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                    proto = parts[0].upper()
                    local_addr = parts[1]
                    foreign_addr = parts[2]
                    state = parts[3] if proto == "TCP" and len(parts) >= 4 else "LISTENING"

                    # Parse local IP and port
                    if ":" in local_addr:
                        src_ip, _, src_port = local_addr.rpartition(":")
                    else:
                        src_ip, src_port = local_addr, "0"

                    # Parse remote IP and port
                    if ":" in foreign_addr:
                        dst_ip, _, dst_port = foreign_addr.rpartition(":")
                    else:
                        dst_ip, dst_port = foreign_addr, "0"

                    # Skip loopback chatter unless active
                    if src_ip in ("0.0.0.0", "[::]", "*") and dst_ip in ("0.0.0.0", "[::]", "*"):
                        continue

                    clean_src = "127.0.0.1" if src_ip in ("0.0.0.0", "[::]", "*") else src_ip
                    clean_dst = "127.0.0.1" if dst_ip in ("0.0.0.0", "[::]", "*") else dst_ip

                    try:
                        port_int = int(dst_port) if dst_port.isdigit() else (int(src_port) if src_port.isdigit() else 80)
                    except Exception:
                        port_int = 80

                    events.append({
                        "timestamp": now_iso,
                        "source_ip": clean_src,
                        "destination_ip": clean_dst,
                        "destination_port": port_int,
                        "protocol": proto,
                        "packets": 1,
                        "bytes": 64,
                        "event_type": "connection",
                        "state": state
                    })
        except Exception as e:
            # Fallback to local network probe
            events.append({
                "timestamp": now_iso,
                "source_ip": socket.gethostbyname(socket.gethostname()) if socket.gethostname() else "127.0.0.1",
                "destination_ip": "1.1.1.1",
                "destination_port": 53,
                "protocol": "UDP",
                "packets": 1,
                "bytes": 56,
                "event_type": "dns_heartbeat"
            })
    else:
        # Cross-platform / Linux fallback connection inspection
        try:
            out = subprocess.check_output(
                ["netstat", "-tun"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            for line in out.splitlines()[2:]:
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0].upper().startswith(("TCP", "UDP")):
                    proto = parts[0].upper()[:3]
                    local_addr = parts[3]
                    foreign_addr = parts[4]

                    src_ip = local_addr.rpartition(":")[0] or "127.0.0.1"
                    dst_ip = foreign_addr.rpartition(":")[0] or "127.0.0.1"
                    dst_port = foreign_addr.rpartition(":")[2]
                    port_int = int(dst_port) if dst_port.isdigit() else 80

                    events.append({
                        "timestamp": now_iso,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": port_int,
                        "protocol": proto,
                        "packets": 1,
                        "bytes": 64,
                        "event_type": "flow"
                    })
        except Exception:
            events.append({
                "timestamp": now_iso,
                "source_ip": "127.0.0.1",
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "protocol": "UDP",
                "packets": 1,
                "bytes": 48,
                "event_type": "heartbeat"
            })

    return events[:50]  # Cap per cycle to prevent packet floods


def generate_synthetic_telemetry(cycle_count: int) -> List[Dict[str, Any]]:
    """
    Generate realistic network flow telemetry for Dockerized collectors
    and defensive simulation demonstrations.
    """
    now = datetime.datetime.now()
    now_iso = now.isoformat()
    events = []

    # Nominal enterprise baseline flows
    nominal_sources = ["192.168.1.105", "192.168.1.112", "192.168.1.140"]
    nominal_dests = [
        ("142.250.190.46", 443, "TCP", "HTTPS Cloud Sync"),
        ("1.1.1.1", 53, "UDP", "DNS Query"),
        ("192.168.1.1", 443, "TCP", "Gateway Router Admin"),
        ("13.107.42.16", 443, "TCP", "Microsoft Update")
    ]

    for src in nominal_sources:
        dst, port, proto, desc = nominal_dests[cycle_count % len(nominal_dests)]
        events.append({
            "timestamp": now_iso,
            "source_ip": src,
            "destination_ip": dst,
            "destination_port": port,
            "protocol": proto,
            "packets": 12 + (cycle_count % 8),
            "bytes": 1024 + (cycle_count * 128 % 4096),
            "event_type": "flow",
            "metadata": {"activity": desc}
        })

    # Periodically inject a suspicious synthetic probe to demonstrate dynamic SOC detection
    if cycle_count % 4 == 0:
        # Simulated external port reconnaissance
        scanner_ip = "198.51.100.99"
        probe_ports = [22, 80, 443, 3389, 8080, 8443]
        for p in probe_ports:
            events.append({
                "timestamp": now_iso,
                "source_ip": scanner_ip,
                "destination_ip": "192.168.1.200",
                "destination_port": p,
                "protocol": "TCP",
                "packets": 1,
                "bytes": 44,
                "event_type": "flow",
                "metadata": {"probe": "SYN_SCAN"}
            })

    return events


def load_file_telemetry(file_path: str) -> List[Dict[str, Any]]:
    """Load telemetry events from JSON or CSV file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Telemetry file not found: {file_path}")

    now_iso = datetime.datetime.now().isoformat()
    events = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if file_path.endswith(".json"):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                events = parsed
            elif isinstance(parsed, dict):
                events = parsed.get("events", [parsed])
        except Exception:
            # Try line-delimited JSON (Suricata EVE)
            for line in content.splitlines():
                if line.strip():
                    try:
                        record = json.loads(line)
                        src = record.get("src_ip", record.get("source_ip", "127.0.0.1"))
                        dst = record.get("dest_ip", record.get("destination_ip", "127.0.0.1"))
                        port = record.get("dest_port", record.get("destination_port", 80))
                        proto = record.get("proto", "TCP")
                        events.append({
                            "timestamp": record.get("timestamp", now_iso),
                            "source_ip": src,
                            "destination_ip": dst,
                            "destination_port": port,
                            "protocol": proto,
                            "packets": record.get("flow", {}).get("pkts_toserver", 1),
                            "bytes": record.get("flow", {}).get("bytes_toserver", 64),
                            "event_type": record.get("event_type", "alert")
                        })
                    except Exception:
                        continue
    elif file_path.endswith(".csv"):
        import csv
        import io
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            events.append({
                "timestamp": row.get("Timestamp", now_iso),
                "source_ip": row.get("Source IP", row.get("source_ip", "127.0.0.1")),
                "destination_ip": row.get("Destination IP", row.get("dest_ip", "127.0.0.1")),
                "destination_port": int(row.get("Port", row.get("port", 80))),
                "protocol": row.get("Protocol", row.get("proto", "TCP")),
                "packets": int(row.get("Packets", row.get("packets", 1))),
                "bytes": 64,
                "event_type": "csv_flow"
            })

    return events


def transmit_telemetry(
    api_url: str,
    agent_secret: str,
    host_id: str,
    events: List[Dict[str, Any]],
    os_type: str = "windows"
) -> Dict[str, Any]:
    """Send authenticated telemetry payload to SentinelAI API."""
    endpoint = f"{api_url.rstrip('/')}/api/agent/telemetry"
    payload = {
        "host_id": host_id,
        "agent_version": "2.5.0",
        "os_type": os_type,
        "events": events
    }
    data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=data_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Secret": agent_secret,
            "Authorization": f"Bearer {agent_secret}",
            "User-Agent": f"SentinelAI-Agent/{host_id}"
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_agent_loop(args):
    """Main execution loop for endpoint agent."""
    api_url = args.api_url or os.environ.get("SENTINEL_API_URL", "http://localhost:8000")
    agent_secret = args.agent_secret or os.environ.get("SENTINEL_AGENT_SECRET", "sentinel-agent-secret-token")
    mode = args.mode or os.environ.get("AGENT_MODE", "synthetic" if os.environ.get("DOCKER_CONTAINER") else "native")
    interval = int(args.interval or os.environ.get("AGENT_INTERVAL", 10))
    host_id = args.host_id or os.environ.get("AGENT_HOST_ID", get_default_host_id())
    os_type = platform.system().lower()

    print("=" * 70)
    print("🛡️  SENTINELAI ENDPOINT TELEMETRY AGENT")
    print(f"Host Identifier:  {host_id}")
    print(f"Platform:         {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Collection Mode:  {mode.upper()}")
    print(f"API Destination:  {api_url}")
    print(f"Interval:         {interval}s")
    print(f"Authentication:   {'Configured (X-Agent-Secret)' if agent_secret else 'None (Open)'}")
    print("=" * 70)

    if os.environ.get("DOCKER_CONTAINER") and mode == "native":
        print(
            "⚠️  NOTICE: Agent running inside a Docker container.\n"
            "   A standard Linux container CANNOT see native Windows host network events.\n"
            "   Falling back to SYNTHETIC mode for continuous defensive demonstration.\n"
            "   To capture real Windows sockets, run this script directly on the host machine:\n"
            "   python agent/agent.py --mode native --api-url http://localhost:8000"
        )
        mode = "synthetic"

    cycle = 0
    try:
        while True:
            cycle += 1
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if mode == "file":
                if not args.file:
                    print("❌ Error: --file argument is required when mode is 'file'.")
                    sys.exit(1)
                events = load_file_telemetry(args.file)
            elif mode == "synthetic":
                events = generate_synthetic_telemetry(cycle)
            else:
                events = collect_native_connections()

            print(f"[{now_str}] Cycle #{cycle}: Collected {len(events)} telemetry flow event(s)...", end=" ")

            if args.dry_run:
                print("\n[DRY RUN] Telemetry payload sample:")
                print(json.dumps(events[:2], indent=2))
            else:
                try:
                    res = transmit_telemetry(
                        api_url=api_url,
                        agent_secret=agent_secret,
                        host_id=host_id,
                        events=events,
                        os_type=os_type
                    )
                    inc_count = res.get("correlated_incidents", 0)
                    print(f"✅ Ingested successfully. Correlated incidents: {inc_count}")
                except urllib.error.HTTPError as e:
                    body = e.read().decode("utf-8", errors="ignore")
                    print(f"❌ HTTP Error {e.code}: {body}")
                except urllib.error.URLError as e:
                    print(f"❌ Connection Failed: Cannot reach {api_url} ({e.reason})")
                except Exception as e:
                    print(f"❌ Unexpected Error: {str(e)}")

            if args.once:
                print("Single-shot execution completed. Exiting.")
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n🛑 SentinelAI Agent terminated cleanly by user.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Endpoint Telemetry Agent")
    parser.add_argument("--api-url", default=None, help="Target SentinelAI API base URL (default: http://localhost:8000)")
    parser.add_argument("--agent-secret", default=None, help="Agent authentication secret key")
    parser.add_argument("--mode", choices=["native", "synthetic", "file"], default=None, help="Collection mode")
    parser.add_argument("--interval", type=int, default=10, help="Interval in seconds between collection rounds")
    parser.add_argument("--host-id", default=None, help="Host identifier name")
    parser.add_argument("--file", default=None, help="Log file path (for --mode file)")
    parser.add_argument("--once", action="store_true", help="Collect and send once, then exit")
    parser.add_argument("--dry-run", action="store_true", help="Print collected events without sending to API")

    args = parser.parse_args()
    run_agent_loop(args)


if __name__ == "__main__":
    main()
