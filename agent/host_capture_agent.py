"""
SentinelAI - Supervised Host TShark Capture Agent
Runs natively on the host operating system (Windows or Linux) outside Docker.
Captures live packets using TShark on a designated interface, aggregates
bidirectional flows, and transmits authenticated flow batches to the SentinelAI API.

Do not run inside Docker Desktop container if you need to capture the host's physical network adapter.
"""

import os
import sys
import time
import json
import socket
import argparse
import datetime
import subprocess
import threading
from typing import Dict, Any, List, Optional
import urllib.request
import urllib.error

# Ensure root in sys.path if run directly
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from pcap_engine import TSharkSubprocessParser, BidirectionalFlowAggregator, PacketRecord


class HostTSharkCaptureAgent:
    """
    Supervised host agent capturing live network traffic via TShark.
    Buffers packets into bidirectional flow records and periodically posts batches to SentinelAI API.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        agent_secret: Optional[str] = None,
        interface: Optional[str] = None,
        batch_interval_seconds: float = 5.0,
        bpf_filter: Optional[str] = None,
        host_id: Optional[str] = None
    ):
        self.api_url = api_url.rstrip("/")
        self.agent_secret = agent_secret or os.environ.get("SENTINEL_AGENT_SECRET", "")
        self.interface = interface
        self.batch_interval = batch_interval_seconds
        self.bpf_filter = bpf_filter
        self.host_id = host_id or socket.gethostname() or "host-capture-agent"

        self.running = False
        self.process: Optional[subprocess.Popen] = None
        self.aggregator = BidirectionalFlowAggregator()
        self.total_packets_captured = 0
        self.total_flows_transmitted = 0
        self.last_error = None

    def list_interfaces(self) -> List[str]:
        """Lists available network capture interfaces using tshark -D."""
        tshark_bin = TSharkSubprocessParser.get_tshark_path()
        if not tshark_bin:
            return ["No tshark binary found on host path."]
        try:
            out = subprocess.check_output([tshark_bin, "-D"], text=True, stderr=subprocess.DEVNULL)
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception as e:
            return [f"Error querying interfaces: {str(e)}"]

    def start_capture(self, max_duration_seconds: Optional[int] = None):
        """Starts live capture subprocess and flow dispatcher loop."""
        tshark_bin = TSharkSubprocessParser.get_tshark_path()
        if not tshark_bin:
            print("[HostAgent] ERROR: TShark is not installed on this host.")
            print("[HostAgent] Please install Wireshark/TShark with Npcap (Windows) or libpcap (Linux).")
            return

        args = [
            tshark_bin,
            "-l",  # Flush standard output after each packet
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-E", "header=n",
            "-E", "separator=\t",
            "-E", "occurrence=f"
        ]

        if self.interface:
            args.extend(["-i", self.interface])
        if self.bpf_filter:
            args.extend(["-f", self.bpf_filter])

        print(f"[HostAgent] Starting live capture on interface: {self.interface or 'default'}")
        print(f"[HostAgent] Transmitting to SentinelAI API at: {self.api_url}")

        self.running = True
        start_time = time.time()

        # Thread for flushing flows periodically
        flush_thread = threading.Thread(target=self._periodic_flush_loop, daemon=True)
        flush_thread.start()

        try:
            self.process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            for line in self.process.stdout:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 10:
                    continue

                try:
                    ts_epoch = float(parts[0]) if parts[0] else time.time()
                    src_ip = parts[1] or parts[2] or "0.0.0.0"
                    dst_ip = parts[3] or parts[4] or "0.0.0.0"
                    proto_val = parts[5] or parts[6] or "6"
                    src_port = int(parts[7] or parts[8] or 0)
                    dst_port = int(parts[9] or parts[10] or 0)
                    frame_len = int(parts[11]) if len(parts) > 11 and parts[11] else 60

                    proto_num = int(proto_val) if proto_val.isdigit() else 6
                    protocol = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num in (1, 58) else f"PROTO_{proto_num}"))

                    flags_dict = {}
                    raw_flags = 0
                    if len(parts) > 12 and parts[12]:
                        try:
                            raw_flags = int(parts[12], 16) if parts[12].startswith("0x") else int(parts[12])
                            flags_dict = {
                                "FIN": bool(raw_flags & 0x01),
                                "SYN": bool(raw_flags & 0x02),
                                "RST": bool(raw_flags & 0x04),
                                "PSH": bool(raw_flags & 0x08),
                                "ACK": bool(raw_flags & 0x10),
                                "URG": bool(raw_flags & 0x20),
                            }
                        except ValueError:
                            pass

                    pkt = PacketRecord(
                        timestamp=ts_epoch,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        ip_version=6 if ":" in src_ip else 4,
                        packet_length=frame_len,
                        tcp_flags=flags_dict,
                        raw_flags=raw_flags
                    )

                    self.aggregator.add_packet(pkt)
                    self.total_packets_captured += 1

                except Exception:
                    continue

                if max_duration_seconds and (time.time() - start_time) >= max_duration_seconds:
                    print(f"[HostAgent] Capture duration reached ({max_duration_seconds}s). Stopping.")
                    break

        except KeyboardInterrupt:
            print("\n[HostAgent] Received stop signal.")
        finally:
            self.stop()

    def _periodic_flush_loop(self):
        """Periodically flushes completed flows and transmits to SentinelAI API."""
        while self.running:
            time.sleep(self.batch_interval)
            flows = self.aggregator.flush()
            if flows:
                self._transmit_flows(flows)

    def _transmit_flows(self, flows: List[Any]):
        """HTTP POST batch of flows to SentinelAI API."""
        endpoint = f"{self.api_url}/api/pcap/live-stream"
        payload = {
            "host_id": self.host_id,
            "agent_type": "host_tshark_capture",
            "timestamp": datetime.datetime.now().isoformat(),
            "flows": [f.to_dict() for f in flows]
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Agent-Secret": self.agent_secret or ""
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    self.total_flows_transmitted += len(flows)
                    print(f"[HostAgent] Transmitted {len(flows)} flows to SentinelAI (Total: {self.total_flows_transmitted})")
        except Exception as e:
            self.last_error = str(e)
            print(f"[HostAgent] Transmission notice: {str(e)}")

    def stop(self):
        """Stops capture and terminates child process."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        # Final flush
        flows = self.aggregator.flush()
        if flows:
            self._transmit_flows(flows)
        print(f"[HostAgent] Stopped. Captured {self.total_packets_captured} packets, sent {self.total_flows_transmitted} flows.")


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Supervised Host TShark Capture Agent")
    parser.add_argument("--api-url", default=os.environ.get("SENTINEL_API_URL", "http://localhost:8000"), help="SentinelAI API URL")
    parser.add_argument("--interface", "-i", default=None, help="Capture interface index or name")
    parser.add_argument("--agent-secret", default=os.environ.get("SENTINEL_AGENT_SECRET", ""), help="Authentication secret")
    parser.add_argument("--interval", type=float, default=5.0, help="Transmission batch interval in seconds")
    parser.add_argument("--bpf", default=None, help="BPF capture filter expression (e.g. 'tcp port 80 or tcp port 443')")
    parser.add_argument("--duration", type=int, default=None, help="Max capture duration in seconds")
    parser.add_argument("--list-interfaces", action="store_true", help="List available capture interfaces and exit")

    args = parser.parse_args()

    agent = HostTSharkCaptureAgent(
        api_url=args.api_url,
        agent_secret=args.agent_secret,
        interface=args.interface,
        batch_interval_seconds=args.interval,
        bpf_filter=args.bpf
    )

    if args.list_interfaces:
        print("Available Capture Interfaces:")
        for iface in agent.list_interfaces():
            print(f"  {iface}")
        sys.exit(0)

    agent.start_capture(max_duration_seconds=args.duration)


if __name__ == "__main__":
    main()
