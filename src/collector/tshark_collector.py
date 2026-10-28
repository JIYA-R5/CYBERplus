"""
SentinelAI - Supervised Windows TShark Live Network Collector & PCAP Replayer
Captures live packet metadata using TShark/Npcap outside Docker on the Windows host.
Aggregates bidirectional flows and transmits authenticated batches to SentinelAI API.
Provides robust offline PCAP replay mode distinguishable from live traffic.
"""

import os
import sys
import time
import json
import uuid
import signal
import socket
import datetime
import argparse
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple
import urllib.request
import urllib.error

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from pcap_engine import TSharkSubprocessParser, BidirectionalFlowAggregator, PacketRecord, FlowRecord


class TSharkCollector:
    """
    Supervised host-side network collector wrapping TShark/Npcap.
    """

    DEFAULT_WIN_PATHS = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        agent_secret: Optional[str] = None,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        batch_interval: float = 3.0,
        batch_size: int = 25,
        host_id: Optional[str] = None,
        pcap_out: Optional[str] = None,
        pcap_retention_hours: int = 24,
        health_file: str = "reports/collector_health.json",
        max_restarts: int = 5
    ):
        self.api_url = api_url.rstrip("/")
        self.agent_secret = agent_secret or os.environ.get("SENTINEL_AGENT_SECRET", "")
        self.interface = interface or os.environ.get("SENTINEL_CAPTURE_INTERFACE")
        self.bpf_filter = bpf_filter or os.environ.get("SENTINEL_BPF_FILTER")
        self.batch_interval = batch_interval
        self.batch_size = batch_size
        self.host_id = host_id or socket.gethostname() or "windows-tshark-collector"
        self.pcap_out = pcap_out
        self.pcap_retention_hours = pcap_retention_hours
        self.health_file = health_file
        self.max_restarts = max_restarts

        self.running = False
        self.is_replay = False
        self.process: Optional[subprocess.Popen] = None
        self.aggregator = BidirectionalFlowAggregator()
        self.lock = threading.Lock()

        # Telemetry & Health counters
        self.packets_captured = 0
        self.flows_transmitted = 0
        self.parsing_errors = 0
        self.transmission_errors = 0
        self.restart_count = 0
        self.last_event_time: Optional[str] = None
        self.last_error: Optional[str] = None
        self.start_timestamp = time.time()

        self.tshark_path = self.locate_tshark()

    @classmethod
    def locate_tshark(cls) -> Optional[str]:
        """Locates tshark executable across PATH, common directories, or environment."""
        env_path = os.environ.get("TSHARK_PATH")
        if env_path and os.path.isfile(env_path):
            return env_path

        # Check system PATH
        which_path = shutil_which("tshark")
        if which_path and os.path.isfile(which_path):
            return which_path

        # Check Windows common default installation locations
        for p in cls.DEFAULT_WIN_PATHS:
            if os.path.isfile(p):
                return p

        # Check Unix common paths
        for p in ["/usr/bin/tshark", "/usr/local/bin/tshark"]:
            if os.path.isfile(p):
                return p

        return None

    @classmethod
    def list_interfaces(cls) -> List[str]:
        """Lists available network capture interfaces using tshark -D."""
        tshark_bin = cls.locate_tshark()
        if not tshark_bin:
            return ["TShark executable not found. Please install Wireshark with Npcap."]

        try:
            out = subprocess.check_output([tshark_bin, "-D"], text=True, stderr=subprocess.DEVNULL)
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception as e:
            return [f"Error querying interfaces via TShark: {str(e)}"]

    def write_health(self):
        """Dumps current collector health status to file."""
        os.makedirs(os.path.dirname(os.path.abspath(self.health_file)), exist_ok=True)
        health_data = {
            "status": "RUNNING" if self.running else "STOPPED",
            "collector_mode": "PCAP_REPLAY" if self.is_replay else "LIVE_CAPTURE",
            "host_id": self.host_id,
            "interface": self.interface or "default",
            "bpf_filter": self.bpf_filter,
            "tshark_path": self.tshark_path,
            "tshark_version": "4.6.x (Npcap)",
            "uptime_seconds": round(time.time() - self.start_timestamp, 1),
            "packets_captured": self.packets_captured,
            "flows_transmitted": self.flows_transmitted,
            "parsing_errors": self.parsing_errors,
            "transmission_errors": self.transmission_errors,
            "restart_count": self.restart_count,
            "last_event_time": self.last_event_time,
            "last_error": self.last_error,
            "timestamp": datetime.datetime.now().isoformat()
        }
        try:
            with open(self.health_file, "w", encoding="utf-8") as f:
                json.dump(health_data, f, indent=2)
        except Exception:
            pass

    def start_live_capture(self, max_duration_seconds: Optional[int] = None):
        """
        Executes supervised live packet capture on configured interface.
        Handles recoverable restarts and periodic flow batch flushing.
        """
        self.is_replay = False
        if not self.tshark_path:
            raise RuntimeError(
                "TShark not found. Please install Wireshark with Npcap or configure TSHARK_PATH."
            )

        print("=" * 80)
        print("SENTINELAI TSHARK LIVE NETWORK COLLECTOR (WINDOWS HOST)")
        print("=" * 80)
        print(f"TShark Binary : {self.tshark_path}")
        print(f"Interface     : {self.interface or 'Default active interface'}")
        print(f"BPF Filter    : {self.bpf_filter or 'None (All IP Traffic)'}")
        print(f"Destination   : {self.api_url}/api/pcap/live-stream")
        print(f"Batch Interval: {self.batch_interval}s (Max batch size: {self.batch_size})")
        print("-" * 80)

        self.running = True
        self.start_timestamp = time.time()

        # Background thread for periodic flow flushing
        flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        flush_thread.start()

        capture_start = time.time()
        while self.running and self.restart_count <= self.max_restarts:
            try:
                self._run_capture_process(max_duration_seconds, capture_start)
                break
            except Exception as e:
                self.last_error = str(e)
                self.restart_count += 1
                print(f"[Collector] Capture exception: {e}")
                if self.running and self.restart_count <= self.max_restarts:
                    print(f"[Collector] Backing off 2s before restart ({self.restart_count}/{self.max_restarts})...")
                    time.sleep(2.0)
                else:
                    break

        self.stop()

    def _run_capture_process(self, max_duration_seconds: Optional[int], overall_start: float):
        """Spawns TShark subprocess with line buffering and parses packet stream."""
        cmd = [
            self.tshark_path,
            "-l",  # Flush standard output per line
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
            cmd.extend(["-i", str(self.interface)])
        if self.bpf_filter:
            cmd.extend(["-f", str(self.bpf_filter)])

        # Optional raw capture recording for authorized forensic review
        if self.pcap_out:
            os.makedirs(os.path.dirname(os.path.abspath(self.pcap_out)), exist_ok=True)
            cmd.extend(["-w", self.pcap_out])

        print(f"[Collector] Spawning TShark PID... (Command: {' '.join(cmd[:6])}...)")
        self.process = subprocess.Popen(
            cmd,
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

            parsed_pkt = self._parse_tshark_line(line)
            if parsed_pkt:
                with self.lock:
                    self.aggregator.add_packet(parsed_pkt)
                    self.packets_captured += 1
                    self.last_event_time = datetime.datetime.now().isoformat()
            else:
                self.parsing_errors += 1

            if max_duration_seconds and (time.time() - overall_start) >= max_duration_seconds:
                print(f"[Collector] Specified duration ({max_duration_seconds}s) elapsed.")
                self.running = False
                break

        # Check process exit code
        ret = self.process.poll()
        if ret not in (0, None) and self.running:
            stderr_out = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"TShark terminated with code {ret}: {stderr_out[:200]}")

    def _parse_tshark_line(self, line: str) -> Optional[PacketRecord]:
        """Converts tab-delimited TShark line into PacketRecord."""
        parts = line.split("\t")
        if len(parts) < 10:
            return None

        try:
            ts = float(parts[0]) if parts[0] else time.time()
            src_ip = parts[1] or parts[2] or "0.0.0.0"
            dst_ip = parts[3] or parts[4] or "0.0.0.0"
            proto_val = parts[5] or parts[6] or "6"
            src_p = int(parts[7] or parts[8] or 0)
            dst_p = int(parts[9] or parts[10] or 0)
            frame_len = int(parts[11]) if len(parts) > 11 and parts[11] else 60

            proto_num = int(proto_val) if proto_val.isdigit() else 6
            if proto_num == 6:
                proto_str = "TCP"
            elif proto_num == 17:
                proto_str = "UDP"
            elif proto_num in (1, 58):
                proto_str = "ICMP"
            else:
                proto_str = f"PROTO_{proto_num}"

            flags = {}
            raw_flags = 0
            if len(parts) > 12 and parts[12]:
                f_str = parts[12]
                raw_flags = int(f_str, 16) if f_str.startswith("0x") else int(f_str)
                flags = {
                    "FIN": bool(raw_flags & 0x01),
                    "SYN": bool(raw_flags & 0x02),
                    "RST": bool(raw_flags & 0x04),
                    "PSH": bool(raw_flags & 0x08),
                    "ACK": bool(raw_flags & 0x10),
                    "URG": bool(raw_flags & 0x20),
                }

            return PacketRecord(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_p,
                dst_port=dst_p,
                protocol=proto_str,
                ip_version=6 if ":" in src_ip else 4,
                packet_length=frame_len,
                tcp_flags=flags,
                raw_flags=raw_flags
            )
        except Exception:
            return None

    def _flush_loop(self):
        """Periodically polls aggregator, flushes completed flows, and posts to API."""
        while self.running:
            time.sleep(self.batch_interval)
            flows = []
            with self.lock:
                flows = self.aggregator.flush()

            if flows:
                self._transmit_flow_batch(flows)
            self.write_health()

    def _transmit_flow_batch(self, flows: List[FlowRecord]):
        """Posts a normalized flow batch to SentinelAI ingestion endpoint."""
        endpoint = f"{self.api_url}/api/pcap/live-stream"
        payload_flows = []

        for f in flows:
            d = f.to_dict()
            d["is_replay"] = self.is_replay
            d["source"] = "pcap_replay" if self.is_replay else "tshark_live"
            payload_flows.append(d)

        payload = {
            "host_id": self.host_id,
            "agent_type": "pcap_replay" if self.is_replay else "host_tshark_capture",
            "timestamp": datetime.datetime.now().isoformat(),
            "flows": payload_flows
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
                if resp.status in (200, 201):
                    self.flows_transmitted += len(flows)
                    tag = "[REPLAY]" if self.is_replay else "[LIVE]"
                    print(f"{tag} Transmitted {len(flows)} flows -> SentinelAI (Total: {self.flows_transmitted})")
        except Exception as e:
            self.transmission_errors += 1
            self.last_error = f"Transmission notice: {str(e)}"
            print(f"[Collector] Notice: Unable to post {len(flows)} flows to {endpoint} ({e})")

    def replay_pcap(self, pcap_path: str, max_packets: Optional[int] = None):
        """
        Replays existing PCAP or PCAPNG capture file into the SentinelAI pipeline.
        Tags all resulting flow events with is_replay=True and source='pcap_replay'
        so they are distinctly identifiable in dashboards from live traffic.
        """
        self.is_replay = True
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        print("=" * 80)
        print("SENTINELAI OFFLINE PCAP/PCAPNG REPLAY RUNNER")
        print("=" * 80)
        print(f"Replay File: {pcap_path}")
        print(f"Destination: {self.api_url}/api/pcap/live-stream")
        print("Telemetry Tag: is_replay = True, source = 'pcap_replay'")
        print("-" * 80)

        self.running = True
        self.start_timestamp = time.time()

        # Parse via TSharkSubprocessParser
        try:
            generator = TSharkSubprocessParser.parse_packets(pcap_path, max_packets=max_packets)
        except Exception as e:
            print(f"[Replay] TShark unavailable or failed ({e}). Falling back to Native PCAP Parser.")
            from pcap_engine import NativePCAPReader
            generator = NativePCAPReader.parse_pcap(pcap_path)

        count = 0
        batch_packets = []
        for pkt in generator:
            self.aggregator.add_packet(pkt)
            count += 1
            self.packets_captured += 1
            if count % 200 == 0:
                flows = self.aggregator.flush()
                if flows:
                    self._transmit_flow_batch(flows)
                time.sleep(0.05)

        # Final flush
        flows = self.aggregator.flush()
        if flows:
            self._transmit_flow_batch(flows)

        self.write_health()
        print(f"[Replay Finished] Replayed {count:,} packets, generated {self.flows_transmitted:,} flows.")

    def stop(self):
        """Terminates TShark process and cleanly dispatches remaining buffer."""
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
            self.process = None

        with self.lock:
            remaining_flows = self.aggregator.flush()
        if remaining_flows:
            self._transmit_flow_batch(remaining_flows)

        self.write_health()
        print(f"[Collector Stopped] Captured {self.packets_captured:,} packets | Sent {self.flows_transmitted:,} flows.")


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Supervised TShark Capture & Replay Agent")
    parser.add_argument("--api-url", default=os.environ.get("SENTINEL_API_URL", "http://localhost:8000"), help="SentinelAI API URL")
    parser.add_argument("--interface", "-i", default=None, help="Capture interface index or name (e.g. 4 or Wi-Fi)")
    parser.add_argument("--agent-secret", default=os.environ.get("SENTINEL_AGENT_SECRET", ""), help="Authentication secret")
    parser.add_argument("--interval", type=float, default=3.0, help="Batch transmit interval in seconds")
    parser.add_argument("--batch-size", type=int, default=25, help="Batch size in flows")
    parser.add_argument("--bpf", default=None, help="BPF capture filter (e.g. 'tcp or udp')")
    parser.add_argument("--duration", type=int, default=None, help="Max duration in seconds")
    parser.add_argument("--list-interfaces", action="store_true", help="List all capture interfaces and exit")
    parser.add_argument("--replay-pcap", default=None, help="Path to PCAP/PCAPNG file to replay into pipeline")
    parser.add_argument("--pcap-out", default=None, help="Optional path to write raw PCAP file")

    args = parser.parse_args()

    collector = TSharkCollector(
        api_url=args.api_url,
        agent_secret=args.agent_secret,
        interface=args.interface,
        bpf_filter=args.bpf,
        batch_interval=args.interval,
        batch_size=args.batch_size,
        pcap_out=args.pcap_out
    )

    # Signal handlers for graceful shutdown
    def handle_signal(sig, frame):
        print("\n[Signal] Interrupted. Stopping collector safely...")
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if args.list_interfaces:
        print("Available Capture Interfaces on Host:")
        for iface in collector.list_interfaces():
            print(f"  {iface}")
        sys.exit(0)

    if args.replay_pcap:
        collector.replay_pcap(args.replay_pcap)
    else:
        collector.start_live_capture(max_duration_seconds=args.duration)


if __name__ == "__main__":
    main()
