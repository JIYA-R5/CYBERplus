"""
SentinelAI - Wireshark / TShark PCAP & PCAPNG Ingestion and Bidirectional Flow Engine
Extracts packet metadata, protocol fields, TCP flags, bidirectional flow records,
and inter-arrival-time statistics using TShark subprocess with pure-Python fallback.
"""

import os
import sys
import time
import struct
import socket
import shutil
import subprocess
import threading
import uuid
import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Generator


# PCAP and PCAPNG Magic Signatures
PCAP_MAGIC_MICRO_BE = b'\xa1\xb2\xc3\xd4'  # Standard microsecond big-endian
PCAP_MAGIC_MICRO_LE = b'\xd4\xc3\xb2\xa1'  # Standard microsecond little-endian
PCAP_MAGIC_NANO_BE  = b'\xa1\xb2\x3c\x4d'  # Nanosecond big-endian
PCAP_MAGIC_NANO_LE  = b'\x4d\x3c\xb2\xa1'  # Nanosecond little-endian
PCAPNG_MAGIC        = b'\x0a\x0d\x0d\x0a'  # PCAPNG Section Header Block magic (\n\r\r\n)

MAX_PCAP_FILE_SIZE = int(os.environ.get("MAX_PCAP_FILE_SIZE_BYTES", str(100 * 1024 * 1024)))  # 100 MB default
TSHARK_TIMEOUT_SECONDS = int(os.environ.get("TSHARK_TIMEOUT_SECONDS", "120"))


@dataclass
class PacketRecord:
    """Raw packet metadata extracted from capture."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str       # TCP, UDP, ICMP, ICMPV6, OTHER
    ip_version: int     # 4 or 6
    packet_length: int  # Frame length in bytes
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    raw_flags: int = 0


@dataclass
class FlowRecord:
    """
    Bidirectional network flow record aggregating forward and backward packet transmissions.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    ip_version: int
    start_time: float
    end_time: float
    duration: float
    forward_packets: int
    backward_packets: int
    total_packets: int
    forward_bytes: int
    backward_bytes: int
    total_bytes: int
    mean_packet_length: float
    std_packet_length: float
    min_packet_length: int
    max_packet_length: int
    tcp_flags_seen: Dict[str, int]
    flow_iat_mean: float
    flow_iat_std: float
    flow_iat_min: float
    flow_iat_max: float
    fwd_iat_mean: float
    bwd_iat_mean: float
    packets_per_sec: float
    bytes_per_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PCAPValidationError(Exception):
    """Raised when uploaded capture file fails validation."""
    pass


class PCAPValidator:
    """Validates capture file format, magic bytes, and size limits."""

    @staticmethod
    def validate_file(file_path: str, max_size_bytes: int = MAX_PCAP_FILE_SIZE) -> Tuple[bool, str, str]:
        """
        Validates capture file header and size.
        Returns:
            (is_valid: bool, file_format: str ['pcap', 'pcapng'], message: str)
        """
        if not os.path.isfile(file_path):
            raise PCAPValidationError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise PCAPValidationError("File is empty (0 bytes).")
        if file_size > max_size_bytes:
            raise PCAPValidationError(
                f"File size ({file_size / (1024*1024):.2f} MB) exceeds allowed limit of "
                f"{max_size_bytes / (1024*1024):.2f} MB."
            )

        with open(file_path, "rb") as f:
            header = f.read(4)

        if len(header) < 4:
            raise PCAPValidationError("File too short to contain a valid capture header.")

        if header in (PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_BE, PCAP_MAGIC_NANO_LE):
            return True, "pcap", f"Valid PCAP capture ({file_size:,} bytes)"
        elif header == PCAPNG_MAGIC:
            return True, "pcapng", f"Valid PCAPNG capture ({file_size:,} bytes)"
        else:
            raise PCAPValidationError(
                f"Unsupported file signature: {header.hex()}. Only standard .pcap and .pcapng files are supported."
            )


class NativePCAPReader:
    """
    Pure-Python binary reader for both PCAP and PCAPNG files.
    Decodes Ethernet, SLL (Linux Cooked), IPv4, IPv6, TCP, UDP, and ICMP frames
    without requiring Wireshark/tshark binaries to be present.
    """

    @staticmethod
    def parse_pcap(file_path: str) -> Generator[PacketRecord, None, None]:
        """Parse classic .pcap file (microsecond or nanosecond)."""
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic in (PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_NANO_BE):
                endian = ">"
                is_nano = (magic == PCAP_MAGIC_NANO_BE)
            elif magic in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
                endian = "<"
                is_nano = (magic == PCAP_MAGIC_NANO_LE)
            else:
                return

            # Read 20-byte global header: version_major (2), version_minor (2), thiszone (4),
            # sigfigs (4), snaplen (4), network (4)
            global_hdr = f.read(20)
            if len(global_hdr) < 20:
                return
            version_major, version_minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", global_hdr)

            # Record Header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
            hdr_size = 16
            while True:
                rec_hdr = f.read(hdr_size)
                if len(rec_hdr) < hdr_size:
                    break
                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec_hdr)
                if is_nano:
                    timestamp = ts_sec + (ts_frac / 1e9)
                else:
                    timestamp = ts_sec + (ts_frac / 1e6)

                packet_bytes = f.read(incl_len)
                if len(packet_bytes) < incl_len:
                    break

                pkt = NativePCAPReader._decode_frame(packet_bytes, linktype, timestamp, orig_len)
                if pkt:
                    yield pkt

    @staticmethod
    def parse_pcapng(file_path: str) -> Generator[PacketRecord, None, None]:
        """Parse modern .pcapng file (Enhanced Packet Blocks & Simple Packet Blocks)."""
        with open(file_path, "rb") as f:
            endian = "<"
            ts_resolutions = {}  # interface_id -> resolution power of 10 (default 1e6)
            current_iface_linktype = 1  # default Ethernet

            while True:
                block_hdr = f.read(8)
                if len(block_hdr) < 8:
                    break
                block_type, block_total_len = struct.unpack(endian + "II", block_hdr)

                # Check Section Header Block (SHB = 0x0A0D0D0A) to determine endianness
                if block_type == 0x0A0D0D0A:
                    body = f.read(block_total_len - 8)
                    if len(body) >= 4:
                        byte_order_magic = body[:4]
                        if byte_order_magic == b"\x1a\x2b\x3c\x4d":
                            endian = ">"
                        else:
                            endian = "<"
                    continue

                # Interface Description Block (IDB = 0x00000001)
                elif block_type == 0x00000001:
                    body = f.read(block_total_len - 8)
                    if len(body) >= 8:
                        link_type, _ = struct.unpack(endian + "HH", body[:4])
                        iface_id = len(ts_resolutions)
                        ts_resolutions[iface_id] = 1e6  # standard 1 microsecond
                        current_iface_linktype = link_type
                    continue

                # Enhanced Packet Block (EPB = 0x00000006)
                elif block_type == 0x00000006:
                    body = f.read(block_total_len - 8)
                    if len(body) < 20:
                        continue
                    iface_id, ts_high, ts_low, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
                    res = ts_resolutions.get(iface_id, 1e6)
                    raw_ts = (ts_high << 32) | ts_low
                    timestamp = raw_ts / res

                    packet_bytes = body[20:20 + caplen]
                    pkt = NativePCAPReader._decode_frame(packet_bytes, current_iface_linktype, timestamp, origlen)
                    if pkt:
                        yield pkt

                # Simple Packet Block (SPB = 0x00000003)
                elif block_type == 0x00000003:
                    body = f.read(block_total_len - 8)
                    if len(body) >= 4:
                        origlen, = struct.unpack(endian + "I", body[:4])
                        packet_bytes = body[4:block_total_len - 12]
                        pkt = NativePCAPReader._decode_frame(packet_bytes, current_iface_linktype, time.time(), origlen)
                        if pkt:
                            yield pkt
                else:
                    # Skip other blocks safely
                    skip = block_total_len - 8
                    if skip > 0:
                        f.seek(skip, 1)

    @staticmethod
    def _decode_frame(data: bytes, linktype: int, timestamp: float, orig_len: int) -> Optional[PacketRecord]:
        """Decode link layer, IP layer (v4/v6), and transport layer (TCP/UDP/ICMP)."""
        try:
            ip_data = b""
            ip_version = 4

            # Link Type 1 = Ethernet IEEE 802.3
            if linktype == 1:
                if len(data) < 14:
                    return None
                eth_type = struct.unpack(">H", data[12:14])[0]
                # VLAN tag 0x8100
                offset = 14
                if eth_type == 0x8100 and len(data) >= 18:
                    eth_type = struct.unpack(">H", data[16:18])[0]
                    offset = 18

                if eth_type == 0x0800:   # IPv4
                    ip_data = data[offset:]
                    ip_version = 4
                elif eth_type == 0x86DD: # IPv6
                    ip_data = data[offset:]
                    ip_version = 6
                else:
                    return None

            # Link Type 113 = Linux Cooked Capture (SLL)
            elif linktype == 113:
                if len(data) < 16:
                    return None
                proto = struct.unpack(">H", data[14:16])[0]
                if proto == 0x0800:
                    ip_data = data[16:]
                    ip_version = 4
                elif proto == 0x86DD:
                    ip_data = data[16:]
                    ip_version = 6
                else:
                    return None

            # Link Type 101 / 12 = Raw IP
            elif linktype in (101, 12):
                if not data:
                    return None
                version_nibble = (data[0] >> 4) & 0x0F
                ip_data = data
                ip_version = 4 if version_nibble == 4 else 6
            else:
                return None

            # Decode IPv4
            if ip_version == 4:
                if len(ip_data) < 20:
                    return None
                ihl = (ip_data[0] & 0x0F) * 4
                proto_num = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
                transport_data = ip_data[ihl:]

            # Decode IPv6
            else:
                if len(ip_data) < 40:
                    return None
                proto_num = ip_data[6]
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
                transport_data = ip_data[40:]

            src_port = 0
            dst_port = 0
            flags_dict = {}
            raw_flags = 0

            # TCP
            if proto_num == 6:
                protocol = "TCP"
                if len(transport_data) >= 14:
                    src_port, dst_port = struct.unpack(">HH", transport_data[:4])
                    raw_flags = transport_data[13]
                    flags_dict = {
                        "FIN": bool(raw_flags & 0x01),
                        "SYN": bool(raw_flags & 0x02),
                        "RST": bool(raw_flags & 0x04),
                        "PSH": bool(raw_flags & 0x08),
                        "ACK": bool(raw_flags & 0x10),
                        "URG": bool(raw_flags & 0x20),
                    }
            # UDP
            elif proto_num == 17:
                protocol = "UDP"
                if len(transport_data) >= 4:
                    src_port, dst_port = struct.unpack(">HH", transport_data[:4])
            # ICMP
            elif proto_num == 1:
                protocol = "ICMP"
            elif proto_num == 58:
                protocol = "ICMPV6"
            else:
                protocol = f"PROTO_{proto_num}"

            return PacketRecord(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                ip_version=ip_version,
                packet_length=orig_len or len(data),
                tcp_flags=flags_dict,
                raw_flags=raw_flags
            )
        except Exception:
            return None


class TSharkSubprocessParser:
    """
    Subprocess-isolated TShark packet processor.
    Strictly controls argument arrays to prevent command injection and shell interpolation.
    """

    @staticmethod
    def get_tshark_path() -> Optional[str]:
        """Locates tshark executable across Linux and Windows paths."""
        custom_path = os.environ.get("TSHARK_PATH")
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        which_path = shutil.which("tshark")
        if which_path:
            return which_path

        # Common Windows installations
        win_candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for c in win_candidates:
            if os.path.isfile(c):
                return c

        # Common Linux installations
        linux_candidates = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
        for c in linux_candidates:
            if os.path.isfile(c):
                return c

        return None

    @staticmethod
    def is_available() -> bool:
        return TSharkSubprocessParser.get_tshark_path() is not None

    @staticmethod
    def parse_packets(file_path: str, max_packets: Optional[int] = None) -> Generator[PacketRecord, None, None]:
        """
        Executes TShark safely with controlled arguments.
        Streams decoded packet records.
        """
        tshark_bin = TSharkSubprocessParser.get_tshark_path()
        if not tshark_bin:
            raise RuntimeError("TShark binary not available on system.")

        # Controlled arguments without shell interpolation
        args = [
            tshark_bin,
            "-r", file_path,
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

        if max_packets:
            args.extend(["-c", str(max_packets)])

        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False
        )

        try:
            for line in proc.stdout:
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
                    if proto_num == 6:
                        protocol = "TCP"
                    elif proto_num == 17:
                        protocol = "UDP"
                    elif proto_num in (1, 58):
                        protocol = "ICMP"
                    else:
                        protocol = f"PROTO_{proto_num}"

                    flags_dict = {}
                    raw_flags = 0
                    if len(parts) > 12 and parts[12]:
                        raw_flags_str = parts[12]
                        try:
                            raw_flags = int(raw_flags_str, 16) if raw_flags_str.startswith("0x") else int(raw_flags_str)
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

                    yield PacketRecord(
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
                except Exception:
                    continue
            proc.wait(timeout=TSHARK_TIMEOUT_SECONDS)
        except Exception as e:
            proc.kill()
            raise RuntimeError(f"TShark processing error: {str(e)}")


class BidirectionalFlowAggregator:
    """
    Groups individual packet events into bidirectional flow records.
    Calculates forward/backward packet counts, byte volumes, duration,
    TCP flag statistics, and inter-arrival time (IAT) metrics.
    """

    def __init__(self, flow_timeout_seconds: float = 120.0):
        self.flow_timeout_seconds = flow_timeout_seconds
        # Key: (ip_low, port_low, ip_high, port_high, proto)
        self.active_flows: Dict[Tuple, Dict[str, Any]] = {}

    def _get_flow_key(self, pkt: PacketRecord) -> Tuple[Tuple, bool]:
        """
        Returns canonical flow key and boolean indicating if pkt is forward direction.
        Forward direction: initiator host (client) -> target host (server).
        """
        ip1, p1 = pkt.src_ip, pkt.src_port
        ip2, p2 = pkt.dst_ip, pkt.dst_port
        proto = pkt.protocol

        # Canonical ordering
        if (ip1, p1) <= (ip2, p2):
            canonical_key = (ip1, p1, ip2, p2, proto)
            is_forward = True
        else:
            canonical_key = (ip2, p2, ip1, p1, proto)
            is_forward = False

        return canonical_key, is_forward

    def add_packet(self, pkt: PacketRecord):
        """Add packet to active flow state."""
        key, is_forward = self._get_flow_key(pkt)
        now = pkt.timestamp

        if key not in self.active_flows:
            self.active_flows[key] = {
                "flow_id": f"FLOW-{uuid.uuid4().hex[:10].upper()}",
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": pkt.protocol,
                "ip_version": pkt.ip_version,
                "start_time": now,
                "last_time": now,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "packet_lengths": [],
                "all_timestamps": [],
                "fwd_timestamps": [],
                "bwd_timestamps": [],
                "tcp_flags": {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0}
            }

        flow = self.active_flows[key]
        flow["last_time"] = max(flow["last_time"], now)
        flow["packet_lengths"].append(pkt.packet_length)
        flow["all_timestamps"].append(now)

        if pkt.src_ip == flow["src_ip"] and pkt.src_port == flow["src_port"]:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt.packet_length
            flow["fwd_timestamps"].append(now)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt.packet_length
            flow["bwd_timestamps"].append(now)

        for flag_name, is_set in pkt.tcp_flags.items():
            if is_set and flag_name in flow["tcp_flags"]:
                flow["tcp_flags"][flag_name] += 1

    def get_flows(self) -> List[FlowRecord]:
        """Alias for flush() to retrieve compiled flow records."""
        return self.flush()

    def flush(self) -> List[FlowRecord]:
        """Finalize and compile all aggregated flow records."""
        import numpy as np

        records = []
        for flow in self.active_flows.values():
            duration = max(0.0001, flow["last_time"] - flow["start_time"])
            tot_pkts = flow["fwd_packets"] + flow["bwd_packets"]
            tot_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

            lens = flow["packet_lengths"]
            mean_len = float(np.mean(lens)) if lens else 0.0
            std_len = float(np.std(lens)) if len(lens) > 1 else 0.0
            min_len = int(np.min(lens)) if lens else 0
            max_len = int(np.max(lens)) if lens else 0

            # Flow IAT calculations
            ts_all = sorted(flow["all_timestamps"])
            if len(ts_all) > 1:
                iats = np.diff(ts_all)
                flow_iat_mean = float(np.mean(iats))
                flow_iat_std = float(np.std(iats))
                flow_iat_min = float(np.min(iats))
                flow_iat_max = float(np.max(iats))
            else:
                flow_iat_mean = 0.0
                flow_iat_std = 0.0
                flow_iat_min = 0.0
                flow_iat_max = 0.0

            # Forward IAT
            ts_fwd = sorted(flow["fwd_timestamps"])
            fwd_iat_mean = float(np.mean(np.diff(ts_fwd))) if len(ts_fwd) > 1 else 0.0

            # Backward IAT
            ts_bwd = sorted(flow["bwd_timestamps"])
            bwd_iat_mean = float(np.mean(np.diff(ts_bwd))) if len(ts_bwd) > 1 else 0.0

            records.append(FlowRecord(
                flow_id=flow["flow_id"],
                src_ip=flow["src_ip"],
                dst_ip=flow["dst_ip"],
                src_port=flow["src_port"],
                dst_port=flow["dst_port"],
                protocol=flow["protocol"],
                ip_version=flow["ip_version"],
                start_time=flow["start_time"],
                end_time=flow["last_time"],
                duration=round(duration, 4),
                forward_packets=flow["fwd_packets"],
                backward_packets=flow["bwd_packets"],
                total_packets=tot_pkts,
                forward_bytes=flow["fwd_bytes"],
                backward_bytes=flow["bwd_bytes"],
                total_bytes=tot_bytes,
                mean_packet_length=round(mean_len, 2),
                std_packet_length=round(std_len, 2),
                min_packet_length=min_len,
                max_packet_length=max_len,
                tcp_flags_seen=flow["tcp_flags"],
                flow_iat_mean=round(flow_iat_mean, 6),
                flow_iat_std=round(flow_iat_std, 6),
                flow_iat_min=round(flow_iat_min, 6),
                flow_iat_max=round(flow_iat_max, 6),
                fwd_iat_mean=round(fwd_iat_mean, 6),
                bwd_iat_mean=round(bwd_iat_mean, 6),
                packets_per_sec=round(tot_pkts / duration, 2),
                bytes_per_sec=round(tot_bytes / duration, 2),
            ))

        self.active_flows.clear()
        return records


class PCAPJobManager:
    """
    Manages asynchronous, resource-limited background capture processing tasks.
    Maintains thread-safe status updates, progress percentages, and flow storage.
    """

    def __init__(self):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create_job(self, filename: str, file_size: int, saved_path: str) -> str:
        job_id = f"PCAP-{uuid.uuid4().hex[:8].upper()}"
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "filename": filename,
                "file_size": file_size,
                "saved_path": saved_path,
                "status": "QUEUED",
                "progress_percent": 0,
                "packet_count": 0,
                "flow_count": 0,
                "engine_used": "Pending",
                "started_at": datetime.datetime.now().isoformat(),
                "completed_at": None,
                "error_message": None,
                "flows": []
            }
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return dict(job)

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {k: v for k, v in j.items() if k != "flows"}
                for j in reversed(list(self._jobs.values()))
            ]

    def run_job_async(self, job_id: str):
        """Spawns background daemon thread to process capture file."""
        t = threading.Thread(target=self._process_worker, args=(job_id,), daemon=True)
        t.start()

    def _process_worker(self, job_id: str):
        with self._lock:
            if job_id not in self._jobs:
                return
            job = self._jobs[job_id]
            job["status"] = "PROCESSING"
            job["progress_percent"] = 5
            file_path = job["saved_path"]

        aggregator = BidirectionalFlowAggregator()
        packet_count = 0
        engine_used = "NativePCAPReader"

        try:
            # 1. Validation
            is_valid, fmt, msg = PCAPValidator.validate_file(file_path)

            # 2. Select engine: TShark if available, otherwise pure-Python native reader
            packets_gen = None
            if TSharkSubprocessParser.is_available():
                try:
                    packets_gen = TSharkSubprocessParser.parse_packets(file_path)
                    engine_used = "TShark Subprocess"
                except Exception:
                    packets_gen = None

            if packets_gen is None:
                if fmt == "pcap":
                    packets_gen = NativePCAPReader.parse_pcap(file_path)
                    engine_used = "Native PCAP Binary Parser"
                else:
                    packets_gen = NativePCAPReader.parse_pcapng(file_path)
                    engine_used = "Native PCAPNG Binary Parser"

            # 3. Stream & Aggregate
            for pkt in packets_gen:
                aggregator.add_packet(pkt)
                packet_count += 1
                if packet_count % 500 == 0:
                    with self._lock:
                        job["packet_count"] = packet_count
                        job["progress_percent"] = min(90, 5 + int(packet_count / 100))

            flows = aggregator.flush()
            flows_dicts = [f.to_dict() for f in flows]

            with self._lock:
                job["status"] = "COMPLETED"
                job["progress_percent"] = 100
                job["packet_count"] = packet_count
                job["flow_count"] = len(flows_dicts)
                job["engine_used"] = engine_used
                job["completed_at"] = datetime.datetime.now().isoformat()
                job["flows"] = flows_dicts

        except Exception as e:
            with self._lock:
                job["status"] = "FAILED"
                job["error_message"] = str(e)
                job["completed_at"] = datetime.datetime.now().isoformat()


_global_job_manager = None

def get_job_manager() -> PCAPJobManager:
    global _global_job_manager
    if _global_job_manager is None:
        _global_job_manager = PCAPJobManager()
    return _global_job_manager
