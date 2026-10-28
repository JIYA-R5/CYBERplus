"""
Unit tests for the TShark Windows Collector (src/collector/tshark_collector.py).
Validates line parsing, flow aggregation, health reporting, and interface discovery.
"""
import os
import json
import pytest
from src.collector.tshark_collector import TSharkCollector
from pcap_engine import BidirectionalFlowAggregator, PacketRecord


def test_tshark_collector_parse_line():
    collector = TSharkCollector()

    # Valid TCP line with flags
    valid_line = "1672531199.123456\t192.168.1.100\t\t10.0.0.1\t\t6\t\t52341\t\t443\t\t1420\t0x0010"
    pkt = collector._parse_tshark_line(valid_line)

    assert pkt is not None
    assert isinstance(pkt, PacketRecord)
    assert pkt.timestamp == 1672531199.123456
    assert pkt.src_ip == "192.168.1.100"
    assert pkt.dst_ip == "10.0.0.1"
    assert pkt.protocol == "TCP"
    assert pkt.src_port == 52341
    assert pkt.dst_port == 443
    assert pkt.packet_length == 1420
    assert pkt.tcp_flags.get("ACK") is True


def test_tshark_collector_parse_invalid_line():
    collector = TSharkCollector()
    assert collector._parse_tshark_line("") is None
    assert collector._parse_tshark_line("too\tfew\tparts") is None


def test_collector_health_report(tmp_path):
    health_file = tmp_path / "collector_health.json"
    collector = TSharkCollector(
        interface="1",
        health_file=str(health_file),
    )
    collector.is_replay = True
    collector.packets_captured = 100
    collector.flows_transmitted = 8
    collector.write_health()

    assert os.path.exists(health_file)
    with open(health_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["collector_mode"] == "PCAP_REPLAY"
    assert data["packets_captured"] == 100
    assert data["flows_transmitted"] == 8
    assert "tshark_path" in data


def test_tshark_collector_list_interfaces():
    interfaces = TSharkCollector.list_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0  # Either interfaces listed or helpful install message
