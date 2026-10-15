"""
SentinelAI - Log Ingestion & Normalization Module
Parses and normalizes security telemetry from Suricata EVE JSON, Zeek/Bro logs,
standard JSON arrays, and CSV files into standard SentinelAI event records.
"""

import json
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd


class LogParser:
    """
    Normalizes multi-format network telemetry into a standardized security schema.
    """

    @staticmethod
    def parse_suricata_eve(eve_content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse Suricata EVE JSON (one JSON object per line).
        Extracts flow and alert telemetry, normalizing timestamps and port numbers.
        Returns (parsed_events, error_messages).
        """
        events = []
        errors = []

        lines = eve_content.strip().split("\n")
        for line_num, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line:
                continue

            try:
                raw = json.loads(clean_line)
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: Malformed JSON - {e}")
                continue

            event_type = raw.get("event_type", "unknown")
            timestamp = raw.get("timestamp", "N/A")
            src_ip = raw.get("src_ip", "0.0.0.0")
            dest_ip = raw.get("dest_ip", "0.0.0.0")
            src_port = raw.get("src_port")
            dest_port = raw.get("dest_port")
            proto = raw.get("proto", "TCP")

            # Extract packet count depending on event type
            packets = 1
            if "flow" in raw and isinstance(raw["flow"], dict):
                packets = raw["flow"].get("pkts_toserver", 1) + raw["flow"].get("pkts_toclient", 0)

            # Extract signature or category
            activity = "Normal Traffic"
            risk = "Low"
            if "alert" in raw and isinstance(raw["alert"], dict):
                alert_info = raw["alert"]
                activity = alert_info.get("signature", "Suricata Alert")
                severity_val = alert_info.get("severity", 3)
                # Suricata severity 1 = High, 2 = Medium, 3 = Low
                if severity_val == 1:
                    risk = "Critical"
                elif severity_val == 2:
                    risk = "High"
                else:
                    risk = "Medium"

            events.append({
                "Time": str(timestamp)[:19].replace("T", " "),
                "Source IP": str(src_ip),
                "Destination IP": str(dest_ip),
                "Port": dest_port if dest_port is not None else 80,
                "Source Port": src_port,
                "Protocol": str(proto),
                "Packets": int(packets),
                "Activity": str(activity),
                "Risk": risk,
                "Log Format": "Suricata EVE JSON"
            })

        return events, errors

    @staticmethod
    def parse_generic_json(json_content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse structured generic JSON arrays or line-delimited JSON events.
        """
        events = []
        errors = []

        try:
            data = json.loads(json_content.strip())
            if isinstance(data, list):
                raw_events = data
            elif isinstance(data, dict):
                raw_events = data.get("events", [data])
            else:
                return [], ["Root JSON must be a list of objects or a dict containing an 'events' list."]
        except json.JSONDecodeError:
            # Fallback to line-delimited JSON
            return LogParser.parse_suricata_eve(json_content)

        for idx, item in enumerate(raw_events, 1):
            if not isinstance(item, dict):
                errors.append(f"Record {idx} is not a valid JSON object.")
                continue

            events.append({
                "Time": str(item.get("time", item.get("timestamp", "N/A"))),
                "Source IP": str(item.get("source_ip", item.get("src_ip", "0.0.0.0"))),
                "Destination IP": str(item.get("destination_ip", item.get("dest_ip", "10.0.0.1"))),
                "Port": int(item.get("port", item.get("dest_port", 80))) if str(item.get("port", item.get("dest_port", ""))).isdigit() else 80,
                "Packets": int(item.get("packets", item.get("pkts", 100))) if str(item.get("packets", item.get("pkts", ""))).isdigit() else 100,
                "Activity": str(item.get("activity", "Normal Traffic")),
                "Risk": str(item.get("risk", "Low")),
                "Log Format": "Generic JSON"
            })

        return events, errors

    @staticmethod
    def events_to_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert list of parsed event dicts into a validated DataFrame."""
        if not events:
            return pd.DataFrame(columns=["Time", "Source IP", "Destination IP", "Port", "Packets", "Activity", "Risk"])
        return pd.DataFrame(events)
