"""
SentinelAI - Authorized Live Monitoring & Realistic Event Simulator
Provides background telemetry capture simulation and Suricata live event tailing.
Ensures 100% transparent labeling of simulated laboratory telemetry.
"""

import threading
import time
import datetime
import random
from typing import Dict, Any, List, Optional
import pandas as pd


class LiveMonitoringSimulator:
    """
    Controlled, thread-safe network telemetry simulator for local demonstrations and testing.
    Strictly annotates all generated telemetry as '[SIMULATED: Lab Scenario]'.
    """

    def __init__(self, buffer_size: int = 200):
        self.buffer_size = buffer_size
        self._events_buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._is_running = False
        self._thread: Optional[threading.Thread] = None
        self._counter = 0

        # Normal background host profile
        self.internal_hosts = ["192.168.1.10", "192.168.1.12", "192.168.1.20", "192.168.1.25"]
        self.target_servers = ["10.0.0.1", "10.0.0.2", "10.0.0.5"]
        self.standard_services = [
            (443, "HTTPS Web Traffic", "Normal Traffic", 120),
            (80, "HTTP Web Traffic", "Normal Traffic", 85),
            (53, "DNS Resolution", "Normal Traffic", 45),
            (123, "NTP Time Sync", "Normal Traffic", 30),
        ]

    def start(self, interval_seconds: float = 1.5):
        """Start background simulation thread."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._thread = threading.Thread(
                target=self._run_simulation,
                args=(interval_seconds,),
                daemon=True
            )
            self._thread.start()

    def stop(self):
        """Halt background simulation thread."""
        with self._lock:
            self._is_running = False

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def _run_simulation(self, interval: float):
        while True:
            with self._lock:
                if not self._is_running:
                    break

            event = self._generate_telemetry_event()
            with self._lock:
                self._events_buffer.append(event)
                if len(self._events_buffer) > self.buffer_size:
                    self._events_buffer.pop(0)

            time.sleep(interval)

    def _generate_telemetry_event(self) -> Dict[str, Any]:
        """Generate a single realistic network telemetry event."""
        self._counter += 1
        now_ts = datetime.datetime.now().strftime("%H:%M:%S")

        # 85% normal traffic, 15% laboratory attack scenario injection
        scenario_roll = random.random()

        if scenario_roll < 0.85:
            # Normal enterprise traffic
            src_ip = random.choice(self.internal_hosts)
            dest_ip = random.choice(self.target_servers)
            port, desc, act, base_pkts = random.choice(self.standard_services)
            packets = base_pkts + random.randint(-15, 35)
            risk = "Low"
        elif scenario_roll < 0.90:
            # Injected Port Scan probe scenario
            src_ip = "192.168.1.155"
            dest_ip = "10.0.0.1"
            port = random.choice([21, 22, 23, 80, 443, 3389, 8080, 8443])
            packets = random.randint(180, 320)
            act = "Port Scan"
            risk = "High"
        elif scenario_roll < 0.95:
            # Injected Brute Force authentication scenario
            src_ip = "192.168.1.188"
            dest_ip = "10.0.0.2"
            port = random.choice([22, 3389])
            packets = random.randint(300, 450)
            act = "Brute Force"
            risk = "High"
        else:
            # Injected DDoS volumetric spike scenario
            src_ip = "192.168.1.250"
            dest_ip = "10.0.0.5"
            port = 8080
            packets = random.randint(850, 1200)
            act = "DDoS Flood"
            risk = "Critical"

        return {
            "Event ID": f"SIM-{self._counter:05d}",
            "Time": now_ts,
            "Source IP": src_ip,
            "Destination IP": dest_ip,
            "Port": port,
            "Packets": max(10, packets),
            "Activity": act,
            "Risk": risk,
            "Telemetry Type": "SIMULATED: Lab Scenario"
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve a copy of recent events from the ring buffer."""
        with self._lock:
            return list(self._events_buffer[-limit:])

    def get_events_dataframe(self, limit: int = 50) -> pd.DataFrame:
        """Return recent events as a Pandas DataFrame."""
        events = self.get_recent_events(limit=limit)
        if not events:
            return pd.DataFrame(columns=["Event ID", "Time", "Source IP", "Destination IP", "Port", "Packets", "Activity", "Risk", "Telemetry Type"])
        return pd.DataFrame(events)

    def clear(self):
        """Clear telemetry buffer."""
        with self._lock:
            self._events_buffer.clear()
            self._counter = 0

    def inject_attack(self, attack_type: str = "port_scan"):
        """Inject specific laboratory attack scenario events into the telemetry buffer."""
        with self._lock:
            now_ts = datetime.datetime.now().strftime("%H:%M:%S")
            if attack_type == "port_scan":
                for p in [21, 22, 23, 80, 443, 3389]:
                    self._counter += 1
                    self._events_buffer.append({
                        "Event ID": f"SIM-{self._counter:05d}",
                        "Time": now_ts,
                        "Source IP": "192.168.1.155",
                        "Destination IP": "10.0.0.1",
                        "Port": p,
                        "Packets": random.randint(180, 320),
                        "Activity": "Port Scan",
                        "Risk": "High",
                        "Telemetry Type": "SIMULATED: Lab Scenario"
                    })
            elif attack_type == "brute_force":
                for _ in range(5):
                    self._counter += 1
                    self._events_buffer.append({
                        "Event ID": f"SIM-{self._counter:05d}",
                        "Time": now_ts,
                        "Source IP": "192.168.1.188",
                        "Destination IP": "10.0.0.2",
                        "Port": 22,
                        "Packets": random.randint(300, 450),
                        "Activity": "Brute Force",
                        "Risk": "High",
                        "Telemetry Type": "SIMULATED: Lab Scenario"
                    })


# Global singleton instance for Streamlit session continuity
_simulator_instance = None

def get_live_simulator() -> LiveMonitoringSimulator:
    global _simulator_instance
    if _simulator_instance is None:
        _simulator_instance = LiveMonitoringSimulator()
    return _simulator_instance
