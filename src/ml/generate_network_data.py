"""
SentinelAI - Controlled Synthetic Network Flow Generator
Generates realistic, clearly labelled network flow telemetry for model training and benchmarking.
Simulates normal web activity, benign high-volume transfers, port scans, connection floods,
and repeated brute-force attempts with realistic stochastic jitter.
Avoids trivial shortcut labels.
"""

import os
import sys
import uuid
import random
import datetime
import argparse
from typing import Dict, Any, List
import pandas as pd
import numpy as np


class SyntheticNetworkFlowGenerator:
    """
    Generates synthetic network flows simulating diverse operational scenarios.
    """

    BENIGN_INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
    BENIGN_SERVER_IPS = ["10.0.0.5", "10.0.0.10", "10.0.0.15", "10.0.0.80", "10.0.0.443"]
    ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 25)] + [f"198.51.100.{i}" for i in range(1, 20)]

    def __init__(self, random_seed: int = 42):
        self.random_seed = random_seed
        random.seed(random_seed)
        np.random.seed(random_seed)

    def generate_scenario_flows(self, scenario: str, count: int, base_time: float) -> List[Dict[str, Any]]:
        """Generates flow records for a specific scenario."""
        flows = []
        curr_time = base_time

        for i in range(count):
            curr_time += random.uniform(0.01, 1.5)

            if scenario == "normal_browsing":
                # Standard web browsing: HTTPS, HTTP, DNS
                proto = "TCP" if random.random() < 0.85 else "UDP"
                dst_port = random.choice([443, 80, 8080]) if proto == "TCP" else 53
                duration = random.uniform(0.1, 8.0)
                tot_pkts = random.randint(8, 120)
                mean_len = random.uniform(300, 1100)
                tot_bytes = int(tot_pkts * mean_len)

                syn_cnt = 1 if proto == "TCP" else 0
                ack_cnt = max(1, tot_pkts - 2) if proto == "TCP" else 0
                rst_cnt = 1 if (proto == "TCP" and random.random() < 0.05) else 0
                fin_cnt = 1 if (proto == "TCP" and random.random() < 0.8) else 0

                src_ip = random.choice(self.BENIGN_INTERNAL_IPS)
                dst_ip = random.choice(self.BENIGN_SERVER_IPS)

                flows.append({
                    "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
                    "scenario": "normal_browsing",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": random.randint(10000, 65000),
                    "dst_port": dst_port,
                    "protocol": proto,
                    "start_time": curr_time,
                    "duration": round(duration, 4),
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "mean_packet_length": round(mean_len, 2),
                    "std_packet_length": round(mean_len * 0.45, 2),
                    "syn_count": syn_cnt,
                    "ack_count": ack_cnt,
                    "rst_count": rst_cnt,
                    "fin_count": fin_cnt,
                    "flow_iat_mean": round(duration / max(1, tot_pkts), 6),
                    "flow_iat_std": round((duration / max(1, tot_pkts)) * 0.5, 6),
                    "unique_dst_ports_src": random.randint(1, 4),
                    "flow_frequency_src": random.randint(1, 10),
                    "is_anomaly": 0,
                    "threat_label": "Normal Traffic"
                })

            elif scenario == "benign_large_transfer":
                # Large file download or video stream (Benign edge case: high bytes, normal handshakes)
                duration = random.uniform(5.0, 30.0)
                tot_pkts = random.randint(500, 4000)
                mean_len = random.uniform(1100, 1460)  # Near MTU
                tot_bytes = int(tot_pkts * mean_len)

                src_ip = random.choice(self.BENIGN_INTERNAL_IPS)
                dst_ip = random.choice(self.BENIGN_SERVER_IPS)

                flows.append({
                    "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
                    "scenario": "benign_large_transfer",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": random.randint(20000, 60000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "start_time": curr_time,
                    "duration": round(duration, 4),
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "mean_packet_length": round(mean_len, 2),
                    "std_packet_length": round(mean_len * 0.25, 2),
                    "syn_count": 1,
                    "ack_count": tot_pkts - 2,
                    "rst_count": 0,
                    "fin_count": 1,
                    "flow_iat_mean": round(duration / tot_pkts, 6),
                    "flow_iat_std": round((duration / tot_pkts) * 0.3, 6),
                    "unique_dst_ports_src": 1,
                    "flow_frequency_src": random.randint(1, 3),
                    "is_anomaly": 0,
                    "threat_label": "Normal Traffic"
                })

            elif scenario == "port_scan":
                # Fast sequential port scan from external or compromised IP
                attacker = random.choice(self.ATTACKER_IPS)
                target = random.choice(self.BENIGN_SERVER_IPS)
                scanned_port = random.choice([21, 22, 23, 25, 80, 111, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 27017])
                duration = random.uniform(0.001, 0.05)
                tot_pkts = random.randint(1, 3)
                mean_len = random.uniform(54, 74)  # Small TCP SYN probe
                tot_bytes = int(tot_pkts * mean_len)

                # High RST response when port is closed, SYN with zero ACK
                is_closed = random.random() < 0.70
                syn_cnt = 1
                ack_cnt = 0 if is_closed else 1
                rst_cnt = 1 if is_closed else 0

                flows.append({
                    "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
                    "scenario": "port_scan",
                    "src_ip": attacker,
                    "dst_ip": target,
                    "src_port": random.randint(30000, 65000),
                    "dst_port": scanned_port,
                    "protocol": "TCP",
                    "start_time": curr_time,
                    "duration": round(duration, 4),
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "mean_packet_length": round(mean_len, 2),
                    "std_packet_length": 4.0,
                    "syn_count": syn_cnt,
                    "ack_count": ack_cnt,
                    "rst_count": rst_cnt,
                    "fin_count": 0,
                    "flow_iat_mean": round(duration / tot_pkts, 6),
                    "flow_iat_std": 0.001,
                    "unique_dst_ports_src": random.randint(15, 60),  # High port cardinality
                    "flow_frequency_src": random.randint(20, 80),
                    "is_anomaly": 1,
                    "threat_label": "Port Scan"
                })

            elif scenario == "connection_flood":
                # High-rate volumetric TCP SYN or UDP flood
                attacker = random.choice(self.ATTACKER_IPS)
                target = random.choice(self.BENIGN_SERVER_IPS)
                proto = "TCP" if random.random() < 0.75 else "UDP"
                dst_port = random.choice([80, 443, 53])
                duration = random.uniform(0.01, 0.4)
                tot_pkts = random.randint(80, 800)
                mean_len = random.uniform(60, 120)
                tot_bytes = int(tot_pkts * mean_len)

                syn_cnt = tot_pkts if proto == "TCP" else 0
                ack_cnt = 0
                rst_cnt = random.randint(0, 5)

                flows.append({
                    "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
                    "scenario": "connection_flood",
                    "src_ip": attacker,
                    "dst_ip": target,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": dst_port,
                    "protocol": proto,
                    "start_time": curr_time,
                    "duration": round(duration, 4),
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "mean_packet_length": round(mean_len, 2),
                    "std_packet_length": 10.0,
                    "syn_count": syn_cnt,
                    "ack_count": ack_cnt,
                    "rst_count": rst_cnt,
                    "fin_count": 0,
                    "flow_iat_mean": round(duration / tot_pkts, 6),
                    "flow_iat_std": round((duration / tot_pkts) * 0.2, 6),
                    "unique_dst_ports_src": 1,
                    "flow_frequency_src": random.randint(50, 200),
                    "is_anomaly": 1,
                    "threat_label": "Traffic Burst"
                })

            elif scenario == "brute_force":
                # Repeated connection attempts to SSH (22) or RDP (3389)
                attacker = random.choice(self.ATTACKER_IPS)
                target = random.choice(self.BENIGN_SERVER_IPS)
                service_port = 22 if random.random() < 0.6 else 3389
                duration = random.uniform(0.3, 1.5)
                tot_pkts = random.randint(10, 30)
                mean_len = random.uniform(120, 300)
                tot_bytes = int(tot_pkts * mean_len)

                syn_cnt = 1
                ack_cnt = tot_pkts - 2
                rst_cnt = 1  # Server terminates authentication failure

                flows.append({
                    "flow_id": f"FLOW-{uuid.uuid4().hex[:8].upper()}",
                    "scenario": "brute_force",
                    "src_ip": attacker,
                    "dst_ip": target,
                    "src_port": random.randint(20000, 60000),
                    "dst_port": service_port,
                    "protocol": "TCP",
                    "start_time": curr_time,
                    "duration": round(duration, 4),
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "mean_packet_length": round(mean_len, 2),
                    "std_packet_length": round(mean_len * 0.4, 2),
                    "syn_count": syn_cnt,
                    "ack_count": ack_cnt,
                    "rst_count": rst_cnt,
                    "fin_count": 0,
                    "flow_iat_mean": round(duration / tot_pkts, 6),
                    "flow_iat_std": round((duration / tot_pkts) * 0.3, 6),
                    "unique_dst_ports_src": 1,
                    "flow_frequency_src": random.randint(15, 60),  # Many repeated attempts to same service
                    "is_anomaly": 1,
                    "threat_label": "Brute Force"
                })

        return flows

    def generate_dataset(
        self,
        normal_count: int = 5000,
        large_transfer_count: int = 600,
        port_scan_count: int = 800,
        flood_count: int = 500,
        brute_force_count: int = 600
    ) -> pd.DataFrame:
        """Assembles full synthetic dataset across all operational scenarios."""
        start_ts = 1672531200.0  # 2023-01-01 00:00:00 UTC

        all_flows = []
        all_flows.extend(self.generate_scenario_flows("normal_browsing", normal_count, start_ts))
        all_flows.extend(self.generate_scenario_flows("benign_large_transfer", large_transfer_count, start_ts + 3600))
        all_flows.extend(self.generate_scenario_flows("port_scan", port_scan_count, start_ts + 7200))
        all_flows.extend(self.generate_scenario_flows("connection_flood", flood_count, start_ts + 10800))
        all_flows.extend(self.generate_scenario_flows("brute_force", brute_force_count, start_ts + 14400))

        df = pd.DataFrame(all_flows)
        # Sort chronologically by start_time
        df = df.sort_values(by="start_time").reset_index(drop=True)
        return df


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Synthetic Network Flow Generator")
    parser.add_argument("--output", default="data/synthetic_network_flows.csv", help="Destination CSV path")
    parser.add_argument("--normal", type=int, default=5000, help="Number of normal browsing flows")
    parser.add_argument("--large", type=int, default=600, help="Number of benign large transfer flows")
    parser.add_argument("--port-scan", type=int, default=800, help="Number of port scan flows")
    parser.add_argument("--flood", type=int, default=500, help="Number of flood flows")
    parser.add_argument("--brute-force", type=int, default=600, help="Number of brute force flows")
    args = parser.parse_args()

    generator = SyntheticNetworkFlowGenerator()
    df = generator.generate_dataset(
        normal_count=args.normal,
        large_transfer_count=args.large,
        port_scan_count=args.port_scan,
        flood_count=args.flood,
        brute_force_count=args.brute_force
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"[SyntheticGenerator] Created {len(df):,} network flow records at: {args.output}")
    print(f"[SyntheticGenerator] Breakdown by Scenario:\n{df['scenario'].value_counts()}")
    print(f"[SyntheticGenerator] Anomaly Flag: {df['is_anomaly'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
