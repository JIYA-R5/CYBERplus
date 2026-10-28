"""
SentinelAI - Network Flow Feature Engineering Pipeline
Extracts packet-level and aggregated bidirectional flow features for network intrusion
and anomaly detection. Completely distinct from application/web-log features.
"""

import os
import sys
from typing import Dict, Any, List, Union, Tuple, Optional
import numpy as np
import pandas as pd


NETWORK_FEATURE_NAMES = [
    "total_packets",
    "total_bytes",
    "duration",
    "packets_per_sec",
    "bytes_per_sec",
    "src_port",
    "dst_port",
    "is_privileged_port",
    "is_admin_port",
    "is_ephemeral_src",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "syn_ratio",
    "rst_ratio",
    "mean_packet_length",
    "std_packet_length",
    "flow_iat_mean",
    "flow_iat_std",
    "unique_dst_ports_src",
    "flow_frequency_src",
    "failed_conn_indicator"
]

ADMIN_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}


class NetworkFlowFeaturePipeline:
    """
    Standardized feature extraction pipeline for network flows.
    Consistent across training, offline PCAP replay, and live inference.
    Handles incomplete flows, missing attributes, and zero-duration divisions safely.
    """

    def __init__(self):
        self.feature_names = list(NETWORK_FEATURE_NAMES)

    def extract_features(
        self,
        data: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]]
    ) -> Tuple[np.ndarray, pd.DataFrame]:
        """
        Transforms network flow records into a fixed-schema numeric feature matrix.
        Returns:
            (X: np.ndarray [N, len(NETWORK_FEATURE_NAMES)], feature_df: pd.DataFrame)
        """
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data) if data else pd.DataFrame()
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            df = pd.DataFrame()

        if df.empty:
            empty_df = pd.DataFrame(columns=self.feature_names)
            return np.empty((0, len(self.feature_names))), empty_df

        # Normalize column key names (case-insensitive & snake_case)
        col_lookup = {str(c).lower().replace(" ", "_"): c for c in df.columns}

        def get_series(col_keys: List[str], default: float = 0.0) -> pd.Series:
            for k in col_keys:
                if k in col_lookup:
                    orig_col = col_lookup[k]
                    return pd.to_numeric(df[orig_col], errors="coerce").fillna(default)
            return pd.Series(default, index=df.index, dtype=float)

        def get_str_series(col_keys: List[str], default: str = "") -> pd.Series:
            for k in col_keys:
                if k in col_lookup:
                    orig_col = col_lookup[k]
                    return df[orig_col].astype(str).fillna(default)
            return pd.Series(default, index=df.index, dtype=str)

        # 1. Volume and Duration Features
        total_packets = get_series(["total_packets", "packets", "packet_count"], default=1.0).clip(lower=1.0)
        total_bytes = get_series(["total_bytes", "bytes", "byte_count"], default=64.0).clip(lower=0.0)
        duration = get_series(["duration", "flow_duration"], default=0.05).clip(lower=0.0001)

        packets_per_sec = (total_packets / duration).round(2)
        bytes_per_sec = (total_bytes / duration).round(2)

        # 2. Port Features
        dst_port = get_series(["dst_port", "destination_port", "port"], default=80.0).clip(lower=0.0, upper=65535.0)
        src_port = get_series(["src_port", "source_port"], default=0.0).clip(lower=0.0, upper=65535.0)

        is_privileged_port = ((dst_port > 0) & (dst_port < 1024)).astype(float)
        is_admin_port = dst_port.isin(ADMIN_PORTS).astype(float)
        is_ephemeral_src = (src_port >= 1024).astype(float)

        # 3. Protocol One-Hot Encoding
        proto_str = get_str_series(["protocol", "proto"], default="TCP").str.upper()
        protocol_tcp = (proto_str == "TCP").astype(float)
        protocol_udp = (proto_str == "UDP").astype(float)
        protocol_icmp = (proto_str.str.contains("ICMP")).astype(float)
        protocol_other = (~(protocol_tcp.astype(bool) | protocol_udp.astype(bool) | protocol_icmp.astype(bool))).astype(float)

        # 4. TCP Flag Features & Ratios
        syn_count = get_series(["syn_count", "tcp_flag_syn", "syn"], default=0.0).clip(lower=0.0)
        ack_count = get_series(["ack_count", "tcp_flag_ack", "ack"], default=0.0).clip(lower=0.0)
        rst_count = get_series(["rst_count", "tcp_flag_rst", "rst"], default=0.0).clip(lower=0.0)
        fin_count = get_series(["fin_count", "tcp_flag_fin", "fin"], default=0.0).clip(lower=0.0)

        # Support dictionary-packed tcp_flags_seen
        if "tcp_flags_seen" in col_lookup:
            flags_col = df[col_lookup["tcp_flags_seen"]]
            for idx, val in flags_col.items():
                if isinstance(val, dict):
                    syn_count.iloc[idx] = float(val.get("SYN", syn_count.iloc[idx]))
                    ack_count.iloc[idx] = float(val.get("ACK", ack_count.iloc[idx]))
                    rst_count.iloc[idx] = float(val.get("RST", rst_count.iloc[idx]))
                    fin_count.iloc[idx] = float(val.get("FIN", fin_count.iloc[idx]))

        syn_ratio = (syn_count / total_packets).clip(lower=0.0, upper=1.0).round(4)
        rst_ratio = (rst_count / total_packets).clip(lower=0.0, upper=1.0).round(4)

        # 5. Packet Length Statistics
        mean_packet_length = get_series(["mean_packet_length", "mean_pkt_len"], default=0.0)
        # Fallback if not directly provided: compute rough mean from total_bytes / total_packets
        mask_zero_mean = mean_packet_length <= 0
        mean_packet_length[mask_zero_mean] = (total_bytes[mask_zero_mean] / total_packets[mask_zero_mean]).round(2)

        std_packet_length = get_series(["std_packet_length", "std_pkt_len"], default=0.0).clip(lower=0.0)

        # 6. Inter-Arrival Time (IAT) Statistics
        flow_iat_mean = get_series(["flow_iat_mean", "iat_mean"], default=0.0).clip(lower=0.0)
        flow_iat_std = get_series(["flow_iat_std", "iat_std"], default=0.0).clip(lower=0.0)

        # 7. Source Host Contextual Diversity (Sliding Window / Batch Context)
        src_ip = get_str_series(["src_ip", "source_ip"], default="0.0.0.0")
        if len(df) > 1 and "src_ip" in col_lookup:
            temp_df = pd.DataFrame({"src": src_ip, "port": dst_port})
            unique_ports_map = temp_df.groupby("src")["port"].nunique().to_dict()
            unique_dst_ports_src = src_ip.map(unique_ports_map).fillna(1.0).astype(float)

            freq_map = src_ip.value_counts().to_dict()
            flow_frequency_src = src_ip.map(freq_map).fillna(1.0).astype(float)
        else:
            unique_dst_ports_src = get_series(["unique_dst_ports_src", "unique_ports_contacted"], default=1.0)
            flow_frequency_src = get_series(["flow_frequency_src", "flow_frequency"], default=1.0)

        # 8. Failed Connection Indicator (High SYN or RST with negligible ACK)
        failed_conn_indicator = (
            ((syn_count > 0) & (ack_count == 0)) |
            (rst_count > 0) |
            ((protocol_tcp == 1.0) & (total_packets <= 3) & (duration < 0.1))
        ).astype(float)

        # Assemble feature DataFrame
        feature_dict = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "src_port": src_port,
            "dst_port": dst_port,
            "is_privileged_port": is_privileged_port,
            "is_admin_port": is_admin_port,
            "is_ephemeral_src": is_ephemeral_src,
            "protocol_tcp": protocol_tcp,
            "protocol_udp": protocol_udp,
            "protocol_icmp": protocol_icmp,
            "protocol_other": protocol_other,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "syn_ratio": syn_ratio,
            "rst_ratio": rst_ratio,
            "mean_packet_length": mean_packet_length,
            "std_packet_length": std_packet_length,
            "flow_iat_mean": flow_iat_mean,
            "flow_iat_std": flow_iat_std,
            "unique_dst_ports_src": unique_dst_ports_src,
            "flow_frequency_src": flow_frequency_src,
            "failed_conn_indicator": failed_conn_indicator,
        }

        feature_df = pd.DataFrame(feature_dict, columns=self.feature_names)
        X = feature_df.to_numpy(dtype=np.float32)

        return X, feature_df


_global_network_pipeline = None

def get_network_pipeline() -> NetworkFlowFeaturePipeline:
    global _global_network_pipeline
    if _global_network_pipeline is None:
        _global_network_pipeline = NetworkFlowFeaturePipeline()
    return _global_network_pipeline
