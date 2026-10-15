#analyze the traffic and calculate risk level 
"""
SentinelAI - Network Traffic Analyzer Module
Computes risk levels, anomaly metrics, and traffic statistics.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


class TrafficAnalyzer:
    """
    Analyzes network telemetry data to evaluate overall security risk posture,
    detect anomalies, and generate statistical summaries.
    """

    def __init__(self, baseline_avg_packets: float = 150.0):
        self.baseline_avg_packets = baseline_avg_packets
        self.risk_weights = {
            "Low": 10,
            "Medium": 40,
            "High": 80,
            "Critical": 100,
        }

    def calculate_flow_risk_score(self, packets: int, risk_level: str) -> int:
        """
        Calculate an integer risk score between 0 and 100 for an individual event.
        """
        base_score = self.risk_weights.get(risk_level, 10)
        # Scale score according to volumetric deviation
        volumetric_factor = min(30, int((packets / max(1, self.baseline_avg_packets)) * 10))
        calculated = min(100, max(0, base_score + (volumetric_factor if risk_level != "Low" else 0)))
        return calculated

    def analyze_traffic(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Perform complete multi-dimensional analysis on the traffic dataset.
        """
        if df.empty:
            return {
                "total_records": 0,
                "total_packets": 0,
                "avg_packets": 0.0,
                "peak_packets": 0,
                "suspicious_count": 0,
                "high_risk_count": 0,
                "critical_risk_count": 0,
                "overall_risk_score": 0,
                "overall_risk_label": "Low",
                "top_ips": [],
                "activity_distribution": {},
                "risk_distribution": {},
            }

        total_records = len(df)
        packets_series = df.get("Packets", pd.Series([0] * total_records))
        total_packets = int(packets_series.sum())
        avg_packets = round(float(packets_series.mean()), 1)
        peak_packets = int(packets_series.max())

        # Determine risk column
        risk_col = "Risk" if "Risk" in df.columns else None
        if risk_col:
            suspicious_count = int((df[risk_col].isin(["Medium", "High", "Critical"])).sum())
            high_risk_count = int((df[risk_col] == "High").sum())
            critical_risk_count = int((df[risk_col] == "Critical").sum())
            risk_dist = df[risk_col].value_counts().to_dict()
        else:
            suspicious_count = 0
            high_risk_count = 0
            critical_risk_count = 0
            risk_dist = {}

        # Activity distribution
        activity_col = "Activity" if "Activity" in df.columns else None
        activity_dist = df[activity_col].value_counts().to_dict() if activity_col else {}

        # Source IP traffic analysis
        top_ips = []
        if "Source IP" in df.columns:
            ip_group = df.groupby("Source IP").agg(
                Packets=("Packets", "sum"),
                Events=("Source IP", "count")
            ).reset_index()
            ip_group = ip_group.sort_values(by="Packets", ascending=False)
            top_ips = ip_group.to_dict(orient="records")

        # Composite overall network risk score (0-100)
        if total_records > 0 and risk_col:
            weighted_scores = [self.calculate_flow_risk_score(p, r) for p, r in zip(packets_series, df[risk_col])]
            overall_score = int(np.mean(weighted_scores))
        else:
            overall_score = 0

        # Classify overall risk level
        if overall_score >= 80 or critical_risk_count > 0:
            overall_label = "Critical"
        elif overall_score >= 50 or high_risk_count > 0:
            overall_label = "High"
        elif overall_score >= 25 or suspicious_count > 0:
            overall_label = "Medium"
        else:
            overall_label = "Low"

        return {
            "total_records": total_records,
            "total_packets": total_packets,
            "avg_packets": avg_packets,
            "peak_packets": peak_packets,
            "suspicious_count": suspicious_count,
            "high_risk_count": high_risk_count,
            "critical_risk_count": critical_risk_count,
            "overall_risk_score": overall_score,
            "overall_risk_label": overall_label,
            "top_ips": top_ips,
            "activity_distribution": activity_dist,
            "risk_distribution": risk_dist,
        }

    def get_timeline_aggregates(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregate packet volume and incident counts over timestamps for time-series charts.
        """
        if df.empty or "Time" not in df.columns:
            return df.copy()

        timeline = df.groupby("Time").agg(
            Total_Packets=("Packets", "sum"),
            Flow_Count=("Time", "count"),
            Max_Risk=("Risk", lambda x: "Critical" if "Critical" in x.values else ("High" if "High" in x.values else ("Medium" if "Medium" in x.values else "Low")))
        ).reset_index()

        return timeline


# Helper factory function
def get_analyzer() -> TrafficAnalyzer:
    return TrafficAnalyzer()
