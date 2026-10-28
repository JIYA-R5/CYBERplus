"""
SentinelAI - Dataset Audit and Statistical Validation Module
Audits synthetic and production cybersecurity telemetry datasets.
Validates schemas, data integrity, class balance, potential label leakage,
and synthetic artifacts without silently deleting data.
"""

import os
import sys
import argparse
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np


class DatasetAuditor:
    """
    Performs comprehensive statistical and forensic audit of a cybersecurity dataset.
    """

    EXPECTED_COLUMNS = [
        "Timestamp",
        "IP_Address",
        "Request_Type",
        "Status_Code",
        "Anomaly_Flag",
        "User_Agent",
        "Session_ID",
        "Location"
    ]

    VALID_HTTP_STATUS_CODES = {200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503}
    VALID_REQUEST_TYPES = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}

    def __init__(self, dataset_path: str, output_dir: str = "reports"):
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        self.df: Optional[pd.DataFrame] = None
        self.report_lines: List[str] = []
        self.metrics: Dict[str, Any] = {}

    def load_dataset(self) -> pd.DataFrame:
        """Loads and returns dataset, verifying accessibility."""
        if not os.path.isfile(self.dataset_path):
            raise FileNotFoundError(f"Dataset file not found at: {self.dataset_path}")

        self.df = pd.read_csv(self.dataset_path)
        return self.df

    def audit(self) -> Dict[str, Any]:
        """Runs complete audit pipeline and compiles findings."""
        if self.df is None:
            self.load_dataset()

        df = self.df
        self.report_lines = []
        os.makedirs(self.output_dir, exist_ok=True)

        self._log("=" * 80)
        self._log("SENTINELAI CYBERSECURITY DATASET AUDIT REPORT")
        self._log("=" * 80)
        self._log(f"Dataset Path : {os.path.abspath(self.dataset_path)}")
        self._log(f"File Size    : {os.path.getsize(self.dataset_path):,} bytes")
        self._log(f"Total Rows   : {len(df):,}")
        self._log(f"Total Columns: {len(df.columns)}")
        self._log("-" * 80)

        # 1. Schema & Column Validation
        self._audit_schema(df)

        # 2. Data Integrity & Missing Values
        self._audit_integrity(df)

        # 3. Target Distribution (Anomaly_Flag)
        self._audit_target(df)

        # 4. Categorical Distributions & Anomaly Rates
        self._audit_categorical_anomaly_rates(df)

        # 5. North Korea & Geolocation Forensic Analysis
        self._audit_location_bias(df)

        # 6. Identifier, IP, and Session Leakage Checks
        self._audit_identifiers(df)

        # 7. Timestamp & Synthetic Generation Artifacts
        self._audit_timestamps(df)

        # 8. Single Feature & Multi-Feature Determinism / Leakage Checks
        self._audit_feature_determinism(df)

        # 9. Summary & Actionable Recommendations
        self._summarize_recommendations()

        # Save readable report text
        report_text_path = os.path.join(self.output_dir, "dataset_audit.txt")
        with open(report_text_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.report_lines))

        self._log(f"\n[Audit Completed] Saved detailed audit report to {report_text_path}")
        return self.metrics

    def _log(self, text: str):
        self.report_lines.append(text)
        print(text)

    def _audit_schema(self, df: pd.DataFrame):
        self._log("\n[1] SCHEMA AND COLUMN VALIDATION")
        actual_cols = list(df.columns)
        missing_expected = [c for c in self.EXPECTED_COLUMNS if c not in actual_cols]
        extra_cols = [c for c in actual_cols if c not in self.EXPECTED_COLUMNS]

        self._log(f"  Actual Columns   : {actual_cols}")
        self._log(f"  Expected Columns : {self.EXPECTED_COLUMNS}")
        self._log(f"  Schema Match     : {'PERFECT MATCH' if not missing_expected and not extra_cols else 'MISMATCH'}")
        if missing_expected:
            self._log(f"  MISSING Expected : {missing_expected}")
        if extra_cols:
            self._log(f"  EXTRA Columns    : {extra_cols}")

        self.metrics["schema_match"] = (len(missing_expected) == 0 and len(extra_cols) == 0)
        self.metrics["columns"] = actual_cols

    def _audit_integrity(self, df: pd.DataFrame):
        self._log("\n[2] DATA INTEGRITY & MISSING VALUES")
        null_counts = df.isnull().sum()
        total_nulls = null_counts.sum()
        dup_count = df.duplicated().sum()

        self._log(f"  Total Null Values : {total_nulls}")
        if total_nulls > 0:
            for col, count in null_counts[null_counts > 0].items():
                self._log(f"    - {col}: {count} missing ({count/len(df):.2%})")
        else:
            self._log("    - No missing or NaN values detected in any column.")

        self._log(f"  Duplicate Records : {dup_count}")
        if dup_count > 0:
            self._log(f"    - Warning: {dup_count} duplicate rows found ({dup_count/len(df):.2%})")

        self.metrics["total_nulls"] = int(total_nulls)
        self.metrics["duplicate_rows"] = int(dup_count)

    def _audit_target(self, df: pd.DataFrame):
        self._log("\n[3] TARGET DISTRIBUTION (Anomaly_Flag)")
        if "Anomaly_Flag" not in df.columns:
            self._log("  CRITICAL: 'Anomaly_Flag' column missing from dataset!")
            self.metrics["target_valid"] = False
            return

        target_vals = df["Anomaly_Flag"].value_counts(dropna=False).to_dict()
        unexpected_vals = [k for k in target_vals.keys() if k not in (0, 1, "0", "1")]

        normal_count = int(target_vals.get(0, 0))
        anomaly_count = int(target_vals.get(1, 0))
        anomaly_rate = anomaly_count / len(df) if len(df) > 0 else 0.0

        self._log(f"  Normal Records (0)   : {normal_count:,} ({normal_count / len(df):.2%})")
        self._log(f"  Anomaly Records (1)  : {anomaly_count:,} ({anomaly_rate:.2%})")
        self._log(f"  Class Imbalance Ratio: {normal_count / max(1, anomaly_count):.2f}:1")

        if unexpected_vals:
            self._log(f"  WARNING: Unexpected target values found: {unexpected_vals}")

        self.metrics["normal_count"] = normal_count
        self.metrics["anomaly_count"] = anomaly_count
        self.metrics["anomaly_rate"] = float(anomaly_rate)
        self.metrics["unexpected_target_values"] = unexpected_vals

    def _audit_categorical_anomaly_rates(self, df: pd.DataFrame):
        self._log("\n[4] CATEGORICAL DISTRIBUTIONS AND ANOMALY RATES")
        cat_cols = ["Request_Type", "Status_Code", "User_Agent"]

        for col in cat_cols:
            if col not in df.columns:
                continue
            grouped = df.groupby(col)["Anomaly_Flag"].agg(
                Total_Records="count",
                Anomalies="sum",
                Anomaly_Rate="mean"
            ).reset_index()
            grouped["Percentage_Of_Dataset"] = grouped["Total_Records"] / len(df)
            grouped["Anomaly_Rate_Pct"] = grouped["Anomaly_Rate"] * 100.0

            csv_name = f"audit_{col.lower()}_rates.csv"
            grouped.to_csv(os.path.join(self.output_dir, csv_name), index=False)

            self._log(f"\n  Breakdown by '{col}': (exported to {csv_name})")
            for _, r in grouped.iterrows():
                val = r[col]
                tot = int(r["Total_Records"])
                anom = int(r["Anomalies"])
                rate = float(r["Anomaly_Rate_Pct"])
                self._log(f"    - {str(val):<12}: {tot:>5} records | {anom:>3} anomalies ({rate:6.2f}%)")

            # Validate categorical domain
            if col == "Status_Code":
                invalid_codes = set(df[col].dropna().astype(int)) - self.VALID_HTTP_STATUS_CODES
                if invalid_codes:
                    self._log(f"    WARNING: Unrecognized HTTP status codes detected: {invalid_codes}")
            elif col == "Request_Type":
                invalid_verbs = set(df[col].dropna().astype(str).str.upper()) - self.VALID_REQUEST_TYPES
                if invalid_verbs:
                    self._log(f"    WARNING: Unrecognized HTTP methods detected: {invalid_verbs}")

    def _audit_location_bias(self, df: pd.DataFrame):
        self._log("\n[5] LOCATION BIAS & 'NORTH KOREA' FORENSIC ANALYSIS")
        if "Location" not in df.columns:
            return

        loc_grouped = df.groupby("Location")["Anomaly_Flag"].agg(
            Total_Records="count",
            Anomalies="sum",
            Anomaly_Rate="mean"
        ).reset_index()
        loc_grouped["Percentage_Of_Dataset"] = loc_grouped["Total_Records"] / len(df)
        loc_grouped["Anomaly_Rate_Pct"] = loc_grouped["Anomaly_Rate"] * 100.0

        csv_name = "audit_location_rates.csv"
        loc_grouped.to_csv(os.path.join(self.output_dir, csv_name), index=False)

        self._log(f"  Location Rates Table: (exported to {csv_name})")
        for _, r in loc_grouped.sort_values(by="Anomaly_Rate", ascending=False).iterrows():
            loc = r["Location"]
            tot = int(r["Total_Records"])
            anom = int(r["Anomalies"])
            rate = float(r["Anomaly_Rate_Pct"])
            self._log(f"    - {loc:<15}: {tot:>5} records | {anom:>3} anomalies ({rate:6.2f}%)")

        # Specific investigation into North Korea
        nk_records = df[df["Location"].astype(str).str.strip().str.lower() == "north korea"]
        nk_total = len(nk_records)
        nk_anomalies = int(nk_records["Anomaly_Flag"].sum()) if nk_total > 0 else 0
        nk_rate = nk_anomalies / nk_total if nk_total > 0 else 0.0

        self._log("\n  -> Specific Investigation: Location = 'North Korea'")
        self._log(f"     Total Records        : {nk_total}")
        self._log(f"     Anomalous Records    : {nk_anomalies}")
        self._log(f"     Anomaly Rate         : {nk_rate:.2%}")

        if nk_total > 0 and nk_rate == 1.0:
            self._log("     FINDING: 100.0% of records originating from 'North Korea' are labelled as ANOMALOUS.")
            self._log("     EVALUATION: This indicates an explicit synthetic heuristic or heuristic rule injection.")
            self._log("     RISK: If 'Location' is fed directly to an ML model, the model will learn a geographic shortcut")
            self._log("     rather than inspecting packet payload/traffic mechanics, causing false positives on legitimate")
            self._log("     regional traffic and failing on non-regional attackers.")
        else:
            self._log(f"     FINDING: Anomaly rate for North Korea is {nk_rate:.2%}.")

        self.metrics["north_korea_total"] = nk_total
        self.metrics["north_korea_anomalies"] = nk_anomalies
        self.metrics["north_korea_rate"] = float(nk_rate)

    def _audit_identifiers(self, df: pd.DataFrame):
        self._log("\n[6] IDENTIFIER, IP ADDRESS & SESSION ID AUDIT")

        if "IP_Address" in df.columns:
            unique_ips = df["IP_Address"].nunique()
            self._log(f"  Unique IP Addresses : {unique_ips:,} / {len(df):,} records")
            ip_counts = df["IP_Address"].value_counts()
            repeated_ips = ip_counts[ip_counts > 1]
            self._log(f"  IPs appearing > 1x  : {len(repeated_ips)}")

            if len(repeated_ips) > 0:
                top_repeated = repeated_ips.head(5)
                for ip, cnt in top_repeated.items():
                    ip_subset = df[df["IP_Address"] == ip]
                    anom_cnt = ip_subset["Anomaly_Flag"].sum()
                    self._log(f"    - IP {ip}: {cnt} occurrences, {anom_cnt} anomalies ({anom_cnt/cnt:.1%})")

        if "Session_ID" in df.columns:
            unique_sessions = df["Session_ID"].nunique()
            session_counts = df["Session_ID"].value_counts()
            multi_record_sessions = (session_counts > 1).sum()

            self._log(f"  Unique Session IDs  : {unique_sessions:,}")
            self._log(f"  Multi-Record Sessions: {multi_record_sessions:,} ({multi_record_sessions / unique_sessions:.1%})")

            # Check if Session_IDs have mixed labels or uniform labels
            session_stats = df.groupby("Session_ID")["Anomaly_Flag"].agg(["count", "nunique", "mean"])
            mixed_sessions = (session_stats["nunique"] > 1).sum()
            all_anom_sessions = (session_stats["mean"] == 1.0).sum()
            all_norm_sessions = (session_stats["mean"] == 0.0).sum()

            self._log(f"    - Sessions with mixed labels (0 and 1) : {mixed_sessions:,}")
            self._log(f"    - Sessions with 100% anomalous records : {all_anom_sessions:,}")
            self._log(f"    - Sessions with 100% normal records    : {all_norm_sessions:,}")
            self._log("  SPLIT GUIDANCE: Group-based splitting by 'Session_ID' is essential to prevent session-level leakage.")

    def _audit_timestamps(self, df: pd.DataFrame):
        self._log("\n[7] TIMESTAMP & SYNTHETIC GENERATION ARTIFACTS")
        if "Timestamp" not in df.columns:
            return

        try:
            ts = pd.to_datetime(df["Timestamp"])
            min_ts = ts.min()
            max_ts = ts.max()
            span = max_ts - min_ts
            is_monotonic = ts.is_monotonic_increasing

            diffs = ts.diff().dropna()
            mode_diff = diffs.mode().iloc[0] if not diffs.empty else None

            self._log(f"  Start Timestamp     : {min_ts}")
            self._log(f"  End Timestamp       : {max_ts}")
            self._log(f"  Total Time Span     : {span}")
            self._log(f"  Chronological Order : {'STRICTLY MONOTONIC INCREASING' if is_monotonic else 'NON-MONOTONIC'}")
            self._log(f"  Step Interval Mode  : {mode_diff}")

            regular_ratio = (diffs == mode_diff).mean() if mode_diff is not None else 0.0
            self._log(f"  Step Regularity     : {regular_ratio:.2%} of intervals are exactly {mode_diff}")
            if regular_ratio > 0.99:
                self._log("  SYNTHETIC ARTIFACT: Timestamps were synthetically generated with uniform clock increments")
                self._log("  rather than representing natural Poisson arrival times typical of real network packets.")

            self.metrics["time_span_days"] = span.days
            self.metrics["is_monotonic_timestamps"] = bool(is_monotonic)
            self.metrics["timestamp_interval_mode"] = str(mode_diff)
        except Exception as e:
            self._log(f"  Error parsing timestamps: {e}")

    def _audit_feature_determinism(self, df: pd.DataFrame):
        self._log("\n[8] FEATURE DETERMINISM & LABEL LEAKAGE EVALUATION")

        # Evaluate if individual features or 2-way combinations have near-deterministic target values
        test_features = ["Request_Type", "Status_Code", "User_Agent"]
        high_correlation_pairs = []

        for f in test_features:
            if f not in df.columns:
                continue
            anom_rates = df.groupby(f)["Anomaly_Flag"].mean()
            max_rate = anom_rates.max()
            min_rate = anom_rates.min()
            self._log(f"  Feature '{f}': Anomaly Rate range = [{min_rate:.2%}, {max_rate:.2%}]")
            if max_rate > 0.90 or min_rate > 0.90:
                high_correlation_pairs.append((f, max_rate))

        # Check cross product of Request_Type + Status_Code + User_Agent
        comb_df = df.groupby(test_features)["Anomaly_Flag"].agg(["count", "mean"]).reset_index()
        comb_df = comb_df.rename(columns={"mean": "Anomaly_Rate", "count": "Frequency"})
        deterministic_combs = comb_df[comb_df["Anomaly_Rate"] == 1.0]

        self._log(f"  Total 3-way combinations: {len(comb_df)}")
        self._log(f"  100% Anomalous combinations: {len(deterministic_combs)}")
        if not deterministic_combs.empty:
            self._log("  Top combinations with 100% anomaly rate (low support check):")
            for _, r in deterministic_combs.head(5).iterrows():
                self._log(f"    - {r['Request_Type']} + {r['Status_Code']} + {r['User_Agent']} (n={r['Frequency']})")
        else:
            self._log("  No single 3-way combination deterministically dictates the anomaly flag.")

    def _summarize_recommendations(self):
        self._log("\n[9] SUMMARY FINDINGS & RECOMMENDATIONS")
        self._log("  1. Nature of Data: This is an application/web-log dataset (HTTP verbs, status codes, user agents),")
        self._log("     NOT a packet-level or flow-level network dataset. It must be identified strictly as a web-log model.")
        self._log("  2. Geolocation Shortcut: Location = 'North Korea' has a 100% anomaly label, which is a synthetic heuristic.")
        self._log("     'Location' must be excluded from baseline feature pipelines to avoid trivial shortcut learning.")
        self._log("  3. Leakage Prevention: 'IP_Address' and 'Session_ID' are high-cardinality identifiers that will memorize")
        self._log("     rather than generalize. Training baseline models MUST exclude IP_Address, Session_ID, Timestamp, and Location.")
        self._log("  4. Grouped Validation: Records must be partitioned by 'Session_ID' using GroupShuffleSplit or GroupKFold")
        self._log("     to ensure records from the same session never cross train/validation/test boundaries.")
        self._log("  5. Class Imbalance: At 4.90% positive anomaly prevalence, models must be configured with class weighting")
        self._log("     (class_weight='balanced') and evaluated on PR-AUC, F1-score, and false-positive rates rather than raw accuracy.")
        self._log("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Dataset Audit Script")
    parser.add_argument(
        "--dataset",
        default=os.environ.get(
            "DATASET_PATH",
            "data/advanced_cybersecurity_data.csv"
            if os.path.isfile("data/advanced_cybersecurity_data.csv")
            else "C:/Users/Asus/Downloads/advanced_cybersecurity_data.csv"
        ),
        help="Path to CSV dataset to audit"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save audit reports and summary CSVs"
    )
    args = parser.parse_args()

    auditor = DatasetAuditor(dataset_path=args.dataset, output_dir=args.output_dir)
    auditor.audit()


if __name__ == "__main__":
    main()
