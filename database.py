"""
SentinelAI - Database & Persistence Module
Embedded SQLite persistence engine managing security incidents, raw/correlated telemetry,
analyst audit trails, and status transitions.
"""

import sqlite3
import json
import uuid
import datetime
import os
from typing import Dict, Any, List, Optional
import pandas as pd


class DatabaseManager:
    """
    Manages local SQLite database operations for SentinelAI with automatic table creation,
    safe parameterized queries, deduplication, and audit logging.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(__file__)
            self.db_path = os.path.join(base_dir, "sentinel.db")
        else:
            self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema with proper indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Incidents table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                destination_ports TEXT,
                event_count INTEGER DEFAULT 1,
                total_packets INTEGER DEFAULT 0,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                rule_id TEXT,
                mitre_id TEXT,
                evidence TEXT,
                recommended_action TEXT,
                detection_method TEXT,
                status TEXT DEFAULT 'Open'
            )
            """)

            # Audit logs table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                incident_id TEXT,
                action_type TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                execution_mode TEXT NOT NULL,
                operator TEXT NOT NULL,
                details TEXT,
                result TEXT NOT NULL
            )
            """)

            # Raw events table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                port INTEGER,
                packets INTEGER DEFAULT 0,
                activity TEXT,
                risk TEXT
            )
            """)

            # Indexes for performant filtering
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_source ON incidents(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")
            conn.commit()

    def save_incident(self, incident_data: Dict[str, Any]) -> str:
        """
        Insert or update a security incident. Handles both Incident objects and dicts.
        """
        inc_id = incident_data.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"
        ts = incident_data.get("first_seen") or incident_data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ports = incident_data.get("destination_ports", [])
        if isinstance(ports, list):
            ports_json = json.dumps(ports)
        else:
            ports_json = str(ports)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                incident_id, timestamp, category, source_ip, destination_ip,
                destination_ports, event_count, total_packets, severity,
                confidence, rule_id, mitre_id, evidence, recommended_action,
                detection_method, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inc_id,
                ts,
                incident_data.get("category", "Unknown Threat"),
                incident_data.get("source_ip", "0.0.0.0"),
                incident_data.get("destination_ip", "Internal Subnet"),
                ports_json,
                int(incident_data.get("event_count", 1)),
                int(incident_data.get("total_packets", 0)),
                incident_data.get("severity", "Medium"),
                float(incident_data.get("confidence", 0.5)),
                incident_data.get("rule_id", "N/A"),
                incident_data.get("mitre_id", "N/A"),
                incident_data.get("evidence", ""),
                incident_data.get("recommended_action", ""),
                incident_data.get("detection_method", "Rule-based heuristic"),
                incident_data.get("status", "Open")
            ))
            conn.commit()
        return inc_id

    def get_incidents(
        self,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query incidents with optional status and severity filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status_filter and status_filter != "All":
            query += " AND status = ?"
            params.append(status_filter)
        if severity_filter and severity_filter != "All":
            query += " AND severity = ?"
            params.append(severity_filter)

        query += " ORDER BY timestamp DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["destination_ports"] = json.loads(item["destination_ports"])
                except Exception:
                    pass
                results.append(item)
            return results

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific incident by its unique identifier."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if row:
                item = dict(row)
                try:
                    item["destination_ports"] = json.loads(item["destination_ports"])
                except Exception:
                    pass
                return item
            return None

    def update_incident_status(
        self,
        incident_id: str,
        new_status: str,
        operator: str = "SOC Analyst"
    ) -> bool:
        """Update incident lifecycle state and record an audit entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, incident_id))
            if cursor.rowcount > 0:
                conn.commit()
                # Log audit action
                self.log_audit_action(
                    incident_id=incident_id,
                    action_type="STATUS_UPDATE",
                    target_ip="N/A",
                    execution_mode="live",
                    operator=operator,
                    details=f"Incident status updated to '{new_status}'",
                    result="SUCCESS"
                )
                return True
            return False

    def log_audit_action(
        self,
        incident_id: str,
        action_type: str,
        target_ip: str,
        execution_mode: str,
        operator: str,
        details: str,
        result: str
    ) -> str:
        """Record an immutable entry in the SOC response audit trail."""
        log_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO audit_logs (
                log_id, timestamp, incident_id, action_type,
                target_ip, execution_mode, operator, details, result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id, ts, incident_id, action_type,
                target_ip, execution_mode, operator, details, result
            ))
            conn.commit()
        return log_id

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit log entries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def reset_demo_data(self, sample_csv_path: Optional[str] = None):
        """Safely seed initial realistic demonstration incidents."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents")
            cursor.execute("DELETE FROM audit_logs")
            conn.commit()

        initial_incidents = [
            {
                "incident_id": "INC-1001",
                "first_seen": "10:00:05",
                "category": "Port Scan",
                "source_ip": "192.168.1.15",
                "destination_ip": "192.168.1.1",
                "destination_ports": [80, 22, 443, 8080],
                "event_count": 4,
                "total_packets": 450,
                "severity": "High",
                "confidence": 0.90,
                "rule_id": "RULE-PORT-SCAN-01",
                "mitre_id": "T1046",
                "evidence": "Host contacted 4 distinct ports across 4 connection attempts within 10 seconds.",
                "recommended_action": "Apply border firewall drop for source IP.",
                "detection_method": "Stateful Port Diversity Correlation",
                "status": "Open"
            },
            {
                "incident_id": "INC-1002",
                "first_seen": "10:00:15",
                "category": "Brute Force",
                "source_ip": "192.168.1.15",
                "destination_ip": "192.168.1.200",
                "destination_ports": [22],
                "event_count": 8,
                "total_packets": 380,
                "severity": "High",
                "confidence": 0.92,
                "rule_id": "RULE-BRUTE-FORCE-01",
                "mitre_id": "T1110",
                "evidence": "Repeated authentication failures against SSH port 22 from source host.",
                "recommended_action": "Drop active sessions and enforce mandatory password reset.",
                "detection_method": "Heuristic Authentication Frequency",
                "status": "Investigating"
            },
            {
                "incident_id": "INC-1003",
                "first_seen": "10:00:18",
                "category": "Data Exfiltration",
                "source_ip": "192.168.1.42",
                "destination_ip": "203.0.113.88",
                "destination_ports": [443],
                "event_count": 1,
                "total_packets": 520,
                "severity": "High",
                "confidence": 0.86,
                "rule_id": "RULE-EXFIL-01",
                "mitre_id": "T1048",
                "evidence": "Atypical outbound bulk transmission directed towards external IP 203.0.113.88.",
                "recommended_action": "Quarantine host, dump memory for forensics, and sever egress.",
                "detection_method": "Outbound Volume Baseline Deviation",
                "status": "Investigating"
            },
            {
                "incident_id": "INC-1004",
                "first_seen": "10:00:24",
                "category": "DDoS Flood",
                "source_ip": "192.168.1.99",
                "destination_ip": "192.168.1.1",
                "destination_ports": [8080],
                "event_count": 1,
                "total_packets": 920,
                "severity": "Critical",
                "confidence": 0.95,
                "rule_id": "RULE-DDOS-01",
                "mitre_id": "T1498",
                "evidence": "Volumetric packet surge: 920 packets exceeds critical link threshold (800).",
                "recommended_action": "Activate upstream DDoS scrubbing and rate-limiting scrubbers.",
                "detection_method": "Volumetric Surge Threshold",
                "status": "Mitigated"
            }
        ]

        for inc in initial_incidents:
            self.save_incident(inc)

        # Log reset audit action
        self.log_audit_action(
            incident_id="SYSTEM",
            action_type="DEMO_DATA_RESET",
            target_ip="ALL",
            execution_mode="live",
            operator="System Initialization",
            details="Demo security incidents initialized.",
            result="SUCCESS"
        )


# Factory function
_db_instance = None

def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    global _db_instance
    if _db_instance is None or db_path is not None:
        _db_instance = DatabaseManager(db_path=db_path)
    return _db_instance
