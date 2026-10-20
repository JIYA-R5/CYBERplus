"""
SentinelAI - Database & Persistence Module
Embedded SQLite persistence engine managing security incidents, raw/correlated telemetry,
analyst audit trails, analyst feedback & ground-truth labels, model registry,
temporary containment blocks, and status transitions.
"""

import sqlite3
import json
import uuid
import datetime
import os
import re
from typing import Dict, Any, List, Optional, Union
import pandas as pd


IDENTITY_DISCLAIMER = (
    "Network IP Indicator Notice: IP addresses identify routing endpoints and may be "
    "dynamically assigned via DHCP, shared via NAT/CGNAT, or spoofed. Indicator recurrence "
    "represents repeated telemetry observations from this address, NOT proof of a specific person's identity."
)


def mask_sensitive_payload(data: Any) -> Any:
    """
    Sanitize sensitive log data (passwords, bearer tokens, API keys) before storing raw evidence.
    """
    if isinstance(data, str):
        # Mask authorization headers, bearer tokens, passwords
        data = re.sub(r'(bearer\s+)[a-zA-Z0-9_\-\.]{8,}', r'\1[REDACTED_TOKEN]', data, flags=re.IGNORECASE)
        data = re.sub(r'(password[\"\'\s:=]+)[\"\'\w\-\.@!#$%^&*]+', r'\1[REDACTED]', data, flags=re.IGNORECASE)
        data = re.sub(r'(key[\"\'\s:=]+)[\"\'\w\-\.@!#$%^&*]{16,}', r'\1[REDACTED_KEY]', data, flags=re.IGNORECASE)
        return data
    elif isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if any(s in k.lower() for s in ["password", "secret", "token", "auth_key", "api_key", "credential", "key"]):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = mask_sensitive_payload(v)
        return cleaned
    elif isinstance(data, list):
        return [mask_sensitive_payload(item) for item in data]
    return data


class DatabaseManager:
    """
    Manages local SQLite database operations for SentinelAI with automatic table creation,
    schema migrations, safe parameterized queries, deduplication, and audit logging.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
                tmp_dir = "/tmp"
                self.db_path = os.path.join(tmp_dir, "sentinel.db")
                base_dir = os.path.dirname(__file__)
                orig_db = os.path.join(base_dir, "sentinel.db")
                if os.path.exists(orig_db) and not os.path.exists(self.db_path):
                    import shutil
                    try:
                        shutil.copy2(orig_db, self.db_path)
                    except Exception:
                        pass
            else:
                base_dir = os.path.dirname(__file__)
                self.db_path = os.path.join(base_dir, "sentinel.db")
        else:
            self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema and perform non-destructive migrations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Incidents table
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

            # Schema Migration: dynamically add new columns to incidents if they don't exist
            cursor.execute("PRAGMA table_info(incidents)")
            existing_cols = {row["name"] for row in cursor.fetchall()}

            new_columns = [
                ("last_seen", "TEXT"),
                ("protocols", "TEXT"),
                ("model_version", "TEXT DEFAULT 'N/A'"),
                ("ml_anomaly_score", "REAL DEFAULT 0.0"),
                ("ml_is_anomaly", "INTEGER DEFAULT 0"),
                ("recurrence_count", "INTEGER DEFAULT 1"),
                ("analyst_verdict", "TEXT DEFAULT 'Unreviewed'"),
                ("analyst_user", "TEXT"),
                ("analyst_reason", "TEXT"),
                ("analyst_timestamp", "TEXT"),
                ("response_history", "TEXT"),
                ("raw_evidence", "TEXT"),
            ]

            for col_name, col_type in new_columns:
                if col_name not in existing_cols:
                    cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type}")

            # 2. Audit logs table
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

            # 3. Raw events table
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

            # 4. Analyst feedback & ground truth reviewed labels table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                feedback_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                analyst_user TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT,
                model_version TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
            )
            """)

            # 5. Model registry table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_registry (
                model_id TEXT PRIMARY KEY,
                version TEXT NOT NULL UNIQUE,
                algorithm TEXT NOT NULL,
                created_at TEXT NOT NULL,
                trained_by TEXT NOT NULL,
                sample_count INTEGER NOT NULL,
                metrics TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                is_active INTEGER DEFAULT 0
            )
            """)

            # 6. Active temporary & permanent blocks table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_blocks (
                block_id TEXT PRIMARY KEY,
                incident_id TEXT,
                target_ip TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                duration_minutes INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                status TEXT NOT NULL,
                approval_status TEXT NOT NULL,
                approved_by TEXT,
                verification_status TEXT NOT NULL,
                rollback_commands TEXT,
                audit_id TEXT
            )
            """)

            # Indexes for performant filtering
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_source ON incidents(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_inc ON analyst_feedback(incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocks_status ON active_blocks(status)")
            conn.commit()

    def get_ip_recurrence_count(self, source_ip: str) -> int:
        """Calculate how many incidents have been observed from this source IP."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM incidents WHERE source_ip = ?", (source_ip,))
            row = cursor.fetchone()
            return int(row["count"]) if row else 0

    def save_incident(self, incident_data: Dict[str, Any]) -> str:
        """
        Insert or update a security incident. Handles both Incident objects and dicts.
        Preserves raw evidence, model versions, and recurrence history.
        """
        inc_id = incident_data.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"
        first_seen = incident_data.get("first_seen") or incident_data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = incident_data.get("last_seen") or first_seen

        ports = incident_data.get("destination_ports", [])
        ports_json = json.dumps(ports) if isinstance(ports, list) else str(ports)

        protocols = incident_data.get("protocols", ["TCP"])
        proto_json = json.dumps(protocols) if isinstance(protocols, list) else str(protocols)

        src_ip = incident_data.get("source_ip", "0.0.0.0")

        # Recurrence calculation
        recurrence = incident_data.get("recurrence_count")
        if recurrence is None:
            prev_count = self.get_ip_recurrence_count(src_ip)
            # If incident already exists, maintain count; otherwise count + 1
            existing = self.get_incident_by_id(inc_id)
            recurrence = prev_count if existing else (prev_count + 1)
            recurrence = max(1, recurrence)

        raw_ev = incident_data.get("raw_evidence") or incident_data.get("evidence", "")
        raw_ev_safe = json.dumps(mask_sensitive_payload(raw_ev)) if isinstance(raw_ev, (dict, list)) else str(raw_ev)

        resp_hist = incident_data.get("response_history", [])
        resp_hist_json = json.dumps(resp_hist) if isinstance(resp_hist, list) else str(resp_hist)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                incident_id, timestamp, category, source_ip, destination_ip,
                destination_ports, event_count, total_packets, severity,
                confidence, rule_id, mitre_id, evidence, recommended_action,
                detection_method, status, last_seen, protocols, model_version,
                ml_anomaly_score, ml_is_anomaly, recurrence_count,
                analyst_verdict, analyst_user, analyst_reason, analyst_timestamp,
                response_history, raw_evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inc_id,
                first_seen,
                incident_data.get("category", "Unknown Threat"),
                src_ip,
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
                incident_data.get("status", "Open"),
                last_seen,
                proto_json,
                incident_data.get("model_version", "v1.0.0"),
                float(incident_data.get("ml_anomaly_score", 0.0)),
                int(bool(incident_data.get("ml_is_anomaly", False))),
                int(recurrence),
                incident_data.get("analyst_verdict", "Unreviewed"),
                incident_data.get("analyst_user", ""),
                incident_data.get("analyst_reason", ""),
                incident_data.get("analyst_timestamp", ""),
                resp_hist_json,
                raw_ev_safe
            ))
            conn.commit()
        return inc_id

    def get_incidents(
        self,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        verdict_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query incidents with optional filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status_filter and status_filter != "All":
            query += " AND status = ?"
            params.append(status_filter)
        if severity_filter and severity_filter != "All":
            query += " AND severity = ?"
            params.append(severity_filter)
        if verdict_filter and verdict_filter != "All":
            query += " AND analyst_verdict = ?"
            params.append(verdict_filter)

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
                try:
                    item["protocols"] = json.loads(item["protocols"]) if item.get("protocols") else ["TCP"]
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
                try:
                    item["protocols"] = json.loads(item["protocols"]) if item.get("protocols") else ["TCP"]
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

    def record_analyst_feedback(
        self,
        incident_id: str,
        verdict: str,
        analyst_user: str,
        reason: str,
        model_version: Optional[str] = None
    ) -> str:
        """
        Record authorized analyst feedback (True Positive, False Positive, Benign, Unresolved).
        Stores ground-truth feedback separately in analyst_feedback table and updates the incident.
        """
        valid_verdicts = ["True Positive", "False Positive", "Benign", "Unresolved"]
        if verdict not in valid_verdicts:
            raise ValueError(f"Invalid verdict '{verdict}'. Must be one of {valid_verdicts}")

        feedback_id = f"FB-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        inc = self.get_incident_by_id(incident_id)
        active_version = model_version or (inc.get("model_version") if inc else "v1.0.0")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Insert into dedicated ground-truth feedback table
            cursor.execute("""
            INSERT INTO analyst_feedback (
                feedback_id, incident_id, timestamp, analyst_user, verdict, reason, model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (feedback_id, incident_id, ts, analyst_user, verdict, reason, active_version))

            # 2. Update incident record
            cursor.execute("""
            UPDATE incidents SET
                analyst_verdict = ?,
                analyst_user = ?,
                analyst_reason = ?,
                analyst_timestamp = ?
            WHERE incident_id = ?
            """, (verdict, analyst_user, reason, ts, incident_id))

            conn.commit()

        # 3. Log audit entry
        self.log_audit_action(
            incident_id=incident_id,
            action_type="ANALYST_FEEDBACK",
            target_ip=inc.get("source_ip", "N/A") if inc else "N/A",
            execution_mode="live",
            operator=analyst_user,
            details=f"Analyst verdict recorded: '{verdict}'. Reason: {reason}",
            result="SUCCESS"
        )
        return feedback_id

    def get_feedback_history(self, incident_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve feedback entries for an incident or overall audit history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if incident_id:
                cursor.execute(
                    "SELECT * FROM analyst_feedback WHERE incident_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (incident_id, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM analyst_feedback ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
            return [dict(r) for r in cursor.fetchall()]

    def register_model(
        self,
        version: str,
        algorithm: str,
        sample_count: int,
        metrics: Dict[str, Any],
        artifact_path: str,
        trained_by: str = "SOC ML Pipeline",
        set_active: bool = True
    ) -> str:
        """Register a newly trained model version in the database model registry."""
        model_id = f"MOD-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if set_active:
                cursor.execute("UPDATE model_registry SET is_active = 0")

            cursor.execute("""
            INSERT OR REPLACE INTO model_registry (
                model_id, version, algorithm, created_at, trained_by,
                sample_count, metrics, artifact_path, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                model_id,
                version,
                algorithm,
                ts,
                trained_by,
                int(sample_count),
                json.dumps(metrics),
                artifact_path,
                1 if set_active else 0
            ))
            conn.commit()

        self.log_audit_action(
            incident_id="SYSTEM",
            action_type="MODEL_REGISTERED",
            target_ip="N/A",
            execution_mode="live",
            operator=trained_by,
            details=f"Model {version} ({algorithm}) registered with {sample_count} training samples.",
            result="SUCCESS"
        )
        return model_id

    def get_model_registry(self) -> List[Dict[str, Any]]:
        """Retrieve all registered models and their evaluation metrics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM model_registry ORDER BY created_at DESC")
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["metrics"] = json.loads(item["metrics"])
                except Exception:
                    pass
                results.append(item)
            return results

    def get_active_model(self) -> Optional[Dict[str, Any]]:
        """Get the currently active model from the registry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM model_registry WHERE is_active = 1 LIMIT 1")
            row = cursor.fetchone()
            if row:
                item = dict(row)
                try:
                    item["metrics"] = json.loads(item["metrics"])
                except Exception:
                    pass
                return item
            return None

    def set_active_model_version(self, version: str) -> bool:
        """Promote or revert active model to specified version."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM model_registry WHERE version = ?", (version,))
            if not cursor.fetchone():
                return False

            cursor.execute("UPDATE model_registry SET is_active = 0")
            cursor.execute("UPDATE model_registry SET is_active = 1 WHERE version = ?", (version,))
            conn.commit()

        self.log_audit_action(
            incident_id="SYSTEM",
            action_type="MODEL_ACTIVATED",
            target_ip="N/A",
            execution_mode="live",
            operator="SOC Admin",
            details=f"Active model set to version '{version}'",
            result="SUCCESS"
        )
        return True

    def create_active_block(
        self,
        incident_id: str,
        target_ip: str,
        rule_type: str,
        duration_minutes: Optional[int],
        approval_status: str,
        approved_by: Optional[str],
        verification_status: str,
        rollback_commands: Dict[str, str],
        audit_id: Optional[str] = None
    ) -> str:
        """Create and track an active containment block with expiry tracking."""
        block_id = f"BLK-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")

        expires_at = None
        if rule_type == "Temporary" and duration_minutes:
            exp_dt = now + datetime.timedelta(minutes=duration_minutes)
            expires_at = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO active_blocks (
                block_id, incident_id, target_ip, rule_type, duration_minutes,
                created_at, expires_at, status, approval_status, approved_by,
                verification_status, rollback_commands, audit_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                block_id,
                incident_id,
                target_ip,
                rule_type,
                duration_minutes,
                created_at,
                expires_at,
                "Active" if approval_status == "Approved" else "Pending",
                approval_status,
                approved_by,
                verification_status,
                json.dumps(rollback_commands),
                audit_id
            ))
            conn.commit()
        return block_id

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Retrieve all tracked active or temporary firewall rules."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM active_blocks ORDER BY created_at DESC")
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["rollback_commands"] = json.loads(item["rollback_commands"])
                except Exception:
                    pass
                results.append(item)
            return results

    def check_and_expire_blocks(self) -> List[Dict[str, Any]]:
        """Check for temporary blocks past their expiration and mark them Expired."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expired_list = []

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM active_blocks WHERE status = 'Active' AND expires_at IS NOT NULL AND expires_at <= ?",
                (now_str,)
            )
            rows = cursor.fetchall()
            for r in rows:
                item = dict(r)
                cursor.execute("UPDATE active_blocks SET status = 'Expired' WHERE block_id = ?", (item["block_id"],))
                expired_list.append(item)
            conn.commit()

        for item in expired_list:
            self.log_audit_action(
                incident_id=item["incident_id"] or "SYSTEM",
                action_type="FIREWALL_EXPIRED",
                target_ip=item["target_ip"],
                execution_mode="live",
                operator="Automated Expiry Watchdog",
                details=f"Temporary block rule {item['block_id']} expired. Rollback executed.",
                result="SUCCESS"
            )
        return expired_list

    def rollback_block(self, block_id: str, operator: str = "SOC Admin") -> Dict[str, Any]:
        """Roll back an active firewall block."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM active_blocks WHERE block_id = ?", (block_id,))
            row = cursor.fetchone()
            if not row:
                return {"status": "ERROR", "message": f"Block ID '{block_id}' not found."}

            item = dict(row)
            cursor.execute("UPDATE active_blocks SET status = 'Rolled_Back' WHERE block_id = ?", (block_id,))
            conn.commit()

        self.log_audit_action(
            incident_id=item["incident_id"] or "SYSTEM",
            action_type="FIREWALL_ROLLBACK",
            target_ip=item["target_ip"],
            execution_mode="live",
            operator=operator,
            details=f"Block {block_id} on {item['target_ip']} rolled back.",
            result="SUCCESS"
        )
        return {"status": "SUCCESS", "block_id": block_id, "target_ip": item["target_ip"]}

    def apply_data_retention(self, retention_days: int = 30, operator: str = "System Maintenance") -> Dict[str, int]:
        """
        Purge unflagged telemetry events and archived benign/resolved incidents older than retention window.
        """
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM telemetry_events WHERE timestamp < ?", (cutoff,))
            purged_telemetry = cursor.rowcount

            cursor.execute(
                "DELETE FROM incidents WHERE status IN ('Resolved', 'False Positive') AND timestamp < ?",
                (cutoff,)
            )
            purged_incidents = cursor.rowcount
            conn.commit()

        self.log_audit_action(
            incident_id="SYSTEM",
            action_type="DATA_RETENTION_PURGE",
            target_ip="ALL",
            execution_mode="live",
            operator=operator,
            details=f"Data retention policy applied: {purged_telemetry} telemetry events and {purged_incidents} resolved incidents purged.",
            result="SUCCESS"
        )
        return {"purged_telemetry": purged_telemetry, "purged_incidents": purged_incidents}

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
            cursor.execute("DELETE FROM analyst_feedback")
            cursor.execute("DELETE FROM active_blocks")
            cursor.execute("DELETE FROM model_registry")
            conn.commit()

        initial_incidents = [
            {
                "incident_id": "INC-1001",
                "first_seen": "10:00:05",
                "last_seen": "10:00:15",
                "category": "Port Scan",
                "source_ip": "192.168.1.15",
                "destination_ip": "192.168.1.1",
                "destination_ports": [80, 22, 443, 8080],
                "protocols": ["TCP"],
                "event_count": 4,
                "total_packets": 450,
                "severity": "High",
                "confidence": 0.90,
                "rule_id": "RULE-PORT-SCAN-01",
                "mitre_id": "T1046",
                "evidence": "Host contacted 4 distinct ports across 4 connection attempts within 10 seconds.",
                "recommended_action": "Apply border firewall drop for source IP.",
                "detection_method": "Stateful Port Diversity Correlation",
                "model_version": "v1.0.0",
                "ml_anomaly_score": -0.18,
                "ml_is_anomaly": 1,
                "recurrence_count": 1,
                "analyst_verdict": "Unreviewed",
                "status": "Open"
            },
            {
                "incident_id": "INC-1002",
                "first_seen": "10:00:15",
                "last_seen": "10:00:25",
                "category": "Brute Force",
                "source_ip": "192.168.1.15",
                "destination_ip": "192.168.1.200",
                "destination_ports": [22],
                "protocols": ["TCP"],
                "event_count": 8,
                "total_packets": 380,
                "severity": "High",
                "confidence": 0.92,
                "rule_id": "RULE-BRUTE-FORCE-01",
                "mitre_id": "T1110",
                "evidence": "Repeated authentication failures against SSH port 22 from source host.",
                "recommended_action": "Drop active sessions and enforce mandatory password reset.",
                "detection_method": "Heuristic Authentication Frequency",
                "model_version": "v1.0.0",
                "ml_anomaly_score": -0.22,
                "ml_is_anomaly": 1,
                "recurrence_count": 2,
                "analyst_verdict": "True Positive",
                "analyst_user": "Senior SOC Analyst",
                "analyst_reason": "Verified multiple failed root login attempts in auth.log",
                "status": "Investigating"
            },
            {
                "incident_id": "INC-1003",
                "first_seen": "10:00:18",
                "last_seen": "10:00:22",
                "category": "Data Exfiltration",
                "source_ip": "192.168.1.42",
                "destination_ip": "203.0.113.88",
                "destination_ports": [443],
                "protocols": ["TCP"],
                "event_count": 1,
                "total_packets": 520,
                "severity": "High",
                "confidence": 0.86,
                "rule_id": "RULE-EXFIL-01",
                "mitre_id": "T1048",
                "evidence": "Atypical outbound bulk transmission directed towards external IP 203.0.113.88.",
                "recommended_action": "Quarantine host, dump memory for forensics, and sever egress.",
                "detection_method": "Outbound Volume Baseline Deviation",
                "model_version": "v1.0.0",
                "ml_anomaly_score": -0.15,
                "ml_is_anomaly": 1,
                "recurrence_count": 1,
                "analyst_verdict": "Unreviewed",
                "status": "Investigating"
            },
            {
                "incident_id": "INC-1004",
                "first_seen": "10:00:24",
                "last_seen": "10:00:30",
                "category": "DDoS Flood",
                "source_ip": "192.168.1.99",
                "destination_ip": "192.168.1.1",
                "destination_ports": [8080],
                "protocols": ["TCP"],
                "event_count": 1,
                "total_packets": 920,
                "severity": "Critical",
                "confidence": 0.95,
                "rule_id": "RULE-DDOS-01",
                "mitre_id": "T1498",
                "evidence": "Volumetric packet surge: 920 packets exceeds critical link threshold (800).",
                "recommended_action": "Activate upstream DDoS scrubbing and rate-limiting scrubbers.",
                "detection_method": "Volumetric Surge Threshold",
                "model_version": "v1.0.0",
                "ml_anomaly_score": -0.35,
                "ml_is_anomaly": 1,
                "recurrence_count": 1,
                "analyst_verdict": "True Positive",
                "analyst_user": "Lead Incident Responder",
                "analyst_reason": "Upstream SYN flood corroborated by ISP edge flow telemetry.",
                "status": "Mitigated"
            }
        ]

        for inc in initial_incidents:
            self.save_incident(inc)

        # Register baseline model version v1.0.0 in registry
        self.register_model(
            version="v1.0.0",
            algorithm="IsolationForest",
            sample_count=200,
            metrics={
                "contamination": 0.15,
                "empirical_outlier_ratio": 0.15,
                "features": ["packets", "port", "flow_frequency", "unique_ports_contacted"]
            },
            artifact_path="models/isolation_forest_v1.0.0.joblib",
            trained_by="SentinelAI Baseline Initialization",
            set_active=True
        )

        # Log reset audit action
        self.log_audit_action(
            incident_id="SYSTEM",
            action_type="DEMO_DATA_RESET",
            target_ip="ALL",
            execution_mode="live",
            operator="System Initialization",
            details="Demo security incidents initialized with persistent threat memory schema.",
            result="SUCCESS"
        )


# Factory function
_db_instance = None

def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    global _db_instance
    if _db_instance is None or db_path is not None:
        _db_instance = DatabaseManager(db_path=db_path)
    return _db_instance
