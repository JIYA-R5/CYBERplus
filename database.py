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
import threading
from typing import Dict, Any, List, Optional, Union
import pandas as pd


SAFE_LOG_RETENTION_HOURS = int(os.environ.get("SAFE_LOG_RETENTION_HOURS", "24"))

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
        target_env = os.environ.get("DATABASE_PATH") or os.environ.get("SENTINEL_DB_PATH")
        if db_path is None:
            if target_env:
                self.db_path = target_env
                # If target db doesn't exist yet but root sentinel.db exists, seed it
                base_dir = os.path.dirname(os.path.abspath(__file__))
                orig_db = os.path.join(base_dir, "sentinel.db")
                if os.path.exists(orig_db) and not os.path.exists(self.db_path) and os.path.abspath(orig_db) != os.path.abspath(self.db_path):
                    import shutil
                    try:
                        parent_target = os.path.dirname(os.path.abspath(self.db_path))
                        if parent_target:
                            os.makedirs(parent_target, exist_ok=True)
                        shutil.copy2(orig_db, self.db_path)
                    except Exception:
                        pass
            elif os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
                tmp_dir = "/tmp"
                self.db_path = os.path.join(tmp_dir, "sentinel.db")
                base_dir = os.path.dirname(os.path.abspath(__file__))
                orig_db = os.path.join(base_dir, "sentinel.db")
                if os.path.exists(orig_db) and not os.path.exists(self.db_path):
                    import shutil
                    try:
                        shutil.copy2(orig_db, self.db_path)
                    except Exception:
                        pass
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                self.db_path = os.path.join(base_dir, "sentinel.db")
        else:
            self.db_path = db_path

        self.retention_hours = int(os.environ.get("SAFE_LOG_RETENTION_HOURS", "24"))

        # Ensure parent directory exists
        parent_dir = os.path.dirname(os.path.abspath(self.db_path))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        self._init_db()
        self.pg_url = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL")
        self.pg_conn = None
        self._init_postgres()

    def _init_postgres(self):
        """Initializes PostgreSQL connection if POSTGRES_URL or DATABASE_URL is configured."""
        if not self.pg_url or not (self.pg_url.startswith("postgres://") or self.pg_url.startswith("postgresql://")):
            return
        try:
            import psycopg2
            self.pg_conn = psycopg2.connect(self.pg_url, connect_timeout=5)
            self.pg_conn.autocommit = True
            with self.pg_conn.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_id VARCHAR(64) PRIMARY KEY,
                    timestamp VARCHAR(64) NOT NULL,
                    source_ip VARCHAR(64) NOT NULL,
                    destination_ip VARCHAR(64),
                    port INTEGER,
                    packets INTEGER DEFAULT 0,
                    activity VARCHAR(128),
                    risk VARCHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id VARCHAR(64) PRIMARY KEY,
                    timestamp VARCHAR(64) NOT NULL,
                    category VARCHAR(128) NOT NULL,
                    source_ip VARCHAR(64) NOT NULL,
                    destination_ip VARCHAR(64),
                    destination_ports TEXT,
                    event_count INTEGER DEFAULT 1,
                    total_packets INTEGER DEFAULT 0,
                    severity VARCHAR(64) NOT NULL,
                    confidence REAL NOT NULL,
                    rule_id VARCHAR(64),
                    mitre_id VARCHAR(64),
                    evidence TEXT,
                    recommended_action TEXT,
                    detection_method TEXT,
                    status VARCHAR(64) DEFAULT 'Open',
                    last_seen VARCHAR(64),
                    ml_anomaly_score REAL DEFAULT 0.0,
                    ml_is_anomaly INTEGER DEFAULT 0,
                    recurrence_count INTEGER DEFAULT 1,
                    analyst_verdict VARCHAR(64) DEFAULT 'Unreviewed',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """)
        except Exception:
            self.pg_conn = None

    def get_postgres_status(self) -> Dict[str, Any]:
        """Check PostgreSQL connection status and metrics."""
        if not self.pg_url:
            return {"configured": False, "connected": False, "message": "POSTGRES_URL / DATABASE_URL not set"}
        if self.pg_conn is None:
            self._init_postgres()
        if self.pg_conn:
            try:
                with self.pg_conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM telemetry_events;")
                    evt_count = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM incidents;")
                    inc_count = cur.fetchone()[0]
                return {
                    "configured": True,
                    "connected": True,
                    "events_count": evt_count,
                    "incidents_count": inc_count
                }
            except Exception as e:
                self.pg_conn = None
                return {"configured": True, "connected": False, "error": str(e)}
        return {"configured": True, "connected": False, "message": "Failed to connect to PostgreSQL"}

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
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
                ("is_replay", "INTEGER DEFAULT 0"),
                ("telemetry_source", "TEXT DEFAULT 'live'"),
                ("associated_log_ids", "TEXT DEFAULT '[]'"),
                ("gemini_analysis", "TEXT"),
                ("first_detected", "TEXT"),
                ("last_detected", "TEXT"),
                ("recommended_response", "TEXT"),
                ("user_review_status", "TEXT DEFAULT 'Unreviewed'"),
                ("geoip_country", "TEXT"),
                ("geoip_region", "TEXT"),
                ("geoip_city", "TEXT"),
                ("latitude", "REAL"),
                ("longitude", "REAL"),
                ("accuracy_km", "INTEGER"),
                ("accuracy_radius", "INTEGER"),
                ("geoip_status", "TEXT DEFAULT 'pending'"),
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

            # 7. PCAP Captures metadata table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS pcap_captures (
                capture_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                format TEXT NOT NULL,
                packet_count INTEGER DEFAULT 0,
                flow_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'Completed',
                metadata TEXT
            )
            """)

            # 8. PCAP Bidirectional Flow Records table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS pcap_flows (
                flow_id TEXT PRIMARY KEY,
                capture_id TEXT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                duration REAL,
                total_packets INTEGER,
                total_bytes INTEGER,
                forward_packets INTEGER,
                backward_packets INTEGER,
                tcp_flags TEXT,
                start_time REAL,
                end_time REAL,
                supervised_label TEXT,
                ml_anomaly_score REAL,
                FOREIGN KEY (capture_id) REFERENCES pcap_captures(capture_id)
            )
            """)

            # 9. GeoIP Cache table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS geoip_cache (
                ip_address TEXT PRIMARY KEY,
                is_public INTEGER NOT NULL,
                ip_type TEXT,
                country TEXT,
                country_code TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn TEXT,
                org TEXT,
                provider TEXT,
                accuracy_radius INTEGER,
                status TEXT NOT NULL,
                lookup_time TEXT NOT NULL,
                expires_at TEXT,
                raw_response TEXT
            )
            """)

            # 10. Incident Investigations Cache table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_investigations (
                investigation_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                provider TEXT NOT NULL,
                model_name TEXT,
                report_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """)

            # 11. Network Logs Table (Continuous Real-Time Telemetry & 24h Safe-Log Retention)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_logs (
                log_id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                timestamp TEXT NOT NULL,
                packet_size INTEGER DEFAULT 0,
                event_type TEXT DEFAULT 'network_flow',
                collector_id TEXT DEFAULT 'host_agent',
                detection_status TEXT DEFAULT 'unprocessed',
                severity TEXT DEFAULT 'Low',
                detection_reason TEXT,
                ml_anomaly_score REAL DEFAULT 0.0,
                geoip_country TEXT,
                geoip_region TEXT,
                geoip_city TEXT,
                latitude REAL,
                longitude REAL,
                accuracy_radius INTEGER,
                accuracy_km INTEGER,
                geoip_status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                retention_status TEXT DEFAULT 'auto_delete',
                expires_at TEXT NOT NULL,
                is_preserved INTEGER DEFAULT 0,
                preserved_at TEXT,
                export_status TEXT DEFAULT 'not_exported',
                incident_id TEXT,
                ingestion_delay_ms REAL DEFAULT 0.0,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL
            )
            """)

            # 12. System Activity & Governance Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_activity (
                activity_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                operator TEXT DEFAULT 'System',
                details TEXT,
                result TEXT DEFAULT 'SUCCESS'
            )
            """)

            # Schema Migration for network_logs
            cursor.execute("PRAGMA table_info(network_logs)")
            existing_netlog_cols = {row["name"] for row in cursor.fetchall()}
            netlog_mig_cols = [
                ("packet_size", "INTEGER DEFAULT 0"),
                ("event_type", "TEXT DEFAULT 'network_flow'"),
                ("collector_id", "TEXT DEFAULT 'host_agent'"),
                ("detection_status", "TEXT DEFAULT 'unprocessed'"),
                ("detection_reason", "TEXT"),
                ("ml_anomaly_score", "REAL DEFAULT 0.0"),
                ("geoip_country", "TEXT"),
                ("geoip_region", "TEXT"),
                ("geoip_city", "TEXT"),
                ("latitude", "REAL"),
                ("longitude", "REAL"),
                ("accuracy_radius", "INTEGER"),
                ("accuracy_km", "INTEGER"),
                ("geoip_status", "TEXT DEFAULT 'pending'"),
                ("retention_status", "TEXT DEFAULT 'auto_delete'"),
                ("expires_at", "TEXT"),
                ("is_preserved", "INTEGER DEFAULT 0"),
                ("preserved_at", "TEXT"),
                ("export_status", "TEXT DEFAULT 'not_exported'"),
                ("incident_id", "TEXT"),
                ("ingestion_delay_ms", "REAL DEFAULT 0.0")
            ]
            for col_name, col_type in netlog_mig_cols:
                if col_name not in existing_netlog_cols:
                    cursor.execute(f"ALTER TABLE network_logs ADD COLUMN {col_name} {col_type}")

            # Indexes for performant filtering
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_source ON incidents(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_inc ON analyst_feedback(incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocks_status ON active_blocks(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_capture ON pcap_flows(capture_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src ON pcap_flows(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_geoip_status ON geoip_cache(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigation_inc_hash ON incident_investigations(incident_id, evidence_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_timestamp ON network_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_created_at ON network_logs(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_source_ip ON network_logs(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_severity ON network_logs(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_detection_status ON network_logs(detection_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_retention ON network_logs(retention_status, is_preserved, expires_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netlogs_incident_id ON network_logs(incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sysact_timestamp ON system_activity(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sysact_type ON system_activity(activity_type)")
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
                response_history, raw_evidence, is_replay, telemetry_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                raw_ev_safe,
                1 if incident_data.get("is_replay") else 0,
                str(incident_data.get("telemetry_source") or ("pcap_replay" if incident_data.get("is_replay") else "live"))
            ))
            conn.commit()

        # Publish alert to Redis Stream
        try:
            from stream_engine import get_stream_publisher
            get_stream_publisher().publish_alert({
                "incident_id": inc_id,
                "timestamp": first_seen,
                "category": incident_data.get("category", "Unknown Threat"),
                "source_ip": src_ip,
                "destination_ip": incident_data.get("destination_ip", "Internal Subnet"),
                "severity": incident_data.get("severity", "Medium"),
                "confidence": float(incident_data.get("confidence", 0.5)),
                "rule_id": incident_data.get("rule_id", "N/A"),
                "detection_method": incident_data.get("detection_method", "Rule-based heuristic")
            })
        except Exception:
            pass

        # Persist alert to PostgreSQL if configured
        if self.pg_conn:
            try:
                with self.pg_conn.cursor() as cur:
                    cur.execute("""
                    INSERT INTO incidents (
                        incident_id, timestamp, category, source_ip, destination_ip,
                        destination_ports, event_count, total_packets, severity,
                        confidence, rule_id, mitre_id, evidence, recommended_action,
                        detection_method, status, last_seen, ml_anomaly_score, ml_is_anomaly,
                        recurrence_count, analyst_verdict
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (incident_id) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen,
                        event_count = EXCLUDED.event_count,
                        total_packets = EXCLUDED.total_packets,
                        status = EXCLUDED.status,
                        analyst_verdict = EXCLUDED.analyst_verdict;
                    """, (
                        inc_id, first_seen, incident_data.get("category", "Unknown Threat"),
                        src_ip, incident_data.get("destination_ip", "Internal Subnet"),
                        ports_json, int(incident_data.get("event_count", 1)),
                        int(incident_data.get("total_packets", 0)), incident_data.get("severity", "Medium"),
                        float(incident_data.get("confidence", 0.5)), incident_data.get("rule_id", "N/A"),
                        incident_data.get("mitre_id", "N/A"), incident_data.get("evidence", ""),
                        incident_data.get("recommended_action", ""), incident_data.get("detection_method", "Rule-based heuristic"),
                        incident_data.get("status", "Open"), last_seen,
                        float(incident_data.get("ml_anomaly_score", 0.0)), int(bool(incident_data.get("ml_is_anomaly", False))),
                        int(recurrence), incident_data.get("analyst_verdict", "Unreviewed")
                    ))
            except Exception:
                pass

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

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Alias for get_incident_by_id."""
        return self.get_incident_by_id(incident_id)

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

    def save_pcap_capture(self, capture_data: Dict[str, Any]) -> str:
        """Stores PCAP/PCAPNG capture metadata in database."""
        cap_id = capture_data.get("capture_id") or f"CAP-{uuid.uuid4().hex[:8].upper()}"
        ts = capture_data.get("uploaded_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO pcap_captures (
                capture_id, filename, file_size, uploaded_at, format,
                packet_count, flow_count, status, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cap_id,
                capture_data.get("filename", "unknown.pcap"),
                int(capture_data.get("file_size", 0)),
                ts,
                capture_data.get("format", "pcap"),
                int(capture_data.get("packet_count", 0)),
                int(capture_data.get("flow_count", 0)),
                capture_data.get("status", "Completed"),
                json.dumps(capture_data.get("metadata", {}))
            ))
            conn.commit()
        return cap_id

    def get_pcap_captures(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List uploaded PCAP captures."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pcap_captures ORDER BY uploaded_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["metadata"] = json.loads(item["metadata"])
                except Exception:
                    pass
                results.append(item)
            return results

    def get_pcap_capture_by_id(self, capture_id: str) -> Optional[Dict[str, Any]]:
        """Get PCAP capture by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pcap_captures WHERE capture_id = ?", (capture_id,))
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["metadata"] = json.loads(item["metadata"])
            except Exception:
                pass
            return item

    def save_pcap_flows(self, capture_id: str, flows: List[Dict[str, Any]]):
        """Batch insert extracted bidirectional flow records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for f in flows:
                f_id = f.get("flow_id") or f"FLOW-{uuid.uuid4().hex[:8].upper()}"
                flags_str = json.dumps(f.get("tcp_flags_seen", {})) if isinstance(f.get("tcp_flags_seen"), dict) else str(f.get("tcp_flags_seen", ""))
                cursor.execute("""
                INSERT OR REPLACE INTO pcap_flows (
                    flow_id, capture_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, duration, total_packets, total_bytes, forward_packets,
                    backward_packets, tcp_flags, start_time, end_time,
                    supervised_label, ml_anomaly_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f_id,
                    capture_id,
                    f.get("src_ip", "0.0.0.0"),
                    f.get("dst_ip", "0.0.0.0"),
                    int(f.get("src_port", 0)),
                    int(f.get("dst_port", 0)),
                    f.get("protocol", "TCP"),
                    float(f.get("duration", 0.0)),
                    int(f.get("total_packets", 0)),
                    int(f.get("total_bytes", 0)),
                    int(f.get("forward_packets", 0)),
                    int(f.get("backward_packets", 0)),
                    flags_str,
                    float(f.get("start_time", 0.0)),
                    float(f.get("end_time", 0.0)),
                    f.get("supervised_label", "Normal Traffic"),
                    float(f.get("ml_anomaly_score", 0.0))
                ))
            conn.commit()

    def get_pcap_flows(self, capture_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve stored flow records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if capture_id:
                cursor.execute("SELECT * FROM pcap_flows WHERE capture_id = ? LIMIT ?", (capture_id, limit))
            else:
                cursor.execute("SELECT * FROM pcap_flows ORDER BY start_time DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["tcp_flags"] = json.loads(item["tcp_flags"])
                except Exception:
                    pass
                results.append(item)
            return results

    def log_telemetry_event(self, event_data: Dict[str, Any]) -> str:
        """Insert a raw telemetry event and stream to Redis."""
        ev_id = event_data.get("event_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"
        ts = event_data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO telemetry_events (
                event_id, timestamp, source_ip, destination_ip, port, packets, activity, risk
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev_id,
                ts,
                event_data.get("source_ip", "0.0.0.0"),
                event_data.get("destination_ip", "10.0.0.1"),
                int(event_data.get("port", event_data.get("destination_port", 80))),
                int(event_data.get("packets", 1)),
                event_data.get("activity", "Normal Traffic"),
                event_data.get("risk", "Low")
            ))
            conn.commit()

        # Stream event to Redis
        try:
            from stream_engine import get_stream_publisher
            get_stream_publisher().publish_event({
                "event_id": ev_id,
                "timestamp": ts,
                "source_ip": event_data.get("source_ip", "0.0.0.0"),
                "destination_ip": event_data.get("destination_ip", "10.0.0.1"),
                "port": int(event_data.get("port", event_data.get("destination_port", 80))),
                "packets": int(event_data.get("packets", 1)),
                "activity": event_data.get("activity", "Normal Traffic")
            })
        except Exception:
            pass

        # Persist event to PostgreSQL if configured
        if self.pg_conn:
            try:
                with self.pg_conn.cursor() as cur:
                    cur.execute("""
                    INSERT INTO telemetry_events (
                        event_id, timestamp, source_ip, destination_ip, port, packets, activity, risk
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING;
                    """, (
                        ev_id, ts, event_data.get("source_ip", "0.0.0.0"),
                        event_data.get("destination_ip", "10.0.0.1"),
                        int(event_data.get("port", event_data.get("destination_port", 80))),
                        int(event_data.get("packets", 1)),
                        event_data.get("activity", "Normal Traffic"),
                        event_data.get("risk", "Low")
                    ))
            except Exception:
                pass

        return ev_id

    def get_telemetry_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Query recent raw telemetry events."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT ?", (limit,))
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

    # --------------------------------------------------------------------------
    # GeoIP Cache & Network Intelligence Persistence
    # --------------------------------------------------------------------------
    def get_cached_geoip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached GeoIP intelligence for an IP address."""
        if not ip_address:
            return None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM geoip_cache WHERE ip_address = ?", (ip_address.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res["ip"] = res.get("ip_address")
            res["is_public"] = bool(res.get("is_public", 1))
            res["disclaimer"] = IDENTITY_DISCLAIMER
            return res

    def save_cached_geoip(self, record: Dict[str, Any]):
        """Persist GeoIP intelligence record into SQLite cache."""
        ip = record.get("ip") or record.get("ip_address")
        if not ip:
            return
        ip = str(ip).strip()
        is_pub = 1 if record.get("is_public", True) else 0
        lookup_t = record.get("lookup_time") or datetime.datetime.now().isoformat()
        exp_t = record.get("expires_at")
        if not exp_t:
            # Default TTL: 24h
            exp_t = (datetime.datetime.now() + datetime.timedelta(hours=24)).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO geoip_cache (
                ip_address, is_public, ip_type, country, country_code, region, city,
                latitude, longitude, asn, org, provider, accuracy_radius, status,
                lookup_time, expires_at, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                is_public=excluded.is_public,
                ip_type=excluded.ip_type,
                country=excluded.country,
                country_code=excluded.country_code,
                region=excluded.region,
                city=excluded.city,
                latitude=excluded.latitude,
                longitude=excluded.longitude,
                asn=excluded.asn,
                org=excluded.org,
                provider=excluded.provider,
                accuracy_radius=excluded.accuracy_radius,
                status=excluded.status,
                lookup_time=excluded.lookup_time,
                expires_at=excluded.expires_at,
                raw_response=excluded.raw_response
            """, (
                ip, is_pub, record.get("ip_type", "public"),
                record.get("country"), record.get("country_code"),
                record.get("region"), record.get("city"),
                record.get("latitude"), record.get("longitude"),
                record.get("asn"), record.get("org"),
                record.get("provider", "unknown"),
                record.get("accuracy_radius"),
                record.get("status", "available"),
                lookup_t, exp_t,
                json.dumps(record.get("raw_response", {})) if isinstance(record.get("raw_response"), dict) else str(record.get("raw_response") or "")
            ))
            conn.commit()

    def get_all_cached_geoip(self) -> List[Dict[str, Any]]:
        """Retrieve all cached GeoIP records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM geoip_cache ORDER BY lookup_time DESC")
            rows = cursor.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["ip"] = d.get("ip_address")
                d["is_public"] = bool(d.get("is_public", 1))
                results.append(d)
            return results

    # --------------------------------------------------------------------------
    # AI Incident Investigation Report Persistence
    # --------------------------------------------------------------------------
    def get_cached_investigation(self, incident_id: str, evidence_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached structured Gemini/local investigation report by incident and evidence hash."""
        if not incident_id or not evidence_hash:
            return None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM incident_investigations
            WHERE incident_id = ? AND evidence_hash = ?
            ORDER BY created_at DESC LIMIT 1
            """, (incident_id, evidence_hash))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["report"] = json.loads(res.get("report_json", "{}"))
            except Exception:
                res["report"] = {}
            return res

    def save_cached_investigation(
        self,
        incident_id: str,
        evidence_hash: str,
        provider: str,
        model_name: Optional[str],
        report_data: Union[Dict[str, Any], str]
    ) -> str:
        """Persist structured investigation report into cache table."""
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.datetime.now().isoformat()
        report_json = json.dumps(report_data) if isinstance(report_data, dict) else str(report_data)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO incident_investigations (
                investigation_id, incident_id, evidence_hash, provider, model_name, report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (inv_id, incident_id, evidence_hash, provider, model_name or "N/A", report_json, now_str))
            conn.commit()
        return inv_id

    # --------------------------------------------------------------------------
    # Continuous Real-Time Network Logs & 24h Safe-Log Retention Governance
    # --------------------------------------------------------------------------
    def insert_network_log(self, log_data: Optional[Dict[str, Any]] = None, **kwargs) -> str:
        """
        Insert a validated network telemetry log with automatic 24h retention calculation.
        Supports both single dictionary argument and keyword arguments.
        """
        data = {}
        if isinstance(log_data, dict):
            data.update(log_data)
        if kwargs:
            data.update(kwargs)
        log_data = data

        log_id = log_data.get("log_id") or f"LOG-{uuid.uuid4().hex[:12].upper()}"
        now_dt = datetime.datetime.now()
        created_at = log_data.get("created_at") or now_dt.isoformat()
        ts = log_data.get("timestamp") or now_dt.strftime("%Y-%m-%d %H:%M:%S")

        src_ip = str(log_data.get("source_ip") or log_data.get("src_ip") or "0.0.0.0")
        dst_ip = str(log_data.get("destination_ip") or log_data.get("dst_ip") or "")
        src_port = log_data.get("source_port") or log_data.get("src_port")
        dst_port = log_data.get("destination_port") or log_data.get("dst_port")
        proto = str(log_data.get("protocol") or "TCP").upper()
        pkt_size = int(log_data.get("packet_size") or log_data.get("bytes") or log_data.get("total_bytes") or 0)
        event_type = str(log_data.get("event_type") or "network_flow")
        collector_id = str(log_data.get("collector_id") or log_data.get("host_id") or "host_collector")
        det_status = str(log_data.get("detection_status") or "unprocessed").lower()
        severity = str(log_data.get("severity") or "Low")
        det_reason = log_data.get("detection_reason")
        ml_score = float(log_data.get("ml_anomaly_score") or 0.0)

        # GeoIP fields
        country = log_data.get("geoip_country") or log_data.get("country")
        region = log_data.get("geoip_region") or log_data.get("region")
        city = log_data.get("geoip_city") or log_data.get("city")
        lat = log_data.get("latitude")
        lon = log_data.get("longitude")
        acc = log_data.get("accuracy_radius") or log_data.get("accuracy_km")
        acc_km = log_data.get("accuracy_km") or log_data.get("accuracy_radius")
        geoip_status = log_data.get("geoip_status") or ("resolved" if country else "pending")

        # Retention classification
        is_pres = int(log_data.get("is_preserved", 0))
        ret_status = log_data.get("retention_status")
        pres_at = log_data.get("preserved_at")
        exp_status = log_data.get("export_status") or "not_exported"
        inc_id = log_data.get("incident_id")
        ingestion_delay = float(log_data.get("ingestion_delay_ms") or 0.0)
        user_expires_at = log_data.get("expires_at")

        if user_expires_at:
            expires_at = user_expires_at
            if not ret_status:
                ret_status = "preserved" if is_pres else "auto_delete"
        elif det_status == "safe":
            if is_pres:
                ret_status = "preserved"
                expires_at = "9999-12-31T23:59:59"
            else:
                ret_status = ret_status or "auto_delete"
                try:
                    c_dt = datetime.datetime.fromisoformat(str(created_at).replace("Z", ""))
                    if c_dt.tzinfo is not None:
                        c_dt = c_dt.astimezone().replace(tzinfo=None)
                    expires_at = (c_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()
                except Exception:
                    expires_at = (now_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()
        elif det_status == "suspicious":
            ret_status = "preserved"
            expires_at = "9999-12-31T23:59:59"
        else:
            # Unprocessed / processing_failed - keep countdown on hold
            ret_status = ret_status or "auto_delete"
            expires_at = "9999-12-31T23:59:59"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO network_logs (
                log_id, source_ip, destination_ip, source_port, destination_port,
                protocol, timestamp, packet_size, event_type, collector_id,
                detection_status, severity, detection_reason, ml_anomaly_score,
                geoip_country, geoip_region, geoip_city, latitude, longitude,
                accuracy_radius, accuracy_km, geoip_status, created_at, retention_status,
                expires_at, is_preserved, preserved_at, export_status, incident_id,
                ingestion_delay_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id, src_ip, dst_ip, src_port, dst_port,
                proto, ts, pkt_size, event_type, collector_id,
                det_status, severity, det_reason, ml_score,
                country, region, city, lat, lon,
                acc, acc_km, geoip_status, created_at, ret_status,
                expires_at, is_pres, pres_at, exp_status, inc_id,
                ingestion_delay
            ))
            conn.commit()
        return log_id

    save_network_log = insert_network_log

    def insert_network_logs_batch(self, logs: List[Dict[str, Any]]) -> int:
        """
        Batch-inserts multiple network logs in a single SQLite transaction with WAL efficiency.
        """
        if not logs:
            return 0
        now_dt = datetime.datetime.now()
        now_iso = now_dt.isoformat()
        default_exp = (now_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()

        rows = []
        for log_data in logs:
            log_id = log_data.get("log_id") or f"LOG-{uuid.uuid4().hex[:12].upper()}"
            created_at = log_data.get("created_at") or now_iso
            ts = log_data.get("timestamp") or now_dt.strftime("%Y-%m-%d %H:%M:%S")
            src_ip = str(log_data.get("source_ip") or log_data.get("src_ip") or "0.0.0.0")
            dst_ip = str(log_data.get("destination_ip") or log_data.get("dst_ip") or "")
            src_port = log_data.get("source_port") or log_data.get("src_port")
            dst_port = log_data.get("destination_port") or log_data.get("dst_port")
            proto = str(log_data.get("protocol") or "TCP").upper()
            pkt_size = int(log_data.get("packet_size") or log_data.get("bytes") or log_data.get("total_bytes") or 0)
            event_type = str(log_data.get("event_type") or "network_flow")
            collector_id = str(log_data.get("collector_id") or log_data.get("host_id") or "host_collector")
            det_status = str(log_data.get("detection_status") or "unprocessed").lower()
            severity = str(log_data.get("severity") or "Low")
            det_reason = log_data.get("detection_reason")
            ml_score = float(log_data.get("ml_anomaly_score") or 0.0)

            country = log_data.get("geoip_country") or log_data.get("country")
            region = log_data.get("geoip_region") or log_data.get("region")
            city = log_data.get("geoip_city") or log_data.get("city")
            lat = log_data.get("latitude")
            lon = log_data.get("longitude")
            acc = log_data.get("accuracy_radius") or log_data.get("accuracy_km")
            acc_km = log_data.get("accuracy_km") or log_data.get("accuracy_radius")
            geoip_status = log_data.get("geoip_status") or ("resolved" if country else "pending")

            is_pres = int(log_data.get("is_preserved", 0))
            pres_at = log_data.get("preserved_at")
            exp_status = log_data.get("export_status") or "not_exported"
            inc_id = log_data.get("incident_id")
            ingestion_delay = float(log_data.get("ingestion_delay_ms") or 0.0)

            if det_status == "safe":
                if is_pres:
                    ret_status = "preserved"
                    exp_at = "9999-12-31T23:59:59"
                else:
                    ret_status = "auto_delete"
                    try:
                        c_dt = datetime.datetime.fromisoformat(str(created_at).replace("Z", ""))
                        if c_dt.tzinfo is not None:
                            c_dt = c_dt.astimezone().replace(tzinfo=None)
                        exp_at = (c_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()
                    except Exception:
                        exp_at = default_exp
            elif det_status == "suspicious":
                ret_status = "preserved"
                exp_at = "9999-12-31T23:59:59"
            else:
                ret_status = "auto_delete"
                exp_at = "9999-12-31T23:59:59"

            rows.append((
                log_id, src_ip, dst_ip, src_port, dst_port,
                proto, ts, pkt_size, event_type, collector_id,
                det_status, severity, det_reason, ml_score,
                country, region, city, lat, lon,
                acc, acc_km, geoip_status, created_at, ret_status,
                exp_at, is_pres, pres_at, exp_status, inc_id,
                ingestion_delay
            ))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
            INSERT OR REPLACE INTO network_logs (
                log_id, source_ip, destination_ip, source_port, destination_port,
                protocol, timestamp, packet_size, event_type, collector_id,
                detection_status, severity, detection_reason, ml_anomaly_score,
                geoip_country, geoip_region, geoip_city, latitude, longitude,
                accuracy_radius, accuracy_km, geoip_status, created_at, retention_status,
                expires_at, is_preserved, preserved_at, export_status, incident_id,
                ingestion_delay_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
        return len(rows)

    def update_log_detection_status(
        self,
        log_id: str,
        detection_status: str,
        severity: str = "Low",
        reason: Optional[str] = None,
        incident_id: Optional[str] = None,
        ml_anomaly_score: Optional[float] = None
    ) -> bool:
        """
        Updates the evaluation outcome of an unprocessed log once evaluated by detection pipeline.
        Calculates 24-hour expiration when marked safe, or marks preserved when suspicious.
        """
        det_status = detection_status.lower()
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT created_at, is_preserved FROM network_logs WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            if not row:
                return False
            created_at = row["created_at"]
            is_pres = row["is_preserved"]

            if det_status == "safe":
                if is_pres:
                    ret_status = "preserved"
                    expires_at = "9999-12-31T23:59:59"
                else:
                    ret_status = "auto_delete"
                    try:
                        c_dt = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    except Exception:
                        c_dt = now_dt
                    expires_at = (c_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()
            elif det_status == "suspicious":
                ret_status = "preserved"
                expires_at = "9999-12-31T23:59:59"
            else:
                ret_status = "auto_delete"
                expires_at = "9999-12-31T23:59:59"

            query = """
            UPDATE network_logs SET
                detection_status = ?,
                severity = ?,
                detection_reason = COALESCE(?, detection_reason),
                incident_id = COALESCE(?, incident_id),
                retention_status = ?,
                expires_at = ?
            """
            params = [det_status, severity, reason, incident_id, ret_status, expires_at]
            if ml_anomaly_score is not None:
                query += ", ml_anomaly_score = ?"
                params.append(ml_anomaly_score)
            query += " WHERE log_id = ?"
            params.append(log_id)

            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def get_network_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        preserved_only: bool = False,
        search: Optional[str] = None,
        status: Optional[str] = None,
        detection_status: Optional[str] = None,
        retention_status: Optional[str] = None,
        severity: Optional[str] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        eff_status = status_filter or status or detection_status
        eff_sev = severity_filter or severity
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM network_logs WHERE 1=1"
            params = []
            if eff_status and eff_status != "all":
                query += " AND LOWER(detection_status) = ?"
                params.append(eff_status.lower())
            if eff_sev and eff_sev != "all":
                query += " AND severity = ?"
                params.append(eff_sev)
            if retention_status and retention_status != "all":
                query += " AND LOWER(retention_status) = ?"
                params.append(retention_status.lower())
            if preserved_only:
                query += " AND (is_preserved = 1 OR retention_status = 'preserved')"
            if search:
                query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR log_id LIKE ? OR detection_reason LIKE ?)"
                term = f"%{search}%"
                params.extend([term, term, term, term])

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._format_network_log_row(dict(r)) for r in rows]

    @staticmethod
    def _format_network_log_row(d: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not d:
            return d
        if "city" not in d and "geoip_city" in d:
            d["city"] = d["geoip_city"]
        if "country" not in d and "geoip_country" in d:
            d["country"] = d["geoip_country"]
        if "region" not in d and "geoip_region" in d:
            d["region"] = d["geoip_region"]
        if "accuracy_km" not in d and "accuracy_radius" in d:
            d["accuracy_km"] = d["accuracy_radius"]
        elif "accuracy_radius" not in d and "accuracy_km" in d:
            d["accuracy_radius"] = d["accuracy_km"]
        return d

    def get_network_log_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM network_logs WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            return self._format_network_log_row(dict(row)) if row else None

    def get_geolocated_suspicious_logs(
        self,
        limit: int = 500,
        time_range: str = "24h",
        severity_filter: Optional[str] = None,
        country_filter: Optional[str] = None,
        attack_type_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves geolocated suspicious events stored in SQLite network_logs for Threat Map.
        Only returns suspicious logs with valid latitude and longitude. Excludes private IPs.
        """
        now_dt = datetime.datetime.now()
        delta_map = {
            "15m": datetime.timedelta(minutes=15),
            "1h": datetime.timedelta(hours=1),
            "24h": datetime.timedelta(hours=24),
            "7d": datetime.timedelta(days=7),
            "all": None
        }
        delta = delta_map.get(time_range.lower())
        cutoff_iso = (now_dt - delta).isoformat() if delta else None
        cutoff_str = (now_dt - delta).strftime("%Y-%m-%d %H:%M:%S") if delta else None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
            SELECT * FROM network_logs
            WHERE (detection_status = 'suspicious' OR severity IN ('Medium', 'High', 'Critical'))
              AND latitude IS NOT NULL
              AND longitude IS NOT NULL
            """
            params: List[Any] = []
            if cutoff_iso:
                query += " AND (created_at >= ? OR timestamp >= ?)"
                params.extend([cutoff_iso, cutoff_str])
            if severity_filter and severity_filter != "All":
                query += " AND severity = ?"
                params.append(severity_filter)
            if country_filter and country_filter != "All":
                query += " AND geoip_country = ?"
                params.append(country_filter)
            if attack_type_filter and attack_type_filter != "All":
                query += " AND (detection_reason LIKE ? OR event_type LIKE ?)"
                params.extend([f"%{attack_type_filter}%", f"%{attack_type_filter}%"])

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._format_network_log_row(dict(r)) for r in rows]

    def seed_baseline_network_logs(self):
        """Seed initial real-time network logs with realistic geolocatable threats if network_logs is empty."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM network_logs;")
            row = cursor.fetchone()
            count = row["c"] if row else 0

        if count > 0:
            return

        from geoip_service import get_geoip_service
        geo_svc = get_geoip_service(db_manager=self)
        now_dt = datetime.datetime.now()

        baseline_events = [
            {
                "src_ip": "128.30.52.100",
                "dst_ip": "10.0.0.15",
                "dst_port": 445,
                "protocol": "TCP",
                "packet_size": 512,
                "det_status": "suspicious",
                "severity": "High",
                "reason": "Port Scan Probe targeting port 445",
                "collector_id": "host-agent"
            },
            {
                "src_ip": "198.51.100.23",
                "dst_ip": "10.0.0.22",
                "dst_port": 22,
                "protocol": "TCP",
                "packet_size": 1024,
                "det_status": "suspicious",
                "severity": "Critical",
                "reason": "SSH Brute Force Credential Spraying",
                "collector_id": "host-agent"
            },
            {
                "src_ip": "198.51.100.99",
                "dst_ip": "10.0.0.80",
                "dst_port": 8080,
                "protocol": "TCP",
                "packet_size": 256,
                "det_status": "suspicious",
                "severity": "High",
                "reason": "Web Reconnaissance Vulnerability Scan",
                "collector_id": "host-agent"
            },
            {
                "src_ip": "192.168.1.15",
                "dst_ip": "192.168.1.1",
                "dst_port": 139,
                "protocol": "TCP",
                "packet_size": 128,
                "det_status": "suspicious",
                "severity": "Medium",
                "reason": "Internal NetBIOS / SMB Probe",
                "collector_id": "host-agent"
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "1.1.1.1",
                "dst_port": 443,
                "protocol": "TCP",
                "packet_size": 64,
                "det_status": "safe",
                "severity": "Low",
                "reason": "Nominal HTTPS Egress Flow",
                "collector_id": "host-agent"
            }
        ]

        for ev in baseline_events:
            src = ev["src_ip"]
            geo = geo_svc.get_ip_intelligence(src)
            self.insert_network_log(
                source_ip=src,
                destination_ip=ev["dst_ip"],
                destination_port=ev["dst_port"],
                protocol=ev["protocol"],
                packet_size=ev["packet_size"],
                timestamp=now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                created_at=now_dt.isoformat(),
                collector_id=ev["collector_id"],
                detection_status=ev["det_status"],
                severity=ev["severity"],
                detection_reason=ev["reason"],
                geoip_country=geo.get("country"),
                geoip_region=geo.get("region"),
                geoip_city=geo.get("city"),
                latitude=geo.get("latitude"),
                longitude=geo.get("longitude"),
                accuracy_km=geo.get("accuracy_km") or geo.get("accuracy_radius"),
                accuracy_radius=geo.get("accuracy_radius"),
                geoip_status=geo.get("status", "unknown")
            )

    def get_threat_map_data(
        self,
        time_range: str = "Last 24 Hours",
        severity_filter: Optional[str] = None,
        country_filter: Optional[str] = None,
        attack_category_filter: Optional[str] = None,
        limit: int = 1000
    ) -> Dict[str, Any]:
        """
        Retrieves real-time and persisted suspicious network events from SQLite for the Threat Intelligence Map.
        Only events with valid GeoIP coordinates are plotted as markers.
        Unlocated suspicious IPs (private, unresolvable) are counted towards unlocated statistics.
        Never fabricates coordinates or synthetic locations.
        """
        self.seed_baseline_network_logs()
        from geoip_service import get_geoip_service
        geoip_svc = get_geoip_service(db_manager=self)
        now_dt = datetime.datetime.now()
        time_map = {
            "15m": datetime.timedelta(minutes=15),
            "last 15 minutes": datetime.timedelta(minutes=15),
            "1h": datetime.timedelta(hours=1),
            "last 1 hour": datetime.timedelta(hours=1),
            "24h": datetime.timedelta(hours=24),
            "last 24 hours": datetime.timedelta(hours=24),
            "7d": datetime.timedelta(days=7),
            "last 7 days": datetime.timedelta(days=7),
            "all": None,
            "all time": None
        }
        delta = time_map.get(time_range.lower(), datetime.timedelta(hours=24))
        cutoff_iso = (now_dt - delta).isoformat() if delta else None
        cutoff_str = (now_dt - delta).strftime("%Y-%m-%d %H:%M:%S") if delta else None

        sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Query all suspicious network logs
            query = """
            SELECT * FROM network_logs
            WHERE (detection_status = 'suspicious' OR severity IN ('Medium', 'High', 'Critical'))
            """
            params: List[Any] = []

            if cutoff_iso:
                query += " AND (created_at >= ? OR timestamp >= ?)"
                params.extend([cutoff_iso, cutoff_str])

            if severity_filter and severity_filter not in ("All", "All Severities"):
                query += " AND severity = ?"
                params.append(severity_filter)

            if country_filter and country_filter not in ("All", "All Countries"):
                query += " AND geoip_country = ?"
                params.append(country_filter)

            if attack_category_filter and attack_category_filter not in ("All", "All Categories"):
                query += " AND (detection_reason LIKE ? OR event_type LIKE ?)"
                params.extend([f"%{attack_category_filter}%", f"%{attack_category_filter}%"])

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            log_rows = [self._format_network_log_row(dict(r)) for r in cursor.fetchall()]

            # 2. Query incidents table from SQLite
            inc_query = "SELECT * FROM incidents WHERE 1=1"
            inc_params: List[Any] = []
            if cutoff_iso:
                inc_query += " AND (timestamp >= ? OR last_seen >= ?)"
                inc_params.extend([cutoff_str, cutoff_str])
            if severity_filter and severity_filter not in ("All", "All Severities"):
                inc_query += " AND severity = ?"
                inc_params.append(severity_filter)
            if attack_category_filter and attack_category_filter not in ("All", "All Categories"):
                inc_query += " AND category = ?"
                inc_params.append(attack_category_filter)

            inc_query += " ORDER BY timestamp DESC LIMIT ?"
            inc_params.append(limit)
            cursor.execute(inc_query, inc_params)
            inc_rows = [dict(r) for r in cursor.fetchall()]

            # 3. Retrieve distinct available countries and categories for filters
            cursor.execute("""
            SELECT DISTINCT geoip_country FROM network_logs
            WHERE geoip_country IS NOT NULL AND geoip_country != ''
            ORDER BY geoip_country
            """)
            avail_countries = set(r["geoip_country"] for r in cursor.fetchall() if r["geoip_country"])

            cursor.execute("""
            SELECT DISTINCT detection_reason FROM network_logs
            WHERE detection_reason IS NOT NULL AND detection_reason != ''
            LIMIT 50
            """)
            avail_cats = set(r["detection_reason"] for r in cursor.fetchall() if r["detection_reason"])

            for inc in inc_rows:
                if inc.get("category"):
                    avail_cats.add(inc["category"])
                if inc.get("geoip_country"):
                    avail_countries.add(inc["geoip_country"])

        seen_incident_ids = set()
        for log in log_rows:
            if log.get("incident_id"):
                seen_incident_ids.add(log["incident_id"])

        unified_records = []
        for log in log_rows:
            unified_records.append({
                "source_ip": log.get("source_ip", "0.0.0.0"),
                "severity": log.get("severity", "Medium"),
                "category": log.get("detection_reason") or log.get("event_type") or "Suspicious Activity",
                "timestamp": log.get("timestamp") or log.get("created_at") or now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "latitude": log.get("latitude"),
                "longitude": log.get("longitude"),
                "country": log.get("geoip_country") or log.get("country"),
                "city": log.get("geoip_city") or log.get("city"),
                "region": log.get("geoip_region") or log.get("region"),
                "accuracy_km": log.get("accuracy_km") or log.get("accuracy_radius"),
                "id": log.get("log_id")
            })

        for inc in inc_rows:
            if inc.get("incident_id") in seen_incident_ids:
                continue
            src_ip = inc.get("source_ip", "0.0.0.0")
            c_geo = self.get_cached_geoip(src_ip) if src_ip else None
            lat = inc.get("latitude") or (c_geo.get("latitude") if c_geo else None)
            lon = inc.get("longitude") or (c_geo.get("longitude") if c_geo else None)
            country = inc.get("geoip_country") or (c_geo.get("country") if c_geo else None)
            city = inc.get("geoip_city") or (c_geo.get("city") if c_geo else None)
            region = inc.get("geoip_region") or (c_geo.get("region") if c_geo else None)
            acc = inc.get("accuracy_km") or inc.get("accuracy_radius") or (c_geo.get("accuracy_radius") if c_geo else None)

            if (lat is None or lon is None) and src_ip and src_ip not in ("0.0.0.0", "Distributed Sources"):
                try:
                    intel = geoip_svc.get_ip_intelligence(src_ip)
                    if intel.get("is_public") and intel.get("latitude") is not None:
                        lat = intel["latitude"]
                        lon = intel["longitude"]
                        country = intel.get("country") or country
                        city = intel.get("city") or city
                        region = intel.get("region") or region
                        acc = intel.get("accuracy_km") or acc
                except Exception:
                    pass

            if country:
                avail_countries.add(country)

            if country_filter and country_filter not in ("All", "All Countries") and country != country_filter:
                continue

            unified_records.append({
                "source_ip": src_ip,
                "severity": inc.get("severity", "Medium"),
                "category": inc.get("category", "Security Incident"),
                "timestamp": inc.get("last_seen") or inc.get("timestamp") or now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "latitude": lat,
                "longitude": lon,
                "country": country,
                "city": city,
                "region": region,
                "accuracy_km": acc,
                "id": inc.get("incident_id")
            })

        # Process and aggregate rows
        geo_markers = {}
        country_aggs = {}
        geolocated_ips = set()
        unlocated_ips = set()
        high_critical_count = 0
        total_suspicious_events = len(unified_records)

        for rec in unified_records:
            s_ip = rec.get("source_ip", "0.0.0.0")
            s_sev = rec.get("severity", "Medium")
            if s_sev in ("High", "Critical"):
                high_critical_count += 1

            lat = rec.get("latitude")
            lon = rec.get("longitude")
            s_ts = rec.get("timestamp") or now_dt.strftime("%Y-%m-%d %H:%M:%S")
            s_cat = rec.get("category", "Suspicious Activity")
            c_name = rec.get("country") or "Unknown"
            city_name = rec.get("city") or "Unknown City"
            reg_name = rec.get("region") or ""

            # Check if valid coordinates
            has_valid_coords = False
            lat_f, lon_f = 0.0, 0.0
            if lat is not None and lon is not None:
                try:
                    lat_f = float(lat)
                    lon_f = float(lon)
                    has_valid_coords = True
                except (ValueError, TypeError):
                    has_valid_coords = False

            if has_valid_coords:
                geolocated_ips.add(s_ip)
                coord_key = (round(lat_f, 2), round(lon_f, 2))

                if coord_key not in geo_markers:
                    geo_markers[coord_key] = {
                        "latitude": lat_f,
                        "longitude": lon_f,
                        "city": city_name,
                        "region": reg_name,
                        "country": c_name,
                        "source_ips": set(),
                        "event_count": 0,
                        "max_severity": s_sev,
                        "categories": set(),
                        "first_seen": s_ts,
                        "last_seen": s_ts,
                        "accuracy_km": rec.get("accuracy_km") or 20,
                        "record_ids": []
                    }
                m = geo_markers[coord_key]
                m["source_ips"].add(s_ip)
                m["event_count"] += 1
                m["categories"].add(s_cat)
                m["record_ids"].append(rec.get("id"))

                # Update timestamps
                if s_ts < m["first_seen"]:
                    m["first_seen"] = s_ts
                if s_ts > m["last_seen"]:
                    m["last_seen"] = s_ts

                # Update max severity
                if sev_order.get(s_sev, 1) > sev_order.get(m["max_severity"], 1):
                    m["max_severity"] = s_sev

                # Country aggregation
                if c_name not in country_aggs:
                    country_aggs[c_name] = {
                        "Country": c_name,
                        "Event Count": 0,
                        "Unique Source IPs": set(),
                        "Top Category": s_cat
                    }
                country_aggs[c_name]["Event Count"] += 1
                country_aggs[c_name]["Unique Source IPs"].add(s_ip)
            else:
                unlocated_ips.add(s_ip)

        # Build marker list
        marker_list = []
        for m in geo_markers.values():
            m_copy = dict(m)
            m_copy["source_ips_str"] = ", ".join(sorted(list(m["source_ips"])))
            m_copy["categories_str"] = ", ".join(sorted(list(m["categories"])))
            m_copy["location_label"] = f"{m['city']}, {m['country']}"
            m_copy["source_ip_count"] = len(m["source_ips"])
            marker_list.append(m_copy)

        return {
            "markers": marker_list,
            "statistics": {
                "total_geolocated_sources": len(geolocated_ips),
                "countries_detected": len(country_aggs),
                "total_suspicious_events": total_suspicious_events,
                "unlocated_source_ips": len(unlocated_ips),
                "high_critical_events": high_critical_count
            },
            "country_rollups": country_aggs,
            "unlocated_ips": sorted(list(unlocated_ips)),
            "available_countries": sorted(list(avail_countries)),
            "available_categories": sorted(list(avail_cats)),
            "raw_records": unified_records
        }

    def preserve_network_log(self, log_id: str, operator: str = "Analyst") -> Dict[str, Any]:
        """Marks a log as preserved by user, preventing automatic 24h deletion."""
        now_iso = datetime.datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE network_logs SET
                is_preserved = 1,
                retention_status = 'preserved',
                preserved_at = ?,
                expires_at = '9999-12-31T23:59:59'
            WHERE log_id = ?
            """, (now_iso, log_id))
            conn.commit()
            success = cursor.rowcount > 0
        if success:
            self.log_system_activity(
                activity_type="user_retention_decision",
                details=f"User preserved log {log_id}. Prevented automatic 24h deletion.",
                operator=operator,
                result="SUCCESS"
            )
            return {"status": "PRESERVED", "log_id": log_id, "preserved": True}
        return {"status": "FAILED", "log_id": log_id, "message": "Log not found"}

    def unpreserve_network_log(self, log_id: str, operator: str = "Analyst") -> Dict[str, Any]:
        """Removes user preservation, restoring normal 24h expiration countdown."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT created_at, detection_status FROM network_logs WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            if not row:
                return {"status": "FAILED", "log_id": log_id, "message": "Log not found"}
            created_at = row["created_at"]
            det_status = row["detection_status"]

            now_dt = datetime.datetime.now()
            if det_status == "safe":
                try:
                    c_dt = datetime.datetime.fromisoformat(str(created_at).replace("Z", ""))
                    if c_dt.tzinfo is not None:
                        c_dt = c_dt.astimezone().replace(tzinfo=None)
                except Exception:
                    c_dt = now_dt
                expires_at = (c_dt + datetime.timedelta(hours=self.retention_hours)).isoformat()
            else:
                expires_at = "9999-12-31T23:59:59"

            cursor.execute("""
            UPDATE network_logs SET
                is_preserved = 0,
                retention_status = 'auto_delete',
                preserved_at = NULL,
                expires_at = ?
            WHERE log_id = ?
            """, (expires_at, log_id))
            conn.commit()
            success = cursor.rowcount > 0
        if success:
            self.log_system_activity(
                activity_type="user_retention_decision",
                details=f"User removed preservation for log {log_id}. Re-enabled 24h automatic deletion.",
                operator=operator,
                result="SUCCESS"
            )
            return {"status": "UNPRESERVED", "log_id": log_id, "preserved": False}
        return {"status": "FAILED", "log_id": log_id, "message": "Log not found"}

    def delete_network_log_now(self, log_id: str, operator: str = "Analyst") -> Dict[str, Any]:
        """Immediately deletes a safe log upon user request. Protects suspicious logs from accidental deletion."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT detection_status FROM network_logs WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            if not row:
                return {"status": "NOT_FOUND", "message": f"Log {log_id} not found."}
            if row["detection_status"] == "suspicious":
                return {"status": "REJECTED", "message": f"Log {log_id} is classified as suspicious threat evidence and cannot be deleted via safe log controls."}
            cursor.execute("DELETE FROM network_logs WHERE log_id = ?", (log_id,))
            conn.commit()
            success = cursor.rowcount > 0
        if success:
            self.log_system_activity(
                activity_type="user_retention_decision",
                details=f"User explicitly deleted safe log {log_id} immediately.",
                operator=operator,
                result="SUCCESS"
            )
            return {"status": "DELETED", "log_id": log_id}
        return {"status": "FAILED", "message": "Failed to delete log"}

    delete_network_log = delete_network_log_now

    def bulk_preserve_network_logs(self, log_ids: List[str], operator: str = "Analyst") -> int:
        if not log_ids:
            return 0
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in log_ids)
            cursor.execute(f"""
            UPDATE network_logs SET
                is_preserved = 1,
                retention_status = 'preserved',
                preserved_at = ?,
                expires_at = '9999-12-31T23:59:59'
            WHERE log_id IN ({placeholders})
            """, [now_iso] + log_ids)
            conn.commit()
            count = cursor.rowcount
        self.log_system_activity(
            activity_type="user_retention_decision",
            details=f"User bulk-preserved {count} log(s).",
            operator=operator,
            result="SUCCESS"
        )
        return count

    def bulk_delete_network_logs_now(self, log_ids: List[str], operator: str = "Analyst") -> int:
        if not log_ids:
            return 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in log_ids)
            cursor.execute(f"DELETE FROM network_logs WHERE log_id IN ({placeholders})", log_ids)
            conn.commit()
            count = cursor.rowcount
        self.log_system_activity(
            activity_type="user_retention_decision",
            details=f"User bulk-deleted {count} log(s) immediately.",
            operator=operator,
            result="SUCCESS"
        )
        return count

    def purge_expired_safe_logs(self) -> Dict[str, Any]:
        """
        Automatic Safe-Log Deletion — 24 Hours.
        Deletes ONLY logs where:
          1. detection_status is 'safe'
          2. is_preserved is 0
          3. retention_status is not 'preserved'
          4. expires_at <= current timestamp (UTC)
        Never deletes suspicious logs, security incidents, or unprocessed logs.
        Transactional and safe across restarts.
        """
        now_dt = datetime.datetime.now()
        now_iso = now_dt.isoformat()
        now_utc_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT log_id FROM network_logs
            WHERE detection_status = 'safe'
              AND is_preserved = 0
              AND retention_status != 'preserved'
              AND (expires_at <= ? OR expires_at <= ?)
            """, (now_iso, now_utc_iso))
            rows = cursor.fetchall()
            count = len(rows)

            if count > 0:
                cursor.execute("""
                DELETE FROM network_logs
                WHERE detection_status = 'safe'
                  AND is_preserved = 0
                  AND retention_status != 'preserved'
                  AND (expires_at <= ? OR expires_at <= ?)
                """, (now_iso, now_utc_iso))
                conn.commit()

        self.log_system_activity(
            activity_type="retention_cleanup",
            details=f"Purged {count} expired safe log(s) older than {self.retention_hours} hours.",
            operator="Retention Watchdog",
            result="SUCCESS"
        )
        return {
            "status": "success",
            "purged_count": count,
            "purged_at": now_iso,
            "retention_hours": self.retention_hours
        }

    def get_log_retention_statistics(self) -> Dict[str, Any]:
        """
        Calculates live retention figures directly from actual SQLite database records.
        """
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()
        one_hour_iso = (now_dt + datetime.timedelta(hours=1)).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM network_logs;")
            total_logs = cursor.fetchone()["c"]

            cursor.execute("""
            SELECT COUNT(*) as c FROM network_logs
            WHERE detection_status = 'safe' AND is_preserved = 0;
            """)
            safe_pending = cursor.fetchone()["c"]

            cursor.execute("""
            SELECT COUNT(*) as c FROM network_logs
            WHERE is_preserved = 1 OR retention_status = 'preserved';
            """)
            preserved_logs = cursor.fetchone()["c"]

            cursor.execute("""
            SELECT COUNT(*) as c FROM network_logs
            WHERE detection_status = 'safe' AND is_preserved = 0 AND expires_at <= ? AND expires_at > ?;
            """, (one_hour_iso, now_iso))
            expiring_soon = cursor.fetchone()["c"]

            cursor.execute("""
            SELECT COUNT(*) as c FROM network_logs
            WHERE detection_status = 'suspicious' OR severity IN ('Medium', 'High', 'Critical');
            """)
            suspicious_logs = cursor.fetchone()["c"]

            cursor.execute("""
            SELECT details, timestamp FROM system_activity
            WHERE activity_type = 'retention_cleanup'
            ORDER BY timestamp DESC LIMIT 1;
            """)
            last_cleanup_row = cursor.fetchone()
            last_cleanup = dict(last_cleanup_row) if last_cleanup_row else None

            cursor.execute("""
            SELECT details FROM system_activity
            WHERE activity_type = 'retention_cleanup' AND result = 'SUCCESS';
            """)
            purged_rows = cursor.fetchall()
            total_purged = 0
            for r in purged_rows:
                match = re.search(r"Purged\s+(\d+)\s+expired", r["details"] or "")
                if match:
                    total_purged += int(match.group(1))

        return {
            "total_logs": total_logs,
            "safe_pending_deletion": safe_pending,
            "preserved_logs": preserved_logs,
            "expiring_soon": expiring_soon,
            "auto_deleted_count": total_purged,
            "suspicious_logs": suspicious_logs,
            "next_cleanup_time": (now_dt + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "last_cleanup_result": last_cleanup.get("details") if last_cleanup else "No cleanups executed yet",
            "last_cleanup_time": last_cleanup.get("timestamp") if last_cleanup else "None"
        }

    def export_network_logs(self, log_ids: Optional[List[str]] = None, format_type: str = "json") -> str:
        """
        Exports selected or recent network logs as JSON or CSV format.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if log_ids:
                placeholders = ",".join("?" for _ in log_ids)
                cursor.execute(f"SELECT * FROM network_logs WHERE log_id IN ({placeholders}) ORDER BY created_at DESC", log_ids)
            else:
                cursor.execute("SELECT * FROM network_logs ORDER BY created_at DESC LIMIT 1000")
            rows = cursor.fetchall()
            logs_list = [dict(r) for r in rows]

            if log_ids and logs_list:
                cursor.execute(f"UPDATE network_logs SET export_status = 'exported' WHERE log_id IN ({placeholders})", log_ids)
                conn.commit()

        if format_type.lower() == "csv":
            df = pd.DataFrame(logs_list)
            return df.to_csv(index=False)
        else:
            return json.dumps(logs_list, indent=2)

    def log_system_activity(
        self,
        activity_type: str,
        details: str,
        operator: str = "System",
        result: str = "SUCCESS"
    ) -> str:
        act_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO system_activity (activity_id, timestamp, activity_type, operator, details, result)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (act_id, now_iso, activity_type, operator, details, result))
            conn.commit()
        return act_id

    def get_system_activities(self, limit: int = 50, activity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if activity_type:
                cursor.execute("""
                SELECT * FROM system_activity WHERE activity_type = ? ORDER BY timestamp DESC LIMIT ?
                """, (activity_type, limit))
            else:
                cursor.execute("""
                SELECT * FROM system_activity ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def start_retention_cleanup_scheduler(self, interval_seconds: int = 300):
        """Starts background retention cleanup thread for this database instance."""
        return start_retention_cleanup_scheduler(self, interval_seconds=interval_seconds)


# ------------------------------------------------------------------------------
# Background Retention Watchdog Scheduler
# ------------------------------------------------------------------------------
_scheduler_thread = None
_scheduler_lock = threading.Lock()

def start_retention_cleanup_scheduler(db_manager: Optional[DatabaseManager] = None, interval_seconds: int = 300):
    """Starts background retention cleanup thread running periodically (default 5 minutes)."""
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return
        db = db_manager or get_db()
        def _worker():
            import time
            while True:
                try:
                    time.sleep(interval_seconds)
                    db.purge_expired_safe_logs()
                except Exception as e:
                    try:
                        db.log_system_activity("system_error", f"Retention scheduler error: {e}", result="FAILURE")
                    except Exception:
                        pass
        _scheduler_thread = threading.Thread(target=_worker, daemon=True, name="SentinelAI-RetentionScheduler")
        _scheduler_thread.start()


# Factory function
_db_instance = None

def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    global _db_instance
    if _db_instance is None or db_path is not None:
        _db_instance = DatabaseManager(db_path=db_path)
    return _db_instance
