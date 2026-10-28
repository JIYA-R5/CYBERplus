"""
SentinelAI - Detection & Flow Aggregation Redis Worker
Consumes network flow telemetry events from Redis Streams ('sentinel:events').
Performs idempotent multi-tier threat detection:
  1. Deterministic Rule-Based Engine (detector.py)
  2. Network Flow ML Anomaly Model (IsolationForest)
  3. Supervised Network Threat Classifier (RandomForest)
Persists detected security incidents to database and publishes alerts to 'sentinel:alerts'.
Gracefully buffers and falls back to in-memory queues when Redis is offline.
"""

import os
import sys
import time
import json
import uuid
import signal
import socket
import logging
import datetime
import threading
from collections import deque
from typing import Dict, Any, List, Optional, Set, Tuple

# Ensure project root in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from detector import ThreatDetector, get_detector
from database import DatabaseManager, get_db
from stream_engine import RedisStreamPublisher, get_stream_publisher, STREAM_EVENTS, STREAM_ALERTS
from src.features.network_features import get_network_pipeline, NETWORK_FEATURE_NAMES

logger = logging.getLogger("sentinel.worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

CONSUMER_GROUP = os.environ.get("SENTINEL_CONSUMER_GROUP", "sentinel_detection_group")
CONSUMER_NAME = os.environ.get("SENTINEL_CONSUMER_NAME", f"worker-{socket.gethostname()}-{os.getpid()}")


class DetectionWorker:
    """
    Asynchronous worker processing network events from Redis Streams.
    Guarantees idempotency, bounded queues, and resilient failover.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        artifacts_dir: str = "artifacts",
        health_file: str = "reports/worker_health.json",
        batch_size: int = 50,
        block_ms: int = 2000
    ):
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self.artifacts_dir = artifacts_dir
        self.health_file = health_file
        self.batch_size = batch_size
        self.block_ms = block_ms

        self.running = False
        self.redis_client = None
        self.is_connected = False
        self.publisher = get_stream_publisher()
        self.detector = get_detector()
        self.db = get_db()
        self.feature_pipeline = get_network_pipeline()

        # ML Models
        self.network_iso_model = None
        self.network_rf_model = None
        self.network_metadata = {}
        self._load_ml_models()

        # Idempotency deduplication cache (stores up to 10,000 processed event IDs)
        self.processed_ids: Set[str] = set()
        self.id_order: deque = deque(maxlen=10000)

        # Worker Metrics
        self.events_processed = 0
        self.duplicates_skipped = 0
        self.incidents_created = 0
        self.ml_anomalies_flagged = 0
        self.last_event_time: Optional[str] = None
        self.last_error: Optional[str] = None
        self.start_time = time.time()

        self._init_redis()

    def _load_ml_models(self):
        """Loads serialized network flow ML pipelines from artifacts directory."""
        import joblib

        iso_path = os.path.join(self.artifacts_dir, "network_anomaly_isolation_forest.joblib")
        rf_path = os.path.join(self.artifacts_dir, "network_threat_classifier.joblib")
        meta_path = os.path.join(self.artifacts_dir, "network_model_metadata.json")

        if os.path.isfile(iso_path):
            try:
                self.network_iso_model = joblib.load(iso_path)
                logger.info("Loaded Network Isolation Forest from %s", iso_path)
            except Exception as e:
                logger.warning("Could not load Isolation Forest: %s", e)

        if os.path.isfile(rf_path):
            try:
                self.network_rf_model = joblib.load(rf_path)
                logger.info("Loaded Network Random Forest from %s", rf_path)
            except Exception as e:
                logger.warning("Could not load Random Forest: %s", e)

        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.network_metadata = json.load(f)
            except Exception:
                pass

    def _init_redis(self):
        """Initializes Redis client and registers consumer group."""
        try:
            import redis
            client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=3.0
            )
            client.ping()
            self.redis_client = client
            self.is_connected = True

            # Create consumer group if not present
            try:
                self.redis_client.xgroup_create(
                    STREAM_EVENTS,
                    CONSUMER_GROUP,
                    id="0",
                    mkstream=True
                )
                logger.info("Created consumer group '%s' on stream '%s'", CONSUMER_GROUP, STREAM_EVENTS)
            except Exception as e:
                # Group already exists is expected on worker restarts
                if "BUSYGROUP" not in str(e):
                    logger.debug("xgroup_create info: %s", e)

            logger.info("Connected to Redis at %s", self.redis_url)
        except Exception as e:
            self.is_connected = False
            self.redis_client = None
            logger.warning("Redis server unavailable at %s (%s). Worker running in in-memory fallback mode.", self.redis_url, e)

    def write_health(self):
        """Serializes worker health state to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(self.health_file)), exist_ok=True)
        data = {
            "status": "RUNNING" if self.running else "STOPPED",
            "consumer_group": CONSUMER_GROUP,
            "consumer_name": CONSUMER_NAME,
            "redis_connected": self.is_connected,
            "redis_url": self.redis_url,
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "events_processed": self.events_processed,
            "duplicates_skipped": self.duplicates_skipped,
            "incidents_created": self.incidents_created,
            "ml_anomalies_flagged": self.ml_anomalies_flagged,
            "last_event_time": self.last_event_time,
            "last_error": self.last_error,
            "timestamp": datetime.datetime.now().isoformat()
        }
        try:
            with open(self.health_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def start(self):
        """Starts main consumption and threat detection loop."""
        self.running = True
        self.start_time = time.time()
        logger.info("Starting SentinelAI Detection Worker [%s]", CONSUMER_NAME)

        while self.running:
            try:
                if self.is_connected and self.redis_client:
                    self._process_redis_stream_batch()
                else:
                    self._process_memory_fallback_batch()
            except Exception as e:
                self.last_error = str(e)
                logger.error("Error in detection worker loop: %s", e)
                time.sleep(1.0)
                # Attempt Redis reconnection periodically
                if not self.is_connected:
                    self._init_redis()

            self.write_health()

        self.write_health()
        logger.info("SentinelAI Detection Worker stopped.")

    def _process_redis_stream_batch(self):
        """Reads and processes consumer group entries from Redis Stream."""
        try:
            entries = self.redis_client.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={STREAM_EVENTS: ">"},
                count=self.batch_size,
                block=self.block_ms
            )
        except Exception as e:
            self.is_connected = False
            self.last_error = f"Redis xreadgroup failed: {str(e)}"
            return

        if not entries:
            return

        for stream_name, message_list in entries:
            for entry_id, fields in message_list:
                parsed_event = self._deserialize_event_fields(fields)
                event_id = parsed_event.get("event_id") or parsed_event.get("flow_id") or entry_id

                # Idempotency check: Skip duplicate events
                if event_id in self.processed_ids:
                    self.duplicates_skipped += 1
                    try:
                        self.redis_client.xack(STREAM_EVENTS, CONSUMER_GROUP, entry_id)
                    except Exception:
                        pass
                    continue

                # Process event through detection tiers
                self._process_single_event(parsed_event)

                # Track event ID for deduplication
                self.processed_ids.add(event_id)
                self.id_order.append(event_id)
                if len(self.id_order) >= 10000:
                    oldest = self.id_order.popleft()
                    self.processed_ids.discard(oldest)

                # Acknowledge message in Redis stream
                try:
                    self.redis_client.xack(STREAM_EVENTS, CONSUMER_GROUP, entry_id)
                except Exception:
                    pass

    def _process_memory_fallback_batch(self):
        """Processes events from publisher memory buffer when Redis is offline."""
        recent_events = self.publisher.get_recent_events(limit=self.batch_size)
        if not recent_events:
            time.sleep(0.5)
            return

        for event in recent_events:
            event_id = event.get("event_id") or event.get("flow_id") or str(uuid.uuid4())
            if event_id in self.processed_ids:
                continue

            self._process_single_event(event)

            self.processed_ids.add(event_id)
            self.id_order.append(event_id)

        time.sleep(0.2)

    def _deserialize_event_fields(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Parses stringified JSON entries from Redis stream."""
        result = {}
        for k, v in fields.items():
            if isinstance(v, str) and (v.startswith("{") or v.startswith("[")):
                try:
                    result[k] = json.loads(v)
                except Exception:
                    result[k] = v
            else:
                result[k] = v
        return result

    def _process_single_event(self, event: Dict[str, Any]):
        """
        Evaluates a single telemetry event through:
        1. Rule-Based Heuristics (ThreatDetector)
        2. ML Network Anomaly Inference (IsolationForest)
        3. Supervised Classification (RandomForest)
        """
        import pandas as pd

        self.events_processed += 1
        self.last_event_time = datetime.datetime.now().isoformat()

        src_ip = event.get("src_ip") or event.get("Source IP") or event.get("source_ip", "0.0.0.0")
        dst_ip = event.get("dst_ip") or event.get("Destination IP") or event.get("destination_ip", "10.0.0.1")
        port = int(event.get("dst_port") or event.get("Port") or event.get("port", 80))
        proto = str(event.get("protocol") or event.get("Protocol") or "TCP").upper()
        packets = int(event.get("total_packets") or event.get("Packets") or event.get("packets", 1))
        bytes_count = int(event.get("total_bytes") or event.get("Bytes") or event.get("bytes", 64))
        is_replay = bool(event.get("is_replay", False))
        source_tag = event.get("source", "pcap_replay" if is_replay else "live_network")

        # 1. Database Event Logging
        try:
            self.db.log_telemetry_event({
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "port": port,
                "packets": packets,
                "activity": event.get("activity", "Network Flow"),
                "risk": "Low"
            })
        except Exception:
            pass

        # 2. Rule-Based Heuristics
        df_single = pd.DataFrame([{
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Port": port,
            "Protocol": proto,
            "Packets": packets,
            "Bytes": bytes_count,
            "Activity": "Normal Traffic",
            "Risk": "Low"
        }])

        rule_incidents = self.detector.correlate_incidents(df_single)
        is_rule_violation = len(rule_incidents) > 0

        # 3. Network ML Anomaly Inference
        ml_is_anomalous = False
        ml_score = 0.0
        ml_category = None

        if self.network_iso_model:
            try:
                X_flow, _ = self.feature_pipeline.extract_features([event])
                # Isolation Forest pipeline includes scaler
                raw_score = -self.network_iso_model.decision_function(X_flow)[0]
                threshold = self.network_metadata.get("isolation_forest_optimal_threshold", 0.0178)
                ml_is_anomalous = bool(raw_score >= threshold)
                ml_score = round(float(raw_score), 4)

                if ml_is_anomalous:
                    self.ml_anomalies_flagged += 1
            except Exception:
                pass

        if self.network_rf_model and ml_is_anomalous:
            try:
                X_flow, _ = self.feature_pipeline.extract_features([event])
                pred_label_idx = self.network_rf_model.predict(X_flow)[0]
                label_names = ["Normal Traffic", "Port Scan", "Brute Force", "Traffic Burst"]
                if 0 <= pred_label_idx < len(label_names):
                    ml_category = label_names[pred_label_idx]
            except Exception:
                pass

        # 4. Synthesize Incident if Rule Violated OR ML Anomaly Detected
        if is_rule_violation or ml_is_anomalous:
            primary_category = "Network Anomaly"
            severity = "Low"
            detection_source = "Rule Engine"

            if is_rule_violation:
                inc = rule_incidents[0]
                primary_category = inc.category
                severity = inc.severity
                detection_source = "Rule-Based Correlation"
            elif ml_is_anomalous:
                primary_category = ml_category or "Statistical Flow Anomaly"
                severity = "Medium" if ml_score > 0.05 else "Low"
                detection_source = "IsolationForest Anomaly Model"

            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            incident_record = {
                "id": incident_id,
                "incident_id": incident_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "target_ip": src_ip,
                "category": primary_category,
                "threat_type": primary_category,
                "severity": severity,
                "risk": severity,
                "port": port,
                "protocol": proto,
                "packets": packets,
                "bytes": bytes_count,
                "detection_type": detection_source,
                "anomaly_score": ml_score,
                "is_replay": is_replay,
                "telemetry_source": source_tag,
                "explanation": (
                    f"Flagged by {detection_source}. Flow from {src_ip}:{port} exhibited unusual behavior "
                    f"(Score: {ml_score}, Packets: {packets}, Replay: {is_replay})."
                ),
                "contributing_features": {
                    "total_packets": packets,
                    "total_bytes": bytes_count,
                    "port": port,
                    "anomaly_score": ml_score
                },
                "recommended_action": "Investigate source host and verify legitimacy of destination service.",
                "status": "Needs Investigation",
                "verdict": "Unreviewed"
            }

            try:
                self.db.save_incident(incident_record)
                self.incidents_created += 1
                self.publisher.publish_alert(incident_record)
                logger.info(
                    "Generated Incident %s: %s from %s [Source: %s | Severity: %s]",
                    incident_id, primary_category, src_ip, detection_source, severity
                )
            except Exception as e:
                logger.error("Failed saving incident to database: %s", e)

    def write_health(self):
        """Dumps current worker health status to file."""
        if not self.health_file:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.health_file)), exist_ok=True)
        health_data = {
            "status": "RUNNING" if self.running else "STOPPED",
            "consumer_group": CONSUMER_GROUP,
            "consumer_name": CONSUMER_NAME,
            "redis_connected": self.is_connected,
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "events_processed": self.events_processed,
            "duplicates_skipped": self.duplicates_skipped,
            "incidents_created": self.incidents_created,
            "ml_anomalies_flagged": self.ml_anomalies_flagged,
            "last_event_time": self.last_event_time,
            "last_error": self.last_error,
            "models_active": {
                "isolation_forest": self.network_iso_model is not None,
                "random_forest": self.network_rf_model is not None,
            }
        }
        try:
            with open(self.health_file, "w", encoding="utf-8") as f:
                json.dump(health_data, f, indent=2)
        except Exception as e:
            logger.warning("Failed writing worker health: %s", e)

    def stop(self):
        """Stops worker execution loop."""
        self.running = False


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Detection and Flow Aggregation Worker")
    parser.add_argument("--redis-url", default=os.environ.get("REDIS_URL", "redis://localhost:6379/0"), help="Redis URL")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size per poll")
    parser.add_argument("--block-ms", type=int, default=2000, help="Redis xreadgroup block timeout ms")
    parser.add_argument("--artifacts-dir", default="artifacts", help="Path to ML artifacts")
    args = parser.parse_args()

    worker = DetectionWorker(
        redis_url=args.redis_url,
        artifacts_dir=args.artifacts_dir,
        batch_size=args.batch_size,
        block_ms=args.block_ms
    )

    def handle_signal(sig, frame):
        print("\n[Signal] Shutting down detection worker...")
        worker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    worker.start()


if __name__ == "__main__":
    main()
