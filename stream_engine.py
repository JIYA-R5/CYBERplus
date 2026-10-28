"""
SentinelAI - Event & Alert Streaming Engine (Redis Streams)
Publishes live telemetry flows, supervised threat classifications, and correlated alerts
to Redis Streams with memory fallback when Redis is offline.
"""

import os
import time
import json
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("sentinel.streams")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STREAM_EVENTS = os.environ.get("SENTINEL_STREAM_EVENTS", "sentinel:events")
STREAM_ALERTS = os.environ.get("SENTINEL_STREAM_ALERTS", "sentinel:alerts")


class RedisStreamPublisher:
    """
    Publishes live network flow events and rule/ML security alerts to Redis Streams.
    Provides graceful buffering in memory if Redis is unavailable or uninstalled.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or REDIS_URL
        self.client = None
        self.is_connected = False
        self._memory_event_buffer: List[Dict[str, Any]] = []
        self._memory_alert_buffer: List[Dict[str, Any]] = []
        self._max_buffer_size = 500
        self._events_published_count = 0
        self._alerts_published_count = 0

        self._init_client()

    def _init_client(self):
        """Attempts connection to Redis server."""
        try:
            import redis
            self.client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0
            )
            # Test ping
            self.client.ping()
            self.is_connected = True
            logger.info("Connected to Redis Streams at %s", self.redis_url)
        except Exception:
            self.client = None
            self.is_connected = False

    def publish_event(self, event_data: Dict[str, Any]) -> bool:
        """Publishes raw/aggregated telemetry flow event to sentinel:events."""
        self._events_published_count += 1
        serialized = {k: (json.dumps(v) if isinstance(v, (dict, list, bool)) else str(v)) for k, v in event_data.items()}

        if self.is_connected and self.client:
            try:
                self.client.xadd(STREAM_EVENTS, serialized, maxlen=10000, approximate=True)
                return True
            except Exception:
                self.is_connected = False

        # Fallback buffer
        if len(self._memory_event_buffer) >= self._max_buffer_size:
            self._memory_event_buffer.pop(0)
        self._memory_event_buffer.append(event_data)
        return False

    def publish_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Publishes verified incident or threat alert to sentinel:alerts."""
        self._alerts_published_count += 1
        serialized = {k: (json.dumps(v) if isinstance(v, (dict, list, bool)) else str(v)) for k, v in alert_data.items()}

        if self.is_connected and self.client:
            try:
                self.client.xadd(STREAM_ALERTS, serialized, maxlen=5000, approximate=True)
                return True
            except Exception:
                self.is_connected = False

        # Fallback buffer
        if len(self._memory_alert_buffer) >= self._max_buffer_size:
            self._memory_alert_buffer.pop(0)
        self._memory_alert_buffer.append(alert_data)
        return False

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Reads recent events from Redis Stream or memory buffer."""
        if self.is_connected and self.client:
            try:
                raw_entries = self.client.xrevrange(STREAM_EVENTS, max="+", min="-", count=limit)
                events = []
                for entry_id, fields in raw_entries:
                    parsed = {}
                    for k, v in fields.items():
                        try:
                            parsed[k] = json.loads(v)
                        except Exception:
                            parsed[k] = v
                    events.append(parsed)
                return events
            except Exception:
                pass
        return list(reversed(self._memory_event_buffer[-limit:]))

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Reads recent alerts from Redis Stream or memory buffer."""
        if self.is_connected and self.client:
            try:
                raw_entries = self.client.xrevrange(STREAM_ALERTS, max="+", min="-", count=limit)
                alerts = []
                for entry_id, fields in raw_entries:
                    parsed = {}
                    for k, v in fields.items():
                        try:
                            parsed[k] = json.loads(v)
                        except Exception:
                            parsed[k] = v
                    alerts.append(parsed)
                return alerts
            except Exception:
                pass
        return list(reversed(self._memory_alert_buffer[-limit:]))

    def get_status(self) -> Dict[str, Any]:
        """Returns streaming engine status and metrics."""
        return {
            "is_connected": self.is_connected,
            "redis_url": self.redis_url,
            "events_stream": STREAM_EVENTS,
            "alerts_stream": STREAM_ALERTS,
            "events_published_total": self._events_published_count,
            "alerts_published_total": self._alerts_published_count,
            "buffered_events_count": len(self._memory_event_buffer),
            "buffered_alerts_count": len(self._memory_alert_buffer),
        }


_global_stream_publisher = None

def get_stream_publisher() -> RedisStreamPublisher:
    global _global_stream_publisher
    if _global_stream_publisher is None:
        _global_stream_publisher = RedisStreamPublisher()
    return _global_stream_publisher
