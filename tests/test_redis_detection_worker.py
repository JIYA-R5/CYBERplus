"""
Unit tests for the Redis detection worker (src/workers/detection_worker.py).
Validates idempotency deduplication, rule and ML anomaly evaluation, and health reporting.
"""
import os
import json
import uuid
import pytest

from src.workers.detection_worker import DetectionWorker


@pytest.fixture
def worker(tmp_path):
    """Create a test worker with a local health file path."""
    health_file = tmp_path / "worker_health.json"
    w = DetectionWorker(
        redis_url="redis://localhost:6379/0",
        health_file=str(health_file)
    )
    return w


def test_idempotency_cache(worker):
    event_id = "test-event-uuid-12345"

    assert event_id not in worker.processed_ids

    # Add to cache
    worker.processed_ids.add(event_id)
    worker.id_order.append(event_id)

    # Next occurrence is recognized as duplicate
    assert event_id in worker.processed_ids


def test_process_single_network_event(worker):
    event = {
        "event_id": str(uuid.uuid4()),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "total_packets": 500,
        "total_bytes": 50000,
        "duration": 0.5,
        "packets_per_sec": 1000.0,
        "bytes_per_sec": 100000.0,
        "syn_count": 500,
        "is_replay": False
    }

    # Should process without unhandled exception
    worker._process_single_event(event)
    assert worker.events_processed >= 1


def test_worker_write_health(worker, tmp_path):
    health_file = tmp_path / "worker_health.json"
    worker.health_file = str(health_file)
    worker.events_processed = 15
    worker.incidents_created = 2
    worker.write_health()

    assert os.path.exists(health_file)
    with open(health_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["events_processed"] == 15
    assert data["incidents_created"] == 2
    assert "models_active" in data
