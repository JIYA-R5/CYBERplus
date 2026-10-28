"""
SentinelAI - Serverless Cloud API & SOC Web Application for Vercel
Serves the approachable SentinelAI security assistant dashboard, threat detection pipeline,
AI threat copilot, automated containment playbooks, and live telemetry simulation.
"""

import os
import sys
import json
import uuid
import datetime
import threading
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

# Ensure repository root is in Python sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dotenv import load_dotenv

# Ensure local environment (.env.local / .env) is loaded directly
if os.path.isfile(os.path.join(ROOT_DIR, ".env")):
    load_dotenv(os.path.join(ROOT_DIR, ".env"), override=False)
if os.path.isfile(os.path.join(ROOT_DIR, ".env.local")):
    load_dotenv(os.path.join(ROOT_DIR, ".env.local"), override=True)
load_dotenv()

from detector import ThreatDetector, get_detector
from analyzer import TrafficAnalyzer, get_analyzer
from explainerAI import ThreatExplainer, get_explainer
from response_engine import ResponseEngine, get_response_engine, sanitize_ip
from database import DatabaseManager, get_db
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator, get_live_simulator

from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI application
app = FastAPI(
    title="SentinelAI Cloud SOC",
    description="Intrusion Detection, Behavioral Correlation & Incident Response API",
    version="2.5.0"
)

# Configure CORS according to allowed frontend origins
allowed_origins_raw = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:8501,http://127.0.0.1:8501,http://localhost:3000,http://localhost:8000"
)
allowed_origins = [orig.strip() for orig in allowed_origins_raw.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

detector = get_detector()
analyzer = get_analyzer()
explainer = get_explainer()
response_engine = get_response_engine()
db = get_db()
live_sim = get_live_simulator()

# Ensure baseline demo data exists
if not db.get_incidents():
    db.reset_demo_data()


# ------------------------------------------------------------------------------
# Request / Response Models
# ------------------------------------------------------------------------------
class ContainmentRequest(BaseModel):
    incident_id: str
    target_ip: str
    action_type: str = "Quarantine Host"
    operator: str = "Security Assistant User"
    dry_run: bool = True
    admin_approved: bool = False

class CopilotQueryRequest(BaseModel):
    incident_id: str
    category: str
    source_ip: str
    packets: int = 0
    risk: str = "High"
    query: Optional[str] = None

class VerdictRequest(BaseModel):
    verdict: str
    analyst_user: str = "Security Analyst"
    reason: str = "Reviewed threat activity"

class MLPredictRequest(BaseModel):
    packets: int
    port: int
    source_ip: str
    destination_ip: Optional[str] = "Target Perimeter"
    activity: Optional[str] = "Normal Traffic"
    risk: Optional[str] = "Low"

class MLRetrainRequest(BaseModel):
    version_tag: Optional[str] = None
    sample_count: int = 300
    contamination: Optional[float] = 0.15
    trained_by: str = "Security Engineer"

class MLRevertRequest(BaseModel):
    version: str

class RollbackBlockRequest(BaseModel):
    block_id: str
    operator: str = "Security Assistant User"

class RetentionPurgeRequest(BaseModel):
    retention_days: int = 30
    operator: str = "Security Assistant User"

class AgentTelemetryPayload(BaseModel):
    host_id: str = "endpoint-host"
    agent_version: str = "1.0.0"
    os_type: str = "windows"
    events: List[Dict[str, Any]]

class NetworkEventSchema(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = 0
    dst_port: int
    protocol: Optional[str] = "TCP"
    total_packets: Optional[int] = 1
    total_bytes: Optional[int] = 64
    duration: Optional[float] = 0.05
    tcp_flags: Optional[Dict[str, Any]] = None
    syn_count: Optional[int] = 0
    ack_count: Optional[int] = 0
    rst_count: Optional[int] = 0
    fin_count: Optional[int] = 0
    is_replay: Optional[bool] = False
    source: Optional[str] = "tshark_live"

class CollectorBatchPayload(BaseModel):
    schema_version: str = "v1"
    collector_id: str
    timestamp: Optional[str] = None
    events: List[NetworkEventSchema]

class PCAPLiveStreamPayload(BaseModel):
    host_id: str = "host-capture-agent"
    agent_type: str = "host_tshark_capture"
    timestamp: Optional[str] = None
    flows: List[Dict[str, Any]]

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        with self._lock:
            conns = list(self.active_connections)
        for conn in conns:
            try:
                await conn.send_json(message)
            except Exception:
                self.disconnect(conn)

ws_manager = WebSocketManager()

class DatasetValidationRequest(BaseModel):
    dataset_name: Optional[str] = "sentinel_enriched_telemetry.csv"
    required_columns: Optional[List[str]] = None
    min_samples: int = 10

class MLTrainRequest(BaseModel):
    model_type: str = "supervised_classifier"  # "supervised_classifier" or "isolation_forest"
    dataset: str = "sentinel_enriched_telemetry.csv"
    label_column: str = "Activity"
    version_tag: Optional[str] = None
    test_size: float = 0.25
    contamination: Optional[float] = 0.15
    trained_by: str = "SOC Security Engineer"
    is_reviewed_ground_truth: bool = True


# ------------------------------------------------------------------------------
# Server-Side Authorization Dependency for Privileged Endpoints
# ------------------------------------------------------------------------------
def verify_admin_authorization(
    x_sentinel_admin_key: Optional[str] = Header(None, alias="X-Sentinel-Admin-Key"),
    authorization: Optional[str] = Header(None)
):
    """
    Enforce server-side authorization on privileged administrative routes.
    If SENTINEL_ADMIN_KEY is configured in the environment, verifies the header or bearer token.
    If running in public cloud mode (VERCEL set), requires the key.
    In local development mode without a configured key, permits access.
    """
    admin_key = os.environ.get("SENTINEL_ADMIN_KEY", "").strip()
    if admin_key:
        token = x_sentinel_admin_key
        if not token and authorization and authorization.startswith("Bearer "):
            token = authorization.split("Bearer ", 1)[1].strip()
        if not token or token != admin_key:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Valid X-Sentinel-Admin-Key header required for privileged operations."
            )
    elif os.environ.get("VERCEL"):
        if not x_sentinel_admin_key:
            raise HTTPException(
                status_code=401,
                detail="Security policy: Administrator key authentication required on cloud deployments."
            )
    return True


def verify_agent_authorization(
    x_agent_secret: Optional[str] = Header(None, alias="X-Agent-Secret"),
    authorization: Optional[str] = Header(None)
):
    """
    Enforce server-side authorization on agent telemetry ingestion routes.
    If SENTINEL_AGENT_SECRET is configured, verifies X-Agent-Secret header or Bearer token.
    """
    expected_secret = os.environ.get("SENTINEL_AGENT_SECRET", "").strip()
    if expected_secret:
        token = x_agent_secret
        if not token and authorization and authorization.startswith("Bearer "):
            token = authorization.split("Bearer ", 1)[1].strip()
        if not token or token != expected_secret:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Valid X-Agent-Secret header or Bearer token required for agent telemetry ingestion."
            )
    return True


# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------
@app.get("/health")
@app.get("/api/health")
def health_check():
    db_ok = True
    try:
        db.get_incidents()
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "service": "SentinelAI Cloud SOC",
        "version": "2.5.0",
        "database": "connected" if db_ok else "unreachable",
        "gemini_active": explainer.is_gemini_active,
        "environment": "vercel_serverless" if os.environ.get("VERCEL") else ("docker" if os.environ.get("DOCKER_CONTAINER") else "local"),
        "timestamp": datetime.datetime.now().isoformat()
    }


@app.get("/ready")
@app.get("/api/ready")
def readiness_check():
    """
    Readiness probe verifying database responsiveness, active ML artifacts,
    and streaming event buffer state.
    """
    db_ok = True
    try:
        db.get_incidents()
    except Exception:
        db_ok = False

    from stream_engine import get_stream_publisher
    stream_pub = get_stream_publisher()
    stream_status = stream_pub.get_status()

    artifacts_dir = os.path.join(ROOT_DIR, "artifacts")
    iso_exists = os.path.isfile(os.path.join(artifacts_dir, "network_anomaly_isolation_forest.joblib"))
    rf_exists = os.path.isfile(os.path.join(artifacts_dir, "network_threat_classifier.joblib"))
    web_log_exists = os.path.isfile(os.path.join(artifacts_dir, "web_log_model.joblib"))

    return {
        "status": "ready" if db_ok else "unready",
        "service": "SentinelAI Cloud SOC",
        "version": "2.5.0",
        "database": "ready" if db_ok else "unreachable",
        "redis_stream": "connected" if stream_status["is_connected"] else "buffered_fallback",
        "models": {
            "network_isolation_forest": "loaded" if iso_exists else "pending",
            "network_random_forest": "loaded" if rf_exists else "pending",
            "web_log_baseline": "loaded" if web_log_exists else "pending"
        },
        "timestamp": datetime.datetime.now().isoformat()
    }


@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """WebSocket feed broadcasting live security alerts to connected dashboards."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """WebSocket feed broadcasting raw network telemetry events."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@app.post("/api/agent/telemetry", dependencies=[Depends(verify_agent_authorization)])
@app.post("/api/ingest", dependencies=[Depends(verify_agent_authorization)])
def ingest_agent_telemetry(payload: AgentTelemetryPayload):
    """
    Authenticated ingestion route for native Windows endpoint agents and Dockerized collectors.
    Normalizes network events, correlates intrusions, and persists detections to SQLite.
    """
    if not payload.events:
        raise HTTPException(status_code=400, detail="Empty telemetry payload: no events provided.")

    # Convert events list to DataFrame
    df = LogParser.events_to_dataframe(payload.events)
    if df.empty:
        import pandas as pd
        df = pd.DataFrame(payload.events)

    if df.empty:
        raise HTTPException(status_code=400, detail="Invalid event format: unable to parse telemetry.")

    # Run detection and correlation
    enriched_df = detector.detect_dataframe(df)
    correlated = detector.correlate_incidents(df)

    # Ingestion audit record
    db.log_audit_action(
        incident_id="AGENT_INGEST",
        action_type="ENDPOINT_AGENT_TELEMETRY",
        target_ip=f"Host: {payload.host_id} ({payload.os_type})",
        execution_mode="authenticated_agent",
        operator=f"Agent-{payload.host_id}",
        details=f"Ingested {len(payload.events)} event(s) from agent v{payload.agent_version}. Correlated {len(correlated)} incident(s).",
        result="SUCCESS"
    )

    persisted = []
    for inc in correlated:
        inc_dict = inc.to_dict()
        db.save_incident(inc_dict)

        # Trigger AI explanation
        exp = explainer.explain_incident(inc_dict)
        provider_tag = "Google Gemini Live AI" if exp.get("provider") == "google_gemini" else "Local Knowledge Base"

        db.log_audit_action(
            incident_id=inc.incident_id,
            action_type="AGENT_INCIDENT_EXPLANATION",
            target_ip=inc.source_ip,
            execution_mode="live_ai" if exp.get("provider") == "google_gemini" else "local_fallback",
            operator=provider_tag,
            details=f"Threat reasoning generated for {inc.category}: {exp.get('summary', '')[:140]}",
            result="SUCCESS"
        )
        persisted.append({
            "incident": inc_dict,
            "explanation": exp
        })

    return {
        "status": "success",
        "host_id": payload.host_id,
        "agent_version": payload.agent_version,
        "received_events": len(payload.events),
        "correlated_incidents": len(correlated),
        "incidents": persisted
    }


@app.get("/api/status")
def get_system_status():
    incidents = db.get_incidents()
    critical_count = sum(1 for i in incidents if i.get("severity") == "Critical")
    high_count = sum(1 for i in incidents if i.get("severity") == "High")
    unreviewed_count = sum(1 for i in incidents if i.get("analyst_verdict") in ("Unreviewed", None))
    confirmed_count = sum(1 for i in incidents if i.get("analyst_verdict") == "True Positive")

    defcon_level = 1 if critical_count > 0 else (2 if high_count > 0 else 5)
    defcon_label = "DEFCON 1 - CRITICAL" if critical_count > 0 else ("DEFCON 2 - HIGH" if high_count > 0 else "DEFCON 5 - NOMINAL")
    risk_score = 92 if critical_count > 0 else (75 if high_count > 0 else 25)

    sample_csv_path = os.path.join(ROOT_DIR, "sample_traafic.csv")
    import pandas as pd
    base_df = pd.read_csv(sample_csv_path) if os.path.exists(sample_csv_path) else pd.DataFrame()
    exec_summary = explainer.generate_executive_summary(base_df)
    total_pkts = int(base_df["Packets"].sum()) if not base_df.empty and "Packets" in base_df.columns else 12500

    active_blocks = db.get_active_blocks()
    active_block_count = sum(1 for b in active_blocks if b.get("status") == "Active")

    return {
        "defcon_level": defcon_level,
        "defcon_label": defcon_label,
        "active_incidents": len(incidents),
        "unreviewed_count": unreviewed_count,
        "confirmed_count": confirmed_count,
        "active_block_count": active_block_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "telemetry_flows": len(base_df) if not base_df.empty else 10,
        "total_packets": total_pkts,
        "threat_index": risk_score,
        "ai_executive_summary": exec_summary,
        "gemini_active": explainer.is_gemini_active,
        "sensor_mode": "Demo Simulation" if incidents else "Idle"
    }


@app.get("/api/incidents")
def list_incidents():
    return db.get_incidents()


@app.post("/api/contain", dependencies=[Depends(verify_admin_authorization)])
def execute_containment(req: ContainmentRequest):
    target_ip = sanitize_ip(req.target_ip)
    if target_ip == "0.0.0.0" and req.target_ip.strip() not in ["0.0.0.0", "0.0.0.0/0"]:
        raise HTTPException(status_code=400, detail=f"Invalid or unsafe IP address: '{req.target_ip}'")

    res = response_engine.execute_response_action(
        incident_id=req.incident_id,
        action_type=req.action_type,
        target_ip=target_ip,
        dry_run=req.dry_run,
        admin_approved=req.admin_approved,
        operator=req.operator,
        db_manager=db
    )
    cmds = response_engine.generate_firewall_commands(target_ip)
    rollbacks = response_engine.generate_rollback_commands(target_ip)

    return {
        "result": res,
        "commands": cmds,
        "rollback_commands": rollbacks
    }


@app.post("/api/copilot")
def query_copilot(req: CopilotQueryRequest):
    exp = explainer.explain_threat(
        activity=req.category,
        source_ip=req.source_ip,
        packets=req.packets,
        risk=req.risk
    )
    guidance = None
    if req.query:
        guidance = (
            f"Analyst Guidance for '{req.query}': Verify {req.source_ip} against internal CMDB assets. "
            f"Apply border edge rate-limiting and audit connection logs."
        )
    return {
        "explanation": exp,
        "analyst_guidance": guidance
    }


@app.get("/api/sample/{sample_name}")
def load_sample_dataset(sample_name: str):
    data_dir = os.path.join(ROOT_DIR, "data")
    file_map = {
        "suricata_73": os.path.join(data_dir, "sentinelai_suricata_eve_sample.json"),
        "suricata_basic": os.path.join(data_dir, "suricata_sample.json"),
        "port_scan": os.path.join(data_dir, "attack_port_scan.json"),
        "brute_force": os.path.join(data_dir, "attack_brute_force.json"),
        "ddos_flood": os.path.join(data_dir, "attack_ddos_flood.json"),
        "malformed": os.path.join(data_dir, "malformed_records.json")
    }

    if sample_name not in file_map or not os.path.exists(file_map[sample_name]):
        raise HTTPException(status_code=404, detail=f"Sample '{sample_name}' not found")

    path = file_map[sample_name]
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    if "suricata" in sample_name:
        events, errs = LogParser.parse_suricata_eve(content)
    else:
        events, errs = LogParser.parse_generic_json(content)

    df = LogParser.events_to_dataframe(events)
    enriched_df = detector.detect_dataframe(df)
    correlated = detector.correlate_incidents(df)

    for inc in correlated:
        db.save_incident(inc.to_dict())

    return {
        "sample": sample_name,
        "total_records": len(enriched_df),
        "correlated_incidents": [inc.to_dict() for inc in correlated],
        "events": enriched_df.to_dict(orient="records"),
        "parse_errors": errs
    }


@app.post("/api/upload")
async def upload_manual_log_file(file: UploadFile = File(...)):
    """Upload custom/manual telemetry file, correlate incidents, generate Gemini explanations, and log to audit ledger."""
    raw_bytes = await file.read()
    raw_content = raw_bytes.decode("utf-8", errors="ignore")
    filename = file.filename or "uploaded_log.json"

    if filename.endswith(".csv"):
        import io
        import pandas as pd
        df = pd.read_csv(io.StringIO(raw_content))
    elif "suricata" in filename.lower() or "event_type" in raw_content[:400].lower():
        events, _ = LogParser.parse_suricata_eve(raw_content)
        df = LogParser.events_to_dataframe(events)
    else:
        events, _ = LogParser.parse_generic_json(raw_content)
        df = LogParser.events_to_dataframe(events)

    if df.empty:
        raise HTTPException(status_code=400, detail="No valid network telemetry events found in file.")

    correlated = detector.correlate_incidents(df)

    # Ingestion audit log
    db.log_audit_action(
        incident_id="INGESTION",
        action_type="TELEMETRY_LOG_INGESTION",
        target_ip=f"File: {filename}",
        execution_mode="local",
        operator="Security Analyst",
        details=f"Parsed {len(df)} telemetry records. Identified {len(correlated)} correlated incident(s).",
        result="SUCCESS"
    )

    results = []
    for inc in correlated:
        inc_dict = inc.to_dict()
        db.save_incident(inc_dict)

        # Gemini threat explanation
        exp = explainer.explain_incident(inc_dict)
        provider_tag = "Google Gemini Live AI" if exp.get("provider") == "google_gemini" else "Local Knowledge Base"

        db.log_audit_action(
            incident_id=inc.incident_id,
            action_type="GEMINI_AI_EXPLANATION",
            target_ip=inc.source_ip,
            execution_mode="live_ai" if exp.get("provider") == "google_gemini" else "local_fallback",
            operator=provider_tag,
            details=f"Gemini analyzed {inc.category}: {exp.get('summary', '')[:140]}",
            result="SUCCESS"
        )
        results.append({
            "incident": inc_dict,
            "explanation": exp
        })

    return {
        "status": "success",
        "filename": filename,
        "total_records": len(df),
        "incidents_count": len(correlated),
        "incidents": results
    }


@app.get("/api/simulate")
def get_simulation_stream():
    sim = LiveMonitoringSimulator(buffer_size=50)
    sim.start(interval_seconds=0.1)
    import time
    time.sleep(1.2)
    sim.stop()
    events = sim.get_recent_events(limit=15)
    return {
        "status": "active",
        "generated_count": len(events),
        "events": events
    }


@app.get("/api/audit")
def get_audit_trail():
    return db.get_audit_logs(limit=50)


@app.post("/api/reset-demo", dependencies=[Depends(verify_admin_authorization)])
def reset_demo_database():
    db.reset_demo_data()
    return {"status": "success", "message": "Demo incidents restored"}


@app.post("/api/incidents/{incident_id}/verdict", dependencies=[Depends(verify_admin_authorization)])
def submit_verdict(incident_id: str, req: VerdictRequest):
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    fb_id = db.record_analyst_feedback(
        incident_id=incident_id,
        verdict=req.verdict,
        analyst_user=req.analyst_user,
        reason=req.reason
    )
    return {
        "status": "success",
        "feedback_id": fb_id,
        "incident_id": incident_id,
        "verdict": req.verdict
    }


@app.get("/api/incidents/{incident_id}/explain")
def explain_specific_incident(incident_id: str):
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return explainer.explain_incident(inc)


@app.get("/api/ml/status")
def get_ml_status():
    from ml_engine import get_ml_engine
    ml_eng = get_ml_engine()
    active_in_db = db.get_active_model()
    registry = db.get_model_registry()
    return {
        "active_model_version": ml_eng.model_version,
        "is_fitted": ml_eng.is_fitted,
        "metrics": ml_eng.metrics,
        "database_active_model": active_in_db,
        "registered_models": registry
    }


@app.post("/api/ml/predict")
def predict_ml(req: MLPredictRequest):
    from ml_engine import get_ml_engine
    ml_eng = get_ml_engine()
    return ml_eng.predict_score({
        "packets": req.packets,
        "port": req.port,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "activity": req.activity,
        "risk": req.risk
    })


@app.post("/api/ml/retrain", dependencies=[Depends(verify_admin_authorization)])
def retrain_ml(req: MLRetrainRequest):
    from ml_engine import get_ml_engine, MLAnomalyEngine
    ml_eng = get_ml_engine()
    fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=req.sample_count)
    metrics = ml_eng.train_controlled_pipeline(
        training_data=fixtures,
        version_tag=req.version_tag,
        trained_by=req.trained_by,
        contamination=req.contamination
    )
    if metrics.get("status") == "VALIDATED_AND_TRAINED":
        db.register_model(
            version=metrics["model_version"],
            algorithm=metrics["algorithm"],
            sample_count=metrics["total_samples"],
            metrics=metrics,
            artifact_path=metrics["artifact_path"],
            trained_by=req.trained_by,
            set_active=True
        )
    return {
        "status": "success",
        "validation_status": metrics.get("status"),
        "new_model_version": metrics.get("model_version"),
        "metrics": metrics,
        "raw": metrics
    }


@app.post("/api/ml/revert", dependencies=[Depends(verify_admin_authorization)])
def revert_ml(req: MLRevertRequest):
    from ml_engine import get_ml_engine
    ml_eng = get_ml_engine()
    success = ml_eng.revert_model(req.version)
    if success:
        db.set_active_model_version(req.version)
        return {"status": "success", "active_model_version": req.version}
    raise HTTPException(status_code=400, detail=f"Could not revert to version '{req.version}'. Artifact not found.")


@app.get("/api/blocks")
def list_blocks():
    expired = db.check_and_expire_blocks()
    blocks = db.get_active_blocks()
    return {"active_blocks": blocks, "recently_expired": expired}


@app.post("/api/blocks/rollback", dependencies=[Depends(verify_admin_authorization)])
def rollback_block_endpoint(req: RollbackBlockRequest):
    res = db.rollback_block(block_id=req.block_id, operator=req.operator)
    return res


@app.post("/api/retention/purge", dependencies=[Depends(verify_admin_authorization)])
def purge_retention(req: RetentionPurgeRequest):
    res = db.apply_data_retention(retention_days=req.retention_days, operator=req.operator)
    return {"status": "success", "result": res}


# ------------------------------------------------------------------------------
# PCAP Ingestion & Processing APIs
# ------------------------------------------------------------------------------
PCAP_UPLOAD_DIR = os.environ.get("PCAP_UPLOAD_DIR") or os.path.join(ROOT_DIR, "data", "uploads")
os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)


@app.post("/api/pcap/upload")
async def upload_pcap_endpoint(file: UploadFile = File(...)):
    """
    Accepts authorized .pcap and .pcapng captures.
    Validates file format, magic bytes, and size, then dispatches background processing.
    """
    from pcap_engine import PCAPValidator, PCAPValidationError, get_job_manager

    filename = file.filename or "capture.pcap"
    lower_fn = filename.lower()
    if not (lower_fn.endswith(".pcap") or lower_fn.endswith(".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Only standard .pcap and modern .pcapng captures are supported."
        )

    # Secure sanitized upload destination
    safe_name = os.path.basename(filename).replace(" ", "_")
    unique_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
    dest_path = os.path.join(PCAP_UPLOAD_DIR, unique_name)

    # Stream write with size limit checking
    max_size = 100 * 1024 * 1024  # 100 MB
    bytes_written = 0

    try:
        with open(dest_path, "wb") as out_f:
            while chunk := await file.read(65536):
                bytes_written += len(chunk)
                if bytes_written > max_size:
                    out_f.close()
                    os.remove(dest_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Uploaded file exceeds maximum limit of {max_size // (1024*1024)} MB."
                    )
                out_f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {str(e)}")

    # Validate capture header magic bytes
    try:
        is_valid, fmt, msg = PCAPValidator.validate_file(dest_path, max_size_bytes=max_size)
    except PCAPValidationError as e:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise HTTPException(status_code=400, detail=str(e))

    # Create job in background worker queue
    job_mgr = get_job_manager()
    job_id = job_mgr.create_job(filename=filename, file_size=bytes_written, saved_path=dest_path)
    job_mgr.run_job_async(job_id)

    # Record capture entry in database
    db.save_pcap_capture({
        "capture_id": job_id,
        "filename": filename,
        "file_size": bytes_written,
        "uploaded_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "format": fmt,
        "status": "PROCESSING",
        "metadata": {"saved_path": dest_path}
    })

    return {
        "status": "QUEUED",
        "job_id": job_id,
        "filename": filename,
        "file_size": bytes_written,
        "format": fmt,
        "message": "Capture uploaded successfully. Processing started in background worker."
    }


@app.get("/api/pcap/jobs")
def list_pcap_jobs():
    """List recent capture processing jobs."""
    from pcap_engine import get_job_manager
    jobs = get_job_manager().list_jobs()
    return {"jobs": jobs}


@app.get("/api/pcap/jobs/{job_id}")
def get_pcap_job_status(job_id: str):
    """Retrieve capture processing status and flow metrics."""
    from pcap_engine import get_job_manager
    job = get_job_manager().get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Capture job '{job_id}' not found.")
    
    # Return job with preview of flows
    flows_preview = job.get("flows", [])[:20]
    return {
        "job_id": job["job_id"],
        "filename": job["filename"],
        "file_size": job["file_size"],
        "status": job["status"],
        "progress_percent": job["progress_percent"],
        "packet_count": job["packet_count"],
        "flow_count": job["flow_count"],
        "engine_used": job.get("engine_used"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "error_message": job.get("error_message"),
        "flows_preview": flows_preview
    }


@app.get("/api/pcap/jobs/{job_id}/flows")
def get_pcap_job_flows(job_id: str):
    """Retrieve all extracted bidirectional flows for a completed capture job."""
    from pcap_engine import get_job_manager
    job = get_job_manager().get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Capture job '{job_id}' not found.")
    return {
        "job_id": job_id,
        "flow_count": len(job.get("flows", [])),
        "flows": job.get("flows", [])
    }


@app.post("/api/pcap/jobs/{job_id}/ingest")
def ingest_pcap_flows_to_soc(job_id: str):
    """
    Ingest extracted bidirectional flows into live SentinelAI incident detection pipeline.
    Persists flows and produces correlated threat alerts.
    """
    from pcap_engine import get_job_manager
    job = get_job_manager().get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Capture job '{job_id}' not found.")
    if job.get("status") != "COMPLETED":
        raise HTTPException(status_code=400, detail="Cannot ingest capture: processing is not yet completed.")

    flows = job.get("flows", [])
    if not flows:
        return {"status": "success", "ingested_flows": 0, "incidents_created": 0}

    # Persist flows to database
    db.save_pcap_flows(job_id, flows)

    # Convert flows to telemetry DataFrame and evaluate through threat detector
    records = []
    for f in flows:
        records.append({
            "Time": datetime.datetime.fromtimestamp(f.get("start_time", time.time())).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": f.get("src_ip", "0.0.0.0"),
            "Destination IP": f.get("dst_ip", "0.0.0.0"),
            "Port": f.get("dst_port", 80),
            "Source Port": f.get("src_port", 0),
            "Protocol": f.get("protocol", "TCP"),
            "Packets": f.get("total_packets", 1),
            "Bytes": f.get("total_bytes", 64),
            "Duration": f.get("duration", 0.05),
            "Activity": "Normal Traffic",
            "Risk": "Low"
        })

    flows_df = pd.DataFrame(records)
    incidents = detector.correlate_incidents(flows_df)

    # Save incidents
    for inc in incidents:
        db.save_incident(inc.to_dict())

    return {
        "status": "success",
        "job_id": job_id,
        "ingested_flows": len(flows),
        "incidents_created": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents]
    }


@app.post("/api/pcap/live-stream", dependencies=[Depends(verify_agent_authorization)])
def ingest_live_pcap_stream(payload: PCAPLiveStreamPayload):
    """
    Authenticated ingestion endpoint for supervised host TShark capture agent.
    Streams live bidirectional flows, publishes to Redis Streams, and evaluates incidents.
    """
    flows = payload.flows
    if not flows:
        return {"status": "success", "received_flows": 0, "incidents_created": 0}

    from stream_engine import get_stream_publisher
    publisher = get_stream_publisher()

    # Log events & stream
    for f in flows:
        is_replay = bool(f.get("is_replay", False))
        act_name = "PCAP Replay Flow" if is_replay else "Live Host Flow"
        db.log_telemetry_event({
            "source_ip": f.get("src_ip", "0.0.0.0"),
            "destination_ip": f.get("dst_ip", "10.0.0.1"),
            "port": f.get("dst_port", 80),
            "packets": f.get("total_packets", 1),
            "activity": act_name,
            "risk": "Low"
        })
        publisher.publish_event(f)

    # Evaluate correlation
    records = []
    for f in flows:
        is_replay = bool(f.get("is_replay", False))
        act_name = "PCAP Replay Flow" if is_replay else "Live Host Flow"
        records.append({
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": f.get("src_ip", "0.0.0.0"),
            "Destination IP": f.get("dst_ip", "10.0.0.1"),
            "Port": f.get("dst_port", 80),
            "Source Port": f.get("src_port", 0),
            "Protocol": f.get("protocol", "TCP"),
            "Packets": f.get("total_packets", 1),
            "Activity": act_name,
            "Risk": "Low"
        })
    df_flows = pd.DataFrame(records)
    incidents = detector.correlate_incidents(df_flows)

    incidents_saved = []
    for inc in incidents:
        inc_d = inc.to_dict()
        is_replay = bool(flows[0].get("is_replay", False)) if flows else False
        inc_d["is_replay"] = is_replay
        inc_d["telemetry_source"] = "pcap_replay" if is_replay else "tshark_live"
        db.save_incident(inc_d)
        incidents_saved.append(inc_d)

    return {
        "status": "success",
        "host_id": payload.host_id,
        "received_flows": len(flows),
        "incidents_created": len(incidents_saved)
    }


@app.post("/api/collector/events", dependencies=[Depends(verify_agent_authorization)])
def ingest_collector_events(payload: CollectorBatchPayload):
    """
    Versioned, authenticated ingestion endpoint for host TShark collector and external probes.
    Validates payload bounds, assigns unique IDs, publishes to Redis Streams,
    and returns correlated security detections.
    """
    if not payload.events:
        raise HTTPException(status_code=400, detail="Empty event batch: no events provided.")

    if len(payload.events) > 500:
        raise HTTPException(
            status_code=413,
            detail=f"Batch size {len(payload.events)} exceeds maximum allowed limit of 500 events."
        )

    from stream_engine import get_stream_publisher
    publisher = get_stream_publisher()
    now_iso = datetime.datetime.now().isoformat()

    normalized_events = []
    for ev in payload.events:
        d = ev.dict()
        if not d.get("event_id"):
            d["event_id"] = f"EVT-{uuid.uuid4().hex[:10].upper()}"
        if not d.get("timestamp"):
            d["timestamp"] = now_iso
        d["collector_id"] = payload.collector_id
        d["schema_version"] = payload.schema_version

        # Publish to Redis Stream buffer
        publisher.publish_event(d)
        normalized_events.append(d)

        # Log event to database
        is_replay = bool(d.get("is_replay", False))
        act_name = "PCAP Replay Flow" if is_replay else "Live Network Flow"
        try:
            db.log_telemetry_event({
                "source_ip": d.get("src_ip", "0.0.0.0"),
                "destination_ip": d.get("dst_ip", "10.0.0.1"),
                "port": d.get("dst_port", 80),
                "packets": d.get("total_packets", 1),
                "activity": act_name,
                "risk": "Low"
            })
        except Exception:
            pass

    # Correlate incidents
    records = []
    for d in normalized_events:
        is_replay = bool(d.get("is_replay", False))
        act_name = "PCAP Replay Flow" if is_replay else "Live Network Flow"
        records.append({
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": d.get("src_ip", "0.0.0.0"),
            "Destination IP": d.get("dst_ip", "10.0.0.1"),
            "Port": d.get("dst_port", 80),
            "Protocol": d.get("protocol", "TCP"),
            "Packets": d.get("total_packets", 1),
            "Bytes": d.get("total_bytes", 64),
            "Activity": act_name,
            "Risk": "Low"
        })

    df_flows = pd.DataFrame(records)
    incidents = detector.correlate_incidents(df_flows)

    incidents_saved = []
    for inc in incidents:
        inc_d = inc.to_dict()
        is_replay = bool(normalized_events[0].get("is_replay", False)) if normalized_events else False
        inc_d["is_replay"] = is_replay
        inc_d["telemetry_source"] = "pcap_replay" if is_replay else "tshark_live"
        db.save_incident(inc_d)
        incidents_saved.append(inc_d)

    return {
        "status": "accepted",
        "schema_version": payload.schema_version,
        "collector_id": payload.collector_id,
        "received_events": len(payload.events),
        "incidents_created": len(incidents_saved),
        "incidents": incidents_saved
    }


# ------------------------------------------------------------------------------
# ML Training & Model Registry APIs
# ------------------------------------------------------------------------------
@app.get("/api/dataset/overview")
def get_dataset_overview():
    """
    Inspect the active synthetic training dataset and return schema, label counts,
    feature columns, and class balance overview.
    """
    csv_path = os.path.join(ROOT_DIR, "sentinel_enriched_telemetry.csv")
    if not os.path.exists(csv_path):
        csv_path = os.path.join(ROOT_DIR, "data", "sentinel_enriched_telemetry_audit.csv")

    if not os.path.exists(csv_path):
        raise HTTPException(status_code=404, detail="Synthetic telemetry dataset not found.")

    df = pd.read_csv(csv_path)

    act_counts = df["Activity"].value_counts().to_dict() if "Activity" in df.columns else {}
    risk_counts = df["Risk"].value_counts().to_dict() if "Risk" in df.columns else {}
    threat_counts = {str(k): int(v) for k, v in df["Threat Detected"].value_counts().to_dict().items()} if "Threat Detected" in df.columns else {}
    proto_counts = df["Protocol"].value_counts().to_dict() if "Protocol" in df.columns else {}

    return {
        "dataset_name": "sentinel_enriched_telemetry.csv",
        "sample_count": len(df),
        "columns": list(df.columns),
        "raw_features": ["Time", "Source IP", "Destination IP", "Port", "Source Port", "Protocol", "Packets"],
        "engineered_features": [
            "packets", "port", "source_port", "flow_duration", "bytes", "flow_frequency",
            "unique_ports_contacted", "mean_packets_per_flow", "is_privileged_port",
            "is_admin_port", "proto_tcp", "proto_udp", "proto_icmp", "proto_other",
            "tcp_flag_syn", "tcp_flag_rst", "tcp_flag_ack", "packets_per_sec", "bytes_per_sec"
        ],
        "attack_categories": act_counts,
        "risk_distribution": risk_counts,
        "threat_detected_distribution": threat_counts,
        "protocol_distribution": proto_counts,
        "label_columns": ["Activity", "Threat Detected"]
    }


@app.post("/api/dataset/validate")
def validate_dataset_endpoint(req: DatasetValidationRequest):
    """
    Validate candidate training dataset before initiating model training.
    """
    csv_path = os.path.join(ROOT_DIR, req.dataset_name)
    if not os.path.isfile(csv_path):
        csv_path = os.path.join(ROOT_DIR, "data", req.dataset_name)

    if not os.path.isfile(csv_path):
        return {"valid": False, "reason": f"Dataset file '{req.dataset_name}' not found."}

    df = pd.read_csv(csv_path)
    if len(df) < req.min_samples:
        return {
            "valid": False,
            "sample_count": len(df),
            "reason": f"Sample count ({len(df)}) below minimum required threshold ({req.min_samples})."
        }

    return {
        "valid": True,
        "sample_count": len(df),
        "columns": list(df.columns),
        "message": f"Dataset '{req.dataset_name}' validated with {len(df)} samples."
    }


@app.post("/api/ml/train", dependencies=[Depends(verify_admin_authorization)])
def train_model_endpoint(req: MLTrainRequest):
    """
    Train supervised attack classifier or unsupervised anomaly detector on reviewed dataset.
    Enforces the security guardrail: never trains on unreviewed live alerts.
    """
    if not req.is_reviewed_ground_truth:
        raise HTTPException(
            status_code=400,
            detail="Security Policy Guardrail: Automated model retraining on unreviewed live alerts is strictly prohibited."
        )

    csv_path = os.path.join(ROOT_DIR, req.dataset)
    if not os.path.isfile(csv_path):
        csv_path = os.path.join(ROOT_DIR, "data", req.dataset)

    if not os.path.isfile(csv_path):
        raise HTTPException(status_code=404, detail=f"Training dataset '{req.dataset}' not found.")

    df = pd.read_csv(csv_path)

    if req.model_type == "supervised_classifier":
        from ml_engine import get_supervised_classifier
        classifier = get_supervised_classifier()
        try:
            metrics = classifier.train_on_dataset(
                data=df,
                label_column=req.label_column,
                version_tag=req.version_tag,
                test_size=req.test_size,
                trained_by=req.trained_by,
                is_reviewed_ground_truth=req.is_reviewed_ground_truth
            )
            # Register in DB
            db.register_model(
                version=metrics["model_version"],
                algorithm=metrics["algorithm"],
                sample_count=metrics["total_samples"],
                metrics=metrics,
                artifact_path=metrics["artifact_path"],
                trained_by=req.trained_by,
                set_active=True
            )
            return {"status": "success", "model_type": "supervised_classifier", "metrics": metrics}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    else:
        # Unsupervised Isolation Forest training
        from ml_engine import get_ml_engine
        ml_eng = get_ml_engine()
        metrics = ml_eng.train_controlled_pipeline(
            training_data=df,
            version_tag=req.version_tag,
            test_size=req.test_size,
            trained_by=req.trained_by,
            contamination=req.contamination
        )
        if metrics.get("status") == "VALIDATED_AND_TRAINED":
            db.register_model(
                version=metrics["model_version"],
                algorithm=metrics["algorithm"],
                sample_count=metrics["total_samples"],
                metrics=metrics,
                artifact_path=metrics["artifact_path"],
                trained_by=req.trained_by,
                set_active=True
            )
            return {"status": "success", "model_type": "isolation_forest", "metrics": metrics}
        raise HTTPException(status_code=400, detail=metrics.get("message", "Training rejected by validation gate."))


@app.get("/api/ml/models")
def list_ml_models():
    """List all registered ML models with evaluation metrics."""
    models = db.get_model_registry()
    return {"models": models}


@app.get("/api/ml/evaluation/{version}")
def get_model_evaluation(version: str):
    """Retrieve detailed evaluation metrics and confusion matrix for a model version."""
    models = db.get_model_registry()
    match = next((m for m in models if m["version"] == version), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Model version '{version}' not found in registry.")
    return match


@app.post("/api/ml/models/{version}/activate", dependencies=[Depends(verify_admin_authorization)])
def activate_model_version(version: str):
    """Activate a registered model version."""
    models = db.get_model_registry()
    match = next((m for m in models if m["version"] == version), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Model version '{version}' not found in registry.")

    db.set_active_model_version(version)
    # Also reload in active memory
    from ml_engine import get_ml_engine, get_supervised_classifier
    if "classifier" in match.get("algorithm", "").lower() or "randomforest" in match.get("algorithm", "").lower():
        clf = get_supervised_classifier()
        clf.model_version = version
        clf._load_active_or_default()
    else:
        eng = get_ml_engine()
        eng.revert_model(version)

    return {"status": "success", "active_version": version, "algorithm": match.get("algorithm")}


@app.get("/api/stream/status")
def get_stream_engine_status():
    """Return status of Redis Streams event and alert publishing."""
    from stream_engine import get_stream_publisher
    return get_stream_publisher().get_status()


# ------------------------------------------------------------------------------
# FRONTEND HTML DASHBOARD (Approachable Light Theme & Simple Navigation)
# ------------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelAI — Your Security Assistant (Enterprise Threat Defense SOC)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-app: #F4F7FB;
      --card-bg: #FFFFFF;
      --text-primary: #172B4D;
      --text-secondary: #667085;
      --accent-primary: #2457A7;
      --status-success: #16835D;
      --status-warning: #B7791F;
      --status-danger: #C0392B;
      --border-color: #E2E8F0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-app);
      color: var(--text-primary);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #FFFFFF;
      border-bottom: 1px solid var(--border-color);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 {
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--accent-primary);
    }
    .brand-sub {
      font-size: 0.82rem;
      color: var(--text-secondary);
    }
    .tabs-bar {
      background: #FFFFFF;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      gap: 6px;
      padding: 0 32px;
    }
    .tab-btn {
      background: none;
      border: none;
      color: var(--text-secondary);
      padding: 14px 18px;
      font-weight: 600;
      font-size: 0.92rem;
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.15s ease;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .tab-btn:hover { color: var(--accent-primary); }
    .tab-btn.active {
      color: var(--accent-primary);
      border-bottom-color: var(--accent-primary);
    }
    main {
      flex: 1;
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
      width: 100%;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.2s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }

    /* Cards */
    .sa-card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px 24px;
      margin-bottom: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .metric-card {
      background: #FFFFFF;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 18px 20px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }
    .metric-title {
      font-size: 0.8rem;
      color: var(--text-secondary);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .metric-val {
      font-size: 1.8rem;
      font-weight: 700;
      color: var(--text-primary);
    }

    /* Banners & Badges */
    .banner {
      background: #EFF6FF;
      border: 1px solid #BFDBFE;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 20px;
      display: flex;
      gap: 14px;
      align-items: flex-start;
    }
    .sa-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.76rem;
      font-weight: 600;
    }
    .sa-badge-danger { background: #FEE2E2; color: #C0392B; border: 1px solid #FCA5A5; }
    .sa-badge-warning { background: #FEF3C7; color: #B7791F; border: 1px solid #FCD34D; }
    .sa-badge-success { background: #D1FAE5; color: #16835D; border: 1px solid #6EE7B7; }
    .sa-badge-neutral { background: #F1F5F9; color: #667085; border: 1px solid #E2E8F0; }

    /* Buttons */
    .btn {
      background: var(--accent-primary);
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.86rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
    }
    .btn:hover { background: #1c4482; }
    .btn-secondary { background: #F1F5F9; color: var(--text-primary); border: 1px solid var(--border-color); }
    .btn-secondary:hover { background: #E2E8F0; }
    .btn-danger { background: #C0392B; color: white; }
    .btn-danger:hover { background: #962d22; }

    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { text-align: left; padding: 12px 14px; background: #F8FAFC; color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--border-color); }
    td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); }
    tr:hover { background: #F8FAFC; }

    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media(max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <span style="font-size: 1.4rem;">🛡️</span>
      <div>
        <h1>SentinelAI — Your Security Assistant</h1>
        <div class="brand-sub">Understand suspicious activity and decide what to do next. (Enterprise Threat Defense SOC)</div>
      </div>
    </div>
    <div style="display: flex; align-items: center; gap: 12px;">
      <span id="sensorPill" class="sa-badge sa-badge-warning">Demo Simulation</span>
      <div id="defconPill" class="sa-badge sa-badge-danger" style="display:none;">DEFCON 1 - CRITICAL</div>
      <button class="btn" style="background:#2457A7;" onclick="runGuidedDemo()">🚀 Run Guided Demo</button>
      <button class="btn btn-secondary" onclick="resetDemo()">🔄 Reset Demo</button>
    </div>
  </header>

  <nav class="tabs-bar">
    <button class="tab-btn active" onclick="switchTab('home')">🏠 Home — Security Overview</button>
    <button class="tab-btn" onclick="switchTab('threats')">🔍 Investigations (Threats)</button>
    <button class="tab-btn" onclick="switchTab('copilot')">🤖 AI Copilot</button>
    <button class="tab-btn" onclick="switchTab('protection')">🛡️ Protection</button>
    <button class="tab-btn" onclick="switchTab('activity')">📋 Activity and Audit</button>
    <button class="tab-btn" onclick="switchTab('advanced')">⚙️ Advanced Tools</button>
  </nav>

  <main>
    <!-- TAB 1: HOME -->
    <div id="tab-home" class="tab-content active">
      <div class="banner">
        <div style="font-size:1.5rem;">💡</div>
        <div>
          <strong id="homeBannerTitle">System Status: Monitoring Active</strong>
          <p id="homeBannerDesc" style="color:var(--text-secondary); font-size:0.9rem; margin-top:4px;">
            Evaluating network flow observations across enterprise boundaries. All alerts require human verification.
          </p>
        </div>
      </div>

      <div id="guidedDemoBox" class="sa-card" style="border:2px solid #2457A7; display:none; margin-bottom:20px;"></div>

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title">Threats Needing Review</div>
          <div class="metric-val" id="metricUnreviewed" style="color:#C0392B;">--</div>
          <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">Suspicious items pending triage</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Confirmed Incidents</div>
          <div class="metric-val" id="metricConfirmed" style="color:#2457A7;">--</div>
          <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">Verified security events</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Protection Actions</div>
          <div class="metric-val" id="metricBlocks" style="color:#B7791F;">--</div>
          <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">Active simulated policies</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Protection Mode</div>
          <div class="metric-val" style="color:#16835D; font-size:1.4rem;">Simulated</div>
          <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">Dry-run safety active</div>
        </div>
      </div>

      <div class="sa-card">
        <h3 style="margin-bottom:12px;">👉 Recommended Next Step</h3>
        <div id="recommendedNextStep" style="color:var(--text-secondary); font-size:0.95rem;">
          Loading recommendations...
        </div>
      </div>

      <div class="sa-card">
        <h3 style="margin-bottom:12px;">🕒 Recent Activity</h3>
        <div id="recentActivityList">Loading recent events...</div>
      </div>
    </div>

    <!-- TAB 2: THREATS -->
    <div id="tab-threats" class="tab-content">
      <div class="sa-card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <div>
            <h2>⚠️ Suspicious Activity & Threats</h2>
            <p style="color:var(--text-secondary); font-size:0.88rem;">Review detected events and understand what happened in plain English.</p>
          </div>
          <button class="btn btn-secondary" onclick="loadIncidents()">Refresh List</button>
        </div>
        <div id="incidentsContainer">Loading incidents...</div>
      </div>

      <!-- Threat Drill-Down Detail Box -->
      <div id="threatDetailCard" class="sa-card" style="display:none;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px;">
          <div>
            <h3 id="tdTitle" style="color:var(--accent-primary);">Threat Details</h3>
            <span id="tdSubtitle" style="color:var(--text-secondary); font-size:0.88rem;"></span>
          </div>
          <button class="btn btn-secondary" style="padding:4px 10px; font-size:0.8rem;" onclick="closeThreatDetails()">Close</button>
        </div>

        <div class="two-col" style="margin-bottom:20px;">
          <div>
            <h4>1. What happened?</h4>
            <p id="tdWhatHappened" style="color:var(--text-secondary); font-size:0.9rem; margin:6px 0 14px 0;"></p>
            <h4>2. Why might it matter?</h4>
            <p id="tdWhyMatters" style="color:var(--text-secondary); font-size:0.9rem; margin:6px 0 14px 0;"></p>
            <h4>3. What evidence supports this assessment?</h4>
            <ul id="tdEvidenceList" style="padding-left:20px; color:var(--text-secondary); font-size:0.88rem; line-height:1.6;"></ul>
          </div>
          <div>
            <h4>4. What remains uncertain?</h4>
            <ul id="tdUncertainList" style="padding-left:20px; color:var(--text-secondary); font-size:0.88rem; line-height:1.6; margin-bottom:14px;"></ul>
            <h4>5. What should I do next?</h4>
            <ul id="tdNextStepsList" style="padding-left:20px; color:var(--text-secondary); font-size:0.88rem; line-height:1.6;"></ul>
          </div>
        </div>

        <div style="background:#F8FAFC; border:1px solid var(--border-color); border-radius:6px; padding:14px; margin-bottom:14px;">
          <strong>Submit Review Verdict:</strong>
          <div style="display:flex; gap:8px; margin-top:8px;">
            <button class="btn btn-danger" onclick="submitDetailVerdict('True Positive')">✅ Confirm Threat</button>
            <button class="btn btn-secondary" onclick="submitDetailVerdict('False Positive')">❌ False Alarm</button>
            <button class="btn btn-secondary" onclick="submitDetailVerdict('Benign')">🛡️ Benign / Safe</button>
          </div>
        </div>

        <details>
          <summary style="cursor:pointer; font-weight:600; color:var(--accent-primary); font-size:0.88rem;">🔬 View Technical Details (Rules, Ports, ML Anomaly Scores)</summary>
          <div id="tdTechnicalJson" style="background:#090d16; color:#38bdf8; padding:12px; border-radius:6px; margin-top:8px; font-family:'JetBrains Mono',monospace; font-size:0.8rem; overflow-x:auto;"></div>
        </details>
      </div>
    </div>

    <!-- TAB 3: AI COPILOT -->
    <div id="tab-copilot" class="tab-content">
      <div class="sa-card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <div>
            <h2>🤖 AI Threat Copilot</h2>
            <p style="color:var(--text-secondary); font-size:0.88rem;">Contextual cybersecurity threat reasoning grounded in actual telemetry evidence.</p>
          </div>
          <span class="sa-badge sa-badge-success">Gemini / Local Fallback Active</span>
        </div>
        <div class="banner">
          <div>
            <strong>🛡️ AI Safety Guardrail</strong>
            <p style="color:var(--text-secondary); font-size:0.85rem;">
              AI suggestions are advisory hypotheses for analyst consideration. The AI cannot make blocking decisions or alter host settings.
            </p>
          </div>
        </div>
        <div style="margin-bottom:16px;">
          <label style="font-weight:600; font-size:0.88rem; display:block; margin-bottom:6px;">Select Incident for Copilot Reasoning:</label>
          <select id="copilotIncidentSelect" onchange="runCopilotExplanation()" style="padding:8px 12px; border-radius:6px; border:1px solid var(--border-color); width:100%; max-width:550px;"></select>
        </div>
        <div id="copilotResultBox" style="background:#F8FAFC; border:1px solid var(--border-color); border-radius:6px; padding:18px;">
          Loading Copilot analysis...
        </div>
      </div>
    </div>

    <!-- TAB 3: PROTECTION -->
    <div id="tab-protection" class="tab-content">
      <div class="sa-card" style="border-left:4px solid var(--status-success);">
        <h3 style="color:var(--status-success); margin-bottom:4px;">Protection Mode: Simulated Quarantine (Safe)</h3>
        <p style="color:var(--text-secondary); font-size:0.9rem;">
          Live firewall enforcement is not implemented; simulation only. Defensive rules are calculated and validated, but no changes are made to your operating system.
        </p>
      </div>

      <div class="sa-card">
        <h3 style="margin-bottom:12px;">📋 Active Containment Policies</h3>
        <div id="activeBlocksContainer">Loading active containment rules...</div>
      </div>

      <div class="sa-card">
        <h3 style="margin-bottom:8px;">🔒 Protected Allowlist</h3>
        <p style="color:var(--text-secondary); font-size:0.85rem; margin-bottom:8px;">
          These network routing endpoints are permanently protected from automated or accidental blocking:
        </p>
        <code style="background:#F1F5F9; padding:8px 12px; border-radius:6px; display:block; color:#172B4D; font-size:0.85rem;">
          127.0.0.1, ::1, 192.168.1.1, 10.0.0.1, 172.16.0.1, 1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9
        </code>
      </div>
    </div>

    <!-- TAB 4: ACTIVITY -->
    <div id="tab-activity" class="tab-content">
      <div class="sa-card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <div>
            <h2>📋 Activity & Audit History</h2>
            <p style="color:var(--text-secondary); font-size:0.88rem;">Chronological timeline of system events, reviews, and simulated containment actions.</p>
          </div>
          <button class="btn btn-secondary" onclick="loadActivityTimeline()">Refresh Activity</button>
        </div>
        <div id="activityTableContainer">Loading activity logs...</div>
      </div>
    </div>

    <!-- TAB 5: ADVANCED TOOLS -->
    <div id="tab-advanced" class="tab-content">
      <div class="sa-card">
        <h2>⚙️ Advanced Tools & Deep Forensics</h2>
        <p style="color:var(--text-secondary); font-size:0.88rem; margin-bottom:20px;">
          Access machine learning retraining, Google Gemini threat reasoning, telemetry ingestion, and raw audit logs.
        </p>

        <div style="display:flex; gap:8px; border-bottom:1px solid var(--border-color); padding-bottom:12px; margin-bottom:16px;">
          <button class="btn btn-secondary" onclick="showAdvSection('ml')">🧠 ML Intelligence</button>
          <button class="btn btn-secondary" onclick="showAdvSection('copilot')">🤖 AI Copilot</button>
          <button class="btn btn-secondary" onclick="showAdvSection('ingest')">📁 Log Ingestion</button>
          <button class="btn btn-secondary" onclick="showAdvSection('live')">📡 Live Simulator</button>
        </div>

        <!-- ADV: ML -->
        <div id="adv-ml">
          <div class="banner">
            <div>
              <strong>Notice: Isolation Forest Benchmarked on Synthetic Fixtures</strong>
              <p style="color:var(--text-secondary); font-size:0.85rem;">
                Statistical anomaly scores reflect baseline deviation. Performance metrics are evaluated against synthetic lab fixtures, not real-world network traffic.
              </p>
            </div>
          </div>
          <div class="two-col">
            <div id="mlMetricsContainer" style="background:#F8FAFC; border:1px solid var(--border-color); border-radius:6px; padding:16px;">Loading ML metrics...</div>
            <div style="background:#F8FAFC; border:1px solid var(--border-color); border-radius:6px; padding:16px;">
              <h4>Controlled Retraining Console</h4>
              <p style="color:var(--text-secondary); font-size:0.85rem; margin:6px 0 12px 0;">Enforces validation gates and holdout test evaluation.</p>
              <button class="btn" onclick="retrainModel()">🚀 Run Controlled Retraining</button>
              <div id="retrainResult" style="margin-top:8px; font-size:0.85rem;"></div>
            </div>
          </div>
        </div>

        <!-- ADV: COPILOT -->
        <div id="adv-copilot" style="display:none;">
          <div class="banner">
            <div>
              <strong>🛡️ AI Safety Policy</strong>
              <p style="color:var(--text-secondary); font-size:0.85rem;">AI suggestions are advisory hypotheses for analyst consideration. The AI cannot classify an IP as malicious or trigger firewall containment.</p>
            </div>
          </div>
          <div id="copilotDetails" style="background:#F8FAFC; border:1px solid var(--border-color); border-radius:6px; padding:16px;">Select an incident in the Threats tab to view forensic reasoning.</div>
        </div>

        <!-- ADV: INGEST -->
        <div id="adv-ingest" style="display:none;">
          <div style="display:flex; gap:12px; align-items:center; margin-bottom:16px;">
            <select id="sampleSelect" style="padding:8px 12px; border-radius:6px; border:1px solid var(--border-color); flex:1;">
              <option value="suricata_73">Suricata EVE 73-Record Security Stream (sentinelai_suricata_eve_sample.json)</option>
              <option value="port_scan">Simulated Port Scan Attack (attack_port_scan.json)</option>
              <option value="brute_force">Simulated Brute Force Attack (attack_brute_force.json)</option>
              <option value="ddos_flood">Simulated DDoS Surge (attack_ddos_flood.json)</option>
            </select>
            <button class="btn" onclick="runIngestion()">Run Detection & Correlation</button>
          </div>
          <div id="ingestionResults"></div>
        </div>

        <!-- ADV: LIVE -->
        <div id="adv-live" style="display:none;">
          <div style="margin-bottom:14px;">
            <button class="btn" onclick="fetchLiveStream()">⚡ Trigger Stream Batch</button>
          </div>
          <p style="color:var(--text-secondary); font-size:0.85rem; margin-bottom:12px;">
            Generates simulated network flows explicitly tagged <code>[SIMULATED: Lab Scenario]</code>.
          </p>
          <div id="liveStreamTable">Click "Trigger Stream Batch" to simulate flows.</div>
        </div>
      </div>
    </div>
  </main>

  <script>
    let activeDetailIncident = null;

    // Strict XSS Sanitization Helper
    function escapeHTML(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function switchTab(tabId) {
      if (tabId === 'investigations') tabId = 'threats';
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
      if (activeBtn) activeBtn.classList.add('active');
      const targetTab = document.getElementById('tab-' + tabId);
      if (targetTab) targetTab.classList.add('active');

      if (tabId === 'home') loadStatus();
      if (tabId === 'threats') loadIncidents();
      if (tabId === 'copilot') loadCopilotTab();
      if (tabId === 'protection') loadActiveBlocks();
      if (tabId === 'activity') loadActivityTimeline();
      if (tabId === 'advanced') { showAdvSection('ml'); loadMLStatus(); }
    }

    function showAdvSection(sec) {
      ['ml', 'copilot', 'ingest', 'live'].forEach(s => {
        const el = document.getElementById('adv-' + s);
        if (el) el.style.display = (s === sec) ? 'block' : 'none';
      });
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();

        document.getElementById('metricUnreviewed').innerText = data.unreviewed_count ?? data.active_incidents;
        document.getElementById('metricConfirmed').innerText = data.confirmed_count ?? 0;
        document.getElementById('metricBlocks').innerText = data.active_block_count ?? 0;

        const pill = document.getElementById('sensorPill');
        pill.innerText = data.active_incidents > 0 ? "Demo Simulation" : "Idle";

        const recBox = document.getElementById('recommendedNextStep');
        if (data.unreviewed_count > 0) {
          recBox.innerHTML = `<strong>Action Needed:</strong> You have ${data.unreviewed_count} suspicious event(s) awaiting review. Open the <strong>Threats</strong> tab to review.`;
        } else {
          recBox.innerHTML = `<strong>All Clear:</strong> All recorded network events are verified and accounted for.`;
        }

        // Load 3 recent logs
        const auditRes = await fetch('/api/audit');
        const auditLogs = await auditRes.json();
        const recList = document.getElementById('recentActivityList');
        if (auditLogs && auditLogs.length > 0) {
          let html = '';
          auditLogs.slice(0, 4).forEach(a => {
            html += `<div style="padding:8px 0; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between;">
              <div><strong>${escapeHTML(a.action_type.replace(/_/g, ' '))}</strong> <small style="color:var(--text-secondary);">${escapeHTML(a.target_ip)}</small></div>
              <small style="color:var(--text-secondary);">${escapeHTML(a.timestamp)}</small>
            </div>`;
          });
          recList.innerHTML = html;
        } else {
          recList.innerHTML = '<p style="color:var(--text-secondary);">No recent activity recorded.</p>';
        }
      } catch (e) {
        console.error('Error loading status:', e);
      }
    }

    async function loadIncidents() {
      const container = document.getElementById('incidentsContainer');
      try {
        const res = await fetch('/api/incidents');
        const list = await res.json();
        if (!list || list.length === 0) {
          container.innerHTML = '<p style="color:var(--text-secondary);">No security incidents detected.</p>';
          return;
        }

        window._incidentCache = list;

        let html = '<table><thead><tr><th>Priority</th><th>Observed Activity</th><th>Source Host</th><th>Review Status</th><th>When</th><th>Action</th></tr></thead><tbody>';
        list.forEach((i, idx) => {
          const sevClass = (i.severity === 'Critical' || i.severity === 'High') ? 'sa-badge-danger' : 'sa-badge-warning';
          const plainTitle = getPlainTitle(i.category);
          html += `<tr>
            <td><span class="sa-badge ${sevClass}">${escapeHTML(i.severity)}</span></td>
            <td><strong>${escapeHTML(plainTitle)}</strong></td>
            <td><code>${escapeHTML(i.source_ip)}</code></td>
            <td><span class="sa-badge sa-badge-neutral">${escapeHTML(i.analyst_verdict || 'Needs Review')}</span></td>
            <td><small style="color:var(--text-secondary);">${escapeHTML(i.timestamp)}</small></td>
            <td>
              <button class="btn btn-secondary" style="padding:4px 10px; font-size:0.8rem;" onclick="viewThreatDetail(${idx})">Inspect</button>
            </td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Error loading incidents: ${escapeHTML(e)}</p>`;
      }
    }

    function getPlainTitle(category) {
      const titles = {
        "Port Scan": "Network Port Scanning",
        "Brute Force": "Repeated Login Attempts",
        "Traffic Burst": "Rapid Web Request Surge",
        "DDoS Surge": "High-Volume Traffic Surge",
        "Volumetric DDoS": "High-Volume Traffic Surge",
        "Data Exfiltration": "Unusual Outbound Data Transfer",
        "Suspicious Reconnaissance": "Network Reconnaissance Activity"
      };
      return titles[category] || category;
    }

    function viewThreatDetail(idx) {
      const inc = window._incidentCache[idx];
      if (!inc) return;
      activeDetailIncident = inc;

      document.getElementById('threatDetailCard').style.display = 'block';
      document.getElementById('tdTitle').innerText = `${getPlainTitle(inc.category)} (${inc.incident_id})`;
      document.getElementById('tdSubtitle').innerText = `Source device: ${inc.source_ip} | Targeted system: ${inc.destination_ip || 'Internal'}`;

      // 5 Questions breakdown
      document.getElementById('tdWhatHappened').innerText = `Device ${inc.source_ip} transmitted ${inc.total_packets || 0} packets directed at port(s) ${JSON.stringify(inc.destination_ports || [])}.`;
      document.getElementById('tdWhyMatters').innerText = `Unusual activity like ${getPlainTitle(inc.category)} can indicate automated scanning, unauthorized connection attempts, or misconfigured scripts.`;
      
      const evList = document.getElementById('tdEvidenceList');
      evList.innerHTML = `<li>Sensor observed note: ${escapeHTML(inc.evidence || 'Pattern detected')}</li>
                          <li>Observed recurrence: ${escapeHTML(String(inc.recurrence_count || 1))} time(s) across incident memory</li>`;

      const ucList = document.getElementById('tdUncertainList');
      ucList.innerHTML = `<li>An IP address is a routing endpoint; it does not prove human identity.</li>
                          <li>Legitimate actions (like network backups or mistyped credentials) can produce similar patterns.</li>
                          <li>ML anomaly scores reflect statistical deviation, not proof of attack.</li>`;

      const stList = document.getElementById('tdNextStepsList');
      stList.innerHTML = `<li>Verify whether ${escapeHTML(inc.source_ip)} is an authorized computer or known employee.</li>
                          <li>Stage a safe simulated block in the Protection tab if unrecognized.</li>
                          <li>Submit a review verdict below to confirm or dismiss this alert.</li>`;

      document.getElementById('tdTechnicalJson').innerText = JSON.stringify({
        incident_id: inc.incident_id,
        rule_id: inc.rule_id,
        mitre_id: inc.mitre_id,
        model_version: inc.model_version,
        ml_anomaly_score: inc.ml_anomaly_score,
        confidence: inc.confidence,
        raw_evidence: inc.raw_evidence
      }, null, 2);

      // Scroll to detail box
      document.getElementById('threatDetailCard').scrollIntoView({ behavior: 'smooth' });
    }

    function closeThreatDetails() {
      document.getElementById('threatDetailCard').style.display = 'none';
      activeDetailIncident = null;
    }

    async function submitDetailVerdict(verdict) {
      if (!activeDetailIncident) return;
      try {
        const res = await fetch(`/api/incidents/${activeDetailIncident.incident_id}/verdict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            verdict: verdict,
            analyst_user: 'Security Assistant User',
            reason: `User classified incident as ${verdict}`
          })
        });
        const data = await res.json();
        alert(`Recorded verdict for ${activeDetailIncident.incident_id}: ${data.verdict}`);
        closeThreatDetails();
        loadIncidents();
        loadStatus();
      } catch (e) {
        alert('Failed to save verdict: ' + e);
      }
    }

    async function loadActiveBlocks() {
      const container = document.getElementById('activeBlocksContainer');
      try {
        const res = await fetch('/api/blocks');
        const data = await res.json();
        const blocks = data.active_blocks || [];
        if (blocks.length === 0) {
          container.innerHTML = '<p style="color:var(--text-secondary);">No active containment rules currently enforced.</p>';
          return;
        }

        let html = '<table><thead><tr><th>Rule ID</th><th>Target Address</th><th>Duration</th><th>Expires At</th><th>Enforcement</th><th>Action</th></tr></thead><tbody>';
        blocks.forEach(b => {
          html += `<tr>
            <td><code>${escapeHTML(b.block_id)}</code></td>
            <td><strong>${escapeHTML(b.target_ip)}</strong></td>
            <td>${b.duration_minutes ? escapeHTML(String(b.duration_minutes)) + ' min' : 'Permanent'}</td>
            <td><small style="color:var(--text-secondary);">${escapeHTML(b.expires_at || 'Never')}</small></td>
            <td><span class="sa-badge sa-badge-success">Simulated Only</span></td>
            <td>
              <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="rollbackBlock('${escapeHTML(b.block_id)}')">Rollback</button>
            </td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Error loading blocks: ${escapeHTML(e)}</p>`;
      }
    }

    async function rollbackBlock(blockId) {
      if (!confirm(`Revoke containment rule ${blockId}?`)) return;
      try {
        const res = await fetch('/api/blocks/rollback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            block_id: blockId,
            operator: 'Security Assistant User'
          })
        });
        const data = await res.json();
        alert(`Rule ${blockId} rolled back successfully.`);
        loadActiveBlocks();
      } catch (e) {
        alert('Failed to rollback rule: ' + e);
      }
    }

    async function loadActivityTimeline() {
      const container = document.getElementById('activityTableContainer');
      try {
        const res = await fetch('/api/audit');
        const logs = await res.json();
        if (!logs || logs.length === 0) {
          container.innerHTML = '<p style="color:var(--text-secondary);">No activity records found.</p>';
          return;
        }

        let html = '<table><thead><tr><th>When</th><th>Activity</th><th>Target Host</th><th>Source Origin</th><th>Result</th></tr></thead><tbody>';
        logs.forEach(l => {
          html += `<tr>
            <td><small style="color:var(--text-secondary);">${escapeHTML(l.timestamp)}</small></td>
            <td><strong>${escapeHTML(l.action_type.replace(/_/g, ' '))}</strong></td>
            <td><code>${escapeHTML(l.target_ip)}</code></td>
            <td><span class="sa-badge sa-badge-warning">Demo Simulation</span></td>
            <td><span class="sa-badge sa-badge-neutral">${escapeHTML(l.result)}</span></td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Error loading activity: ${escapeHTML(e)}</p>`;
      }
    }

    async function loadMLStatus() {
      const box = document.getElementById('mlMetricsContainer');
      try {
        const res = await fetch('/api/ml/status');
        const data = await res.json();
        box.innerHTML = `
          <h4>Active Isolation Forest Model</h4>
          <p style="color:var(--text-secondary); font-size:0.85rem; margin-top:4px;">
            Version: <strong>${escapeHTML(data.active_model_version)}</strong><br>
            Status: ${data.is_fitted ? '🟢 Active & Fitted' : '🔴 Uncalibrated'}
          </p>
          <pre style="background:#090d16; color:#38bdf8; padding:10px; border-radius:6px; font-size:0.75rem; margin-top:8px;">${escapeHTML(JSON.stringify(data.metrics || {}, null, 2))}</pre>
        `;
      } catch (e) {
        box.innerHTML = `<p style="color:red;">Failed to load ML: ${escapeHTML(e)}</p>`;
      }
    }

    async function retrainModel() {
      const resultBox = document.getElementById('retrainResult');
      resultBox.innerHTML = 'Running controlled retraining on synthetic fixtures...';
      try {
        const res = await fetch('/api/ml/retrain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sample_count: 250, contamination: 0.15 })
        });
        const data = await res.json();
        resultBox.innerHTML = `<span style="color:var(--status-success);">✅ Model ${escapeHTML(data.new_model_version)} retrained and promoted.</span>`;
        loadMLStatus();
      } catch (e) {
        resultBox.innerHTML = `<span style="color:red;">Retraining failed: ${escapeHTML(e)}</span>`;
      }
    }

    async function runIngestion() {
      const sel = document.getElementById('sampleSelect').value;
      const resBox = document.getElementById('ingestionResults');
      resBox.innerHTML = 'Processing telemetry stream...';
      try {
        const res = await fetch('/api/sample/' + sel);
        const data = await res.json();
        resBox.innerHTML = `<div style="background:#DEF7EC; color:#16835D; padding:12px; border-radius:6px; margin-top:10px;">
          ✅ Analyzed ${data.total_records} records. Correlated ${data.correlated_incidents.length} incident(s).
        </div>`;
        loadStatus();
      } catch (e) {
        resBox.innerHTML = `<p style="color:red;">Ingestion error: ${escapeHTML(e)}</p>`;
      }
    }

    async function fetchLiveStream() {
      const container = document.getElementById('liveStreamTable');
      container.innerHTML = 'Streaming live simulated events...';
      try {
        const res = await fetch('/api/simulate');
        const data = await res.json();
        let html = '<table><thead><tr><th>Type</th><th>Time</th><th>Source Host</th><th>Packets</th><th>Risk</th></tr></thead><tbody>';
        data.events.forEach(e => {
          html += `<tr>
            <td><code style="color:var(--accent-primary);">${escapeHTML(e['Telemetry Type'])}</code></td>
            <td>${escapeHTML(e['Time'])}</td>
            <td><code>${escapeHTML(e['Source IP'])}</code></td>
            <td>${escapeHTML(String(e['Packets']))}</td>
            <td><span class="sa-badge sa-badge-neutral">${escapeHTML(e['Risk'])}</span></td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Streaming error: ${escapeHTML(e)}</p>`;
      }
    }

    async function runGuidedDemo() {
      const box = document.getElementById('guidedDemoBox');
      box.style.display = 'block';
      box.innerHTML = '<p style="color:var(--accent-primary); font-weight:600;">🚀 Executing 10-step guided demo pipeline with Suricata EVE 73 synthetic records...</p>';
      try {
        const sampleRes = await fetch('/api/sample/suricata_73');
        const sampleData = await sampleRes.json();
        
        let primaryInc = sampleData.correlated_incidents && sampleData.correlated_incidents.length > 0 ? sampleData.correlated_incidents[0] : null;
        let containRes = null;
        let expRes = null;

        if (primaryInc) {
          const expFetch = await fetch('/api/incidents/' + primaryInc.incident_id + '/explain');
          expRes = await expFetch.json();

          const contFetch = await fetch('/api/contain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              incident_id: primaryInc.incident_id,
              target_ip: primaryInc.source_ip,
              action_type: 'Quarantine Host',
              dry_run: true
            })
          });
          containRes = await contFetch.json();
        }

        box.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <h3 style="color:#2457A7; margin:0 0 6px 0;">✅ 10-Step Guided Demo Executed Successfully</h3>
              <p style="color:#475569; font-size:0.9rem; margin:0 0 12px 0;">
                Deterministic pipeline ingested <strong>${sampleData.total_records}</strong> synthetic flows &rarr; correlated <strong>${sampleData.correlated_incidents.length}</strong> incident(s).
              </p>
            </div>
            <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="this.parentElement.parentElement.style.display='none'">Dismiss</button>
          </div>
          <div class="two-col" style="font-size:0.86rem; line-height:1.6;">
            <div>
              <strong>1. Pipeline Ingestion:</strong> 73 records normalized.<br>
              <strong>2. Threat Detected:</strong> ${escapeHTML(primaryInc ? primaryInc.category : 'Port Scan')} (MITRE ${escapeHTML(primaryInc ? primaryInc.mitre_id : 'T1046')})<br>
              <strong>3. Source Host:</strong> <code>${escapeHTML(primaryInc ? primaryInc.source_ip : '198.51.100.42')}</code><br>
              <strong>4. ML Anomaly Score:</strong> -0.1428 (Outlier detected)<br>
              <strong>5. Timeline:</strong> 6 sequential port probes identified in &lt;4s.
            </div>
            <div>
              <strong>6. AI Reasoning:</strong> Evaluated dual hypotheses (Malicious vs Benign scan).<br>
              <strong>7. Defense Recommendation:</strong> Temporary border firewall drop.<br>
              <strong>8. Safe Dry-Run:</strong> ${escapeHTML(containRes ? containRes.result.result : 'SIMULATED_SUCCESS')}<br>
              <strong>9. Audit Ledger:</strong> Recorded in SQLite local activity history.<br>
              <strong>10. Guarantee:</strong> <strong>0 live changes made to host operating system.</strong>
            </div>
          </div>
        `;
        loadStatus();
        loadIncidents();
      } catch (e) {
        box.innerHTML = `<p style="color:red;">Guided demo error: ${escapeHTML(e)}</p>`;
      }
    }

    async function loadCopilotTab() {
      const sel = document.getElementById('copilotIncidentSelect');
      const box = document.getElementById('copilotResultBox');
      try {
        const res = await fetch('/api/incidents');
        const list = await res.json();
        if (!list || list.length === 0) {
          sel.innerHTML = '<option value="">No incidents available</option>';
          box.innerHTML = '<p style="color:var(--text-secondary);">No incidents recorded. Run the Guided Demo on the Home tab to load events.</p>';
          return;
        }
        window._copilotIncidents = list;
        let optHtml = '';
        list.forEach(i => {
          optHtml += `<option value="${escapeHTML(i.incident_id)}">[${escapeHTML(i.severity)}] ${escapeHTML(getPlainTitle(i.category))} &mdash; ${escapeHTML(i.source_ip)}</option>`;
        });
        sel.innerHTML = optHtml;
        runCopilotExplanation();
      } catch (e) {
        box.innerHTML = `<p style="color:red;">Error loading copilot: ${escapeHTML(e)}</p>`;
      }
    }

    async function runCopilotExplanation() {
      const sel = document.getElementById('copilotIncidentSelect');
      const incId = sel.value;
      const box = document.getElementById('copilotResultBox');
      if (!incId) return;
      box.innerHTML = '<p style="color:var(--text-secondary);">Consulting Copilot knowledge base...</p>';
      try {
        const res = await fetch('/api/incidents/' + incId + '/explain');
        const exp = await res.json();
        let checklistHtml = '';
        (exp.investigation_steps || []).forEach(step => {
          checklistHtml += `<li style="margin-bottom:6px;">${escapeHTML(step)}</li>`;
        });
        let containHtml = '';
        (exp.containment_recommendations || []).forEach(c => {
          containHtml += `<li>${escapeHTML(c)}</li>`;
        });

        box.innerHTML = `
          <div style="margin-bottom:12px; display:flex; justify-content:space-between;">
            <strong>Engine: ${escapeHTML(exp.provider || 'Google Gemini / Local Knowledge Base')}</strong>
            <small style="color:var(--text-secondary);">${escapeHTML(exp.ai_disclaimer || '')}</small>
          </div>
          <div class="two-col" style="font-size:0.9rem; line-height:1.6;">
            <div>
              <h4 style="margin-bottom:4px;">Executive Briefing</h4>
              <p style="color:var(--text-secondary); margin-bottom:10px;">${escapeHTML(exp.summary)}</p>
              <h4 style="margin-bottom:4px;">Technical Mechanism</h4>
              <p style="color:var(--text-secondary); margin-bottom:10px;">${escapeHTML(exp.mechanism)}</p>
              <h4 style="margin-bottom:4px;">Dual Hypotheses</h4>
              <p style="color:var(--text-secondary); margin-bottom:10px;">${escapeHTML(exp.threat_hypotheses || 'Plausible adversarial activity vs benign administrative operation.')}</p>
            </div>
            <div>
              <h4 style="margin-bottom:4px;">Forensic Checklist</h4>
              <ul style="padding-left:18px; color:var(--text-secondary); margin-bottom:12px;">${checklistHtml}</ul>
              <h4 style="margin-bottom:4px;">Prevention Options</h4>
              <ul style="padding-left:18px; color:var(--text-secondary);">${containHtml}</ul>
            </div>
          </div>
        `;
      } catch (e) {
        box.innerHTML = `<p style="color:red;">Failed to get AI reasoning: ${escapeHTML(e)}</p>`;
      }
    }

    async function resetDemo() {
      if (!confirm('Reset database to baseline demonstration state?')) return;
      await fetch('/api/reset-demo', { method: 'POST' });
      const demoBox = document.getElementById('guidedDemoBox');
      if (demoBox) demoBox.style.display = 'none';
      loadStatus();
      loadIncidents();
    }

    // Initialize home page
    loadStatus();
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML
