"""
SentinelAI - Serverless Cloud API & SOC Web Application for Vercel
Serves the full SentinelAI cybersecurity dashboard, threat detection pipeline,
AI threat copilot, automated containment playbooks, and live telemetry simulation.
"""

import os
import sys
import json
import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

# Ensure repository root is in Python sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from detector import ThreatDetector, get_detector
from analyzer import TrafficAnalyzer, get_analyzer
from explainerAI import ThreatExplainer, get_explainer
from response_engine import ResponseEngine, get_response_engine, sanitize_ip
from database import DatabaseManager, get_db
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator, get_live_simulator

# Initialize FastAPI application
app = FastAPI(
    title="SentinelAI - Enterprise SOC Threat Defense Center",
    description="Autonomous behavioral threat detection, MITRE ATT&CK correlation, and automated incident containment.",
    version="2.5.0"
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
    operator: str = "SOC Cloud Analyst"

class CopilotQueryRequest(BaseModel):
    incident_id: str
    category: str
    source_ip: str
    packets: int = 0
    risk: str = "High"
    query: Optional[str] = None

class VerdictRequest(BaseModel):
    verdict: str
    analyst_user: str = "SOC Cloud Analyst"
    reason: str = "Confirmed via threat triage"

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
    trained_by: str = "SOC Admin"

class MLRevertRequest(BaseModel):
    version: str


class RollbackBlockRequest(BaseModel):
    block_id: str
    operator: str = "SOC Admin"

class RetentionPurgeRequest(BaseModel):
    retention_days: int = 30
    operator: str = "SOC Admin"


# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelAI Cloud SOC",
        "version": "2.5.0",
        "environment": "vercel_serverless" if os.environ.get("VERCEL") else "local",
        "timestamp": datetime.datetime.now().isoformat()
    }


@app.get("/api/status")
def get_system_status():
    incidents = db.get_incidents()
    critical_count = sum(1 for i in incidents if i.get("severity") == "Critical")
    high_count = sum(1 for i in incidents if i.get("severity") == "High")

    defcon_level = 1 if critical_count > 0 else (2 if high_count > 0 else 5)
    defcon_label = "DEFCON 1 - CRITICAL" if critical_count > 0 else ("DEFCON 2 - HIGH" if high_count > 0 else "DEFCON 5 - NOMINAL")
    risk_score = 92 if critical_count > 0 else (75 if high_count > 0 else 25)

    # Executive Briefing
    sample_csv_path = os.path.join(ROOT_DIR, "sample_traafic.csv")
    import pandas as pd
    base_df = pd.read_csv(sample_csv_path) if os.path.exists(sample_csv_path) else pd.DataFrame()
    exec_summary = explainer.generate_executive_summary(base_df)

    total_pkts = int(base_df["Packets"].sum()) if not base_df.empty and "Packets" in base_df.columns else 12500

    return {
        "defcon_level": defcon_level,
        "defcon_label": defcon_label,
        "active_incidents": len(incidents),
        "critical_count": critical_count,
        "high_count": high_count,
        "telemetry_flows": len(base_df) if not base_df.empty else 10,
        "total_packets": total_pkts,
        "threat_index": risk_score,
        "ai_executive_summary": exec_summary,
        "gemini_active": explainer.is_gemini_active
    }


@app.get("/api/incidents")
def list_incidents():
    return db.get_incidents()


@app.post("/api/contain")
def execute_containment(req: ContainmentRequest):
    target_ip = sanitize_ip(req.target_ip)
    if target_ip == "0.0.0.0" and req.target_ip.strip() not in ["0.0.0.0", "0.0.0.0/0"]:
        raise HTTPException(status_code=400, detail=f"Invalid or unsafe IP address: '{req.target_ip}'")

    res = response_engine.execute_response_action(
        incident_id=req.incident_id,
        action_type=req.action_type,
        target_ip=target_ip,
        dry_run=True,
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


@app.post("/api/reset-demo")
def reset_demo_database():
    db.reset_demo_data()
    return {"status": "success", "message": "Demo incidents restored"}


@app.post("/api/incidents/{incident_id}/verdict")
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


@app.post("/api/ml/retrain")
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


@app.post("/api/ml/revert")
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


@app.post("/api/blocks/rollback")
def rollback_block_endpoint(req: RollbackBlockRequest):
    res = db.rollback_block(block_id=req.block_id, operator=req.operator)
    return res


@app.post("/api/retention/purge")
def purge_retention(req: RetentionPurgeRequest):
    res = db.apply_data_retention(retention_days=req.retention_days, operator=req.operator)
    return {"status": "success", "result": res}


# ------------------------------------------------------------------------------
# FRONTEND HTML DASHBOARD (Cyberpunk / Modern High-Aesthetic SOC UI)
# ------------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelAI - Enterprise Threat Defense SOC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-primary: #0a0f1d;
      --bg-card: #111827;
      --bg-card-hover: #1f293d;
      --border-color: #1e293b;
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
      --accent-green: #10b981;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 {
      font-size: 1.35rem;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #60a5fa 0%, #38bdf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand span {
      background: #1e3a8a;
      color: #93c5fd;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      border: 1px solid #2563eb;
    }
    .header-status {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .defcon-pill {
      padding: 6px 14px;
      border-radius: 8px;
      font-weight: 800;
      font-size: 0.85rem;
      letter-spacing: 0.5px;
      box-shadow: 0 0 15px rgba(239, 68, 68, 0.35);
      background-color: var(--accent-red);
      color: white;
    }
    .tabs-bar {
      background: #0f172a;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      gap: 8px;
      padding: 0 32px;
      overflow-x: auto;
    }
    .tab-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 14px 18px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active {
      color: #60a5fa;
      border-bottom-color: #3b82f6;
    }
    main {
      flex: 1;
      padding: 28px 32px;
      max-width: 1440px;
      margin: 0 auto;
      width: 100%;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.25s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

    /* Metric Cards */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }
    .metric-card::before {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, #3b82f6, #06b6d4);
    }
    .metric-title {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .metric-val {
      font-size: 1.85rem;
      font-weight: 800;
      color: var(--text-main);
      display: flex;
      align-items: baseline;
      gap: 8px;
    }
    .metric-delta {
      font-size: 0.85rem;
      color: var(--accent-orange);
      font-weight: 600;
    }

    /* Executive Alert Banner */
    .briefing-banner {
      background: linear-gradient(135deg, rgba(30, 58, 138, 0.3) 0%, rgba(15, 23, 42, 0.6) 100%);
      border: 1px solid #1e40af;
      border-radius: 12px;
      padding: 18px 24px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      align-items: flex-start;
    }
    .briefing-icon { font-size: 1.6rem; }
    .briefing-text h3 { font-size: 0.95rem; font-weight: 700; color: #93c5fd; margin-bottom: 4px; }
    .briefing-text p { font-size: 0.9rem; color: #e2e8f0; line-height: 1.5; }

    /* Tables & Cards */
    .glass-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
    }
    .card-head h2 { font-size: 1.15rem; font-weight: 700; }
    .btn {
      background: #2563eb;
      color: white;
      border: none;
      padding: 10px 18px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.85rem;
      cursor: pointer;
      transition: background 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { background: #1d4ed8; }
    .btn-secondary { background: #334155; }
    .btn-secondary:hover { background: #475569; }
    .btn-danger { background: #dc2626; }
    .btn-danger:hover { background: #b91c1c; }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316; }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: #86efac; border: 1px solid #10b981; }

    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { text-align: left; padding: 12px 14px; background: #0f172a; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border-color); }
    td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    pre {
      background: #090d16;
      border: 1px solid #1e293b;
      padding: 12px;
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #38bdf8;
      overflow-x: auto;
    }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media(max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <span style="font-size: 1.4rem;">🛡️</span>
      <div>
        <h1>SentinelAI</h1>
      </div>
      <span>v2.5 Enterprise SOC</span>
    </div>
    <div class="header-status">
      <div id="defconPill" class="defcon-pill">DEFCON 1 - CRITICAL</div>
      <button class="btn btn-secondary" onclick="resetDemo()">🔄 Reset Demo Data</button>
    </div>
  </header>

  <nav class="tabs-bar">
    <button class="tab-btn active" onclick="switchTab('overview')">📊 SOC Overview</button>
    <button class="tab-btn" onclick="switchTab('incidents')">🚨 Incident Queue</button>
    <button class="tab-btn" onclick="switchTab('ml')">🧠 ML Threat Intelligence</button>
    <button class="tab-btn" onclick="switchTab('copilot')">🤖 AI Threat Copilot</button>
    <button class="tab-btn" onclick="switchTab('blocks')">🛡️ Active Containment & Expiry</button>
    <button class="tab-btn" onclick="switchTab('ingestion')">📁 Telemetry Ingestion</button>
    <button class="tab-btn" onclick="switchTab('live')">📡 Live Monitoring</button>
    <button class="tab-btn" onclick="switchTab('audit')">📜 Response Audit Trail</button>
  </nav>

  <main>
    <!-- TAB 1: SOC OVERVIEW -->
    <div id="tab-overview" class="tab-content active">
      <div class="briefing-banner">
        <div class="briefing-icon">🤖</div>
        <div class="briefing-text">
          <h3>AI Executive Security Briefing</h3>
          <p id="briefingText">Analyzing real-time threat signals across enterprise telemetry boundaries...</p>
        </div>
      </div>

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title">Active Security Incidents</div>
          <div class="metric-val" id="metricIncidents">3 <span class="metric-delta" id="metricCritical">1 Critical</span></div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Monitored Telemetry Flows</div>
          <div class="metric-val" id="metricFlows">73</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Total Aggregated Packets</div>
          <div class="metric-val" id="metricPackets">14,820</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Enterprise Threat Index</div>
          <div class="metric-val" id="metricThreatIndex">92 / 100 <span class="metric-delta">Defensive Active</span></div>
        </div>
      </div>

      <div class="two-col">
        <div class="glass-card">
          <div class="card-head">
            <h2>📈 Incident Severity Breakdown</h2>
          </div>
          <canvas id="severityChart" height="220"></canvas>
        </div>
        <div class="glass-card">
          <div class="card-head">
            <h2>🛡️ Cloud Infrastructure Posture</h2>
          </div>
          <ul style="list-style: none; display: flex; flex-direction: column; gap: 12px; font-size: 0.9rem;">
            <li>🟢 <strong>Detection Engine:</strong> Multi-Event Temporal Correlation (Active)</li>
            <li>🟢 <strong>Response Mode:</strong> Dry-Run Simulation (Zero Production Impact)</li>
            <li>🟢 <strong>Deployment Platform:</strong> Vercel Serverless Architecture</li>
            <li>🟢 <strong>AI Engine:</strong> Google Gemini Copilot (with Deterministic Fallback)</li>
            <li>🟢 <strong>Database:</strong> SQLite Engine with Neon DB Compatibility</li>
          </ul>
        </div>
      </div>
    </div>

    <!-- TAB 2: INCIDENT QUEUE -->
    <div id="tab-incidents" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>🚨 Active Incident Management Queue</h2>
          <button class="btn btn-secondary" onclick="loadIncidents()">Refresh Queue</button>
        </div>
        <div id="incidentsContainer">Loading active incidents...</div>
      </div>
    </div>

    <!-- TAB 3: AI COPILOT -->
    <div id="tab-copilot" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>🤖 Google Gemini AI Threat Copilot</h2>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 20px;">
          Deep contextual forensic explanation, technical attack mechanics, and MITRE ATT&CK mapping.
        </p>
        <div id="copilotDetails">Select an incident from the Incident Queue to view full AI reasoning.</div>
      </div>
    </div>

    <!-- TAB 4: TELEMETRY INGESTION -->
    <div id="tab-ingestion" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>📁 Structured Log Ingestion & Detection Pipeline</h2>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 20px;">
          Select a pre-configured laboratory telemetry file to execute the SentinelAI detection and multi-event correlation engine.
        </p>
        <div style="display: flex; gap: 12px; align-items: center; margin-bottom: 20px;">
          <select id="sampleSelect" style="background:#1e293b; color:white; border:1px solid #334155; padding:10px 14px; border-radius:8px; font-size:0.9rem; flex:1;">
            <option value="suricata_73">Suricata EVE 73-Record Security Audit Stream (sentinelai_suricata_eve_sample.json)</option>
            <option value="port_scan">Simulated Port Scan Attack (attack_port_scan.json)</option>
            <option value="brute_force">Simulated Brute Force Attack (attack_brute_force.json)</option>
            <option value="ddos_flood">Simulated DDoS Surge (attack_ddos_flood.json)</option>
          </select>
          <button class="btn" onclick="runIngestion()">Run Detection & Correlation</button>
        </div>
        <div id="ingestionResults"></div>
      </div>
    </div>

    <!-- TAB 5: LIVE MONITORING -->
    <div id="tab-live" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>📡 Live Telemetry Stream Simulator</h2>
          <div>
            <button class="btn" onclick="fetchLiveStream()">⚡ Trigger Stream Batch</button>
          </div>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 16px;">
          Generates real-time multi-protocol network flows explicitly tagged <code>[SIMULATED: Lab Scenario]</code>.
        </p>
        <div id="liveStreamTable">Click "Trigger Stream Batch" to simulate network flows.</div>
      </div>
    </div>

    <!-- TAB: ML THREAT INTELLIGENCE -->
    <div id="tab-ml" class="tab-content">
      <div class="two-col">
        <div class="glass-card">
          <div class="card-head">
            <h2>🧠 Active Model Performance & Metrics</h2>
            <button class="btn btn-secondary" onclick="loadMLStatus()">Refresh ML Status</button>
          </div>
          <div id="mlMetricsContainer">Loading active model performance...</div>
        </div>
        <div class="glass-card">
          <div class="card-head">
            <h2>🧪 Controlled Retraining Console</h2>
          </div>
          <p style="color: var(--text-muted); margin-bottom: 14px; font-size: 0.85rem;">
            Executes controlled retraining with validation gates, holdout evaluation, and version registry persistence.
          </p>
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label style="font-size:0.8rem; color:#94a3b8;">Synthetic Fixture Sample Count:</label>
              <input type="number" id="retrainSamples" value="300" min="100" max="1000" style="background:#1e293b; color:white; border:1px solid #334155; padding:8px 12px; border-radius:6px; width:100%;">
            </div>
            <div>
              <label style="font-size:0.8rem; color:#94a3b8;">Contamination Parameter:</label>
              <input type="number" id="retrainContam" value="0.15" step="0.01" min="0.05" max="0.30" style="background:#1e293b; color:white; border:1px solid #334155; padding:8px 12px; border-radius:6px; width:100%;">
            </div>
            <button class="btn" onclick="retrainModel()">🚀 Run Controlled Retraining</button>
            <div id="retrainResult" style="font-size:0.85rem; margin-top:8px;"></div>
          </div>
        </div>
      </div>
      <div class="glass-card">
        <div class="card-head">
          <h2>⚡ Real-Time ML Anomaly Scorer</h2>
        </div>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:12px;">
          <div><label style="font-size:0.75rem; color:#94a3b8;">Packets</label><input type="number" id="evalPackets" value="120" style="background:#1e293b; color:white; border:1px solid #334155; padding:8px; border-radius:6px; width:100%;"></div>
          <div><label style="font-size:0.75rem; color:#94a3b8;">Port</label><input type="number" id="evalPort" value="443" style="background:#1e293b; color:white; border:1px solid #334155; padding:8px; border-radius:6px; width:100%;"></div>
          <div><label style="font-size:0.75rem; color:#94a3b8;">Source IP</label><input type="text" id="evalSrc" value="192.168.1.55" style="background:#1e293b; color:white; border:1px solid #334155; padding:8px; border-radius:6px; width:100%;"></div>
        </div>
        <button class="btn btn-secondary" onclick="evaluateSingleFlow()">Score Telemetry Flow</button>
        <div id="flowScoreResult" style="margin-top:12px; font-size:0.9rem;"></div>
      </div>
    </div>

    <!-- TAB: ACTIVE BLOCKS & EXPIRY -->
    <div id="tab-blocks" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>🛡️ Active Containment Rules & Expiry Watchdog</h2>
          <button class="btn btn-secondary" onclick="loadActiveBlocks()">Check Expiry & Refresh</button>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 16px; font-size: 0.85rem;">
          Temporary containment policies expire automatically. Administrator approvals and rollbacks are logged to the audit ledger.
        </p>
        <div id="activeBlocksContainer">Loading active blocks...</div>
      </div>
      <div class="glass-card">
        <div class="card-head">
          <h2>🔒 Protected Core Infrastructure Allowlist</h2>
        </div>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 8px;">
          The following indicators are permanently protected from automated or accidental firewall blocking:
        </p>
        <code style="background:#0f172a; padding:8px 12px; border-radius:6px; display:block; color:#38bdf8;">127.0.0.1, ::1, 0.0.0.0, 192.168.1.1, 10.0.0.1, 172.16.0.1, 1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9</code>
      </div>
    </div>

    <!-- TAB 6: AUDIT TRAIL -->
    <div id="tab-audit" class="tab-content">
      <div class="glass-card">
        <div class="card-head">
          <h2>📜 SOC Defensive Response & Audit Trail</h2>
          <button class="btn btn-secondary" onclick="loadAuditTrail()">Refresh Audit Log</button>
        </div>
        <p style="color: var(--text-muted); margin-bottom: 16px;">
          Immutable SQLite audit log recording every containment policy simulation, rollback command, and analyst action.
        </p>
        <div id="auditTable">Loading audit logs...</div>
      </div>
    </div>
  </main>

  <script>
    let severityChartInstance = null;

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
      if (activeBtn) activeBtn.classList.add('active');
      const targetTab = document.getElementById('tab-' + tabId);
      if (targetTab) targetTab.classList.add('active');

      if (tabId === 'incidents') loadIncidents();
      if (tabId === 'audit') loadAuditTrail();
      if (tabId === 'overview') loadStatus();
      if (tabId === 'ml') loadMLStatus();
      if (tabId === 'blocks') loadActiveBlocks();
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();

        document.getElementById('briefingText').innerText = data.ai_executive_summary || 'All monitored network perimeter nodes operating within normal baselines.';
        document.getElementById('metricIncidents').innerHTML = `${data.active_incidents} <span class="metric-delta">${data.critical_count} Critical</span>`;
        document.getElementById('metricFlows').innerText = data.telemetry_flows;
        document.getElementById('metricPackets').innerText = data.total_packets.toLocaleString();
        document.getElementById('metricThreatIndex').innerHTML = `${data.threat_index} / 100 <span class="metric-delta">${data.threat_index > 50 ? 'Defensive Active' : 'Quiescent'}</span>`;

        const pill = document.getElementById('defconPill');
        pill.innerText = data.defcon_label;
        pill.style.backgroundColor = data.defcon_level === 1 ? '#ef4444' : (data.defcon_level === 2 ? '#f97316' : '#10b981');

        renderSeverityChart(data.critical_count, data.high_count, data.active_incidents);
      } catch (e) {
        console.error('Failed to load status:', e);
      }
    }

    function renderSeverityChart(critical, high, total) {
      const ctx = document.getElementById('severityChart');
      if (!ctx) return;
      if (severityChartInstance) severityChartInstance.destroy();

      const medium = Math.max(0, total - (critical + high));
      severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium'],
          datasets: [{
            data: [critical || 1, high || 2, medium || 0],
            backgroundColor: ['#ef4444', '#f97316', '#eab308'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
        }
      });
    }

    async function loadIncidents() {
      const container = document.getElementById('incidentsContainer');
      try {
        const res = await fetch('/api/incidents');
        const list = await res.json();
        if (!list || list.length === 0) {
          container.innerHTML = '<p>No active incidents.</p>';
          return;
        }

        let html = '<table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Source Attacker</th><th>Target</th><th>ML Anomaly</th><th>Recur</th><th>Analyst Verdict</th><th>Action</th></tr></thead><tbody>';
        list.forEach(i => {
          const sevClass = 'badge-' + (i.severity || 'low').toLowerCase();
          const mlScoreDisplay = i.ml_is_anomaly
            ? `<span style="color:#f87171; font-weight:700;">⚠️ Yes (${i.ml_anomaly_score !== null && i.ml_anomaly_score !== undefined ? Number(i.ml_anomaly_score).toFixed(2) : 'N/A'})</span>`
            : `<span style="color:#10b981;">Normal</span>`;
          const recurCount = i.recurrence_count ? `${i.recurrence_count}x` : '1x';
          html += `<tr>
            <td><strong>${i.incident_id}</strong></td>
            <td><span class="badge ${sevClass}">${i.severity}</span></td>
            <td><strong>${i.category}</strong></td>
            <td><code>${i.source_ip}</code></td>
            <td><code>${i.destination_ip || 'Internal'}</code></td>
            <td>${mlScoreDisplay}</td>
            <td><code>${recurCount}</code></td>
            <td>
              <div style="display:flex; flex-direction:column; gap:4px;">
                <select id="verdict-${i.incident_id}" style="background:#1e293b; color:white; border:1px solid #334155; padding:4px 6px; border-radius:4px; font-size:0.75rem;">
                  <option value="Unresolved" ${i.analyst_verdict === 'Unresolved' ? 'selected' : ''}>Unresolved</option>
                  <option value="True Positive" ${i.analyst_verdict === 'True Positive' ? 'selected' : ''}>True Positive</option>
                  <option value="False Positive" ${i.analyst_verdict === 'False Positive' ? 'selected' : ''}>False Positive</option>
                  <option value="Benign" ${i.analyst_verdict === 'Benign' ? 'selected' : ''}>Benign</option>
                </select>
                <button class="btn btn-secondary" style="padding:2px 6px; font-size:0.7rem;" onclick="submitVerdict('${i.incident_id}')">Save Verdict</button>
              </div>
            </td>
            <td>
              <button class="btn btn-danger" style="padding:6px 10px; font-size:0.75rem;" onclick="simulateContain('${i.incident_id}', '${i.source_ip}')">🛡️ Contain (Dry-Run)</button>
              <button class="btn btn-secondary" style="padding:6px 10px; font-size:0.75rem; margin-top:4px;" onclick="viewGroundedCopilot('${i.incident_id}')">🤖 AI Triage</button>
            </td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Failed to load incidents: ${e}</p>`;
      }
    }

    async function submitVerdict(id) {
      const select = document.getElementById(`verdict-${id}`);
      if (!select) return;
      const verdict = select.value;
      try {
        const res = await fetch(`/api/incidents/${id}/verdict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            verdict: verdict,
            analyst_user: 'SOC Analyst (Web UI)',
            reason: `Analyst classified incident as ${verdict}`
          })
        });
        const data = await res.json();
        alert(`Analyst verdict saved for ${id}: ${data.verdict}`);
        loadIncidents();
      } catch (e) {
        alert(`Failed to save verdict: ${e}`);
      }
    }

    async function simulateContain(id, ip) {
      try {
        const res = await fetch('/api/contain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ incident_id: id, target_ip: ip })
        });
        const data = await res.json();
        alert(`Containment Simulation for Incident ${id}:\\n\\n` +
              `Status: ${data.result.result}\\n` +
              `Target IP: ${data.result.target_ip}\\n` +
              `PowerShell: ${data.commands['Windows PowerShell']}\\n` +
              `iptables: ${data.commands['Linux iptables']}\\n\\n` +
              `Logged to immutable SQLite audit trail.`);
        loadAuditTrail();
      } catch (e) {
        alert('Containment failed: ' + e);
      }
    }

    async function viewGroundedCopilot(id) {
      switchTab('copilot');
      const box = document.getElementById('copilotDetails');
      box.innerHTML = `<p>Grounding Google Gemini threat investigation in stored evidence for incident <strong>${id}</strong>...</p>`;
      try {
        const res = await fetch(`/api/incidents/${id}/explain`);
        const exp = await res.json();
        box.innerHTML = `
          <div style="background:#0f172a; padding:18px; border-radius:8px; border:1px solid #1e293b; margin-bottom:16px;">
            <div style="background:rgba(239, 68, 68, 0.1); border-left:4px solid #ef4444; padding:8px 12px; margin-bottom:12px; font-size:0.8rem; color:#fca5a5;">
              <strong>🛡️ AI Safety Boundary:</strong> ${exp.ai_safety_notice || 'AI Guidance Notice: This assessment is advisory only. Autonomous firewall modification is strictly prohibited.'}
            </div>
            <h3 style="color:#60a5fa; margin-bottom:8px;">${exp.activity || 'Incident Analysis'} (Target Host: ${exp.source_ip || id})</h3>
            <p style="margin-bottom:12px;"><strong>Executive Summary:</strong> ${exp.summary}</p>
            <p style="margin-bottom:12px;"><strong>Technical Mechanism:</strong> ${exp.mechanism}</p>
            <p style="margin-bottom:12px;"><strong>Potential Impact:</strong> ${exp.potential_impact}</p>
            <p style="margin-bottom:12px;"><strong>MITRE ATT&CK:</strong> <code>${exp.mitre_technique}</code></p>
            
            <h4 style="color:#38bdf8; margin:16px 0 6px 0;">🔍 Observed Telemetry Facts</h4>
            <ul style="padding-left:20px; line-height:1.6; font-size:0.85rem; color:#cbd5e1;">
              ${(exp.observed_facts || []).map(f => `<li>${f}</li>`).join('')}
            </ul>

            <h4 style="color:#a855f7; margin:16px 0 6px 0;">🧠 ML Model Predictions</h4>
            <ul style="padding-left:20px; line-height:1.6; font-size:0.85rem; color:#cbd5e1;">
              ${(exp.model_predictions || []).map(p => `<li>${p}</li>`).join('')}
            </ul>

            <h4 style="color:#f59e0b; margin:16px 0 6px 0;">💡 Threat Hypotheses & Investigation Steps</h4>
            <ul style="padding-left:20px; line-height:1.6; font-size:0.85rem; color:#cbd5e1;">
              ${(exp.investigation_steps || []).map(s => `<li>${s}</li>`).join('')}
            </ul>
          </div>
        `;
      } catch (e) {
        box.innerHTML = `<p style="color:red;">Error loading grounded investigation: ${e}</p>`;
      }
    }

    async function loadMLStatus() {
      const container = document.getElementById('mlMetricsContainer');
      try {
        const res = await fetch('/api/ml/status');
        const data = await res.json();
        const metrics = data.metrics || {};
        container.innerHTML = `
          <div style="display:flex; flex-direction:column; gap:10px; font-size:0.9rem;">
            <div style="background:#090d16; padding:12px; border-radius:6px; border:1px solid #1e293b;">
              <div><strong>Active Model Version:</strong> <span style="color:#38bdf8;">${data.active_model_version || 'None'}</span></div>
              <div><strong>Model Status:</strong> ${data.is_fitted ? '🟢 Active & Fitted' : '🔴 Unfitted'}</div>
              <div><strong>Model Algorithm:</strong> Isolation Forest (scikit-learn)</div>
            </div>
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:8px;">
              <div style="background:#090d16; padding:10px; border-radius:6px; text-align:center;">
                <div style="color:#94a3b8; font-size:0.75rem;">TEST ACCURACY</div>
                <div style="font-size:1.2rem; font-weight:700; color:#10b981;">${metrics.accuracy ? Math.round(metrics.accuracy * 100) + '%' : 'N/A'}</div>
              </div>
              <div style="background:#090d16; padding:10px; border-radius:6px; text-align:center;">
                <div style="color:#94a3b8; font-size:0.75rem;">ROC-AUC</div>
                <div style="font-size:1.2rem; font-weight:700; color:#60a5fa;">${metrics.roc_auc ? metrics.roc_auc.toFixed(3) : 'N/A'}</div>
              </div>
              <div style="background:#090d16; padding:10px; border-radius:6px; text-align:center;">
                <div style="color:#94a3b8; font-size:0.75rem;">PR-AUC</div>
                <div style="font-size:1.2rem; font-weight:700; color:#a855f7;">${metrics.pr_auc ? metrics.pr_auc.toFixed(3) : 'N/A'}</div>
              </div>
            </div>
            <div style="font-size:0.8rem; color:#94a3b8; line-height:1.4;">
              <strong>Sample Volume:</strong> ${metrics.train_samples || 0} training / ${metrics.test_samples || 0} test held-out flows.
            </div>
            <div style="background:rgba(234, 179, 8, 0.1); border-left:3px solid #eab308; padding:8px 10px; font-size:0.75rem; color:#fde047;">
              <strong>Standard ML Notice:</strong> ${data.disclaimer || 'Anomaly scores measure statistical deviation and are NOT proof of an attack.'}
            </div>
          </div>
        `;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Failed to load ML status: ${e}</p>`;
      }
    }

    async function retrainModel() {
      const resultBox = document.getElementById('retrainResult');
      const samples = parseInt(document.getElementById('retrainSamples').value) || 300;
      const contam = parseFloat(document.getElementById('retrainContam').value) || 0.15;
      resultBox.innerHTML = 'Executing controlled retraining pipeline...';
      try {
        const res = await fetch('/api/ml/retrain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ synthetic_samples: samples, contamination: contam })
        });
        const data = await res.json();
        if (data.status === 'success') {
          resultBox.innerHTML = `<span style="color:#10b981;">✅ Trained <strong>${data.new_model_version}</strong>. Accuracy: ${Math.round(data.metrics.accuracy * 100)}%, ROC-AUC: ${data.metrics.roc_auc.toFixed(3)}</span>`;
          loadMLStatus();
        } else {
          resultBox.innerHTML = `<span style="color:#ef4444;">❌ Retraining failed: ${data.detail || JSON.stringify(data)}</span>`;
        }
      } catch (e) {
        resultBox.innerHTML = `<span style="color:#ef4444;">Retrain error: ${e}</span>`;
      }
    }

    async function evaluateSingleFlow() {
      const box = document.getElementById('flowScoreResult');
      const packets = parseInt(document.getElementById('evalPackets').value) || 1;
      const port = parseInt(document.getElementById('evalPort').value) || 80;
      const src = document.getElementById('evalSrc').value || '192.168.1.100';
      box.innerHTML = 'Evaluating flow against Isolation Forest...';
      try {
        const res = await fetch('/api/ml/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ packets: packets, port: port, source_ip: src })
        });
        const data = await res.json();
        const isAnomaly = data.is_anomaly;
        const color = isAnomaly ? '#ef4444' : '#10b981';
        box.innerHTML = `
          <div style="background:#090d16; padding:12px; border-radius:6px; border:1px solid ${color};">
            <div style="font-weight:700; color:${color}; font-size:1rem; margin-bottom:4px;">
              ${isAnomaly ? '⚠️ ML ANOMALY DETECTED' : '✅ STATISTICALLY NORMAL FLOW'}
            </div>
            <div style="font-size:0.85rem; color:#cbd5e1;">
              <strong>Raw Anomaly Score:</strong> ${data.raw_score.toFixed(4)} | 
              <strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}% | 
              <strong>Evaluated By:</strong> <code>${data.model_version}</code>
            </div>
            <div style="font-size:0.75rem; color:#94a3b8; margin-top:6px;">
              <em>${data.disclaimer}</em>
            </div>
          </div>
        `;
      } catch (e) {
        box.innerHTML = `<span style="color:#ef4444;">Evaluation error: ${e}</span>`;
      }
    }

    async function loadActiveBlocks() {
      const container = document.getElementById('activeBlocksContainer');
      try {
        const res = await fetch('/api/blocks');
        const data = await res.json();
        const blocks = data.active_blocks || [];
        if (blocks.length === 0) {
          container.innerHTML = '<p style="color:#94a3b8;">No active containment blocks currently enforced. All network perimeters clear.</p>';
          return;
        }
        let html = '<table><thead><tr><th>Rule ID</th><th>Target IP</th><th>Mode</th><th>Duration</th><th>Applied At</th><th>Expires At</th><th>Admin Approver</th><th>Action</th></tr></thead><tbody>';
        blocks.forEach(b => {
          html += `<tr>
            <td><code>${b.block_id}</code></td>
            <td><strong style="color:#f87171;">${b.ip_address}</strong></td>
            <td><code>${b.execution_mode}</code></td>
            <td>${b.duration_minutes ? b.duration_minutes + ' min' : 'Permanent'}</td>
            <td><small>${b.applied_at || ''}</small></td>
            <td><small style="color:#fdba74;">${b.expires_at || 'Never'}</small></td>
            <td>${b.admin_approver || 'Pending'}</td>
            <td>
              <button class="btn btn-danger" style="padding:4px 8px; font-size:0.75rem;" onclick="rollbackBlock('${b.block_id}')">Rollback</button>
            </td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Failed to load active containment rules: ${e}</p>`;
      }
    }

    async function rollbackBlock(blockId) {
      if (!confirm(`Are you sure you want to rollback containment rule ${blockId}?`)) return;
      try {
        const res = await fetch('/api/blocks/rollback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            block_id: blockId,
            admin_user: 'SOC Admin (Dashboard)',
            reason: 'Authorized manual analyst rollback'
          })
        });
        const data = await res.json();
        alert(`Rollback status: ${data.status} for ${blockId}`);
        loadActiveBlocks();
        loadAuditTrail();
      } catch (e) {
        alert(`Rollback failed: ${e}`);
      }
    }

    async function runIngestion() {
      const select = document.getElementById('sampleSelect');
      const sample = select.value;
      const resBox = document.getElementById('ingestionResults');
      resBox.innerHTML = '<p>Processing telemetry and correlating incidents...</p>';
      try {
        const res = await fetch('/api/sample/' + sample);
        const data = await res.json();
        let html = `<div style="background:#0f172a; padding:16px; border-radius:8px; margin-top:16px; border:1px solid #1e293b;">
          <h3 style="color:#10b981; margin-bottom:12px;">✅ Processed ${data.total_records} Telemetry Flows. Identified ${data.correlated_incidents.length} Correlated Incident(s).</h3>`;
        data.correlated_incidents.forEach(inc => {
          html += `<div style="border-left:4px solid #f97316; padding-left:12px; margin-bottom:12px;">
            <strong>[${inc.severity}] ${inc.incident_id}: ${inc.category}</strong> (${inc.source_ip} -> ${inc.destination_ip})<br>
            <small style="color:#94a3b8;">${inc.evidence}</small>
          </div>`;
        });
        html += '</div>';
        resBox.innerHTML = html;
        loadStatus();
      } catch (e) {
        resBox.innerHTML = `<p style="color:red;">Ingestion error: ${e}</p>`;
      }
    }

    async function fetchLiveStream() {
      const container = document.getElementById('liveStreamTable');
      container.innerHTML = '<p>Streaming live telemetry...</p>';
      try {
        const res = await fetch('/api/simulate');
        const data = await res.json();
        let html = '<table><thead><tr><th>Type</th><th>Time</th><th>Source IP</th><th>Target IP</th><th>Port</th><th>Packets</th><th>Activity</th><th>Risk</th></tr></thead><tbody>';
        data.events.forEach(e => {
          html += `<tr>
            <td><code style="color:#93c5fd;">${e['Telemetry Type']}</code></td>
            <td>${e['Time']}</td>
            <td><code>${e['Source IP']}</code></td>
            <td><code>${e['Destination IP']}</code></td>
            <td>${e['Port']}</td>
            <td>${e['Packets']}</td>
            <td>${e['Activity']}</td>
            <td><span class="badge badge-${e['Risk'].toLowerCase()}">${e['Risk']}</span></td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Streaming error: ${e}</p>`;
      }
    }

    async function loadAuditTrail() {
      const container = document.getElementById('auditTable');
      try {
        const res = await fetch('/api/audit');
        const list = await res.json();
        if (!list || list.length === 0) {
          container.innerHTML = '<p>No audit entries recorded yet.</p>';
          return;
        }
        let html = '<table><thead><tr><th>Timestamp</th><th>Incident ID</th><th>Action</th><th>Target IP</th><th>Mode</th><th>Result</th></tr></thead><tbody>';
        list.forEach(a => {
          html += `<tr>
            <td>${a.timestamp}</td>
            <td><code>${a.incident_id}</code></td>
            <td>${a.action_type}</td>
            <td><code>${a.target_ip}</code></td>
            <td><code>${a.execution_mode}</code></td>
            <td><span class="badge badge-low">${a.result}</span></td>
          </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = `<p style="color:red;">Failed to load audit logs: ${e}</p>`;
      }
    }

    async function resetDemo() {
      if (confirm('Reset database to clean security demo incidents?')) {
        await fetch('/api/reset-demo', { method: 'POST' });
        loadStatus();
        loadIncidents();
      }
    }

    // Initialize dashboard
    loadStatus();
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML
