"""
SentinelAI - End-to-End Demonstration & Simulation Script
Executes full real-time telemetry streaming, 73-record audit log correlation,
automated defensive response generation in dry-run mode, and AI threat copilot triage.
"""

import sys
import time
import os
import pandas as pd

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from live_monitor import LiveMonitoringSimulator
from detector import ThreatDetector, get_detector
from log_parser import LogParser
from explainerAI import ThreatExplainer, get_explainer
from response_engine import ResponseEngine, get_response_engine
from database import DatabaseManager, get_db

def run_full_demo():
    print("=" * 80)
    print("🛡️  [SENTINELAI SOC] LIVE TELEMETRY SIMULATION & END-TO-END DEMONSTRATION")
    print("=" * 80)

    # -------------------------------------------------------------
    # 1. LIVE MONITORING & SIMULATED STREAM
    # -------------------------------------------------------------
    print("\n[PHASE 1] 📡 Initializing Live Network Telemetry Simulator...")
    sim = LiveMonitoringSimulator(buffer_size=100)
    sim.start(interval_seconds=0.2)
    print("  -> Simulator active. Capturing synthetic multi-protocol flows...")
    time.sleep(2.0)
    sim.stop()

    events = sim.get_recent_events(limit=10)
    print(f"  -> Captured {len(events)} real-time telemetry events.")
    print("  -> Sample Captured Telemetry Flows:")
    for e in events[:6]:
        print(f"     [{e['Telemetry Type']}] {e['Time']} | {e['Source IP']:>15} -> {e['Destination IP']:>10}:{e['Port']:<5} | {e['Packets']:>4} pkts | {e['Activity']:<15} | Risk: {e['Risk']}")

    # -------------------------------------------------------------
    # 2. INGESTION & DETECTION ON SURICATA EVE 73-RECORD AUDIT DATASET
    # -------------------------------------------------------------
    print("\n[PHASE 2] 📁 Ingesting & Correlating Suricata EVE 73-Record Telemetry Dataset...")
    sample_file = os.path.join(os.path.dirname(__file__), "data", "sentinelai_suricata_eve_sample.json")

    with open(sample_file, "r", encoding="utf-8") as f:
        raw_events, errs = LogParser.parse_suricata_eve(f.read())
    
    df = LogParser.events_to_dataframe(raw_events)
    detector = get_detector()
    enriched_df = detector.detect_dataframe(df)
    correlated_incidents = detector.correlate_incidents(df)

    print(f"  -> Total Telemetry Records Ingested: {len(enriched_df)}")
    print(f"  -> Telemetry Classifications Breakdown:")
    val_counts = enriched_df["Activity"].value_counts().to_dict()
    for act, count in val_counts.items():
        print(f"     - {act:<20}: {count} records")

    print(f"\n  -> Correlated Multi-Event Incidents Identified: {len(correlated_incidents)}")
    for idx, inc in enumerate(correlated_incidents, 1):
        print(f"     Incident #{idx}: [{inc.severity.upper()}] {inc.incident_id} | {inc.category}")
        print(f"       Attacker: {inc.source_ip} -> Target: {inc.destination_ip} | Ports: {inc.destination_ports}")
        print(f"       MITRE ATT&CK: {inc.mitre_id} | Confidence: {inc.confidence * 100:.1f}%")
        print(f"       Supporting Events Correlated: {len(inc.supporting_events)} event IDs {inc.supporting_events[:5]}...")
        print(f"       Forensic Evidence: {inc.evidence}")

    # -------------------------------------------------------------
    # 3. AUTOMATED DEFENSIVE CONTAINMENT (DRY-RUN MODE)
    # -------------------------------------------------------------
    print("\n[PHASE 3] 🛡️  Simulating Automated Defensive Incident Containment (Dry-Run Mode)...")
    resp_engine = get_response_engine()
    db = get_db()

    for inc in correlated_incidents:
        db.save_incident(inc.to_dict())
        target_ip = inc.source_ip if inc.source_ip != "Distributed Sources" else "192.168.1.100"
        res = resp_engine.execute_response_action(
            incident_id=inc.incident_id,
            action_type="Quarantine Host",
            target_ip=target_ip,
            dry_run=True,
            operator="SOC Automated Orchestrator",
            db_manager=db
        )
        cmds = resp_engine.generate_firewall_commands(target_ip)
        rollbacks = resp_engine.generate_rollback_commands(target_ip)

        print(f"\n  -> [CONTAINMENT ACTION] Incident {inc.incident_id} ({inc.category}):")
        print(f"     Target Attacker IP : {res['target_ip']} (Strictly validated via ipaddress)")
        print(f"     Execution Mode     : {res['execution_mode']} (Simulation - zero production impact)")
        print(f"     Simulated Result   : {res['result']}")
        print(f"     Windows PowerShell : {cmds['Windows PowerShell']}")
        print(f"     Linux iptables     : {cmds['Linux iptables']}")
        print(f"     Reversible Rollback: {rollbacks['Linux iptables']}")

    # -------------------------------------------------------------
    # 4. AI THREAT COPILOT & FORENSIC TRIAGE
    # -------------------------------------------------------------
    print("\n[PHASE 4] 🤖 AI Threat Copilot Reasoning & Investigation Plan...")
    explainer = get_explainer()
    target_inc = correlated_incidents[0].to_dict()
    exp = explainer.explain_threat(
        activity=target_inc["category"],
        source_ip=target_inc["source_ip"],
        packets=target_inc.get("total_packets", 0),
        risk=target_inc["severity"],
        details=target_inc.get("evidence", "")
    )

    print(f"  -> Incident Analyzed : {target_inc['incident_id']} - {target_inc['category']}")
    print(f"  -> Analysis Provider  : {exp['provider']}")
    print(f"  -> Executive Summary  : {exp['summary']}")
    print(f"  -> Technical Vector   : {exp['mechanism']}")
    print(f"  -> Key Analyst Focus  : {exp['recommended_focus']}")
    print(f"  -> Forensic Checklist :")
    for step in exp['investigation_steps'][:3]:
        print(f"     [ ] {step}")

    # -------------------------------------------------------------
    # 5. AUDIT TRAIL VERIFICATION
    # -------------------------------------------------------------
    print("\n[PHASE 5] 📜 Immutable SQLite Audit Trail Verification...")
    audit_logs = db.get_audit_logs(limit=3)
    print(f"  -> Recorded {len(audit_logs)} latest audit entries in SQLite:")
    for log in audit_logs:
        print(f"     [{log['timestamp']}] ID: {log['incident_id']} | Action: {log['action_type']} | Result: {log['result']} | Mode: {log['execution_mode']}")

    print("\n" + "=" * 80)
    print("✅ [SUCCESS] SIMULATION DEMONSTRATION COMPLETE - ALL SYSTEMS RUNNING NOMINALLY")
    print("=" * 80)

if __name__ == "__main__":
    run_full_demo()
