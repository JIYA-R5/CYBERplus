"""
SentinelAI - AI-Powered Network Intrusion Detection & Incident Response Platform
Autonomous telemetry monitoring, behavioral anomaly correlation, Google Gemini copilot,
and safe, auditable incident response playbooks.
"""

import os
import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Backend engine modules
from detector import ThreatDetector, get_detector, Incident
from analyzer import TrafficAnalyzer, get_analyzer
from explainerAI import ThreatExplainer, get_explainer
from response_engine import ResponseEngine, get_response_engine, sanitize_ip
from database import DatabaseManager, get_db
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator, get_live_simulator

# Page configuration
st.set_page_config(
    page_title="SentinelAI - Threat Detection & Response",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize singletons and database
detector = get_detector()
analyzer = get_analyzer()
explainer = get_explainer()
response_engine = get_response_engine()
db = get_db()
live_sim = get_live_simulator()

# Ensure demo data exists if empty
if not db.get_incidents():
    db.reset_demo_data()

# Custom CSS for polished cybersecurity SOC styling
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        padding: 16px 20px;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        color: white;
        margin-bottom: 12px;
    }
    .badge-critical {
        background-color: #DC2626;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-high {
        background-color: #EA580C;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-medium {
        background-color: #D97706;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-low {
        background-color: #16A34A;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# SIDEBAR CONTROLS & ENVIRONMENT STATUS
# ==============================================================================
st.sidebar.title("🛡️ SentinelAI SOC")
st.sidebar.caption("Intrusion Detection & Defense Orchestrator")

# AI Copilot Status
if explainer.is_gemini_active:
    st.sidebar.success("🤖 AI Engine: Google Gemini (Live)")
else:
    st.sidebar.warning("🤖 AI Engine: Deterministic Fallback (Offline Mode)")
    with st.sidebar.expander("Configure Gemini API Key"):
        custom_key = st.text_input("Enter GEMINI_API_KEY", type="password")
        if st.button("Apply API Key"):
            if custom_key:
                os.environ["GEMINI_API_KEY"] = custom_key
                explainer.__init__(api_key=custom_key)
                st.rerun()

# Defensive Response Mode
response_mode = st.sidebar.radio(
    "Response Orchestration Mode",
    ["🛡️ Dry-Run (Simulation)", "⚡ Live Containment Mode"],
    index=0,
    help="In Dry-Run mode, defensive firewall actions are verified and logged without modifying system state."
)
is_dry_run = "Dry-Run" in response_mode

st.sidebar.divider()

# Demo Data Reset
if st.sidebar.button("🔄 Reset Demo Database"):
    db.reset_demo_data()
    st.sidebar.success("Database restored to baseline security demo incidents.")
    st.rerun()

st.sidebar.caption(f"SentinelAI v2.5 | Environment: {os.getenv('SENTINEL_ENV', 'development')}")

# ==============================================================================
# MAIN TABS ARCHITECTURE
# ==============================================================================
tabs = st.tabs([
    "📊 SOC Overview",
    "🚨 Incident Queue",
    "🤖 AI Threat Copilot",
    "📁 Telemetry Ingestion",
    "📡 Live Monitoring",
    "📜 Response Audit Trail"
])

# ------------------------------------------------------------------------------
# TAB 1: SOC OVERVIEW & TELEMETRY
# ------------------------------------------------------------------------------
with tabs[0]:
    # Header Banner
    incidents_list = db.get_incidents()
    total_incidents = len(incidents_list)
    critical_count = sum(1 for i in incidents_list if i.get("severity") == "Critical")
    high_count = sum(1 for i in incidents_list if i.get("severity") == "High")

    defcon_label = "DEFCON 1 - CRITICAL" if critical_count > 0 else ("DEFCON 2 - HIGH" if high_count > 0 else "DEFCON 5 - NOMINAL")
    defcon_color = "#DC2626" if critical_count > 0 else ("#EA580C" if high_count > 0 else "#16A34A")

    col_h1, col_h2 = st.columns([3, 1])
    with col_h1:
        st.title("🛡️ Enterprise Threat Defense Center")
        st.write("Real-time behavioral intrusion detection, MITRE ATT&CK correlation, and automated incident containment.")
    with col_h2:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            f"<div style='background-color:{defcon_color}; padding:12px; border-radius:8px; text-align:center; color:white; font-weight:bold; font-size:1.1rem;'>"
            f"{defcon_label}</div>",
            unsafe_allow_html=True
        )

    # Executive Briefing
    sample_csv_path = os.path.join(os.path.dirname(__file__), "sample_traafic.csv")
    base_df = pd.read_csv(sample_csv_path) if os.path.exists(sample_csv_path) else pd.DataFrame()
    exec_summary = explainer.generate_executive_summary(base_df)
    st.info(f"**🤖 AI Executive Security Briefing:** {exec_summary}")

    # Metrics
    m1, m2, m3, m4 = st.columns(4)
    total_pkts = int(base_df["Packets"].sum()) if not base_df.empty and "Packets" in base_df.columns else 12500
    m1.metric("Active Incidents", total_incidents, delta=f"{critical_count} Critical")
    m2.metric("Telemetry Flows", len(base_df) if not base_df.empty else 10)
    m3.metric("Aggregated Packets", f"{total_pkts:,}")
    risk_score = 92 if critical_count > 0 else (75 if high_count > 0 else 25)
    m4.metric("Threat Index", f"{risk_score} / 100", delta="-Defensive Active" if risk_score > 50 else "+Quiescent")

    st.divider()

    # Visualizations
    col_c1, col_c2 = st.columns([1, 1])
    with col_c1:
        st.subheader("📈 Threat Severity Distribution")
        if incidents_list:
            sev_counts = pd.Series([i["severity"] for i in incidents_list]).value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#D97706", "Low": "#16A34A"}
            fig_pie = px.pie(
                sev_counts,
                values="Count",
                names="Severity",
                color="Severity",
                color_discrete_map=color_map,
                hole=0.45
            )
            fig_pie.update_layout(template="plotly_dark", height=320, margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No active incidents to chart.")

    with col_c2:
        st.subheader("🎯 Attack Category Distribution")
        if incidents_list:
            cat_counts = pd.Series([i["category"] for i in incidents_list]).value_counts().reset_index()
            cat_counts.columns = ["Category", "Count"]
            fig_bar = px.bar(
                cat_counts,
                x="Category",
                y="Count",
                color="Count",
                color_continuous_scale="Reds",
            )
            fig_bar.update_layout(template="plotly_dark", height=320, margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No attack categories to chart.")

# ------------------------------------------------------------------------------
# TAB 2: INCIDENT MANAGEMENT & TRIAGE
# ------------------------------------------------------------------------------
with tabs[1]:
    st.subheader("🚨 Security Incident Queue & Triage Desk")
    st.write("Review correlated multi-event anomalies, inspect forensic evidence, and dispatch defensive containment actions.")

    # Filter Controls
    f_col1, f_col2, f_col3 = st.columns([2, 2, 3])
    with f_col1:
        sev_filter = st.selectbox("Filter Severity", ["All", "Critical", "High", "Medium", "Low"])
    with f_col2:
        status_filter = st.selectbox("Filter Status", ["All", "Open", "Investigating", "Mitigated", "Resolved", "False Positive"])
    with f_col3:
        search_term = st.text_input("🔍 Search Incident (ID, IP, or Category)", "")

    # Retrieve incidents
    filtered_incidents = db.get_incidents(
        status_filter=None if status_filter == "All" else status_filter,
        severity_filter=None if sev_filter == "All" else sev_filter
    )

    if search_term:
        term = search_term.lower()
        filtered_incidents = [
            i for i in filtered_incidents
            if term in i["incident_id"].lower()
            or term in i["source_ip"].lower()
            or term in i["category"].lower()
        ]

    if not filtered_incidents:
        st.success("No security incidents match the current filter criteria.")
    else:
        # Incident Table Overview
        table_records = []
        for inc in filtered_incidents:
            table_records.append({
                "Incident ID": inc["incident_id"],
                "Timestamp": inc["timestamp"],
                "Category": inc["category"],
                "Source IP": inc["source_ip"],
                "Target IP": inc.get("destination_ip", "Internal Target"),
                "Severity": inc["severity"],
                "Confidence": f"{int(inc['confidence']*100)}%",
                "Status": inc["status"],
                "MITRE ID": inc.get("mitre_id", "N/A")
            })

        st.dataframe(pd.DataFrame(table_records), use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("🛠️ Incident Drill-Down & Containment Action Center")

        # Select Incident for action
        incident_ids = [i["incident_id"] for i in filtered_incidents]
        selected_id = st.selectbox("Select Incident to Triage", incident_ids)
        current_inc = next((i for i in filtered_incidents if i["incident_id"] == selected_id), None)

        if current_inc:
            col_d1, col_d2 = st.columns([1, 1])

            with col_d1:
                st.markdown(f"### Incident {current_inc['incident_id']}: **{current_inc['category']}**")
                st.markdown(f"**Source Host:** `{current_inc['source_ip']}` ➡️ **Destination:** `{current_inc.get('destination_ip', 'Internal')}`")
                ports = current_inc.get("destination_ports", [])
                st.markdown(f"**Targeted Ports:** `{ports}`")
                st.markdown(f"**Severity:** `{current_inc['severity']}` | **Confidence:** `{int(current_inc['confidence']*100)}%`")
                st.markdown(f"**Detection Rule:** `{current_inc.get('rule_id', 'N/A')}` | **MITRE ATT&CK:** `{current_inc.get('mitre_id', 'N/A')}`")
                st.info(f"📋 **Correlated Evidence:** {current_inc['evidence']}")

                # Status Transition
                st.markdown("#### Update Lifecycle Status")
                stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
                if stat_col1.button("Investigating", key=f"inv_{selected_id}"):
                    db.update_incident_status(selected_id, "Investigating")
                    st.rerun()
                if stat_col2.button("Mitigated", key=f"mit_{selected_id}"):
                    db.update_incident_status(selected_id, "Mitigated")
                    st.rerun()
                if stat_col3.button("Resolved", key=f"res_{selected_id}"):
                    db.update_incident_status(selected_id, "Resolved")
                    st.rerun()
                if stat_col4.button("False Positive", key=f"fp_{selected_id}"):
                    db.update_incident_status(selected_id, "False Positive")
                    st.rerun()

            with col_d2:
                st.markdown("### 🛡️ Defensive Response Orchestration")
                st.caption(f"Active Mode: **{'Dry-Run Simulation' if is_dry_run else 'Live Authorized Containment'}**")

                # Containment execution button
                btn_label = f"Simulate Firewall Quarantine ({current_inc['source_ip']})" if is_dry_run else f"⚡ Execute Live Block ({current_inc['source_ip']})"
                if st.button(btn_label, type="primary"):
                    action_res = response_engine.execute_response_action(
                        incident_id=current_inc["incident_id"],
                        action_type="FIREWALL_QUARANTINE",
                        target_ip=current_inc["source_ip"],
                        dry_run=is_dry_run,
                        operator="SOC Analyst",
                        db_manager=db
                    )

                    if action_res["status"] == "SUCCESS":
                        st.success(f"Response successfully orchestrated! Audit Record ID: `{action_res['audit_id']}`")
                        st.write(action_res["details"])
                    else:
                        st.error(action_res.get("message", "Response rejected."))

                # Generated Containment & Rollback Commands
                plan = response_engine.get_mitigation_plan(
                    activity=current_inc["category"],
                    source_ip=current_inc["source_ip"],
                    risk=current_inc["severity"]
                )

                st.markdown("#### Copyable Firewall Containment Rules")
                fw_tabs = st.tabs(["PowerShell", "Linux iptables", "Linux ufw", "Cisco ACL"])
                with fw_tabs[0]:
                    st.code(plan["firewall_commands"]["Windows PowerShell"], language="powershell")
                with fw_tabs[1]:
                    st.code(plan["firewall_commands"]["Linux iptables"], language="bash")
                with fw_tabs[2]:
                    st.code(plan["firewall_commands"]["Linux ufw"], language="bash")
                with fw_tabs[3]:
                    st.code(plan["firewall_commands"]["Cisco IOS ACL"], language="text")

                with st.expander("🔄 Reversible Rollback Scripts"):
                    st.code(plan["rollback_commands"]["Windows PowerShell"], language="powershell")
                    st.code(plan["rollback_commands"]["Linux iptables"], language="bash")

# ------------------------------------------------------------------------------
# TAB 3: AI COPILOT & THREAT EXPLAINER
# ------------------------------------------------------------------------------
with tabs[2]:
    st.subheader("🤖 SentinelAI Threat Copilot & Root-Cause Explainer")
    st.write("Comprehensive LLM threat reasoning powered by Google Gemini with deterministic local fallbacks.")

    all_incs = db.get_incidents()
    if not all_incs:
        st.info("No active incidents to analyze.")
    else:
        inc_map = {f"[{i['severity']}] {i['incident_id']} - {i['category']} ({i['source_ip']})": i for i in all_incs}
        selected_label = st.selectbox("Select Incident for AI Deep-Dive", list(inc_map.keys()))
        target_inc = inc_map[selected_label]

        # Call explainerAI
        exp = explainer.explain_threat(
            activity=target_inc["category"],
            source_ip=target_inc["source_ip"],
            packets=target_inc["total_packets"],
            risk=target_inc["severity"],
            details=target_inc["evidence"]
        )

        # Provider attribution
        provider_badge = "🟢 Google Gemini GenAI" if exp["provider"] == "google_gemini" else "🟡 Deterministic Rule-Based Fallback"
        st.caption(f"Analysis Engine: **{provider_badge}** | {exp['ai_disclaimer']}")

        col_a1, col_a2 = st.columns([1, 1])

        with col_a1:
            st.markdown("### 📋 Executive Summary")
            st.write(exp["summary"])

            st.markdown("### ⚙️ Technical Attack Mechanism")
            st.write(exp["mechanism"])

            st.markdown("### 💥 Potential Business & Security Impact")
            st.write(exp["potential_impact"])

            st.markdown(f"**MITRE ATT&CK Mapping:** `{exp['mitre_technique']}`")
            st.info(f"💡 **Key Analyst Focus:** {exp['recommended_focus']}")

        with col_a2:
            st.markdown("### 🔍 Forensic Investigation Checklist")
            st.caption("Interactive triage steps for SOC analysts:")
            for idx, step in enumerate(exp.get("investigation_steps", []), 1):
                st.checkbox(step, key=f"chk_{target_inc['incident_id']}_{idx}")

            st.markdown("### 🛡️ Recommended Containment Steps")
            for step in exp.get("containment_recommendations", []):
                st.markdown(f"- {step}")

        st.divider()

        # Interactive Analyst Q&A
        st.subheader("💬 Ask SentinelAI Copilot")
        copilot_query = st.text_input("Ask a follow-up question about this incident (e.g. 'How can I verify if this IP is a scanner?')")
        if st.button("Submit Question to Copilot"):
            if copilot_query:
                with st.spinner("Analyzing incident context..."):
                    if explainer.is_gemini_active and explainer.gemini_client:
                        try:
                            prompt = (
                                f"You are SentinelAI, an elite SOC analyst assistant. "
                                f"Answer this question regarding incident {target_inc['category']} from source {target_inc['source_ip']}:\n"
                                f"Question: {copilot_query}\n"
                                f"Provide concise, actionable cybersecurity advice."
                            )
                            res = explainer.gemini_client.models.generate_content(
                                model="gemini-2.5-flash",
                                contents=prompt
                            )
                            st.write(res.text)
                        except Exception as e:
                            st.error(f"Copilot query failed: {e}. Falling back.")
                    else:
                        st.write(
                            f"**Copilot Guidance (Deterministic Fallback):** For `{target_inc['category']}`, "
                            f"first correlate `{target_inc['source_ip']}` with internal asset inventories. "
                            f"If the host is untrusted, enforce perimeter firewall drops and inspect related DNS query logs."
                        )

# ------------------------------------------------------------------------------
# TAB 4: TELEMETRY INGESTION & LOG FILE PARSER
# ------------------------------------------------------------------------------
with tabs[3]:
    st.subheader("📁 Structured Log File Ingestion & Parser")
    st.write("Upload Suricata EVE JSON or custom CSV security logs to extract, detect, and store incidents.")

    col_u1, col_u2 = st.columns([1, 1])

    with col_u1:
        st.markdown("#### Option A: Load Built-in Laboratory Samples")
        sample_choice = st.selectbox(
            "Select Pre-configured Sample Dataset",
            [
                "Baseline Dataset (sample_traafic.csv)",
                "Suricata EVE 73-Record Security Audit Stream (sentinelai_suricata_eve_sample.json)",
                "Suricata EVE JSON Alert Stream (suricata_sample.json)",
                "Simulated Port Scan Attack (attack_port_scan.json)",
                "Simulated Brute Force Attack (attack_brute_force.json)",
                "Simulated DDoS Volumetric Surge (attack_ddos_flood.json)",
                "Malformed Telemetry Test (malformed_records.json)"
            ]
        )

        loaded_df = None
        if st.button("Load and Analyze Selected Sample"):
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            file_map = {
                "Baseline Dataset (sample_traafic.csv)": os.path.join(os.path.dirname(__file__), "sample_traafic.csv"),
                "Suricata EVE 73-Record Security Audit Stream (sentinelai_suricata_eve_sample.json)": os.path.join(data_dir, "sentinelai_suricata_eve_sample.json"),
                "Suricata EVE JSON Alert Stream (suricata_sample.json)": os.path.join(data_dir, "suricata_sample.json"),
                "Simulated Port Scan Attack (attack_port_scan.json)": os.path.join(data_dir, "attack_port_scan.json"),
                "Simulated Brute Force Attack (attack_brute_force.json)": os.path.join(data_dir, "attack_brute_force.json"),
                "Simulated DDoS Volumetric Surge (attack_ddos_flood.json)": os.path.join(data_dir, "attack_ddos_flood.json"),
                "Malformed Telemetry Test (malformed_records.json)": os.path.join(data_dir, "malformed_records.json")
            }

            path = file_map[sample_choice]
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                if path.endswith(".csv"):
                    loaded_df = pd.read_csv(path)
                elif "suricata" in path:
                    events, errs = LogParser.parse_suricata_eve(content)
                    loaded_df = LogParser.events_to_dataframe(events)
                    if errs:
                        st.warning(f"Parser notes: {errs}")
                else:
                    events, errs = LogParser.parse_generic_json(content)
                    loaded_df = LogParser.events_to_dataframe(events)
                    if errs:
                        st.warning(f"Parser notes: {errs}")
            else:
                st.error(f"Sample file not found at {path}")

    with col_u2:
        st.markdown("#### Option B: Upload Custom Log File")
        uploaded_file = st.file_uploader("Upload Network Log (CSV or JSON)", type=["csv", "json"])
        if uploaded_file is not None:
            raw_bytes = uploaded_file.read()
            text_content = raw_bytes.decode("utf-8", errors="replace")

            if uploaded_file.name.endswith(".csv"):
                import io
                loaded_df = pd.read_csv(io.StringIO(text_content))
            else:
                events, errs = LogParser.parse_generic_json(text_content)
                loaded_df = LogParser.events_to_dataframe(events)
                if errs:
                    st.warning(f"Parser encountered {len(errs)} issues.")

    # Detection Execution on Loaded Dataset
    if loaded_df is not None and not loaded_df.empty:
        st.divider()
        st.subheader("🔍 Detection Pipeline Results")

        # Run detector
        enriched_df = detector.detect_dataframe(loaded_df)
        correlated_incs = detector.correlate_incidents(loaded_df)

        st.success(f"Successfully processed {len(enriched_df)} flow records. Identified {len(correlated_incs)} correlated incident(s).")

        # Save correlated incidents to SQLite
        for inc in correlated_incs:
            db.save_incident(inc.to_dict())

        st.dataframe(enriched_df, use_container_width=True)

        # Download enriched CSV
        csv_data = enriched_df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Export Enriched Telemetry (CSV)", data=csv_data, file_name="sentinel_enriched_telemetry.csv", mime="text/csv")

# ------------------------------------------------------------------------------
# TAB 5: LIVE MONITORING & LAB SIMULATOR
# ------------------------------------------------------------------------------
with tabs[4]:
    st.subheader("📡 Authorized Live Telemetry Monitor & Lab Scenario Simulator")
    st.write(
        "Demonstrates real-time telemetry streaming and lab scenario event generation. "
        "Every event generated in this view is explicitly labeled `[SIMULATED: Lab Scenario]`."
    )

    col_l1, col_l2, col_l3 = st.columns([1, 1, 2])
    with col_l1:
        if live_sim.is_running:
            if st.button("⏹️ Stop Simulation Stream"):
                live_sim.stop()
                st.rerun()
        else:
            if st.button("▶️ Start Live Telemetry Stream"):
                live_sim.start(interval_seconds=1.2)
                st.rerun()

    with col_l2:
        if st.button("🗑️ Clear Buffer"):
            live_sim.clear()
            st.rerun()

    with col_l3:
        status_text = "🟢 STREAM ACTIVE (Capturing Events)" if live_sim.is_running else "⚪ STREAM IDLE (Paused)"
        st.markdown(f"**Status:** `{status_text}`")

    # Display live events
    live_df = live_sim.get_events_dataframe(limit=50)
    if live_df.empty:
        st.info("Simulation stream is idle or buffer is empty. Click 'Start Live Telemetry Stream' to begin monitoring.")
    else:
        st.dataframe(live_df, use_container_width=True, hide_index=True)

# ------------------------------------------------------------------------------
# TAB 6: RESPONSE ACTIONS & AUDIT TRAIL
# ------------------------------------------------------------------------------
with tabs[5]:
    st.subheader("📜 SOC Defensive Response & Audit Trail")
    st.write("Immutable SQLite audit log recording every containment policy execution, status transition, and operator action.")

    audit_records = db.get_audit_logs(limit=100)
    if not audit_records:
        st.info("No audit logs recorded yet.")
    else:
        audit_df = pd.DataFrame(audit_records)
        # Format display columns
        display_cols = [c for c in ["timestamp", "incident_id", "action_type", "target_ip", "execution_mode", "operator", "result", "details"] if c in audit_df.columns]
        st.dataframe(audit_df[display_cols], use_container_width=True, hide_index=True)

        audit_csv = audit_df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Export Audit Log (CSV)", data=audit_csv, file_name="sentinel_audit_log.csv", mime="text/csv")

st.caption("SentinelAI v2.5 | Multi-Tier Threat Detection, Gemini Copilot & Safe Incident Response")

# ==============================================================================
# VERCEL SERVERLESS RUNTIME ENTRYPOINT EXPORT
# ==============================================================================
# When imported outside of Streamlit (e.g. by Vercel serverless build/runtime),
# expose the FastAPI ASGI application so Vercel never errors on [PYTHON_ENTRYPOINT_NOT_FOUND].
try:
    from api.index import app  # noqa: F401
except Exception:
    pass