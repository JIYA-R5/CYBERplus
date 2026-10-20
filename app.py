"""
SentinelAI - AI-Powered Network Intrusion Detection & Incident Response Platform
Autonomous telemetry monitoring, behavioral anomaly correlation, Machine Learning Threat Intelligence,
Google Gemini Copilot, and safe, auditable incident response playbooks.
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
from response_engine import ResponseEngine, get_response_engine, sanitize_ip, is_ip_allowlisted, DEFAULT_PROTECTED_IPS
from database import DatabaseManager, get_db, IDENTITY_DISCLAIMER
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator, get_live_simulator
from ml_engine import get_ml_engine, MLAnomalyEngine

# Page configuration
st.set_page_config(
    page_title="SentinelAI - ML Threat Intelligence & SOC Defense",
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
ml_engine = get_ml_engine()

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
    .verdict-badge {
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .verdict-tp { background: #DC2626; color: white; }
    .verdict-fp { background: #3B82F6; color: white; }
    .verdict-benign { background: #10B981; color: white; }
    .verdict-unresolved { background: #6B7280; color: white; }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# SIDEBAR CONTROLS & ENVIRONMENT STATUS
# ==============================================================================
st.sidebar.title("🛡️ SentinelAI SOC")
st.sidebar.caption("Machine Learning Threat Intelligence & Adaptive Defense")

# Environmental Status Check
gemini_status = "🟢 Active (GenAI Live)" if explainer.is_gemini_active else "🟡 Offline (Rule Fallback)"
st.sidebar.markdown(f"**Gemini AI Status:** {gemini_status}")

active_model_info = db.get_active_model()
active_ver = active_model_info["version"] if active_model_info else ml_engine.model_version
st.sidebar.markdown(f"**ML Engine Version:** `{active_ver}`")
st.sidebar.markdown(f"**Algorithm:** `IsolationForest (k-trees=100)`")

# Dry Run Safety Switch
st.sidebar.divider()
is_dry_run = st.sidebar.checkbox("🔒 Enforce Dry-Run Mode (Safe)", value=True, help="When enabled, containment actions generate firewall commands without modifying real host OS state.")
if is_dry_run:
    st.sidebar.info("🛡️ Dry-Run Active: Containment policies are safely simulated.")
else:
    st.sidebar.warning("⚠️ Live Execution Mode: Authorized containment actions will apply firewall rules (Requires Explicit Admin Approval).")

# Quick Demo Reset
st.sidebar.divider()
if st.sidebar.button("🔄 Reset Demo Environment"):
    db.reset_demo_data()
    st.sidebar.success("Database restored to baseline demonstration state.")
    st.rerun()

# Data Retention Policy Trigger
st.sidebar.divider()
st.sidebar.markdown("### 🧹 Data Retention Controls")
retention_days = st.sidebar.slider("Retention Window (Days)", 7, 90, 30)
if st.sidebar.button("Apply Data Retention Purge"):
    res = db.apply_data_retention(retention_days=retention_days, operator="SOC Admin")
    st.sidebar.success(f"Purged {res['purged_telemetry']} telemetry events & {res['purged_incidents']} resolved incidents.")
    st.rerun()

# Identity Disclaimer
st.sidebar.caption(IDENTITY_DISCLAIMER)

# ==============================================================================
# MAIN TABS ARCHITECTURE
# ==============================================================================
tabs = st.tabs([
    "📊 SOC Overview",
    "🚨 Incident Queue",
    "🧠 ML Threat Intelligence",
    "🤖 AI Threat Copilot",
    "🛡️ Active Containment & Expiry",
    "📁 Telemetry Ingestion",
    "📡 Live Monitoring",
    "📜 Response Audit Trail"
])

# ------------------------------------------------------------------------------
# TAB 1: SOC OVERVIEW & TELEMETRY
# ------------------------------------------------------------------------------
with tabs[0]:
    incidents_list = db.get_incidents()
    total_incidents = len(incidents_list)
    critical_count = sum(1 for i in incidents_list if i.get("severity") == "Critical")
    high_count = sum(1 for i in incidents_list if i.get("severity") == "High")

    defcon_label = "DEFCON 1 - CRITICAL" if critical_count > 0 else ("DEFCON 2 - HIGH" if high_count > 0 else "DEFCON 5 - NOMINAL")
    defcon_color = "#DC2626" if critical_count > 0 else ("#EA580C" if high_count > 0 else "#16A34A")

    col_h1, col_h2 = st.columns([3, 1])
    with col_h1:
        st.title("🛡️ Enterprise Threat Defense Center")
        st.write("Real-time behavioral intrusion detection, MITRE ATT&CK correlation, and adaptive incident containment.")
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
    st.subheader("🚨 Security Incident Queue & Persistent Threat Memory")
    st.write("Review correlated multi-event anomalies, inspect ML anomaly scores, record verified analyst verdicts, and dispatch safe containment.")

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 2, 3])
    with f_col1:
        sev_filter = st.selectbox("Filter Severity", ["All", "Critical", "High", "Medium", "Low"])
    with f_col2:
        status_filter = st.selectbox("Filter Status", ["All", "Open", "Investigating", "Mitigated", "Resolved", "False Positive"])
    with f_col3:
        verdict_filter = st.selectbox("Analyst Verdict", ["All", "Unreviewed", "True Positive", "False Positive", "Benign", "Unresolved"])
    with f_col4:
        search_term = st.text_input("🔍 Search Incident (ID, IP, or Category)", "")

    # Retrieve incidents
    filtered_incidents = db.get_incidents(
        status_filter=None if status_filter == "All" else status_filter,
        severity_filter=None if sev_filter == "All" else sev_filter,
        verdict_filter=None if verdict_filter == "All" else verdict_filter
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
                "Recurrence": f"{inc.get('recurrence_count', 1)}x observed",
                "Severity": inc["severity"],
                "ML Score": f"{inc.get('ml_anomaly_score', 0.0):.2f}",
                "Model Ver": inc.get("model_version", "v1.0.0"),
                "Analyst Verdict": inc.get("analyst_verdict", "Unreviewed"),
                "Status": inc["status"],
            })

        st.dataframe(pd.DataFrame(table_records), use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("🛠️ Incident Drill-Down & Analyst Action Center")

        incident_ids = [i["incident_id"] for i in filtered_incidents]
        selected_id = st.selectbox("Select Incident to Triage", incident_ids)
        current_inc = next((i for i in filtered_incidents if i["incident_id"] == selected_id), None)

        if current_inc:
            col_d1, col_d2 = st.columns([1, 1])

            with col_d1:
                st.markdown(f"### Incident {current_inc['incident_id']}: **{current_inc['category']}**")
                st.markdown(f"**Observed Host:** `{current_inc['source_ip']}` ➡️ **Destination:** `{current_inc.get('destination_ip', 'Internal')}`")
                ports = current_inc.get("destination_ports", [])
                st.markdown(f"**Targeted Ports:** `{ports}` | **Protocols:** `{current_inc.get('protocols', ['TCP'])}`")
                st.markdown(f"**First Seen:** `{current_inc.get('timestamp')}` | **Last Seen:** `{current_inc.get('last_seen', current_inc.get('timestamp'))}`")
                st.markdown(f"**Severity:** `{current_inc['severity']}` | **Rule ID:** `{current_inc.get('rule_id', 'N/A')}` | **MITRE:** `{current_inc.get('mitre_id', 'N/A')}`")

                # ML Anomaly Metrics Box
                ml_score = current_inc.get("ml_anomaly_score", 0.0)
                ml_ver = current_inc.get("model_version", "v1.0.0")
                is_anom = current_inc.get("ml_is_anomaly", False)
                st.markdown(f"""
                <div style="background:#1E293B; padding:12px; border-radius:8px; border-left:4px solid #8B5CF6; margin: 10px 0;">
                    <strong>🧠 ML Anomaly Evaluation (Model {ml_ver}):</strong><br>
                    Continuous Anomaly Score: <code>{ml_score:.4f}</code> | Anomaly Flag: <code>{'YES - STATISTICAL DEVIATION' if is_anom else 'NO - WITHIN BASELINE'}</code><br>
                    <small><em>Notice: Anomaly scores measure baseline divergence and are NOT proof of an attack.</em></small>
                </div>
                """, unsafe_allow_html=True)

                st.info(f"📋 **Correlated Evidence:** {current_inc['evidence']}")

                # Recurrence tracking
                rec_cnt = current_inc.get("recurrence_count", 1)
                st.caption(f"🔄 **Historical Recurrence:** Observed **{rec_cnt}** times across SentinelAI incident history.")
                st.caption(IDENTITY_DISCLAIMER)

                with st.expander("📦 Raw Telemetry Evidence"):
                    st.code(current_inc.get("raw_evidence") or current_inc.get("evidence"), language="text")

                # Analyst Verdict Form (Controlled Learning)
                st.markdown("#### 📝 Record Analyst Verdict (Ground Truth)")
                cur_verdict = current_inc.get("analyst_verdict", "Unreviewed")
                verdict_choices = ["True Positive", "False Positive", "Benign", "Unresolved"]
                default_idx = verdict_choices.index(cur_verdict) if cur_verdict in verdict_choices else 0

                v_col1, v_col2 = st.columns(2)
                with v_col1:
                    new_verdict = st.selectbox("Select Verified Verdict", verdict_choices, index=default_idx)
                with v_col2:
                    reviewer_name = st.text_input("Reviewer Operator", value=current_inc.get("analyst_user") or "SOC Senior Analyst")

                verdict_reason = st.text_input("Justification / Audit Reason", value=current_inc.get("analyst_reason") or "Corroborated by telemetry inspection")

                if st.button("Save Analyst Verdict & Ground Truth", type="secondary"):
                    fb_id = db.record_analyst_feedback(
                        incident_id=selected_id,
                        verdict=new_verdict,
                        analyst_user=reviewer_name,
                        reason=verdict_reason,
                        model_version=ml_ver
                    )
                    st.success(f"Analyst verdict '{new_verdict}' recorded! Feedback ID: `{fb_id}`")
                    st.rerun()

                # Status Transition
                st.markdown("#### Lifecycle State")
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

                # Allowlist check indicator
                target_ip = current_inc["source_ip"]
                is_allowed, allow_reason = is_ip_allowlisted(target_ip)
                if is_allowed:
                    st.error(f"🚫 **PROTECTED ALLOWLIST:** {allow_reason}\nContainment actions targeting this IP will be automatically blocked by safety policy.")
                else:
                    st.success(f"✅ **Safety Check Passed:** `{target_ip}` cleared allowlist and is eligible for authorized containment.")

                # Containment Proposal Form
                c_col1, c_col2 = st.columns(2)
                with c_col1:
                    rule_type = st.selectbox("Containment Rule Type", ["Temporary", "Permanent"])
                with c_col2:
                    duration_opts = [15, 30, 60, 120, 240]
                    duration_min = st.selectbox("Proposed Duration (Minutes)", duration_opts, index=2) if rule_type == "Temporary" else None

                admin_approval = st.checkbox("Require & Grant Explicit Administrator Approval", value=False)
                perm_justification = ""
                if rule_type == "Permanent":
                    perm_justification = st.text_input("Mandatory Written Justification (Permanent Block)", "")

                # Containment Execution Button
                btn_label = f"Simulate Containment ({target_ip})" if is_dry_run else f"⚡ Execute Live Block ({target_ip})"
                if st.button(btn_label, type="primary"):
                    action_res = response_engine.execute_response_action(
                        incident_id=current_inc["incident_id"],
                        action_type="FIREWALL_QUARANTINE",
                        target_ip=target_ip,
                        dry_run=is_dry_run,
                        rule_type=rule_type,
                        duration_minutes=duration_min or 60,
                        admin_approved=admin_approval,
                        operator="SOC Lead Responder",
                        justification=perm_justification if rule_type == "Permanent" else "Standard Containment",
                        db_manager=db
                    )

                    if action_res["status"] == "SUCCESS":
                        st.success(f"Response successfully orchestrated! Audit Record ID: `{action_res['audit_id']}` | Block ID: `{action_res.get('block_id')}`")
                        st.write(action_res["details"])
                    else:
                        st.error(f"Action Rejected: {action_res.get('message', 'Validation or authorization failed.')}")

                # Copyable Firewall Commands
                plan = response_engine.get_mitigation_plan(
                    activity=current_inc["category"],
                    source_ip=target_ip,
                    risk=current_inc["severity"],
                    duration_minutes=duration_min or 60
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
# TAB 3: MACHINE LEARNING THREAT INTELLIGENCE
# ------------------------------------------------------------------------------
with tabs[2]:
    st.subheader("🧠 Machine Learning Threat Intelligence & Controlled Retraining")
    st.write("Isolation Forest statistical anomaly scoring, model evaluation metrics, feature attribution, and controlled retraining pipelines.")

    ml_col1, ml_col2 = st.columns([1, 1])

    with ml_col1:
        st.markdown("### 📊 Active Model Performance & Registry")
        active_model = db.get_active_model()
        active_v = active_model["version"] if active_model else ml_engine.model_version
        metrics = active_model.get("metrics", {}) if active_model else ml_engine.metrics

        st.markdown(f"**Active Model Version:** `{active_v}` | **Algorithm:** `Scikit-Learn IsolationForest`")
        if metrics:
            st.json(metrics)
        else:
            st.info("Active model initialized with default hyperparameters.")

        st.markdown("#### 🔄 Revert to Previous Model Version")
        all_models = db.get_model_registry()
        if all_models:
            versions = [m["version"] for m in all_models]
            target_revert = st.selectbox("Select Registered Model to Activate", versions)
            if st.button("Revert / Promote Model"):
                success = ml_engine.revert_model(target_revert)
                if success:
                    db.set_active_model_version(target_revert)
                    st.success(f"Active model reverted to {target_revert}!")
                    st.rerun()
                else:
                    st.error(f"Could not load artifact for {target_revert}.")
        else:
            st.info("Zero registered historical models.")

    with ml_col2:
        st.markdown("### 🧪 Controlled Retraining Workflow")
        st.caption("Controlled retraining prevents automatic model poisoning and enforces validation gates.")

        retrain_samples = st.slider("Synthetic Lab Fixture Sample Count", 100, 1000, 300)
        retrain_contam = st.slider("Target Contamination Rate", 0.05, 0.30, 0.15)
        new_version_tag = st.text_input("New Model Version Tag (Optional)", value=f"v1.{len(all_models)+1}.0" if all_models else "v1.1.0")

        if st.button("Run Controlled Retraining Pipeline", type="primary"):
            with st.spinner("Generating synthetic lab fixtures and training Isolation Forest..."):
                fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=retrain_samples)
                retrain_res = ml_engine.train_controlled_pipeline(
                    training_data=fixtures,
                    version_tag=new_version_tag,
                    contamination=retrain_contam,
                    trained_by="SOC ML Engineer"
                )

                if retrain_res.get("status") == "VALIDATED_AND_TRAINED":
                    db.register_model(
                        version=retrain_res["model_version"],
                        algorithm=retrain_res["algorithm"],
                        sample_count=retrain_res["total_samples"],
                        metrics=retrain_res,
                        artifact_path=retrain_res["artifact_path"],
                        trained_by="SOC ML Engineer",
                        set_active=True
                    )
                    st.success(f"Model {retrain_res['model_version']} successfully trained, validated on test split, and promoted to active!")
                    st.json(retrain_res)
                    st.rerun()
                else:
                    st.error(f"Retraining Failed: {retrain_res.get('message')}")

    st.divider()

    # Interactive Real-Time Flow Scorer
    st.subheader("⚡ Real-Time ML Anomaly Flow Scorer")
    st.write("Input custom flow telemetry to evaluate continuous anomaly scores and feature contributions.")

    test_c1, test_c2, test_c3, test_c4 = st.columns(4)
    with test_c1:
        test_packets = st.number_input("Packet Count", min_value=1, max_value=100000, value=120)
    with test_c2:
        test_port = st.number_input("Destination Port", min_value=1, max_value=65535, value=443)
    with test_c3:
        test_proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
    with test_c4:
        test_action = st.selectbox("Connection Action", ["Allowed", "Blocked"])

    if st.button("Calculate ML Anomaly Score"):
        flow_record = {
            "Packets": test_packets,
            "Port": test_port,
            "Protocol": test_proto,
            "Action": test_action,
            "Source IP": "192.168.1.55"
        }
        score_res = ml_engine.predict_score(flow_record)
        st.write(f"**ML Prediction:** `{'ANOMALY' if score_res['is_anomaly'] else 'NOMINAL INLIER'}`")
        st.write(f"**Raw Decision Function Score:** `{score_res['raw_score']}`")
        st.write(f"**Normalized Anomaly Confidence:** `{score_res['confidence']*100:.1f}%`")
        st.info(score_res["disclaimer"])

# ------------------------------------------------------------------------------
# TAB 4: AI COPILOT & THREAT EXPLAINER
# ------------------------------------------------------------------------------
with tabs[3]:
    st.subheader("🤖 SentinelAI Threat Copilot & Root-Cause Explainer")
    st.write("Comprehensive LLM threat reasoning powered by Google Gemini with deterministic local fallbacks.")

    all_incs = db.get_incidents()
    if not all_incs:
        st.info("No active incidents to analyze.")
    else:
        inc_map = {f"[{i['severity']}] {i['incident_id']} - {i['category']} ({i['source_ip']})": i for i in all_incs}
        selected_label = st.selectbox("Select Incident for AI Deep-Dive", list(inc_map.keys()))
        target_inc = inc_map[selected_label]

        # Call explainerAI with full incident memory
        exp = explainer.explain_incident(target_inc)

        # Provider attribution
        provider_badge = "🟢 Google Gemini GenAI" if exp["provider"] == "google_gemini" else "🟡 Deterministic Rule-Based Fallback"
        st.caption(f"Analysis Engine: **{provider_badge}** | {exp['ai_disclaimer']}")
        st.warning(f"🛡️ **AI Safety Policy:** {exp.get('ai_safety_notice', 'AI suggestions are advisory only and cannot trigger firewall actions.')}")

        col_a1, col_a2 = st.columns([1, 1])

        with col_a1:
            st.markdown("### 📋 Executive Summary")
            st.write(exp["summary"])

            st.markdown("### 🔎 1. Observed Network Facts")
            st.json(exp.get("observed_facts", {}))

            st.markdown("### 📊 2. Model Predictions & Anomaly Scores")
            st.json(exp.get("model_predictions", {}))

            st.markdown("### 🎯 3. Threat Hypotheses & Scenarios")
            st.write(exp.get("threat_hypotheses", "Hypothesis: External reconnaissance against administrative endpoints."))

            st.markdown("### ⚙️ Technical Attack Mechanism")
            st.write(exp["mechanism"])

            st.markdown(f"**MITRE ATT&CK Mapping:** `{exp['mitre_technique']}`")

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
                                f"Provide concise, actionable cybersecurity advice. Note: IP does not prove identity."
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
# TAB 5: ACTIVE CONTAINMENT & EXPIRY WATCHDOG
# ------------------------------------------------------------------------------
with tabs[4]:
    st.subheader("🛡️ Active Containment Rules & Expiry Watchdog")
    st.write("Monitor active temporary and permanent blocks, track rule expiration, execute reversible rollbacks, and inspect allowlists.")

    # Check expired blocks
    expired = db.check_and_expire_blocks()
    if expired:
        st.info(f"Watchdog auto-expired {len(expired)} temporary rule(s).")

    active_blocks = db.get_active_blocks()
    if active_blocks:
        st.markdown("### 📋 Tracked Firewall Block Policies")
        block_df = pd.DataFrame([{
            "Block ID": b["block_id"],
            "Target IP": b["target_ip"],
            "Rule Type": b["rule_type"],
            "Duration": f"{b.get('duration_minutes', 'Permanent')} min" if b["rule_type"] == "Temporary" else "Permanent",
            "Created At": b["created_at"],
            "Expires At": b.get("expires_at") or "Never",
            "Status": b["status"],
            "Approval": b["approval_status"],
            "Approved By": b.get("approved_by", "N/A"),
            "Verification": b["verification_status"]
        } for b in active_blocks])
        st.dataframe(block_df, use_container_width=True, hide_index=True)

        st.markdown("#### 🔄 Execute Manual Containment Rollback")
        roll_ids = [b["block_id"] for b in active_blocks if b["status"] == "Active"]
        if roll_ids:
            target_roll = st.selectbox("Select Block ID to Rollback / Unblock", roll_ids)
            if st.button("Roll Back Selected Block", type="secondary"):
                res = db.rollback_block(block_id=target_roll, operator="SOC Lead Admin")
                st.success(f"Block rule {target_roll} rolled back successfully!")
                st.rerun()
        else:
            st.info("Zero active temporary blocks requiring rollback.")
    else:
        st.info("No active containment blocks recorded in the database.")

    st.divider()
    st.subheader("🛡️ Core Protected Infrastructure Allowlist")
    st.write("These IP addresses and subnets are strictly protected from accidental or automated containment:")
    st.code(", ".join(sorted(list(DEFAULT_PROTECTED_IPS))), language="text")

# ------------------------------------------------------------------------------
# TAB 6: TELEMETRY INGESTION & LOG FILE PARSER
# ------------------------------------------------------------------------------
with tabs[5]:
    st.subheader("📁 Structured Log File Ingestion & Parser")
    st.write("Upload Suricata EVE JSON or custom CSV security logs to extract, detect, and store incidents.")

    col_u1, col_u2 = st.columns([1, 1])

    with col_u1:
        st.markdown("### 📥 Built-in Pre-Configured Test Datasets")
        st.caption("Select a simulated lab scenario to test the detection engine and ML pipeline:")
        sample_choice = st.selectbox(
            "Select Scenario Sample",
            [
                "Suricata EVE JSON (73-record Audit Dataset)",
                "Port Scan Attack (attack_port_scan.json)",
                "Brute Force Attack (attack_brute_force.json)",
                "DDoS Volumetric Flood (attack_ddos_flood.json)",
                "Normal Nominal Traffic (normal_traffic.csv)",
                "Malformed & Edge Cases (malformed_records.json)"
            ]
        )

        if st.button("Parse & Ingest Selected Dataset", type="primary"):
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            file_map = {
                "Suricata EVE JSON (73-record Audit Dataset)": os.path.join(data_dir, "sentinelai_suricata_eve_sample.json"),
                "Port Scan Attack (attack_port_scan.json)": os.path.join(data_dir, "attack_port_scan.json"),
                "Brute Force Attack (attack_brute_force.json)": os.path.join(data_dir, "attack_brute_force.json"),
                "DDoS Volumetric Flood (attack_ddos_flood.json)": os.path.join(data_dir, "attack_ddos_flood.json"),
                "Normal Nominal Traffic (normal_traffic.csv)": os.path.join(data_dir, "normal_traffic.csv"),
                "Malformed & Edge Cases (malformed_records.json)": os.path.join(data_dir, "malformed_records.json"),
            }

            target_file = file_map.get(sample_choice)
            if target_file and os.path.exists(target_file):
                if target_file.endswith(".csv"):
                    df_ingest = pd.read_csv(target_file)
                else:
                    with open(target_file, "r", encoding="utf-8") as f:
                        raw_content = f.read()
                    if "suricata" in target_file:
                        events, errors = LogParser.parse_suricata_eve(raw_content)
                    else:
                        events, errors = LogParser.parse_generic_json(raw_content)
                    df_ingest = LogParser.events_to_dataframe(events)

                st.session_state["ingested_df"] = df_ingest
                st.success(f"Successfully parsed {len(df_ingest)} telemetry records!")
            else:
                st.error("Sample dataset file not found.")

    with col_u2:
        st.markdown("### 📤 Upload Custom Security Logs")
        uploaded_file = st.file_uploader("Upload JSON / CSV Log Stream", type=["json", "csv"])
        if uploaded_file is not None:
            if uploaded_file.name.endswith(".csv"):
                df_custom = pd.read_csv(uploaded_file)
            else:
                raw_text = uploaded_file.read().decode("utf-8")
                events, errors = LogParser.parse_generic_json(raw_text)
                df_custom = LogParser.events_to_dataframe(events)
            st.session_state["ingested_df"] = df_custom
            st.success(f"Custom file loaded: {len(df_custom)} records.")

    if "ingested_df" in st.session_state:
        st.divider()
        st.subheader("🔍 Ingested Telemetry Preview & Incident Correlation")
        raw_df = st.session_state["ingested_df"]

        # Detect with hybrid engine
        enriched_df = detector.detect_dataframe(raw_df)
        correlated_incs = detector.correlate_incidents(raw_df)

        st.dataframe(enriched_df.head(20), use_container_width=True)

        st.markdown(f"**Engine Output:** Discovered **{len(correlated_incs)}** security incident(s) from this telemetry stream.")
        if st.button("Commit Correlated Incidents to Sentinel Database"):
            for inc in correlated_incs:
                db.save_incident(inc.to_dict())
            st.success(f"Committed {len(correlated_incs)} incidents to SQLite database.")
            st.rerun()

# ------------------------------------------------------------------------------
# TAB 7: LIVE MONITORING SIMULATOR
# ------------------------------------------------------------------------------
with tabs[6]:
    st.subheader("📡 Real-Time Telemetry Stream Simulator")
    st.write("Generate synthetic live background enterprise telemetry with controllable laboratory scenario injection.")
    st.warning("⚠️ **Notice:** This simulator runs in a defensive sandbox and does not transmit network packets or affect physical network adapters.")

    col_s1, col_s2, col_s3 = st.columns(3)
    with col_s1:
        if st.button("▶️ Start Live Stream (10 Events)"):
            live_sim.start(interval_seconds=0.1)
            import time
            time.sleep(1.2)
            live_sim.stop()
            st.rerun()
    with col_s2:
        if st.button("💉 Inject Scenario: Port Scan Probing"):
            live_sim.inject_attack("port_scan")
            st.success("Scenario injected: 6 port scan probes emitted.")
            st.rerun()
    with col_s3:
        if st.button("💉 Inject Scenario: SSH Brute Force"):
            live_sim.inject_attack("brute_force")
            st.success("Scenario injected: 5 SSH auth failures emitted.")
            st.rerun()

    live_events = live_sim.get_recent_events(limit=30)
    if live_events:
        st.markdown("### Live Stream Telemetry Buffer")
        st.dataframe(pd.DataFrame(live_events), use_container_width=True)
    else:
        st.info("Live stream buffer empty. Click Start Live Stream to emit events.")

# ------------------------------------------------------------------------------
# TAB 8: AUDIT TRAIL
# ------------------------------------------------------------------------------
with tabs[7]:
    st.subheader("📜 SOC Response Audit Trail & Compliance Ledger")
    st.write("Immutable SQLite audit log documenting status transitions, defensive containment scripts, analyst verdicts, and data retention.")

    audit_records = db.get_audit_logs(limit=100)
    if audit_records:
        df_audit = pd.DataFrame(audit_records)
        st.dataframe(df_audit, use_container_width=True, hide_index=True)
    else:
        st.info("No audit logs recorded.")