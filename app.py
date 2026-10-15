# main dahboard
import os
import streamlit as st
import pandas as pd
import plotly.express as px

# Import backend modules
from detector import ThreatDetector, get_detector
from analyzer import TrafficAnalyzer, get_analyzer
from explainerAI import ThreatExplainer, get_explainer
from response_enigne import ResponseEngine, get_response_engine

# Page configuration
st.set_page_config(
    page_title="SentinelAI - Threat Detection & Response",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize backend engine instances
detector = get_detector()
analyzer = get_analyzer()
explainer = get_explainer()
response_engine = get_response_engine()

# Custom CSS for polished styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1E293B;
        padding: 18px;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        color: white;
    }
    .badge-critical {
        background-color: #DC2626;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #EA580C;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #D97706;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
    }
    .badge-low {
        background-color: #16A34A;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar controls
st.sidebar.title("🛡️ SentinelAI Controls")
st.sidebar.markdown("Configure traffic stream and detection sensitivity.")

data_source = st.sidebar.radio(
    "Data Source",
    ["Loaded Dataset (sample_traafic.csv)", "Built-in Demo Snapshot", "Upload Custom CSV"]
)

raw_df = None
if data_source == "Loaded Dataset (sample_traafic.csv)":
    csv_path = os.path.join(os.path.dirname(__file__), "sample_traafic.csv")
    if os.path.exists(csv_path):
        raw_df = pd.read_csv(csv_path)
    else:
        st.sidebar.warning("sample_traafic.csv not found, using fallback data.")
elif data_source == "Upload Custom CSV":
    uploaded = st.sidebar.file_uploader("Upload Network CSV", type=["csv"])
    if uploaded is not None:
        raw_df = pd.read_csv(uploaded)

if raw_df is None:
    # Default built-in security data fallback
    raw_df = pd.DataFrame({
        "Time": ["10:00:01", "10:00:05", "10:00:10", "10:00:15", "10:00:20"],
        "Source IP": ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.15", "192.168.1.25"],
        "Activity": ["Normal Traffic", "Port Scan", "Normal Traffic", "Brute Force", "Normal Traffic"],
        "Risk": ["Low", "High", "Low", "High", "Low"],
        "Packets": [120, 450, 150, 380, 100],
        "Port": [443, 80, 53, 22, 80]
    })

# Run backend threat detection pipeline
processed_df = detector.detect_dataframe(raw_df)

# Sidebar risk filter
risk_filter = st.sidebar.multiselect(
    "Filter by Risk Level",
    options=["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"]
)

filtered_df = processed_df[processed_df["Risk"].isin(risk_filter)]

# Run backend traffic analytics
analytics = analyzer.analyze_traffic(processed_df)

# Dashboard header
col_head1, col_head2 = st.columns([4, 1])
with col_head1:
    st.title("🛡️ SentinelAI")
    st.subheader("AI-Powered Network Threat Detection & Response")
    st.write("Autonomous telemetry monitoring, behavioral anomaly detection, and automated SOC response playbooks.")
with col_head2:
    st.markdown("<br>", unsafe_allow_html=True)
    status_label = analytics["overall_risk_label"]
    badge_color = "#DC2626" if status_label in ["Critical", "High"] else "#16A34A"
    st.markdown(
        f"<div style='background-color:{badge_color}; padding:10px; border-radius:8px; text-align:center; color:white; font-weight:bold;'>"
        f"DEFCON RISK: {status_label.upper()}</div>",
        unsafe_allow_html=True
    )

# Executive AI Briefing
exec_summary = explainer.generate_executive_summary(processed_df)
st.info(f"**🤖 AI Threat Intelligence Briefing:** {exec_summary}")

# Dashboard metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Monitored Flows", analytics["total_records"])
col2.metric("Total Packets", f"{analytics['total_packets']:,}")
col3.metric("High & Critical Alerts", analytics["high_risk_count"] + analytics["critical_risk_count"])
col4.metric("Risk Index Score", f"{analytics['overall_risk_score']} / 100")

st.divider()

# Traffic visualization
st.subheader("📊 Network Traffic Overview")
tab_chart1, tab_chart2 = st.tabs(["Packet Volume Timeline", "Source IP Distribution"])

with tab_chart1:
    if "Time" in filtered_df.columns and not filtered_df.empty:
        fig = px.line(
            filtered_df,
            x="Time",
            y="Packets",
            color="Risk",
            color_discrete_map={"Low": "#10B981", "Medium": "#F59E0B", "High": "#EF4444", "Critical": "#7F1D1D"},
            markers=True,
            hover_data=["Source IP", "Activity"],
            title="Telemetry Packet Rate Over Time"
        )
        fig.update_layout(template="plotly_dark", height=380)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available for current selection.")

with tab_chart2:
    if "Source IP" in filtered_df.columns and not filtered_df.empty:
        ip_summary = filtered_df.groupby("Source IP")["Packets"].sum().reset_index()
        fig_bar = px.bar(
            ip_summary,
            x="Source IP",
            y="Packets",
            title="Aggregated Packet Volume by Host",
            color="Packets",
            color_continuous_scale="Reds"
        )
        fig_bar.update_layout(template="plotly_dark", height=380)
        st.plotly_chart(fig_bar, use_container_width=True)

# Security alerts
st.subheader("🚨 Security Alerts & Detections")
threat_alerts = filtered_df[filtered_df["Risk"].isin(["Critical", "High", "Medium"])]

if threat_alerts.empty:
    st.success("No active security threats identified for the selected filter.")
else:
    display_cols = [c for c in ["Time", "Source IP", "Activity", "Risk", "Packets", "Confidence", "Threat Details"] if c in threat_alerts.columns]
    st.dataframe(
        threat_alerts[display_cols],
        use_container_width=True,
        hide_index=True
    )

st.divider()

# AI threat explanation and automated incident response
st.subheader("🤖 Threat Explanation & Automated Response Playbooks")

if threat_alerts.empty:
    st.write("All hosts are currently operating normally.")
else:
    for idx, row in threat_alerts.iterrows():
        act = row["Activity"]
        src = row["Source IP"]
        pkts = int(row["Packets"])
        risk = row["Risk"]
        details = row.get("Threat Details", "")

        # Call explainerAI and response_enigne backend modules
        explanation = explainer.explain_threat(act, src, pkts, risk, details)
        mitigation = response_engine.get_mitigation_plan(act, src, risk)

        with st.expander(f"⚠️ [{risk}] {act} — Source: {src} ({pkts} packets)"):
            col_exp1, col_exp2 = st.columns([1, 1])

            with col_exp1:
                st.markdown(f"#### 🔍 AI Threat Analysis")
                st.write(explanation["summary"])
                st.markdown(f"**Mechanism:** {explanation['mechanism']}")
                st.markdown(f"**Potential Impact:** {explanation['potential_impact']}")
                st.markdown(f"**MITRE ATT&CK:** `{explanation['mitre_technique']}`")
                st.info(f"💡 **Recommended Analyst Focus:** {explanation['recommended_focus']}")

            with col_exp2:
                st.markdown(f"#### 🛡️ Automated Response & Containment")
                st.markdown(f"**Priority:** `{mitigation['priority']}` | **Policy:** `{mitigation['recommended_policy']}`")
                st.markdown("**Incident Response Playbook Actions:**")
                for step in mitigation["action_steps"]:
                    st.markdown(f"- {step}")

                st.markdown("**Firewall Isolation Commands:**")
                fw_tabs = st.tabs(["PowerShell", "Linux iptables", "Cisco ACL"])
                with fw_tabs[0]:
                    st.code(mitigation["firewall_commands"]["Windows PowerShell"], language="powershell")
                with fw_tabs[1]:
                    st.code(mitigation["firewall_commands"]["Linux iptables"], language="bash")
                with fw_tabs[2]:
                    st.code(mitigation["firewall_commands"]["Cisco IOS ACL"], language="text")

st.caption("SentinelAI v2.0 | Integrated Threat Detection, Analysis, Explanation & Response")