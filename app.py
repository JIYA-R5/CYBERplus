"""
SentinelAI - Your Security Assistant
Simple by default. Technical details on demand.
Understand suspicious activity and decide what to do next.
"""

import os
import datetime
from typing import Dict, Any, List, Optional
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

# Ensure local environment (.env.local / .env) is loaded directly
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.isfile(os.path.join(_BASE_DIR, ".env")):
    load_dotenv(os.path.join(_BASE_DIR, ".env"), override=False)
if os.path.isfile(os.path.join(_BASE_DIR, ".env.local")):
    load_dotenv(os.path.join(_BASE_DIR, ".env.local"), override=True)
load_dotenv()

# Backend engine modules
from detector import ThreatDetector, get_detector, Incident
from analyzer import TrafficAnalyzer, get_analyzer
from explainerAI import ThreatExplainer, get_explainer
from response_engine import ResponseEngine, get_response_engine, sanitize_ip, is_ip_allowlisted, DEFAULT_PROTECTED_IPS
from database import DatabaseManager, get_db, IDENTITY_DISCLAIMER
from log_parser import LogParser
from live_monitor import LiveMonitoringSimulator, get_live_simulator
from ml_engine import get_ml_engine, MLAnomalyEngine

# ------------------------------------------------------------------------------
# PAGE CONFIGURATION (Light theme by default)
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelAI — Your Security Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize backend singletons
detector = get_detector()
analyzer = get_analyzer()
explainer = get_explainer()
response_engine = get_response_engine()
db = get_db()
live_sim = get_live_simulator()
ml_engine = get_ml_engine()

# Ensure baseline demo data exists if database is brand new
if not db.get_incidents():
    db.reset_demo_data()

# ------------------------------------------------------------------------------
# CENTRALIZED LIGHT THEME CSS TOKENS
# ------------------------------------------------------------------------------
st.markdown("""
<style>
    /* SentinelAI Approachable Light Theme */
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

    .stApp {
        background-color: #F4F7FB;
        color: #172B4D;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Clean Card Container */
    .sa-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }

    /* Metric Stat Box */
    .sa-stat-box {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 12px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
    }
    .sa-stat-label {
        font-size: 0.82rem;
        font-weight: 600;
        color: #667085;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }
    .sa-stat-val {
        font-size: 1.85rem;
        font-weight: 700;
        color: #172B4D;
        line-height: 1.2;
    }
    .sa-stat-sub {
        font-size: 0.85rem;
        color: #667085;
        margin-top: 4px;
    }

    /* Sensor Status Banner */
    .sa-sensor-banner {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #2457A7;
        border-radius: 8px;
        padding: 14px 20px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Badges */
    .sa-badge {
        display: inline-block;
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 600;
    }
    .sa-badge-danger {
        background-color: #FEE2E2;
        color: #C0392B;
        border: 1px solid #FCA5A5;
    }
    .sa-badge-warning {
        background-color: #FEF3C7;
        color: #B7791F;
        border: 1px solid #FCD34D;
    }
    .sa-badge-success {
        background-color: #D1FAE5;
        color: #16835D;
        border: 1px solid #6EE7B7;
    }
    .sa-badge-neutral {
        background-color: #F1F5F9;
        color: #667085;
        border: 1px solid #E2E8F0;
    }
    .sa-badge-accent {
        background-color: #E0E7FF;
        color: #2457A7;
        border: 1px solid #C7D2FE;
    }

    /* Action Recommendation Card */
    .sa-recommendation {
        background-color: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 16px 0;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        border-bottom: 2px solid #E2E8F0;
        margin-bottom: 20px;
    }
    .stTabs [data-baseweb="tab"],
    .stTabs [data-baseweb="tab"] *,
    .stTabs [data-baseweb="tab"] p,
    .stTabs [data-baseweb="tab"] span {
        padding: 6px 12px;
        font-weight: 600 !important;
        font-size: 0.95rem;
        color: #172B4D !important;
        border-radius: 6px 6px 0 0;
    }
    .stTabs [aria-selected="true"],
    .stTabs [aria-selected="true"] *,
    .stTabs [aria-selected="true"] p {
        color: #2457A7 !important;
        font-weight: 700 !important;
        border-bottom: 3px solid #2457A7 !important;
    }

    /* Universal Dark Text for All Widget Labels & Inputs */
    div[data-testid="stWidgetLabel"],
    div[data-testid="stWidgetLabel"] *,
    label[data-testid="stWidgetLabel"] * {
        color: #172B4D !important;
        font-weight: 600 !important;
    }

    /* Radio button options and labels */
    div[data-testid="stRadio"],
    div[data-testid="stRadio"] *,
    div[data-testid="stRadio"] label,
    div[data-testid="stRadio"] p,
    div[data-testid="stRadio"] span,
    div[data-testid="stRadio"] div,
    div[data-testid="stRadio"] [data-testid="stMarkdownContainer"] p,
    div[data-baseweb="radio"],
    div[data-baseweb="radio"] *,
    div[data-baseweb="radio"] div,
    div[data-baseweb="radio"] span,
    div[data-baseweb="radio"] label {
        color: #172B4D !important;
        font-weight: 500 !important;
    }

    /* Slider labels, numbers, and tick values */
    div[data-testid="stSlider"],
    div[data-testid="stSlider"] *,
    div[data-testid="stSlider"] label,
    div[data-testid="stSlider"] p,
    div[data-testid="stSlider"] div,
    div[data-testid="stSlider"] span {
        color: #172B4D !important;
        font-weight: 500 !important;
    }

    /* Selectbox dropdown text */
    div[data-testid="stSelectbox"] *,
    div[data-baseweb="select"] * {
        color: #172B4D !important;
    }

    /* General headings and paragraphs */
    .stMarkdown, .stMarkdown *, p, span, li {
        color: #172B4D;
    }
    .stCaption, [data-testid="stCaptionContainer"] p {
        color: #667085 !important;
    }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# PLAIN-ENGLISH HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def get_plain_english_title(category: str) -> str:
    """Translate technical attack classifications into friendly, clear titles."""
    titles = {
        "Port Scan": "Network Port Scanning",
        "Brute Force": "Repeated Login Attempts",
        "Traffic Burst": "Rapid Web Request Surge",
        "DDoS Surge": "High-Volume Traffic Surge",
        "Volumetric DDoS": "High-Volume Traffic Surge",
        "Data Exfiltration": "Unusual Outbound Data Transfer",
        "Suspicious Reconnaissance": "Network Reconnaissance Activity",
        "High Volume Anomaly": "Unusual High-Volume Flow"
    }
    return titles.get(category, category)


def get_plain_english_summary(incident: Dict[str, Any]) -> str:
    """Generate a friendly one-sentence summary for non-technical users."""
    category = incident.get("category", "")
    src = incident.get("source_ip", "A remote device")
    dst = incident.get("destination_ip", "your network")
    ports = incident.get("destination_ports", [])
    count = incident.get("event_count", 1)

    if category == "Port Scan":
        return f"{src} probed {len(ports)} different network ports in a short time to look for open services."
    elif category == "Brute Force":
        return f"{src} repeatedly attempted to log into an administrative service on port {ports[0] if ports else 22}."
    elif category == "Traffic Burst":
        return f"{src} sent a rapid burst of connection requests to a web service, creating temporary load."
    elif category in ("DDoS Surge", "Volumetric DDoS"):
        return f"A high volume of data packets was directed toward {dst}, which could overwhelm connection capacity."
    elif category == "Data Exfiltration":
        return f"An unusually large amount of data was transmitted from {dst} to external address {src}."
    elif category == "Suspicious Reconnaissance":
        return f"{src} was observed scanning multiple addresses to map out connected devices."
    return f"Suspicious network pattern ({category}) observed between {src} and {dst}."


def get_plain_english_breakdown(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Structure incident explanation into the 5 core questions."""
    category = incident.get("category", "Suspicious Activity")
    src = incident.get("source_ip", "Unknown host")
    dst = incident.get("destination_ip", "Internal system")
    ports = incident.get("destination_ports", [])
    packets = incident.get("total_packets", 0)
    evidence = incident.get("evidence", "")
    rec_cnt = incident.get("recurrence_count", 1)

    # 1. What happened?
    if category == "Port Scan":
        what_happened = (
            f"The device at {src} attempted to contact {len(ports)} different network ports on your systems "
            f"within a few seconds. In normal operation, devices usually communicate over just one or two specific ports."
        )
    elif category == "Brute Force":
        what_happened = (
            f"The device at {src} made repeated, rapid connection or login attempts against port(s) {ports}. "
            f"This behavior is characteristic of an automated script guessing passwords."
        )
    elif category == "Traffic Burst":
        what_happened = (
            f"A concentrated burst of connection requests was sent to port(s) {ports} on {dst}, "
            f"causing a sudden spike in traffic volume."
        )
    elif category in ("DDoS Surge", "Volumetric DDoS"):
        what_happened = (
            f"A flood of {packets:,} packets was directed toward {dst}. "
            f"This volume significantly exceeds normal operating baselines."
        )
    else:
        what_happened = f"The sensor detected unusual network communication ({category}) from {src} to {dst} involving {packets:,} packets."

    # 2. Why might it matter?
    if category == "Port Scan":
        why_matters = (
            "Port scanning is often a preparatory step where an attacker searches for unpatched or poorly protected services. "
            "If vulnerable ports are exposed, they may attempt an unauthorized connection."
        )
    elif category == "Brute Force":
        why_matters = (
            "If an automated password-guessing tool is allowed to continue unchecked, it could eventually discover weak "
            "or default credentials, granting unauthorized access to your system."
        )
    elif category == "Traffic Burst":
        why_matters = (
            "Even brief traffic spikes can slow down web applications, tie up server worker threads, or lead to temporary timeouts for legitimate users."
        )
    elif category in ("DDoS Surge", "Volumetric DDoS"):
        why_matters = (
            "Extreme packet volumes can saturate internet bandwidth and take critical services offline, resulting in downtime."
        )
    else:
        why_matters = "Unusual traffic patterns can indicate security breaches, misconfigurations, or automated bots operating without authorization."

    # 3. What evidence supports this assessment?
    evidence_points = [
        f"Factual network telemetry: {packets:,} total packets recorded to port(s) {ports}.",
        f"Automated detection observation: {evidence}",
        f"Historical recurrence: This address has been observed {rec_cnt} time(s) across recorded incident memory."
    ]

    # 4. What remains uncertain?
    uncertainties = [
        "Network IP addresses identify routing endpoints; an IP address does not prove human identity.",
        "Legitimate activity—such as an employee mistyping a password, an authorized vulnerability scan, or a network backup—can produce similar traffic.",
        "Statistical anomaly scores measure deviation from past baselines and are NOT proof of a malicious attack."
    ]

    # 5. What should I do next?
    next_steps = [
        f"Verify whether {src} belongs to an authorized internal computer, a known remote employee, or an approved automated service.",
        "If the address is unrecognized, consider staging a simulated quarantine block in the Protection tab.",
        "Mark an analyst review verdict (True Positive, False Alarm, or Benign) to help train the system's baseline safely."
    ]

    return {
        "what_happened": what_happened,
        "why_matters": why_matters,
        "evidence_points": evidence_points,
        "uncertainties": uncertainties,
        "next_steps": next_steps
    }


def get_sensor_status_info() -> Dict[str, str]:
    """Determine unmistakable real-time sensor connection status."""
    if live_sim and live_sim.is_running:
        return {
            "title": "Live Telemetry Simulator Active",
            "badge": "Live Simulation Active",
            "badge_class": "sa-badge-success",
            "desc": "Simulating multi-protocol enterprise network flows in an isolated defensive lab.",
            "is_demo": True
        }

    if "ingested_df" in st.session_state and not st.session_state["ingested_df"].empty:
        source_name = st.session_state.get("data_source_name", "Uploaded Security Log")
        return {
            "title": f"Analyzed File: {source_name}",
            "badge": "Uploaded Data",
            "badge_class": "sa-badge-accent",
            "desc": f"Viewing security analysis computed from {len(st.session_state['ingested_df'])} ingested telemetry records.",
            "is_demo": False
        }

    incidents = db.get_incidents()
    if incidents:
        return {
            "title": "Demo Laboratory Simulation",
            "badge": "Demo Simulation",
            "badge_class": "sa-badge-warning",
            "desc": "Viewing pre-configured laboratory demo scenario. Not connected to a real physical network interface.",
            "is_demo": True
        }

    return {
        "title": "No Telemetry Connected",
        "badge": "No Telemetry Connected",
        "badge_class": "sa-badge-neutral",
        "desc": "The security sensor is idle. Upload a security log or load a sample scenario to begin.",
        "is_demo": False
    }


# ------------------------------------------------------------------------------
# SIDEBAR: ASSISTANT CONTROLS & ENVIRONMENT STATUS
# ------------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ SentinelAI")
st.sidebar.caption("Defensive Security Assistant")

sensor_info = get_sensor_status_info()
st.sidebar.markdown(f"**Sensor Status:** <span class='sa-badge {sensor_info['badge_class']}'>{sensor_info['badge']}</span>", unsafe_allow_html=True)

# Protection Mode Card
st.sidebar.markdown("---")
st.sidebar.markdown("### 🔒 Protection Guardrail")
st.sidebar.info(
    "**Simulation Mode Active (Safe)**\n\n"
    "All firewall containment recommendations are simulated without modifying your operating system or physical network."
)

# AI Copilot Engine
ai_engine_name = "Google Gemini Live AI" if explainer.is_gemini_active else "Local Fallback Rules"
ai_engine_badge = "sa-badge-success" if explainer.is_gemini_active else "sa-badge-neutral"
st.sidebar.markdown(f"**AI Engine:** <span class='sa-badge {ai_engine_badge}'>{ai_engine_name}</span>", unsafe_allow_html=True)

# Quick Demo Reset
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Reset Demo Scenario", use_container_width=True):
    db.reset_demo_data()
    st.session_state.pop("ingested_df", None)
    st.sidebar.success("Reset database to baseline sample events.")
    st.rerun()

st.sidebar.caption(IDENTITY_DISCLAIMER)


# ------------------------------------------------------------------------------
# MAIN APPLICATION DESTINATIONS (4 Core Pages + Advanced Tools)
# ------------------------------------------------------------------------------
tab_home, tab_threats, tab_protection, tab_activity, tab_advanced = st.tabs([
    "🏠 Home",
    "⚠️ Threats",
    "🛡️ Protection",
    "📋 Activity",
    "⚙️ Advanced Tools"
])


# ==============================================================================
# 1. HOME SCREEN: Calm, Clear Overview
# ==============================================================================
with tab_home:
    col_title, col_status = st.columns([3, 1])
    with col_title:
        st.title("SentinelAI — Your Security Assistant")
        st.write("Understand suspicious activity and decide what to do next.")
    with col_status:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            f"<div style='text-align: right;'><span class='sa-badge {sensor_info['badge_class']}' style='font-size:0.95rem; padding:6px 12px;'>"
            f"{sensor_info['badge']}</span></div>",
            unsafe_allow_html=True
        )

    # Unmistakable Monitoring Status Banner
    st.markdown(f"""
    <div class="sa-sensor-banner">
        <div>
            <strong>Sensor Connection: {sensor_info['title']}</strong><br>
            <span style="color:#667085; font-size:0.9rem;">{sensor_info['desc']}</span>
        </div>
        <span class="sa-badge {sensor_info['badge_class']}">{sensor_info['badge']}</span>
    </div>
    """, unsafe_allow_html=True)

    # Actual Database State Calculation
    all_incidents = db.get_incidents()
    unreviewed_count = sum(1 for i in all_incidents if i.get("analyst_verdict") in ("Unreviewed", None))
    confirmed_count = sum(1 for i in all_incidents if i.get("analyst_verdict") == "True Positive")
    active_blocks = db.get_active_blocks()
    active_block_count = sum(1 for b in active_blocks if b.get("status") == "Active")

    # 4 Simple Stat Cards
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="sa-stat-box">
            <div class="sa-stat-label">Threats Needing Review</div>
            <div class="sa-stat-val" style="color: {'#C0392B' if unreviewed_count > 0 else '#16835D'};">{unreviewed_count}</div>
            <div class="sa-stat-sub">{'Suspicious items awaiting decision' if unreviewed_count > 0 else 'All items reviewed'}</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
        <div class="sa-stat-box">
            <div class="sa-stat-label">Confirmed Threats</div>
            <div class="sa-stat-val" style="color: #2457A7;">{confirmed_count}</div>
            <div class="sa-stat-sub">Verified real incidents</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
        <div class="sa-stat-box">
            <div class="sa-stat-label">Protection Rules</div>
            <div class="sa-stat-val" style="color: #B7791F;">{active_block_count}</div>
            <div class="sa-stat-sub">Active simulated blocks</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="sa-stat-box">
            <div class="sa-stat-label">Protection Mode</div>
            <div class="sa-stat-val" style="font-size: 1.35rem; color: #16835D;">Simulated</div>
            <div class="sa-stat-sub">Safe dry-run enforcement</div>
        </div>
        """, unsafe_allow_html=True)

    # One Clear Recommended Next Step
    st.markdown("### 💡 Recommended Next Step")
    if unreviewed_count > 0:
        high_sev_unreviewed = [i for i in all_incidents if i.get("severity") in ("Critical", "High") and i.get("analyst_verdict") in ("Unreviewed", None)]
        if high_sev_unreviewed:
            target_inc = high_sev_unreviewed[0]
            st.markdown(f"""
            <div class="sa-recommendation">
                <strong>👉 Action Needed: Review {get_plain_english_title(target_inc['category'])} from {target_inc['source_ip']}</strong><br>
                <span style="color:#667085; font-size:0.9rem;">
                    This activity was flagged as high priority. Go to the <strong>Threats</strong> tab to read a plain-English breakdown and decide whether to confirm it or dismiss it as a false alarm.
                </span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="sa-recommendation">
                <strong>👉 Action Recommended: Review {unreviewed_count} pending lower-priority items.</strong><br>
                <span style="color:#667085; font-size:0.9rem;">
                    Open the <strong>Threats</strong> tab to inspect the pending items when you have a moment.
                </span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="sa-recommendation" style="background:#F0FDF4; border-color:#BBF7D0;">
            <strong style="color:#16835D;">✅ All Clear: No threats currently need review.</strong><br>
            <span style="color:#667085; font-size:0.9rem;">
                All monitored network activity is within expected baselines. No action is required.
            </span>
        </div>
        """, unsafe_allow_html=True)

    # Short Recent-Activity Summary List
    st.markdown("### 🕒 Recent Activity")
    audit_trail = db.get_audit_logs(limit=4)
    if audit_trail:
        for a in audit_trail:
            st.markdown(f"""
            <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; padding:10px 16px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <strong>{a['action_type'].replace('_', ' ').title()}</strong>
                    <span style="color:#667085; font-size:0.85rem; margin-left:8px;">Target: <code>{a['target_ip']}</code></span>
                </div>
                <div style="color:#667085; font-size:0.82rem;">{a['timestamp']}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No recorded activity yet.")


# ==============================================================================
# 2. THREATS PAGE: Approachable Threat Triage (5 Questions)
# ==============================================================================
with tab_threats:
    st.subheader("⚠️ Suspicious Activity & Threats")
    st.write("Review detected activity, understand what happened in plain English, and choose what action to take.")

    incidents = db.get_incidents()

    if not incidents:
        st.info("No security threats currently recorded in the database.")
    else:
        # Search & Filter
        col_flt1, col_flt2, col_flt3 = st.columns([2, 2, 4])
        with col_flt1:
            severity_filter = st.selectbox("Filter Priority", ["All Priorities", "High & Critical", "Medium & Low"])
        with col_flt2:
            verdict_filter = st.selectbox("Review Status", ["All Statuses", "Needs Review", "Confirmed Threats", "False Alarms", "Safe / Benign"])
        with col_flt3:
            search_query = st.text_input("🔍 Search by IP address, title, or ID", "")

        # Apply filtering
        filtered = incidents
        if severity_filter == "High & Critical":
            filtered = [i for i in filtered if i.get("severity") in ("Critical", "High")]
        elif severity_filter == "Medium & Low":
            filtered = [i for i in filtered if i.get("severity") in ("Medium", "Low")]

        if verdict_filter == "Needs Review":
            filtered = [i for i in filtered if i.get("analyst_verdict") in ("Unreviewed", None)]
        elif verdict_filter == "Confirmed Threats":
            filtered = [i for i in filtered if i.get("analyst_verdict") == "True Positive"]
        elif verdict_filter == "False Alarms":
            filtered = [i for i in filtered if i.get("analyst_verdict") == "False Positive"]
        elif verdict_filter == "Safe / Benign":
            filtered = [i for i in filtered if i.get("analyst_verdict") == "Benign"]

        if search_query:
            q = search_query.lower()
            filtered = [
                i for i in filtered
                if q in i.get("incident_id", "").lower()
                or q in i.get("source_ip", "").lower()
                or q in get_plain_english_title(i.get("category", "")).lower()
            ]

        # Threat Selector / Card List
        st.markdown(f"**Showing {len(filtered)} item(s)**")

        # Create user-friendly labels for dropdown selector
        incident_options = {
            f"[{i.get('severity', 'Medium')}] {get_plain_english_title(i.get('category', ''))} — {i.get('source_ip')} ({i.get('incident_id')})": i
            for i in filtered
        }

        if not incident_options:
            st.info("No threats match the current search and filter settings.")
        else:
            selected_label = st.selectbox("Select Threat to Inspect", list(incident_options.keys()))
            current_threat = incident_options[selected_label]
            breakdown = get_plain_english_breakdown(current_threat)

            # Prominent Threat Summary Card
            sev_badge_class = "sa-badge-danger" if current_threat.get("severity") in ("Critical", "High") else "sa-badge-warning"
            st.markdown(f"""
            <div class="sa-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <h2 style="margin:0 0 4px 0; color:#172B4D; font-size:1.35rem;">{get_plain_english_title(current_threat.get('category', ''))}</h2>
                        <span style="color:#667085; font-size:0.9rem;">From device <code>{current_threat.get('source_ip')}</code> directed at <code>{current_threat.get('destination_ip', 'Internal system')}</code></span>
                    </div>
                    <div>
                        <span class="sa-badge {sev_badge_class}">{current_threat.get('severity', 'Medium')} Priority</span>
                        <span class="sa-badge sa-badge-neutral" style="margin-left:6px;">{current_threat.get('analyst_verdict', 'Needs Review')}</span>
                    </div>
                </div>
                <p style="margin:12px 0 0 0; color:#475569; font-size:0.95rem;">
                    {get_plain_english_summary(current_threat)}
                </p>
            </div>
            """, unsafe_allow_html=True)

            # THE 5 CORE QUESTIONS (Simple by default)
            col_q1, col_q2 = st.columns([1, 1])

            with col_q1:
                st.markdown("#### 1. What happened?")
                st.write(breakdown["what_happened"])

                st.markdown("#### 2. Why might it matter?")
                st.write(breakdown["why_matters"])

                st.markdown("#### 3. What evidence supports this assessment?")
                for pt in breakdown["evidence_points"]:
                    st.markdown(f"- {pt}")

            with col_q2:
                st.markdown("#### 4. What remains uncertain?")
                for uc in breakdown["uncertainties"]:
                    st.markdown(f"- {uc}")

                st.markdown("#### 5. What should I do next?")
                for stp in breakdown["next_steps"]:
                    st.markdown(f"- {stp}")

            st.divider()

            # Review & Decision Actions
            st.markdown("### 📝 Your Decision (Analyst Review)")
            st.write("Mark whether this activity was a real threat, a false alarm, or safe test traffic:")

            b_col1, b_col2, b_col3, b_col4 = st.columns(4)
            inc_id = current_threat["incident_id"]

            if b_col1.button("✅ Confirm Threat (True Positive)", key=f"btn_tp_{inc_id}", use_container_width=True):
                db.record_analyst_feedback(inc_id, "True Positive", "Security Analyst", "Confirmed suspicious activity", current_threat.get("model_version", "v1.0.0"))
                st.success("Recorded as Confirmed Threat.")
                st.rerun()

            if b_col2.button("❌ Mark as False Alarm", key=f"btn_fp_{inc_id}", use_container_width=True):
                db.record_analyst_feedback(inc_id, "False Positive", "Security Analyst", "Normal operational traffic", current_threat.get("model_version", "v1.0.0"))
                st.info("Recorded as False Alarm.")
                st.rerun()

            if b_col3.button("🛡️ Mark as Benign / Safe", key=f"btn_benign_{inc_id}", use_container_width=True):
                db.record_analyst_feedback(inc_id, "Benign", "Security Analyst", "Authorized administrative scan or test", current_threat.get("model_version", "v1.0.0"))
                st.success("Recorded as Benign activity.")
                st.rerun()

            if b_col4.button("❓ Mark Unresolved", key=f"btn_unres_{inc_id}", use_container_width=True):
                db.record_analyst_feedback(inc_id, "Unresolved", "Security Analyst", "Pending further investigation", current_threat.get("model_version", "v1.0.0"))
                st.warning("Marked as Unresolved.")
                st.rerun()

            # Technical Details on Demand (Expandable)
            with st.expander("🔬 Technical Details (For Security Engineers & Auditors)"):
                st.caption("Detailed network telemetry, ML mathematical deviation scores, and MITRE mapping:")

                tech_c1, tech_c2 = st.columns(2)
                with tech_c1:
                    st.markdown(f"**Incident Identifier:** `{current_threat.get('incident_id')}`")
                    st.markdown(f"**Observed Ports:** `{current_threat.get('destination_ports', [])}`")
                    st.markdown(f"**Protocols:** `{current_threat.get('protocols', ['TCP'])}`")
                    st.markdown(f"**Observed Timestamp:** `{current_threat.get('timestamp')}`")
                    st.markdown(f"**Recurrence Count:** `{current_threat.get('recurrence_count', 1)}` time(s)")
                with tech_c2:
                    st.markdown(f"**Rule Identifier:** `{current_threat.get('rule_id', 'N/A')}`")
                    st.markdown(f"**MITRE ATT&CK Mapping:** `{current_threat.get('mitre_id', 'N/A')}`")
                    st.markdown(f"**ML Model Version:** `{current_threat.get('model_version', 'v1.0.0')}`")
                    st.markdown(f"**ML Anomaly Score:** `{current_threat.get('ml_anomaly_score', 0.0):.4f}`")
                    st.markdown(f"**Confidence Rating:** `{int(current_threat.get('confidence', 0.85)*100)}%`")

                st.markdown("#### Raw Evidence Log")
                st.code(current_threat.get("raw_evidence") or current_threat.get("evidence", "No raw evidence available"), language="text")


# ==============================================================================
# 3. PROTECTION PAGE: Clear Protection Mode & Controlled Containment
# ==============================================================================
with tab_protection:
    st.subheader("🛡️ Protection & Containment Actions")
    st.write("Inspect active protection rules, understand containment status, and simulate temporary blocks.")

    # Honest Protection Mode Callout
    st.markdown("""
    <div class="sa-card" style="border-left: 4px solid #16835D;">
        <h3 style="margin-top:0; color:#16835D;">Protection Mode: Simulated Quarantine (Dry-Run by Default)</h3>
        <p style="color:#667085; font-size:0.95rem; margin-bottom:0;">
            SentinelAI is operating in safe simulation mode. Recommended defensive rules are calculated and validated, 
            but <strong>zero changes are made to your computer's live operating system firewall</strong>.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Active Rules Section
    st.markdown("### 📋 Active Protection Policies")
    active_blocks = db.get_active_blocks()

    # Expire old blocks automatically
    expired = db.check_and_expire_blocks()
    if expired:
        st.info(f"The expiry watchdog automatically retired {len(expired)} temporary rule(s).")

    if active_blocks:
        active_list = [b for b in active_blocks if b.get("status") == "Active"]
        if active_list:
            display_rows = []
            for b in active_list:
                display_rows.append({
                    "Rule ID": b.get("block_id"),
                    "Target Address": b.get("target_ip"),
                    "Type": b.get("rule_type"),
                    "Duration": f"{b.get('duration_minutes', 60)} min" if b.get("rule_type") == "Temporary" else "Permanent",
                    "Expires At": b.get("expires_at", "Never"),
                    "Enforcement Mode": "Simulated Only",
                    "Approval": b.get("approval_status", "Approved")
                })
            st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)

            # Rollback / Removal Trigger
            st.markdown("#### 🔄 Remove or Roll Back a Rule")
            roll_ids = [b["block_id"] for b in active_list]
            selected_roll = st.selectbox("Select Rule to Revoke", roll_ids)
            if st.button("Roll Back / Remove Rule", type="secondary"):
                db.rollback_block(selected_roll, operator="Security Assistant User")
                st.success(f"Rule {selected_roll} has been safely removed and logged.")
                st.rerun()
        else:
            st.info("No active containment rules currently enforced.")
    else:
        st.info("No protection rules recorded in the database.")

    st.divider()

    # Staging a New Simulated Action
    st.markdown("### 🧪 Propose a Containment Action")
    st.write("Stage a defensive firewall block for a suspicious address:")

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        target_ip_input = st.text_input("Target IP Address", value="198.51.100.88")
        block_duration = st.selectbox("Proposed Duration", [15, 30, 60, 120, 240], index=2, format_func=lambda x: f"{x} Minutes (Temporary)")

    with col_p2:
        st.markdown("<br>", unsafe_allow_html=True)
        # Allowlist safety check
        is_allowed, allow_reason = is_ip_allowlisted(target_ip_input)
        if is_allowed:
            st.error(f"🚫 **Protected Address:** {allow_reason}\nThis address cannot be blocked.")
        else:
            st.success(f"✅ `{target_ip_input}` passed allowlist check.")

    if st.button("Simulate Temporary Block", type="primary"):
        res = response_engine.execute_response_action(
            incident_id="MANUAL-ASSISTANT",
            action_type="FIREWALL_QUARANTINE",
            target_ip=target_ip_input,
            dry_run=True,
            rule_type="Temporary",
            duration_minutes=block_duration,
            operator="Security Assistant User",
            db_manager=db
        )
        if res.get("status") == "SUCCESS":
            st.success(f"Simulated block staged successfully! Rule ID: `{res.get('block_id')}`")
            st.write(res.get("details"))
            st.rerun()
        else:
            st.error(f"Action rejected: {res.get('message')}")

    # Protected Core Allowlist Section
    with st.expander("🔒 Protected Infrastructure Allowlist (Permanently Safe Addresses)"):
        st.write("SentinelAI will never block localhost, local gateway routers, or core public DNS servers:")
        st.code(", ".join(sorted(list(DEFAULT_PROTECTED_IPS))), language="text")


# ==============================================================================
# 4. ACTIVITY PAGE: Unified Chronological Timeline
# ==============================================================================
with tab_activity:
    st.subheader("📋 Security Activity Timeline")
    st.write("A chronological history of observed events, user reviews, recommendations, and simulated containment actions.")

    # Fetch audit logs
    audit_logs = db.get_audit_logs(limit=60)
    all_incs = db.get_incidents()

    # Build timeline entries
    timeline_entries = []
    for a in audit_logs:
        timeline_entries.append({
            "Timestamp": a.get("timestamp"),
            "Activity": a.get("action_type", "").replace("_", " ").title(),
            "Target Host": a.get("target_ip", "System"),
            "Mode": "Simulation" if a.get("execution_mode") == "dry_run" else a.get("execution_mode", "Local"),
            "Result": a.get("result", "Recorded"),
            "Source Tag": "Demo Simulation" if "sample" in a.get("details", "").lower() or "demo" in a.get("details", "").lower() else "System Event",
            "Details": a.get("details", "")
        })

    if timeline_entries:
        df_timeline = pd.DataFrame(timeline_entries)
        st.dataframe(df_timeline, use_container_width=True, hide_index=True)
    else:
        st.info("No activity records found.")


# ==============================================================================
# 5. ADVANCED TOOLS: For Security Analysts & Power Users
# ==============================================================================
with tab_advanced:
    st.subheader("⚙️ Advanced Tools & Deep Forensics")
    st.caption("Access machine learning retraining, Google Gemini threat reasoning, telemetry ingestion, and raw audit logs.")

    adv_tool = st.radio(
        "Select Advanced Tool",
        [
            "🧠 Machine Learning Threat Intelligence",
            "🤖 AI Threat Copilot (Google Gemini)",
            "📁 Telemetry Ingestion & File Parser",
            "📡 Live Monitoring Simulator",
            "📜 Response Audit Trail Ledger",
            "🧹 Data Retention Controls"
        ],
        horizontal=True
    )

    st.markdown("---")

    # TOOL 1: ML THREAT INTELLIGENCE
    if "Machine Learning" in adv_tool:
        st.markdown("### 🧠 Machine Learning Anomaly Detection (Isolation Forest)")
        st.write("SentinelAI utilizes an unsupervised scikit-learn Isolation Forest model to detect statistical deviations from learned network baselines.")

        st.info("ℹ️ **Synthetic Training Notice:** The active model is benchmarked on synthetic laboratory fixtures. Metrics reflect synthetic distributions, not real-world network traffic.")

        ml_c1, ml_c2 = st.columns(2)
        with ml_c1:
            active_model = db.get_active_model()
            active_v = active_model["version"] if active_model else ml_engine.model_version
            st.markdown(f"**Active Model:** `{active_v}` | **Algorithm:** `scikit-learn IsolationForest`")
            metrics = active_model.get("metrics", {}) if active_model else ml_engine.metrics
            if metrics:
                # Approachable Summary Cards for non-technical users
                m_kpi1, m_kpi2 = st.columns(2)
                with m_kpi1:
                    st.metric("Trained Telemetry Flows", f"{metrics.get('total_samples', 300):,}")
                    st.metric("Expected Anomaly Rate", f"{int(metrics.get('contamination_parameter', 0.12) * 100)}%")
                with m_kpi2:
                    st.metric("Validation Gate", "Verified & Active")
                    st.metric("Test Outliers Identified", f"{metrics.get('test_outlier_count', 8)} of {metrics.get('test_sample_count', 75)} tests")

                st.markdown("**Traffic Attributes Monitored:**")
                feats = metrics.get("features_used", ["packets", "port", "flow_frequency", "unique_ports"])
                st.caption(" • ".join([f"`{f}`" for f in feats[:7]]))

                # Technical details on demand (raw JSON hidden by default)
                with st.expander("🛠️ Technical Details (Raw Evaluation JSON)"):
                    st.json(metrics)

            # Revert model
            all_models = db.get_model_registry()
            if len(all_models) > 1:
                st.markdown("#### Revert to Previous Model")
                versions = [m["version"] for m in all_models]
                target_revert = st.selectbox("Select Model Version", versions)
                if st.button("Activate Model Version"):
                    if ml_engine.revert_model(target_revert):
                        db.set_active_model_version(target_revert)
                        st.success(f"Model reverted to {target_revert}!")
                        st.rerun()

        with ml_c2:
            st.markdown("#### Controlled Model Retraining Console")
            st.caption("Controlled retraining enforces validation gates and holdout test evaluation.")
            retrain_samples = st.slider("Synthetic Samples", 100, 1000, 300)
            retrain_contam = st.slider("Contamination Rate", 0.05, 0.30, 0.15)
            if st.button("Run Controlled Retraining Pipeline", type="primary"):
                fixtures = MLAnomalyEngine.generate_synthetic_lab_fixtures(n_samples=retrain_samples)
                res = ml_engine.train_controlled_pipeline(
                    training_data=fixtures,
                    contamination=retrain_contam,
                    trained_by="Security Engineer"
                )
                if res.get("status") == "VALIDATED_AND_TRAINED":
                    db.register_model(res["model_version"], res["algorithm"], res["total_samples"], res, res["artifact_path"], "Security Engineer", set_active=True)
                    st.success(f"Model {res['model_version']} validated and promoted to active!")
                    st.rerun()
                else:
                    st.error(f"Retraining rejected by validation gate: {res.get('message')}")

    # TOOL 2: AI THREAT COPILOT
    elif "Copilot" in adv_tool:
        st.markdown("### 🤖 Google Gemini AI Threat Copilot")
        st.write("Contextual forensic investigation grounded in actual stored telemetry evidence.")

        if explainer.is_gemini_active:
            st.success("🟢 **Google Gemini Connected:** Using API key loaded automatically from your environment (`.env` / `.env.local`). No manual website entry required.")
        else:
            st.info("ℹ️ **Deterministic Local Knowledge Mode:** Gemini API key not detected in `.env` or `.env.local`. Running offline rule-based reasoning. To activate live Google Gemini, simply add `GEMINI_API_KEY=your_key` to your `.env.local` or `.env` file — the application will use it automatically without requiring any input on the website.")

        st.warning("🛡️ **AI Safety Boundary:** AI suggestions are advisory hypotheses for analyst consideration. The AI cannot classify an IP as malicious or trigger firewall containment.")

        all_incs = db.get_incidents()
        if all_incs:
            inc_map = {f"[{i['severity']}] {get_plain_english_title(i['category'])} ({i['source_ip']})": i for i in all_incs}
            selected_label = st.selectbox("Select Incident for AI Reasoning", list(inc_map.keys()))
            target_inc = inc_map[selected_label]

            exp = explainer.explain_incident(target_inc)
            st.caption(f"Engine: **{exp.get('provider')}** | {exp.get('ai_disclaimer')}")

            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                st.markdown("#### Summary & Mechanism")
                st.write(exp.get("summary"))
                st.write(f"**Technical Mechanism:** {exp.get('mechanism')}")
                st.write(f"**MITRE ATT&CK:** `{exp.get('mitre_technique')}`")

            with col_ai2:
                st.markdown("#### Forensic Investigation Checklist")
                for idx, step in enumerate(exp.get("investigation_steps", []), 1):
                    st.checkbox(step, key=f"adv_chk_{target_inc['incident_id']}_{idx}")

                st.markdown("#### Prevention Options")
                for r in exp.get("containment_recommendations", []):
                    st.markdown(f"- {r}")
        else:
            st.info("No incidents to analyze.")

    # TOOL 3: TELEMETRY INGESTION
    elif "Ingestion" in adv_tool:
        st.markdown("### 📁 Telemetry Ingestion & File Parser")
        st.write("Ingest Suricata EVE JSON or custom CSV security logs to detect incidents.")

        sample_choice = st.selectbox(
            "Select Pre-Configured Test Dataset",
            [
                "Suricata EVE JSON (73-record Audit Dataset)",
                "Port Scan Attack (attack_port_scan.json)",
                "Brute Force Attack (attack_brute_force.json)",
                "DDoS Volumetric Flood (attack_ddos_flood.json)",
                "Normal Nominal Traffic (normal_traffic.csv)"
            ]
        )

        if st.button("Parse & Ingest Dataset", type="primary"):
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            file_map = {
                "Suricata EVE JSON (73-record Audit Dataset)": os.path.join(data_dir, "sentinelai_suricata_eve_sample.json"),
                "Port Scan Attack (attack_port_scan.json)": os.path.join(data_dir, "attack_port_scan.json"),
                "Brute Force Attack (attack_brute_force.json)": os.path.join(data_dir, "attack_brute_force.json"),
                "DDoS Volumetric Flood (attack_ddos_flood.json)": os.path.join(data_dir, "attack_ddos_flood.json"),
                "Normal Nominal Traffic (normal_traffic.csv)": os.path.join(data_dir, "normal_traffic.csv"),
            }
            target_file = file_map.get(sample_choice)
            if target_file and os.path.exists(target_file):
                if target_file.endswith(".csv"):
                    df_ingest = pd.read_csv(target_file)
                else:
                    with open(target_file, "r", encoding="utf-8") as f:
                        raw_content = f.read()
                    if "suricata" in target_file:
                        events, _ = LogParser.parse_suricata_eve(raw_content)
                    else:
                        events, _ = LogParser.parse_generic_json(raw_content)
                    df_ingest = LogParser.events_to_dataframe(events)

                st.session_state["ingested_df"] = df_ingest
                st.session_state["data_source_name"] = sample_choice
                st.success(f"Parsed {len(df_ingest)} telemetry records!")

                # Correlate incidents
                correlated = detector.correlate_incidents(df_ingest)
                st.write(f"Identified **{len(correlated)}** correlated incident(s).")
                for c in correlated:
                    db.save_incident(c.to_dict())
                st.rerun()

    # TOOL 4: LIVE MONITORING
    elif "Live Monitoring" in adv_tool:
        st.markdown("### 📡 Live Monitoring Simulator")
        st.caption("Generates simulated network traffic in a defensive sandbox with `[SIMULATED: Lab Scenario]` labeling.")

        c_s1, c_s2 = st.columns(2)
        with c_s1:
            if st.button("▶️ Generate 10 Background Events"):
                live_sim.start(interval_seconds=0.1)
                import time
                time.sleep(1.1)
                live_sim.stop()
                st.rerun()
        with c_s2:
            if st.button("💉 Inject Port Scan Probes"):
                live_sim.inject_attack("port_scan")
                st.success("Injected 6 port scan probe events.")
                st.rerun()

        events = live_sim.get_recent_events(limit=15)
        if events:
            st.dataframe(pd.DataFrame(events), use_container_width=True)

    # TOOL 5: AUDIT LOG
    elif "Audit" in adv_tool:
        st.markdown("### 📜 System Activity Audit Ledger")
        st.write("Application activity ledger documenting containment simulations, analyst verdicts, and configuration changes.")
        audit_records = db.get_audit_logs(limit=100)
        if audit_records:
            st.dataframe(pd.DataFrame(audit_records), use_container_width=True, hide_index=True)

    # TOOL 6: DATA RETENTION
    elif "Retention" in adv_tool:
        st.markdown("### 🧹 Data Retention Controls")
        st.write("Prune stale historical telemetry events and resolved incidents beyond a configurable retention window.")
        retention_window = st.slider("Retention Window (Days)", 7, 90, 30)
        if st.button("Purge Stale Records"):
            res = db.apply_data_retention(retention_days=retention_window, operator="Security Assistant User")
            st.success(f"Purged {res['purged_telemetry']} telemetry events and {res['purged_incidents']} resolved incidents.")
            st.rerun()