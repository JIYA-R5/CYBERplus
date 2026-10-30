"""
==============================================================================
SentinelAI — Unified Autonomous SOC Platform (Active Entrypoint)
==============================================================================
Active modern entrypoint for SentinelAI. Renders the Unified Autonomous SOC
Platform natively in Streamlit with modern dark aesthetics (#0B0F19), interactive
Plotly Threat Heat Map with MaxMind GeoLite2 coordinates, Gemini Security
Copilot incident investigations (with dual hypotheses and rollback plans),
and direct bridging to the standalone React interface (http://127.0.0.1:8000).
The legacy Streamlit multi-tab interface has been retired to legacy_app.py.
==============================================================================
"""

import os
import sys
import json
import time
import datetime
from typing import Dict, Any, List, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if os.path.isfile(os.path.join(ROOT_DIR, ".env")):
    load_dotenv(os.path.join(ROOT_DIR, ".env"), override=False)
if os.path.isfile(os.path.join(ROOT_DIR, ".env.local")):
    load_dotenv(os.path.join(ROOT_DIR, ".env.local"), override=True)
load_dotenv()

from database import get_db, IDENTITY_DISCLAIMER
from geoip_service import get_geoip_service, GEOIP_DISCLAIMER
from explainerAI import get_explainer
from response_engine import get_response_engine

# Initialize backend services
db = get_db()
geoip_svc = get_geoip_service(db_manager=db)
explainer = get_explainer()
resp_engine = get_response_engine()

# Configure page metadata matching the New Autonomous SOC theme
st.set_page_config(
    page_title="SentinelAI — Autonomous SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom dark-theme styling matching the New React SOC (#0B0F19)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    code, pre, .font-mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Dark SOC Theme Colors */
    .stApp {
        background-color: #0B0F19 !important;
        color: #F8FAFC !important;
    }
    
    header[data-testid="stHeader"] {
        background-color: #0B0F19 !important;
    }
    
    section[data-testid="stSidebar"] {
        background-color: #0F172A !important;
        border-right: 1px solid #1E293B !important;
    }

    /* Metric Cards */
    .kpi-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .kpi-title {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94A3B8;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .kpi-value {
        font-size: 24px;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        margin-top: 6px;
        color: #F8FAFC;
    }
    .kpi-desc {
        font-size: 11px;
        margin-top: 4px;
    }

    /* Alert / Notice */
    .soc-notice {
        background: rgba(245, 158, 11, 0.1);
        border: 1px solid rgba(245, 158, 11, 0.3);
        border-radius: 10px;
        padding: 12px 16px;
        font-size: 12px;
        color: #FDE68A;
        margin-bottom: 16px;
    }
    
    .soc-banner {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 14px 20px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Hypothesis Box */
    .hypothesis-card {
        background: #0B132B;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }

    iframe {
        border: none !important;
        width: 100% !important;
        min-height: 850px !important;
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)

api_port = os.getenv("API_PORT", "8000")
api_host = os.getenv("API_HOST", "127.0.0.1")
if api_host == "0.0.0.0":
    api_host = "127.0.0.1"

new_ui_url = f"http://{api_host}:{api_port}"

# Top Unified SOC Navigation & Status Banner
col_top1, col_top2 = st.columns([3, 2])
with col_top1:
    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:12px; padding: 4px 0;">
        <div style="background:linear-gradient(135deg, #06B6D4, #2563EB); width:36px; height:36px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:18px;">
            🛡️
        </div>
        <div>
            <div style="font-size:16px; font-weight:800; color:#FFFFFF; letter-spacing:0.02em;">
                Sentinel<span style="color:#06B6D4;">AI</span> Autonomous SOC
            </div>
            <div style="font-size:11px; color:#94A3B8; font-family:monospace;">
                Active Unified Interface &bull; <a href="{new_ui_url}" target="_blank" style="color:#38BDF8; text-decoration:none;">{new_ui_url}</a>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_top2:
    st.markdown(f"""
    <div style="display:flex; justify-content:flex-end; align-items:center; gap:12px; height:100%;">
        <span style="background:rgba(16, 185, 129, 0.15); border:1px solid rgba(16, 185, 129, 0.3); color:#10B981; font-size:11px; font-weight:700; padding:5px 12px; border-radius:8px; font-family:monospace;">
            ● ACTIVE (NEW UNIFIED UI)
        </span>
        <a href="{new_ui_url}" target="_blank" style="background:#06B6D4; color:#0B0F19; font-size:11px; font-weight:700; padding:6px 14px; border-radius:8px; text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
            Open Standalone SPA ↗
        </a>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border:0; border-top:1px solid #1E293B; margin: 12px 0 20px 0;'>", unsafe_allow_html=True)

# Sidebar Navigation
with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0 20px 0; border-bottom: 1px solid #1E293B; margin-bottom: 16px;">
        <div style="font-size:11px; font-weight:700; color:#06B6D4; text-transform:uppercase; letter-spacing:0.1em; font-family:monospace;">
            OPERATIONAL MODULES
        </div>
    </div>
    """, unsafe_allow_html=True)

    nav_selection = st.radio(
        "Navigation",
        [
            "🌐 Threat Intelligence & GeoIP Map",
            "🤖 Gemini Security Copilot & Investigation",
            "📡 Live Network Monitoring",
            "🛡️ Autonomous Response & Containment",
            "💻 Embedded React Web App"
        ],
        label_visibility="collapsed"
    )

    st.markdown("<hr style='border:0; border-top:1px solid #1E293B; margin: 20px 0;'>", unsafe_allow_html=True)
    
    # Engine Status Summary
    st.markdown("""
    <div style="font-size:10px; font-weight:700; color:#64748B; text-transform:uppercase; margin-bottom:10px; font-family:monospace;">
        SUBSYSTEM HEALTH
    </div>
    <div style="font-size:11px; color:#94A3B8; space-y:6px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
            <span>MaxMind GeoLite2:</span>
            <span style="color:#10B981; font-weight:600;">ACTIVE (City.mmdb)</span>
        </div>
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
            <span>Gemini AI Engine:</span>
            <span style="color:{}; font-weight:600;">{}</span>
        </div>
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
            <span>FastAPI Backend:</span>
            <span style="color:#10B981; font-weight:600;">Port {}</span>
        </div>
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
            <span>SQLite Retention:</span>
            <span style="color:#38BDF8; font-weight:600;">24-Hour Safe Logs</span>
        </div>
    </div>
    """.format(
        "#10B981" if explainer.is_gemini_active else "#F59E0B",
        "ONLINE (Live AI)" if explainer.is_gemini_active else "LOCAL FALLBACK",
        api_port
    ), unsafe_allow_html=True)


# ==============================================================================
# VIEW 1: THREAT INTELLIGENCE & GEOLOCATION HEAT MAP
# ==============================================================================
if nav_selection == "🌐 Threat Intelligence & GeoIP Map":
    # Mandatory Disclaimer Notice
    st.markdown(f"""
    <div class="soc-notice">
        <strong>⚠️ IP Geolocation Notice:</strong> {GEOIP_DISCLAIMER}
    </div>
    """, unsafe_allow_html=True)

    # Filter Header & Refresh Map Button
    col_f1, col_f2, col_f3, col_f4, col_f5 = st.columns([2, 2, 2, 2, 1.2])
    with col_f1:
        f_time = st.selectbox("Time Window", ["Last 24 Hours", "Last 1 Hour", "Last 7 Days", "All Time"], index=0)
    with col_f2:
        f_sev = st.selectbox("Severity Level", ["All", "Critical", "High", "Medium", "Low"], index=0)
    
    # Query database incidents and geolocated suspicious events
    all_incidents = db.get_incidents()
    suspicious_logs = db.get_geolocated_suspicious_logs(limit=400)

    # Extract distinct countries
    detected_countries = set()
    for inc in all_incidents:
        s_ip = inc.get("source_ip")
        if s_ip:
            intel = geoip_svc.get_ip_intelligence(s_ip)
            if intel.get("is_public") and intel.get("country"):
                detected_countries.add(intel["country"])
    for slog in suspicious_logs:
        c = slog.get("geoip_country")
        if c and c != "Unknown":
            detected_countries.add(c)
    
    country_options = ["All"] + sorted(list(detected_countries))
    with col_f3:
        f_country = st.selectbox("Country of Origin", country_options, index=0)
    with col_f4:
        f_cat = st.selectbox("Attack Category", ["All", "Port Scan", "Brute Force", "DDoS Flood", "Web Reconnaissance", "Data Exfiltration"], index=0)
    with col_f5:
        st.write("")
        st.write("")
        if st.button("🔄 Refresh Map", use_container_width=True):
            st.rerun()

    # Exact severity weights: Critical=5, High=4, Medium=2, Low=1
    SEVERITY_WEIGHTS = {"Critical": 5, "High": 4, "Medium": 2, "Low": 1}
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    # Aggregate Markers, Countries & Statistics
    public_markers: Dict[str, Dict[str, Any]] = {}
    country_aggregates: Dict[str, Dict[str, Any]] = {}
    local_hosts: Dict[str, Dict[str, Any]] = {}

    for inc in all_incidents:
        s_ip = inc.get("source_ip")
        if not s_ip:
            continue
        sev = inc.get("severity", "Medium")
        cat = inc.get("category", "General Alert")
        pkts = int(inc.get("total_packets", 1))

        if f_sev != "All" and sev != f_sev:
            continue
        if f_cat != "All" and cat != f_cat:
            continue

        intel = geoip_svc.get_ip_intelligence(s_ip)
        if intel.get("is_public") and intel.get("latitude") is not None and intel.get("longitude") is not None:
            if f_country != "All" and intel.get("country") != f_country:
                continue
            key = f"{round(intel['latitude'], 3)}_{round(intel['longitude'], 3)}"
            if key not in public_markers:
                public_markers[key] = {
                    "latitude": intel["latitude"],
                    "longitude": intel["longitude"],
                    "country": intel.get("country", "Unknown"),
                    "city": intel.get("city", "Unknown"),
                    "asn": intel.get("asn", "AS-Unknown"),
                    "org": intel.get("org", "Unknown"),
                    "source_ips": set(),
                    "categories": set(),
                    "total_packets": 0,
                    "incident_count": 0,
                    "max_severity": sev,
                    "accuracy_km": intel.get("accuracy_radius", 50)
                }
            m = public_markers[key]
            m["source_ips"].add(s_ip)
            m["categories"].add(cat)
            m["total_packets"] += pkts
            m["incident_count"] += 1
            if sev_rank.get(sev, 1) > sev_rank.get(m["max_severity"], 1):
                m["max_severity"] = sev

            # Country Aggregate with exact severity weights
            c_name = intel.get("country", "Unknown")
            if c_name not in country_aggregates:
                country_aggregates[c_name] = {
                    "country": c_name,
                    "country_code": intel.get("country_code", "XX"),
                    "intensity_score": 0,
                    "incident_count": 0,
                    "total_packets": 0,
                    "unique_ips": set(),
                    "source_ips": set(),
                    "severities": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                    "categories": {},
                    "recent_incidents": [],
                    "max_severity": sev,
                    "top_category": cat
                }
            c_agg = country_aggregates[c_name]
            w = SEVERITY_WEIGHTS.get(sev, 2)
            c_agg["intensity_score"] += w
            c_agg["incident_count"] += 1
            c_agg["total_packets"] += pkts
            c_agg["unique_ips"].add(s_ip)
            c_agg["source_ips"].add(s_ip)
            c_agg["severities"][sev] = c_agg["severities"].get(sev, 0) + 1
            c_agg["categories"][cat] = c_agg["categories"].get(cat, 0) + 1
            if sev_rank.get(sev, 1) > sev_rank.get(c_agg["max_severity"], 1):
                c_agg["max_severity"] = sev
            if len(c_agg["recent_incidents"]) < 8:
                c_agg["recent_incidents"].append({
                    "incident_id": inc.get("incident_id", "INC-LOG"),
                    "category": cat,
                    "severity": sev,
                    "source_ip": s_ip,
                    "timestamp": inc.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "packets": pkts
                })
        else:
            if s_ip not in local_hosts:
                local_hosts[s_ip] = {
                    "ip": s_ip,
                    "ip_type": intel.get("ip_type", "private"),
                    "destination_ip": inc.get("destination_ip", "10.0.0.1"),
                    "incident_count": 0,
                    "total_packets": 0,
                    "categories": set(),
                    "severity": sev
                }
            lh = local_hosts[s_ip]
            lh["incident_count"] += 1
            lh["total_packets"] += pkts
            lh["categories"].add(cat)

    # Incorporate geolocated suspicious logs from SQLite
    for slog in suspicious_logs:
        s_ip = slog.get("source_ip")
        lat = slog.get("latitude")
        lon = slog.get("longitude")
        if not s_ip or lat is None or lon is None:
            continue
        s_sev = slog.get("severity") or "High"
        s_cat = slog.get("detection_reason") or "Suspicious Probe"
        s_c = slog.get("geoip_country") or "Unknown"

        if f_sev != "All" and s_sev != f_sev:
            continue
        if f_cat != "All" and f_cat.lower() not in s_cat.lower():
            continue
        if f_country != "All" and s_c != f_country:
            continue

        key = f"{round(float(lat), 3)}_{round(float(lon), 3)}"
        if key not in public_markers:
            public_markers[key] = {
                "latitude": float(lat),
                "longitude": float(lon),
                "country": s_c,
                "city": slog.get("geoip_city") or "Unknown",
                "asn": "AS-External",
                "org": "External Threat Actor",
                "source_ips": set(),
                "categories": set(),
                "total_packets": 0,
                "incident_count": 0,
                "max_severity": s_sev,
                "accuracy_km": 50
            }
        m = public_markers[key]
        m["source_ips"].add(s_ip)
        m["categories"].add(s_cat)
        m["total_packets"] += int(slog.get("packet_size") or 1)
        m["incident_count"] += 1
        if sev_rank.get(s_sev, 1) > sev_rank.get(m["max_severity"], 1):
            m["max_severity"] = s_sev

        if s_c not in country_aggregates:
            country_aggregates[s_c] = {
                "country": s_c,
                "country_code": slog.get("geoip_country_code", "XX"),
                "intensity_score": 0,
                "incident_count": 0,
                "total_packets": 0,
                "unique_ips": set(),
                "source_ips": set(),
                "severities": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                "categories": {},
                "recent_incidents": [],
                "max_severity": s_sev,
                "top_category": s_cat
            }
        c_agg = country_aggregates[s_c]
        w = SEVERITY_WEIGHTS.get(s_sev, 2)
        c_agg["intensity_score"] += w
        c_agg["incident_count"] += 1
        c_agg["total_packets"] += int(slog.get("packet_size") or 1)
        c_agg["unique_ips"].add(s_ip)
        c_agg["source_ips"].add(s_ip)
        c_agg["severities"][s_sev] = c_agg["severities"].get(s_sev, 0) + 1
        c_agg["categories"][s_cat] = c_agg["categories"].get(s_cat, 0) + 1
        if sev_rank.get(s_sev, 1) > sev_rank.get(c_agg["max_severity"], 1):
            c_agg["max_severity"] = s_sev
        if len(c_agg["recent_incidents"]) < 8:
            c_agg["recent_incidents"].append({
                "incident_id": slog.get("log_id") or "LOG-SUSP",
                "category": s_cat,
                "severity": s_sev,
                "source_ip": s_ip,
                "timestamp": slog.get("timestamp") or slog.get("created_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "packets": int(slog.get("packet_size") or 1)
            })

    # Determine dominant threat category per country
    for c_agg in country_aggregates.values():
        if c_agg["categories"]:
            c_agg["top_category"] = max(c_agg["categories"].items(), key=lambda x: x[1])[0]

    # 5 Required KPI Metrics
    total_geolocated_ips = sum(len(m["source_ips"]) for m in public_markers.values())
    total_countries = len(country_aggregates)
    total_suspicious = len(all_incidents)
    total_private = len(local_hosts)
    total_high_crit = sum(1 for i in all_incidents if i.get("severity") in ("High", "Critical"))

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title"><span>Geolocated Sources</span><span style="color:#06B6D4;">📍</span></div>
            <div class="kpi-value" style="color:#06B6D4;">{total_geolocated_ips}</div>
            <div class="kpi-desc" style="color:#06B6D4;">Public MaxMind Coordinates</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title"><span>Countries Detected</span><span style="color:#10B981;">🌍</span></div>
            <div class="kpi-value" style="color:#10B981;">{total_countries}</div>
            <div class="kpi-desc" style="color:#10B981;">Global Origin Nations</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title"><span>Suspicious Events</span><span style="color:#38BDF8;">⚡</span></div>
            <div class="kpi-value" style="color:#38BDF8;">{total_suspicious}</div>
            <div class="kpi-desc" style="color:#94A3B8;">Correlated SOC Incidents</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title"><span>Unlocated / Private</span><span style="color:#A855F7;">🏢</span></div>
            <div class="kpi-value" style="color:#A855F7;">{total_private}</div>
            <div class="kpi-desc" style="color:#A855F7;">RFC 1918 Internal Hosts</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi5:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title"><span>High & Critical</span><span style="color:#EF4444;">🚨</span></div>
            <div class="kpi-value" style="color:#EF4444;">{total_high_crit}</div>
            <div class="kpi-desc" style="color:#EF4444;">Immediate Triage Required</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Sub-views: Map, Topology, Inspector
    sub_view = st.radio("Threat Intelligence View", ["🗺️ Interactive Geographic Heat Map", "🏢 Internal Network Topology", "🔍 Source IP Intelligence Inspector"], horizontal=True)

    if sub_view == "🗺️ Interactive Geographic Heat Map":
        if country_aggregates or public_markers:
            # Build Red/Pink Gradient Plotly Choropleth Map with Dark Navy Background
            red_pink_colorscale = [
                [0.0, '#38040E'],   # Deep dark red
                [0.25, '#670A1A'],  # Low: Dark red
                [0.5, '#A8132B'],   # Medium: Medium red
                [0.75, '#EF233C'],  # High: Bright red
                [1.0, '#FF4D6D']    # Critical: Vivid pink/red
            ]

            fig = go.Figure()

            # Choropleth Country Layer
            if country_aggregates:
                c_rows = []
                for c in country_aggregates.values():
                    c_rows.append({
                        "country": c["country"],
                        "intensity": max(1, c["intensity_score"]),
                        "events": c["incident_count"],
                        "unique_ips": len(c["unique_ips"]),
                        "severity": c["max_severity"],
                        "top_cat": c["top_category"]
                    })
                df_c = pd.DataFrame(c_rows)

                fig.add_trace(go.Choropleth(
                    locations=df_c["country"],
                    locationmode="country names",
                    z=df_c["intensity"],
                    colorscale=red_pink_colorscale,
                    autocolorscale=False,
                    reversescale=False,
                    marker=dict(line=dict(color="#1E293B", width=0.8)),
                    colorbar=dict(
                        title=dict(text="Threat Intensity", font=dict(color="#94A3B8", size=10)),
                        tickfont=dict(color="#94A3B8", size=9),
                        bgcolor="rgba(15, 23, 42, 0.85)",
                        bordercolor="#1E293B",
                        thickness=12,
                        len=0.6,
                        x=0.98,
                        y=0.5
                    ),
                    customdata=df_c[["events", "unique_ips", "severity", "top_cat"]],
                    hovertemplate=(
                        "<span style='font-family:sans-serif;'>"
                        "<b style='font-size:14px; color:#FFFFFF;'>%{location}</b><br>"
                        "⚡ Threat Intensity: <b>%{z}</b><br>"
                        "🚨 Suspicious Events: <b>%{customdata[0]}</b><br>"
                        "🌐 Unique Source IPs: <b>%{customdata[1]}</b><br>"
                        "⚠️ Max Severity: <b>%{customdata[2]}</b><br>"
                        "🎯 Primary Threat: <b>%{customdata[3]}</b>"
                        "</span><extra></extra>"
                    )
                ))

            # Precise City Coordinates Scatter Marker Layer
            if public_markers:
                m_rows = []
                sev_colors = {"Critical": "#EF4444", "High": "#F59E0B", "Medium": "#3B82F6", "Low": "#10B981"}
                for m in public_markers.values():
                    ips_str = ", ".join(sorted(list(m["source_ips"]))[:3])
                    cats_str = ", ".join(sorted(list(m["categories"]))[:2])
                    m_sev = m.get("max_severity", "High")
                    m_rows.append({
                        "lat": m["latitude"],
                        "lon": m["longitude"],
                        "location": f"{m['city']}, {m['country']}",
                        "ips": ips_str,
                        "severity": m_sev,
                        "color": sev_colors.get(m_sev, "#F59E0B"),
                        "packets": m["total_packets"],
                        "categories": cats_str,
                        "incidents": m["incident_count"],
                        "asn": m["asn"],
                        "accuracy_km": m["accuracy_km"]
                    })
                df_m = pd.DataFrame(m_rows)

                fig.add_trace(go.Scattergeo(
                    lat=df_m["lat"],
                    lon=df_m["lon"],
                    mode="markers",
                    marker=dict(
                        size=[min(22, max(8, int((p ** 0.5) * 1.5))) for p in df_m["packets"]],
                        color=df_m["color"],
                        line=dict(color="#FFFFFF", width=1.5),
                        opacity=0.95
                    ),
                    text=df_m["location"],
                    customdata=df_m[["ips", "severity", "packets", "categories", "incidents"]],
                    hovertemplate=(
                        "<b>📍 %{text}</b><br>"
                        "Source IP(s): %{customdata[0]}<br>"
                        "Max Severity: %{customdata[1]}<br>"
                        "Packet Volume: %{customdata[2]}<br>"
                        "Categories: %{customdata[3]}<br>"
                        "Incident Count: %{customdata[4]}"
                        "<extra></extra>"
                    )
                ))

            fig.update_layout(
                geo=dict(
                    showland=True,
                    landcolor="#0B132B",  # Dark navy background for unhighlighted countries
                    showocean=True,
                    oceancolor="#070A11", # Deep dark navy ocean
                    showcountries=True,
                    countrycolor="#1E293B",
                    countrywidth=0.8,
                    showcoastlines=True,
                    coastlinecolor="#1E293B",
                    bgcolor="#070A11",
                    projection_type="natural earth",
                ),
                paper_bgcolor="#070A11",
                plot_bgcolor="#070A11",
                margin=dict(l=0, r=0, t=10, b=10),
                height=480,
                showlegend=False
            )

            # Two Column Layout: Choropleth Map + Country Intelligence Panel
            col_map, col_panel = st.columns([1.8, 1.2])

            with col_map:
                st.plotly_chart(fig, use_container_width=True)
                st.caption("🌐 World Choropleth Map &bull; Red/Pink Threat Gradient &bull; MaxMind GeoLite2 &bull; Accurate Boundaries")

            with col_panel:
                # Country Intelligence Panel
                sorted_countries = sorted(country_aggregates.values(), key=lambda x: (x["intensity_score"], x["incident_count"]), reverse=True)
                country_names = [c["country"] for c in sorted_countries]
                
                if country_names:
                    sel_country_name = st.selectbox("Select Country for Deep Intelligence", country_names, index=0)
                    sel_c = next((c for c in sorted_countries if c["country"] == sel_country_name), sorted_countries[0])

                    st.markdown(f"""
                    <div style="background:#0F172A; border:1px solid #1E293B; border-radius:12px; padding:16px; margin-top:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                            <div>
                                <div style="font-size:16px; font-weight:800; color:#FFFFFF;">{sel_c['country']}</div>
                                <div style="font-size:11px; color:#94A3B8; font-family:monospace;">Code: {sel_c.get('country_code', 'XX')} &bull; Primary Threat: {sel_c['top_category']}</div>
                            </div>
                            <div style="background:rgba(239, 35, 60, 0.2); border:1px solid rgba(239, 35, 60, 0.4); color:#FF4D6D; padding:4px 10px; border-radius:8px; font-weight:800; font-size:12px; font-family:monospace;">
                                INTENSITY {sel_c['intensity_score']}
                            </div>
                        </div>
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:12px;">
                            <div style="background:#0B132B; padding:8px 10px; border-radius:8px; border:1px solid #1E293B;">
                                <div style="font-size:10px; color:#94A3B8;">SUSPICIOUS EVENTS</div>
                                <div style="font-size:16px; font-weight:700; color:#F8FAFC; font-family:monospace;">{sel_c['incident_count']}</div>
                            </div>
                            <div style="background:#0B132B; padding:8px 10px; border-radius:8px; border:1px solid #1E293B;">
                                <div style="font-size:10px; color:#94A3B8;">UNIQUE SOURCE IPS</div>
                                <div style="font-size:16px; font-weight:700; color:#38BDF8; font-family:monospace;">{len(sel_c['unique_ips'])}</div>
                            </div>
                        </div>
                        <div style="font-size:11px; font-weight:700; color:#94A3B8; margin-bottom:6px;">SEVERITY BREAKDOWN</div>
                        <div style="display:flex; gap:6px; margin-bottom:12px;">
                            <span style="background:rgba(239, 68, 68, 0.15); border:1px solid rgba(239,68,68,0.3); color:#EF4444; font-size:10px; font-weight:700; padding:3px 8px; border-radius:6px;">Crit: {sel_c['severities'].get('Critical', 0)}</span>
                            <span style="background:rgba(245, 158, 11, 0.15); border:1px solid rgba(245,158,11,0.3); color:#F59E0B; font-size:10px; font-weight:700; padding:3px 8px; border-radius:6px;">High: {sel_c['severities'].get('High', 0)}</span>
                            <span style="background:rgba(59, 130, 246, 0.15); border:1px solid rgba(59,130,246,0.3); color:#3B82F6; font-size:10px; font-weight:700; padding:3px 8px; border-radius:6px;">Med: {sel_c['severities'].get('Medium', 0)}</span>
                            <span style="background:rgba(16, 185, 129, 0.15); border:1px solid rgba(16,185,129,0.3); color:#10B981; font-size:10px; font-weight:700; padding:3px 8px; border-radius:6px;">Low: {sel_c['severities'].get('Low', 0)}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if sel_c.get("recent_incidents"):
                        st.markdown("<div style='font-size:12px; font-weight:700; color:#F8FAFC; margin-top:10px; margin-bottom:4px;'>Recent Country Incidents</div>", unsafe_allow_html=True)
                        df_recent = pd.DataFrame(sel_c["recent_incidents"])
                        st.dataframe(df_recent[["incident_id", "source_ip", "category", "severity", "timestamp"]], hide_index=True, use_container_width=True)

            # Compact Activity Timeline (Requirement 11)
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            st.markdown("#### ⏱️ Real-time Threat Activity Timeline (SQLite Verified)")
            
            # Aggregate timeline buckets from actual incidents
            timeline_buckets = {}
            for inc in all_incidents:
                ts = inc.get("timestamp")
                if not ts:
                    continue
                try:
                    dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    b_key = dt.strftime("%H:00")
                except Exception:
                    b_key = "Recent"
                if b_key not in timeline_buckets:
                    timeline_buckets[b_key] = {"Time": b_key, "Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                s_lvl = inc.get("severity", "Medium")
                timeline_buckets[b_key][s_lvl] = timeline_buckets[b_key].get(s_lvl, 0) + 1

            if timeline_buckets:
                df_tl = pd.DataFrame(list(timeline_buckets.values()))
                fig_tl = px.bar(
                    df_tl,
                    x="Time",
                    y=[col for col in ["Critical", "High", "Medium", "Low"] if col in df_tl.columns],
                    color_discrete_map={"Critical": "#EF4444", "High": "#F59E0B", "Medium": "#3B82F6", "Low": "#10B981"},
                    labels={"value": "Events", "Time": "Hour"},
                    height=200
                )
                fig_tl.update_layout(
                    paper_bgcolor="#0B0F19",
                    plot_bgcolor="#0B0F19",
                    margin=dict(l=20, r=20, t=10, b=10),
                    font=dict(color="#94A3B8", family="Inter", size=10),
                    legend=dict(orientation="h", y=1.2, x=0.8, bgcolor="rgba(0,0,0,0)"),
                    xaxis=dict(gridcolor="#1E293B"),
                    yaxis=dict(gridcolor="#1E293B")
                )
                st.plotly_chart(fig_tl, use_container_width=True)

            # Active Marker Details
            st.markdown("#### 📍 Detected External Threat Origins")
            if public_markers:
                st.dataframe(
                    df_m[["location", "ips", "severity", "categories", "packets", "incidents", "asn", "accuracy_km"]],
                    use_container_width=True,
                    hide_index=True
                )
        else:
            st.info("No public geolocatable events matching current filter criteria. Try selecting 'All' filters or clicking 'Refresh Map'.")

    elif sub_view == "🏢 Internal Network Topology":
        st.markdown("#### 🏢 Internal / Private RFC 1918 Network Topology")
        st.write("Source IPs segregated from public geographic heat map to prevent false attribution on external maps.")
        if local_hosts:
            topo_records = []
            for ip, l in local_hosts.items():
                topo_records.append({
                    "Source IP": ip,
                    "Classification": "RFC 1918 (Private)",
                    "Target Asset": l["destination_ip"],
                    "Threat Category": ", ".join(sorted(list(l["categories"]))),
                    "Total Events": l["incident_count"],
                    "Total Packets": l["total_packets"],
                    "Risk Level": l["severity"]
                })
            df_topo = pd.DataFrame(topo_records)
            st.dataframe(df_topo, use_container_width=True, hide_index=True)
        else:
            st.info("No internal network hosts currently flagged.")

    elif sub_view == "🔍 Source IP Intelligence Inspector":
        st.markdown("#### 🔍 Deep Source IP Provenance Inspector")
        col_search1, col_search2 = st.columns([3, 1])
        with col_search1:
            inspect_ip = st.text_input("Enter IP Address to Inspect", value="128.30.52.100")
        with col_search2:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            run_lookup = st.button("Query GeoLite2 Intelligence", use_container_width=True)

        if inspect_ip:
            intel = geoip_svc.get_ip_intelligence(inspect_ip.strip())
            
            c_res1, c_res2, c_res3 = st.columns(3)
            with c_res1:
                st.markdown(f"""
                <div class="kpi-card">
                    <div class="kpi-title">Classification</div>
                    <div class="kpi-value" style="font-size:18px; color:{'#10B981' if intel.get('is_public') else '#A855F7'};">
                        {'Public Internet IP' if intel.get('is_public') else 'RFC 1918 Private IP'}
                    </div>
                    <div class="kpi-desc">{intel.get('ip_type', 'public')}</div>
                </div>
                """, unsafe_allow_html=True)
            with c_res2:
                st.markdown(f"""
                <div class="kpi-card">
                    <div class="kpi-title">Geographic Location</div>
                    <div class="kpi-value" style="font-size:18px; color:#38BDF8;">
                        {intel.get('city', 'Unknown')}, {intel.get('country', 'Unknown')}
                    </div>
                    <div class="kpi-desc">Region: {intel.get('region', 'N/A')} &bull; Radius: {intel.get('accuracy_radius', 'N/A')} km</div>
                </div>
                """, unsafe_allow_html=True)
            with c_res3:
                st.markdown(f"""
                <div class="kpi-card">
                    <div class="kpi-title">Autonomous System (ASN)</div>
                    <div class="kpi-value" style="font-size:18px; color:#F59E0B;">
                        {intel.get('asn', 'AS-Unknown')}
                    </div>
                    <div class="kpi-desc">{intel.get('org', 'Unknown Provider')}</div>
                </div>
                """, unsafe_allow_html=True)

            if intel.get("latitude") is not None and intel.get("longitude") is not None:
                st.markdown(f"""
                <div style="background:#0F172A; border:1px solid #1E293B; border-radius:10px; padding:12px; margin-top:12px; font-family:monospace; font-size:12px; color:#94A3B8;">
                    <strong>MaxMind Coordinates:</strong> Latitude: {intel['latitude']} &bull; Longitude: {intel['longitude']} &bull; Provider: {intel.get('provider')}
                </div>
                """, unsafe_allow_html=True)


# ==============================================================================
# VIEW 2: GEMINI SECURITY COPILOT & INCIDENT INVESTIGATION
# ==============================================================================
elif nav_selection == "🤖 Gemini Security Copilot & Investigation":
    st.markdown("""
    <div style="background:#0F172A; border:1px solid #1E293B; border-radius:12px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0; font-size:18px; font-weight:700; color:#FFFFFF;">
                    🤖 Gemini Security Copilot & Incident Investigation
                </h3>
                <p style="margin:4px 0 0 0; font-size:12px; color:#94A3B8;">
                    Automated threat reasoning, dual hypotheses (adversary vs benign), and containment plans.
                </p>
            </div>
            <div>
                <span style="background:rgba(6, 182, 212, 0.15); border:1px solid rgba(6, 182, 212, 0.3); color:#06B6D4; font-size:11px; font-weight:700; padding:5px 12px; border-radius:8px; font-family:monospace;">
                    {}
                </span>
            </div>
        </div>
    </div>
    """.format(
        "● GOOGLE GEMINI LIVE AI (ACTIVE)" if explainer.is_gemini_active else "● LOCAL KNOWLEDGE BASE FALLBACK"
    ), unsafe_allow_html=True)

    incidents = db.get_incidents()
    if not incidents:
        st.warning("No security incidents currently in the database.")
    else:
        # Incident Selector
        incident_labels = [
            f"{i.get('incident_id', 'INC')} — {i.get('category', 'Threat')} ({i.get('severity', 'Medium')}) from {i.get('source_ip', '0.0.0.0')}"
            for i in incidents
        ]
        selected_idx = st.selectbox("Select Security Incident for AI Triage", range(len(incidents)), format_func=lambda idx: incident_labels[idx])
        selected_inc = incidents[selected_idx]

        # Trigger deep investigation report
        with st.spinner("Generating Gemini Copilot Threat Reasoning..."):
            investigation = explainer.investigate_incident(selected_inc)
            basic_exp = explainer.explain_incident(selected_inc)
            safe_actions = resp_engine.recommend_safe_actions(selected_inc)

        # Overview Metadata Row
        col_meta1, col_meta2, col_meta3, col_meta4 = st.columns(4)
        with col_meta1:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Incident ID</div>
                <div class="kpi-value" style="font-size:16px;">{selected_inc.get('incident_id')}</div>
                <div class="kpi-desc">Status: {selected_inc.get('status', 'Investigating')}</div>
            </div>
            """, unsafe_allow_html=True)
        with col_meta2:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Severity Assessment</div>
                <div class="kpi-value" style="font-size:16px; color:{'#EF4444' if selected_inc.get('severity') == 'Critical' else '#F59E0B'};">
                    {selected_inc.get('severity', 'High')}
                </div>
                <div class="kpi-desc">Category: {selected_inc.get('category')}</div>
            </div>
            """, unsafe_allow_html=True)
        with col_meta3:
            src_ip = selected_inc.get("source_ip", "0.0.0.0")
            intel = geoip_svc.get_ip_intelligence(src_ip)
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Source Host & GeoIP</div>
                <div class="kpi-value" style="font-size:16px; color:#38BDF8;">{src_ip}</div>
                <div class="kpi-desc">{intel.get('city', 'Unknown')}, {intel.get('country', 'Local / RFC1918')}</div>
            </div>
            """, unsafe_allow_html=True)
        with col_meta4:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Target Asset</div>
                <div class="kpi-value" style="font-size:16px; color:#10B981;">{selected_inc.get('destination_ip', '10.0.0.5')}</div>
                <div class="kpi-desc">Ports: {selected_inc.get('destination_ports', [80])}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # 1. Executive Summary
        st.markdown("#### 📋 Executive Grounded Summary")
        exec_summary = investigation.get("executive_summary") or basic_exp.get("summary")
        st.markdown(f"""
        <div style="background:#0F172A; border-left:4px solid #06B6D4; border-radius:8px; padding:14px 18px; font-size:13px; line-height:1.6; color:#E2E8F0;">
            {exec_summary}
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # 2. Dual Hypotheses (Malicious vs Benign)
        st.markdown("#### ⚖️ Dual Hypotheses Analysis")
        hypotheses = investigation.get("attack_interpretation_and_hypotheses", {})
        col_hyp1, col_hyp2 = st.columns(2)
        with col_hyp1:
            st.markdown(f"""
            <div class="hypothesis-card" style="border-left:4px solid #EF4444;">
                <div style="color:#EF4444; font-weight:700; font-size:12px; text-transform:uppercase; margin-bottom:6px;">
                    🔴 Hypothesis A: Malicious Intrusion
                </div>
                <div style="font-size:12px; color:#CBD5E1; line-height:1.5;">
                    {hypotheses.get('attack_hypothesis', 'Adversary activity targeting network boundary perimeter to execute intrusion techniques.')}
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_hyp2:
            st.markdown(f"""
            <div class="hypothesis-card" style="border-left:4px solid #10B981;">
                <div style="color:#10B981; font-weight:700; font-size:12px; text-transform:uppercase; margin-bottom:6px;">
                    🟢 Hypothesis B: Benign Operational Activity
                </div>
                <div style="font-size:12px; color:#CBD5E1; line-height:1.5;">
                    {hypotheses.get('benign_alternative', 'Authorized internal vulnerability scan, operational backup job, or developer microservice probe.')}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 3. Technical Mechanism & MITRE ATT&CK
        col_tech1, col_tech2 = st.columns(2)
        with col_tech1:
            st.markdown("#### 🔬 Technical Attack Mechanism")
            mech = basic_exp.get("mechanism", "Packet-level anomalous traffic flow deviating from established baseline.")
            st.markdown(f"""
            <div style="background:#0F172A; border:1px solid #1E293B; border-radius:10px; padding:14px; font-size:12px; line-height:1.6; color:#94A3B8;">
                {mech}
            </div>
            """, unsafe_allow_html=True)

        with col_tech2:
            st.markdown("#### 🎯 MITRE ATT&CK Alignment")
            mitre = basic_exp.get("mitre_technique", "T1046 - Network Service Discovery")
            st.markdown(f"""
            <div style="background:#0F172A; border:1px solid #1E293B; border-radius:10px; padding:14px; font-size:12px; line-height:1.6; color:#94A3B8;">
                <strong style="color:#06B6D4;">Technique:</strong> {mitre}<br>
                <strong style="color:#F59E0B;">Impact:</strong> {basic_exp.get('potential_impact', 'Unauthorized perimeter discovery and operational exposure.')}
            </div>
            """, unsafe_allow_html=True)

        # 4. Containment Recommendations & Rollback Plan
        st.markdown("#### 🛡️ Safe Containment Plan & Rollback Verification")
        target_ip = selected_inc.get("source_ip", "192.168.1.100")
        block_cmds = resp_engine.generate_firewall_commands(target_ip)
        rollback_cmds = resp_engine.generate_rollback_commands(target_ip)

        tab_plan, tab_cmds, tab_rollback = st.tabs(["Containment Actions", "Firewall Commands (Windows/Linux)", "Safe Rollback Instructions"])
        with tab_plan:
            st.write("Recommended containment steps:")
            recs = basic_exp.get("containment_recommendations", ["Drop source IP at boundary firewall", "Verify host credentials"])
            for r in recs:
                st.markdown(f"- **{r}**")
        with tab_cmds:
            st.markdown(f"**Windows Netsh Command:**")
            st.code(block_cmds.get("windows_netsh", f"netsh advfirewall firewall add rule name=\"SentinelAI_Block_{target_ip}\" dir=in action=block remoteip={target_ip}"), language="bat")
            st.markdown(f"**Linux Iptables Command:**")
            st.code(block_cmds.get("linux_iptables", f"iptables -I INPUT -s {target_ip} -j DROP"), language="bash")
        with tab_rollback:
            st.markdown(f"**Windows Netsh Rollback:**")
            st.code(rollback_cmds.get("windows_netsh", f"netsh advfirewall firewall delete rule name=\"SentinelAI_Block_{target_ip}\""), language="bat")
            st.markdown(f"**Linux Iptables Rollback:**")
            st.code(rollback_cmds.get("linux_iptables", f"iptables -D INPUT -s {target_ip} -j DROP"), language="bash")


# ==============================================================================
# VIEW 3: LIVE NETWORK MONITORING
# ==============================================================================
elif nav_selection == "📡 Live Network Monitoring":
    st.markdown("### 📡 Real-Time Network Packet Telemetry")
    logs = db.get_network_logs(limit=100)
    if logs:
        df_logs = pd.DataFrame(logs)
        cols_to_show = [c for c in ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "packet_size", "detection_reason", "severity"] if c in df_logs.columns]
        st.dataframe(df_logs[cols_to_show], use_container_width=True, hide_index=True)
    else:
        st.info("No active telemetry flows captured yet.")


# ==============================================================================
# VIEW 4: AUTONOMOUS RESPONSE & CONTAINMENT
# ==============================================================================
elif nav_selection == "🛡️ Autonomous Response & Containment":
    st.markdown("### 🛡️ Active Containment Rules & Safe Rollbacks")
    blocks = db.get_active_blocks()
    if blocks:
        st.dataframe(pd.DataFrame(blocks), use_container_width=True, hide_index=True)
    else:
        st.info("No active host quarantines currently applied.")


# ==============================================================================
# VIEW 5: EMBEDDED REACT WEB APP
# ==============================================================================
elif nav_selection == "💻 Embedded React Web App":
    st.markdown(f"""
    <div style="background:#0F172A; border:1px solid #1E293B; border-radius:10px; padding:12px 18px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center;">
        <div>
            <span style="color:#06B6D4; font-weight:700;">React Standalone SPA:</span>
            <span style="color:#94A3B8; font-size:12px; margin-left:8px;">Running at {new_ui_url}</span>
        </div>
        <a href="{new_ui_url}" target="_blank" style="background:#06B6D4; color:#0B0F19; font-weight:700; font-size:11px; padding:5px 12px; border-radius:6px; text-decoration:none;">
            Open in Full Browser Tab ↗
        </a>
    </div>
    """, unsafe_allow_html=True)
    components.iframe(new_ui_url, height=920, scrolling=True)