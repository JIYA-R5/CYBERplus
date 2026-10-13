# main dahboard
import streamlit as st
import pandas as pd
import plotly.express as px

# Page configuration
st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide"
)

# Dashboard title
st.title("🛡️ SentinelAI")
st.subheader("AI-Powered Network Threat Detection & Response")

st.write(
    "Monitor network activity, identify suspicious patterns, "
    "and understand potential security threats."
)

# Sample security data
data = {
    "Time": [
        "10:00:01",
        "10:00:05",
        "10:00:10",
        "10:00:15",
        "10:00:20"
    ],
    "Source IP": [
        "192.168.1.10",
        "192.168.1.15",
        "192.168.1.20",
        "192.168.1.15",
        "192.168.1.25"
    ],
    "Activity": [
        "Normal Traffic",
        "Port Scan",
        "Normal Traffic",
        "Brute Force",
        "Normal Traffic"
    ],
    "Risk": [
        "Low",
        "High",
        "Low",
        "High",
        "Low"
    ],
    "Packets": [
        120,
        450,
        150,
        380,
        100
    ]
}

df = pd.DataFrame(data)

# Dashboard metrics
col1, col2, col3 = st.columns(3)

col1.metric(
    "Traffic Records",
    len(df)
)

col2.metric(
    "Suspicious Activities",
    int((df["Risk"] == "High").sum())
)

col3.metric(
    "High-Risk Alerts",
    int((df["Risk"] == "High").sum())
)

st.divider()

# Traffic visualization
st.subheader("📊 Network Traffic Overview")

fig = px.line(
    df,
    x="Time",
    y="Packets",
    markers=True,
    title="Sample Network Traffic"
)

st.plotly_chart(
    fig,
    use_container_width=True
)

# Security alerts
st.subheader("🚨 Security Alerts")

alerts = df[df["Risk"] == "High"]

st.dataframe(
    alerts,
    use_container_width=True,
    hide_index=True
)

# AI explanation preview
st.subheader("🤖 Threat Explanation")

for _, row in alerts.iterrows():

    with st.expander(
        f"{row['Activity']} — {row['Source IP']}"
    ):

        if row["Activity"] == "Port Scan":

            st.write(
                "Possible port scanning activity. "
                "Investigate whether the source is attempting "
                "connections to multiple network ports."
            )

        elif row["Activity"] == "Brute Force":

            st.write(
                "Possible repeated login attempts. "
                "Review authentication logs to determine "
                "whether unauthorized access was attempted."
            )

        st.warning(
            f"Risk Level: {row['Risk']}"
        )

st.caption(
    "SentinelAI MVP | Demonstration data only"
)