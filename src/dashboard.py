import streamlit as st
import pandas as pd
import plotly.express as px

from src.pcap_analysis import (
    load_flows,
    flag_suspicious_downloads,
    detect_beaconing
)
from src.firewall_analysis import load_firewall_logs
from src.threat_intel import enrich_with_threat_intel

st.set_page_config(layout="wide", page_title="FlowSleuth DFIR Dashboard")

# custom CSS
with open("src/style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# -------------------------
# HEADER
# -------------------------
st.markdown("<h1 class='app-title'>🕵️‍♂️ FlowSleuth: Network Threat Intelligence Dashboard</h1>", unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(["🌊 Flows", "🛡 Firewall", "🧠 Threat Intel", "📊 Summary"])


# ============================================================
# 1️⃣ FLOWS TAB
# ============================================================
with tab1:
    st.markdown("## 🌊 Flow Analysis")

    flow_file = st.file_uploader("Upload Flow CSV", type=["csv"], key="flow")

    if flow_file:
        df = load_flows(flow_file)
        df = flag_suspicious_downloads(df)
        beacon_df = detect_beaconing(df)

        st.markdown("### 📄 Uploaded Flow Data")
        st.dataframe(df, height=250, use_container_width=True)

        # -------- GRID LAYOUT (Equal Boxes) --------
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 📥 Top Destination IPs by Bytes")
            top_dst = df.groupby("dst_ip")["bytes"].sum().reset_index()
            fig1 = px.bar(
                top_dst.sort_values("bytes", ascending=False),
                x="bytes", y="dst_ip", orientation="h",
                height=350
            )
            st.plotly_chart(fig1, use_container_width=True)

        with col2:
            st.markdown("### 📁 File Type Distribution")
            fig2 = px.pie(
                df,
                names="file_type",
                height=350,
                hole=0.4
            )
            st.plotly_chart(fig2, use_container_width=True)

        # -------- Next Row --------
        col3, col4 = st.columns(2)

        with col3:
            st.markdown("### 🚦 Port Usage (Suspicious vs Normal)")
            df["port_type"] = df["is_suspicious_port"].map({True: "Suspicious", False: "Normal"})
            fig3 = px.bar(
                df.groupby(["dst_port", "port_type"]).size().reset_index(name="count"),
                x="dst_port", y="count", color="port_type",
                height=350,
                color_discrete_map={"Suspicious": "#ff6b6b", "Normal": "#4caf50"}
            )
            st.plotly_chart(fig3, use_container_width=True)

        with col4:
            st.markdown("### 🛰 Potential Beaconing")
            st.dataframe(beacon_df, height=350, use_container_width=True)


# ============================================================
# 2️⃣ FIREWALL TAB
# ============================================================
with tab2:
    st.markdown("## 🛡 Firewall Logs")

    firewall_file = st.file_uploader("Upload Firewall CSV", type=["csv"], key="fw")

    if firewall_file:
        fw = load_firewall_logs(firewall_file)

        # Replace None/empty rule names with meaningful labels
        fw["rule_name"] = fw["rule_name"].replace({"": "Unspecified Policy", None: "Unspecified Policy"})

        st.dataframe(fw, height=250, use_container_width=True)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🔥 Firewall Actions (Allow vs Block)")
            chart = px.bar(
                fw.groupby("action").size().reset_index(name="count"),
                x="action", y="count",
                color="action",
                height=350,
                color_discrete_map={"ALLOW": "#6bc46b", "BLOCK": "#ff5252"}
            )
            st.plotly_chart(chart, use_container_width=True)

        with col2:
            st.markdown("### 🌍 Destination IP Hit Count")
            ip_hits = fw.groupby("dst_ip").size().reset_index(name="count")
            fig = px.bar(
                ip_hits.sort_values("count", ascending=False),
                x="count", y="dst_ip", orientation="h",
                height=350
            )
            st.plotly_chart(fig, use_container_width=True)


# ============================================================
# 3️⃣ THREAT INTEL TAB
# ============================================================
with tab3:
    st.markdown("## 🧠 Threat Intelligence Enrichment")

    ti_file = st.file_uploader("Upload Flow CSV for TI Enrichment", type=["csv"], key="ti")

    if ti_file:
        df = load_flows(ti_file)
        df = flag_suspicious_downloads(df)
        enriched = enrich_with_threat_intel(df)

        st.markdown("### 🧩 TI-Enriched Suspicious Flows")
        st.dataframe(enriched, height=250, use_container_width=True)

        st.download_button(
            "⬇ Download TI-Enriched CSV",
            enriched.to_csv(index=False).encode("utf-8"),
            "ti_enriched_flows.csv",
            "text/csv"
        )

        colA, colB = st.columns(2)

        with colA:
            st.markdown("### 🚨 Top High-Risk Destinations")
            fig = px.bar(
                enriched.groupby(["dst_ip", "risk_level"])["risk_score"]
                .max()
                .reset_index(),
                x="risk_score",
                y="dst_ip",
                color="risk_level",
                height=350,
                color_discrete_map={
                    "HIGH": "#ff4d4d",
                    "MEDIUM": "#ffb84d",
                    "LOW": "#7cd992"
                }
            )
            st.plotly_chart(fig, use_container_width=True)

        with colB:
            st.markdown("### 🌎 GeoIP Distribution (Demo)")
            geo_demo = pd.DataFrame({
                "country": ["NL", "US"],
                "count": [4, 6]
            })
            fig = px.bar(geo_demo, x="country", y="count", height=350)
            st.plotly_chart(fig, use_container_width=True)


# ============================================================
# 4️⃣ SUMMARY TAB
# ============================================================
with tab4:
    st.markdown("## 📊 Summary Dashboard")

    st.markdown("""
    ### 🚀 Key Highlights  
    - Suspicious flows detected  
    - High-risk destinations identified  
    - Threat intel enrichment completed  
    - Visual analysis across ports, file types, IPs  
    """)

    st.info("More summary charts and ML anomaly detection can be added here.")
