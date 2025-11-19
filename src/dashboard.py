import streamlit as st
import pandas as pd
import altair as alt

from pcap_analysis import (
    load_flows,
    flag_suspicious_downloads,
    detect_beaconing,
    summarize_suspicious
)

from log_analysis import load_firewall_logs
from threat_intel import enrich_with_threat_intel

# ============================================
# PAGE SETTINGS (makes the UI wide + modern)
# ============================================
st.set_page_config(
    page_title="FlowSleuth Network DFIR Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================
# LOAD CSS THEME (Darktrace/Splunk look)
# ============================================
with open("src/style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.markdown(
    "<h1 class='title-center'>🕵️ FlowSleuth: Network Threat Intelligence Dashboard</h1>",
    unsafe_allow_html=True,
)

# ============================================
# FILE UPLOAD SECTION
# ============================================
st.markdown("### 📥 Upload Data")

col1, col2 = st.columns(2)

with col1:
    flow_file = st.file_uploader("**Upload Network Flow CSV**", type=["csv"])
with col2:
    fw_file = st.file_uploader("**Upload Firewall Log CSV**", type=["csv"])


# ============================================
# PROCESS DATA
# ============================================
flows_df, firewall_df = None, None
suspicious_df, beacon_df, threat_df = None, None, None

if flow_file:
    flows_df = load_flows(flow_file)
    flows_df = flag_suspicious_downloads(flows_df)
    suspicious_df = summarize_suspicious(flows_df)
    beacon_df = detect_beaconing(flows_df)
    threat_df = enrich_with_threat_intel(suspicious_df)

if fw_file:
    firewall_df = load_firewall_logs(fw_file)


# ============================================
# TABS (Splunk-like)
# ============================================
tab1, tab2, tab3, tab4 = st.tabs(
    ["📊 Flows", "🛡 Firewall", "🚨 Threat Intel", "📈 Summary"]
)

# ============================================
# FLOWS TAB
# ============================================
with tab1:
    st.subheader("📊 Network Flow Records")

    if flows_df is None:
        st.info("Upload a Flow CSV to view this section.")
    else:
        st.dataframe(flows_df, use_container_width=True)

        # --- TOP ATTACKERS CHART ---
        st.markdown("### 🔥 Top Source IPs (Attackers)")
        chart1 = (
            alt.Chart(flows_df)
            .mark_bar(color="#cc3300")
            .encode(
                x=alt.X("src_ip:N", sort="-y"),
                y="count()"
            )
        )
        st.altair_chart(chart1, use_container_width=True)

        # --- TOP TARGETS CHART ---
        st.markdown("### 🎯 Top Targeted Destination IPs")
        chart2 = (
            alt.Chart(flows_df)
            .mark_bar(color="#0066cc")
            .encode(
                x=alt.X("dst_ip:N", sort="-y"),
                y="count()"
            )
        )
        st.altair_chart(chart2, use_container_width=True)

        # --- RISKY PORTS ---
        st.markdown("### ⚠️ Risky Destination Ports")
        chart3 = (
            alt.Chart(flows_df)
            .mark_bar(color="#ffaa00")
            .encode(
                x=alt.X("dst_port:O"),
                y="count()"
            )
        )
        st.altair_chart(chart3, use_container_width=True)


# ============================================
# FIREWALL TAB
# ============================================
with tab2:
    st.subheader("🛡 Firewall Logs")

    if firewall_df is None:
        st.info("Upload a Firewall CSV to view this section.")
    else:
        st.dataframe(firewall_df, use_container_width=True)

        chart_fw = (
            alt.Chart(firewall_df)
            .mark_bar(color="#33cc33")
            .encode(
                x=alt.X("action:N"),
                y="count()"
            )
        )
        st.markdown("### 🔥 Firewall Actions (Allow vs Block)")
        st.altair_chart(chart_fw, use_container_width=True)


# ============================================
# THREAT INTEL TAB
# ============================================
with tab3:
    st.subheader("🚨 Enriched Threat Intelligence")

    if threat_df is None:
        st.info("Upload a Flow CSV to view this section.")
    else:
        st.dataframe(threat_df, use_container_width=True)

        st.markdown("### 🔎 IOC Counts")
        chart_threat = (
            alt.Chart(threat_df)
            .mark_bar(color="#9900cc")
            .encode(
                x=alt.X("threat_label:N"),
                y="count()"
            )
        )
        st.altair_chart(chart_threat, use_container_width=True)


# ============================================
# SUMMARY TAB
# ============================================
with tab4:
    st.subheader("📈 Summary & Analytics")

    if flows_df is None:
        st.info("Upload a Flow CSV to view summary charts.")
    else:
        colA, colB = st.columns(2)

        with colA:
            st.metric("Total Flows", len(flows_df))
            st.metric("Suspicious Flows", len(suspicious_df))

        with colB:
            st.metric("Unique Source IPs", flows_df["src_ip"].nunique())
            st.metric("Unique Destinations", flows_df["dst_ip"].nunique())

        st.markdown("### 📡 Beaconing Detection")
        if beacon_df is not None and len(beacon_df) > 0:
            st.dataframe(beacon_df, use_container_width=True)
        else:
            st.success("No beaconing detected.")
