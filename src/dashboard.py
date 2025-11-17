import streamlit as st
import pandas as pd
from pcap_analysis import (
    load_flows,
    flag_suspicious_downloads,
    detect_beaconing,
    summarize_suspicious
)
from log_analysis import load_firewall_logs
from threat_intel import enrich_with_threat_intel

# -------- Load Custom CSS -------- #
def load_css():
    try:
        with open("src/style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        pass

st.set_page_config(
    page_title="FlowSleuth Network DFIR Dashboard",
    layout="wide"
)

load_css()

st.markdown("""
<div class="app-title">
🕵️ FlowSleuth: Network Threat Intelligence Dashboard
</div>
""", unsafe_allow_html=True)


# ===== File Upload Section ===== #
st.markdown("### 📥 Upload Network Flow CSV")
flow_file = st.file_uploader("Upload Flow CSV", type=["csv"])

st.markdown("### 🛡 Upload Firewall Log CSV")
fw_file = st.file_uploader("Upload Firewall CSV", type=["csv"])


# ===== Flow Analysis Section ===== #
if flow_file:
    st.markdown("---")
    st.markdown("### 🚨 Suspicious Network Activity")

    flows = load_flows(flow_file)
    flows = flag_suspicious_downloads(flows)
    suspicious = summarize_suspicious(flows)
    suspicious = enrich_with_threat_intel(suspicious)

    st.subheader("🔎 Suspicious Connections")
    st.dataframe(suspicious, use_container_width=True)

    beacon = detect_beaconing(flows)
    st.subheader("📡 Possible Beacon
