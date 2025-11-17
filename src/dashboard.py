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


# --------------------- Load Custom Dark CSS --------------------- #
def load_css():
    try:
        with open("src/style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning("⚠ style.css not found. Using default Streamlit theme.")


# --------------------- Streamlit Page Config --------------------- #
st.set_page_config(
    page_title="FlowSleuth - Network DFIR Dashboard",
    layout="wide"
)
load_css()

# Header Banner
st.markdown("""
<div style='padding:10px 0;font-size:28px;color:#00e5ff;font-weight:600;
text-align:center;text-shadow:0 0 10px rgba(0,229,255,0.7);'>
🚨 FlowSleuth Network Threat Intelligence Dashboard 🚨
</div>
""", unsafe_allow_html=True)


# --------------------- File Upload Section --------------------- #
flow_file = st.file_uploader("📥 Upload Network Flow CSV", type=["csv"])
fw_file = st.file_uploader("🛡 Upload Firewall Log CSV", type=["csv"])

# --------------------- Flow Data Processing --------------------- #
if flow_file:
    st.info("⏳ Processing network flow data...")

    flows = load_flows(flow_file)
    flows = flag_suspicious_downloads(flows)

    suspicious = summarize_suspicious(flows)
    suspicious = enrich_with_threat_intel(suspicious)

    st.subheader("🚨 Suspicious Connections")
    st.dataframe(suspicious, use_container_width=True)

    # Beaconing detection
    beacon = detect_beaconing(flows)
    st.subheader("📡 Potential Beaconing Activity")
    st.dataframe(beacon, use_container_width=True)

    # Basic stats
    st.subheader("📊 Network Summary Stats")
    st.metric("Total Connections", len(flows))
    st.metric("Suspicious Connections", len(suspicious))
    st.metric("Beaconing Candidates", len(beacon))

# --------------------- Firewall Log Processing --------------------- #
if fw_file:
    st.info("⏳ Loading firewall logs...")
    fw = load_firewall_logs(fw_file)

    st.subheader("🛡 Firewall Logs")
    st.dataframe(fw, use_container_width=True)

