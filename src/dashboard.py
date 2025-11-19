import sys, os
sys.path.append(os.path.dirname(__file__))

import streamlit as st
from pcap_analysis import load_flows, flag_suspicious_downloads, detect_beaconing, summarize_suspicious
from log_analysis import load_firewall_logs
from threat_intel import enrich_with_threat_intel
import pandas as pd

st.set_page_config(layout="wide")

# Apply custom CSS
with open(os.path.join(os.path.dirname(__file__), "style.css")) as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.markdown("<h1 class='title'>🕵️ FlowSleuth: Network Threat Intelligence Dashboard</h1>", unsafe_allow_html=True)

# Upload sections
st.subheader("📥 Upload Network Flow CSV")
flow_file = st.file_uploader("Upload Flow CSV", type=["csv"])

st.subheader("🛡 Upload Firewall Log CSV")
fw_file = st.file_uploader("Upload Firewall CSV", type=["csv"])

# Process Flow CSV
if flow_file:
    try:
        flows = load_flows(flow_file)
        flows = flag_suspicious_downloads(flows)
        suspicious = summarize_suspicious(flows)
        suspicious = enrich_with_threat_intel(suspicious)

        st.subheader("🚨 Suspicious Network Activity")
        st.dataframe(suspicious)

        beacon = detect_beaconing(flows)
        st.subheader("📡 Beaconing Detection")
        st.dataframe(beacon)

    except Exception as e:
        st.error(f"Error processing flow file: {e}")

# Process Firewall CSV
if fw_file:
    try:
        fw = load_firewall_logs(fw_file)
        st.subheader("🛡 Firewall Logs")
        st.dataframe(fw)
    except Exception as e:
        st.error(f"Error processing firewall file: {e}")
