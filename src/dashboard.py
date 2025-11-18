import streamlit as st
import pandas as pd
from src.pcap_analysis import load_flows, flag_suspicious_downloads, detect_beaconing, summarize_suspicious
from src.log_analysis import load_firewall_logs

st.set_page_config(page_title="FlowSleuth DFIR Dashboard", layout="wide")

st.markdown("<h1 style='text-align: center; color: #117A65;'>🕵️ FlowSleuth: Network Threat Intelligence Dashboard</h1>", unsafe_allow_html=True)

flow_file = st.file_uploader("📥 Upload Network Flow CSV/XLSX", type=["csv", "xlsx"])
fw_file = st.file_uploader("🛡 Upload Firewall Log CSV/XLSX", type=["csv", "xlsx"])

# ----- FLOW ANALYSIS -----
if flow_file:
    try:
        flows = load_flows(flow_file)
        flows = flag_suspicious_downloads(flows)
        suspicious = summarize_suspicious(flows)
        beacon = detect_beaconing(flows)

        st.subheader("🚨 Suspicious Network Activity")
        st.dataframe(suspicious, use_container_width=True)

        st.subheader("📡 Potential Beaconing Behavior")
        st.dataframe(beacon, use_container_width=True)

    except Exception as e:
        st.error(f"❌ Error processing Flow file: {e}")

# ----- FIREWALL LOG ANALYSIS -----
if fw_file:
    try:
        logs = load_firewall_logs(fw_file)
        st.subheader("🧱 Firewall Logs")
        st.dataframe(logs, use_container_width=True)

    except Exception as e:
        st.error(f"❌ Error processing Firewall log file: {e}")
