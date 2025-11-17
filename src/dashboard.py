import streamlit as st
from src.pcap_analysis import load_flows, flag_suspicious_downloads, detect_beaconing, summarize_suspicious
from src.log_analysis import load_firewall_logs
from src.threat_intel import enrich_with_threat_intel

st.title("🕵️ FlowSleuth - Network DFIR Dashboard")

flow_file = st.file_uploader("Upload Flow CSV", type=["csv"])
fw_file = st.file_uploader("Upload Firewall CSV", type=["csv"])

if flow_file:
    flows = load_flows(flow_file)
    flows = flag_suspicious_downloads(flows)
    suspicious = summarize_suspicious(flows)
    suspicious = enrich_with_threat_intel(suspicious)

    st.subheader("🚨 Suspicious Connections")
    st.dataframe(suspicious)

    beacon = detect_beaconing(flows)
    st.subheader("📡 Potential Beaconing")
    st.dataframe(beacon)

if fw_file:
    fw = load_firewall_logs(fw_file)
    st.subheader("🛡 Firewall Logs")
    st.dataframe(fw)
