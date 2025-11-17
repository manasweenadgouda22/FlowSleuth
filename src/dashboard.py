import streamlit as st
import pandas as pd

from pcap_analysis import load_flows, flag_suspicious_downloads, detect_beaconing, summarize_suspicious
from log_analysis import load_firewall_logs, correlate_with_flows
from threat_intel import enrich_with_threat_intel

st.set_page_config(page_title="FlowSleuth DFIR Dashboard", layout="wide")

st.title("🔍 FlowSleuth Network Threat Analysis Dashboard")

flows_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])
fw_file = st.file_uploader("Upload Firewall Logs CSV", type=["csv"])

if flows_file:
    flows = load_flows(flows_file)
    flows = flag_suspicious_downloads(flows)
    flows = detect_beaconing(flows)

    st.subheader("📌 Suspicious Flow Activity")
    st.write(flows.head())

if flows_file and fw_file:
    fw = load_firewall_logs(fw_file)
    merged = correlate_with_flows(flows, fw)
    enriched = enrich_with_threat_intel(merged)

    st.subheader("🚨 Correlated Threat Events")
    st.dataframe(summarize_suspicious(enriched))

    st.download_button(
        "⬇ Download Correlated Report",
        enriched.to_csv(index=False),
        "correlated_report.csv",
        "text/csv"
    )
