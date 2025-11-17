import streamlit as st
import pandas as pd

from pcap_analysis import load_flows, flag_suspicious_downloads, detect_beaconing, summarize_suspicious
from .log_analysis import load_firewall_logs, correlate_with_flows
from .threat_intel import enrich_with_dummy_threat_scores

st.set_page_config(page_title="FlowSleuth", layout="wide")

st.title("FlowSleuth – Suspicious Outbound Traffic Hunter")

st.markdown(
    "Analyze PCAP-derived flow data and firewall logs to quickly spot **suspicious outbound connections** " \
    "for DFIR and threat‑hunting demos."
)

# Sidebar – file upload
st.sidebar.header("Upload Data")

flow_file = st.sidebar.file_uploader("Flow/PCAP metadata CSV", type=["csv"], key="flow")
fw_file = st.sidebar.file_uploader("Firewall log CSV", type=["csv"], key="fw")

sample_mode = st.sidebar.checkbox("Use built-in sample data", value=not (flow_file and fw_file))

@st.cache_data
def load_sample_data():
    flows = pd.read_csv("data/sample_flows.csv")
    fw = pd.read_csv("data/sample_firewall.csv")
    flows["timestamp"] = pd.to_datetime(flows["timestamp"])
    fw["timestamp"] = pd.to_datetime(fw["timestamp"])
    return flows, fw

if sample_mode:
    flows_df, fw_df = load_sample_data()
else:
    if not flow_file or not fw_file:
        st.warning("Upload both a flow CSV and a firewall CSV, or select sample mode.")
        st.stop()
    flows_df = load_flows(flow_file)
    fw_df = load_firewall_logs(fw_file)

# Analysis pipeline
flows_df = flag_suspicious_downloads(flows_df)
flows_df = detect_beaconing(flows_df)
merged_df = correlate_with_flows(flows_df, fw_df)
suspicious_df = summarize_suspicious(merged_df)
suspicious_df = enrich_with_dummy_threat_scores(suspicious_df)

# KPI cards
total_flows = len(flows_df)
total_unique_dst = flows_df["dst_ip"].nunique()
total_suspicious = len(suspicious_df)
high_risk = (suspicious_df["threat_level"] == "High").sum()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total flows", f"{total_flows}")
c2.metric("Unique destinations", f"{total_unique_dst}")
c3.metric("Suspicious flows", f"{total_suspicious}")
c4.metric("High-risk destinations", f"{high_risk}")

st.subheader("Suspicious Outbound Connections")

if suspicious_df.empty:
    st.info("No suspicious flows detected with current heuristics. Try adjusting thresholds in config.py or different data.")
else:
    st.dataframe(suspicious_df.sort_values("threat_score", ascending=False))

    st.subheader("Top Suspicious Destination IPs")

    top_dst = (
        suspicious_df.groupby(["dst_ip", "threat_level"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
        .head(10)
    )

    # Simple bar chart using Streamlit's built-in charting
    chart_data = top_dst.set_index("dst_ip")["count"]
    st.bar_chart(chart_data)

st.markdown("---")
st.markdown("Created for Master-level DFIR / Threat-Hunting portfolio demos.")
