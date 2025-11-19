"""
dashboard.py – FlowSleuth Hybrid Visual Dashboard
Run locally with:  streamlit run src/dashboard.py
"""

import io

import altair as alt
import pandas as pd
import streamlit as st

from config import SUSPICIOUS_PORTS
from log_analysis import (
    load_firewall_logs,
    summarize_firewall_actions,
    top_blocked_destinations,
)
from pcap_analysis import (
    load_flows,
    flag_suspicious_downloads,
    detect_beaconing,
    summarize_suspicious,
    compute_flow_kpis,
)
from threat_intel import enrich_with_threat_intel, apply_risk_scoring, add_geoip_country


# ------------------------------------------------------------------
# Page config + CSS
# ------------------------------------------------------------------
st.set_page_config(
    page_title="FlowSleuth – Network Threat Intelligence Dashboard",
    layout="wide",
    page_icon="🕵️",
)


def load_local_css(path: str = "src/style.css") -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        # Safe to ignore in case someone runs from a different folder
        pass


load_local_css()

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------
st.markdown(
    '<div class="app-title">🕵️ FlowSleuth: Network Threat Intelligence Dashboard</div>',
    unsafe_allow_html=True,
)
st.caption(
    "Upload flow and firewall logs to quickly spot risky file transfers, "
    "suspicious ports, and indicators enriched with basic threat intel."
)

# ------------------------------------------------------------------
# File upload section
# ------------------------------------------------------------------
st.markdown("### 📁 Upload Data")

col_flow, col_fw = st.columns(2)

with col_flow:
    flow_file = st.file_uploader(
        "Upload Network Flow CSV/XLSX",
        type=["csv", "xlsx", "xls"],
        key="flow",
    )

with col_fw:
    fw_file = st.file_uploader(
        "Upload Firewall Log CSV/XLSX",
        type=["csv", "xlsx", "xls"],
        key="fw",
    )

flows = None
fw_logs = None
suspicious = None
beaconing = None
ti_enriched = None

# ------------------------------------------------------------------
# Load & process data
# ------------------------------------------------------------------
if flow_file is not None:
    flows = load_flows(flow_file)
    flows = flag_suspicious_downloads(flows)
    suspicious = summarize_suspicious(flows)
    beaconing = detect_beaconing(flows)

    # Threat intel + risk
    ti_enriched = enrich_with_threat_intel(suspicious)
    ti_enriched = apply_risk_scoring(ti_enriched)
    ti_enriched = add_geoip_country(ti_enriched)

if fw_file is not None:
    fw_logs = load_firewall_logs(fw_file)

# ------------------------------------------------------------------
# Tabs
# ------------------------------------------------------------------
tab_flows, tab_fw, tab_ti, tab_summary = st.tabs(
    ["📊 Flows", "🛡 Firewall", "🧠 Threat Intel", "📈 Summary"]
)

# ------------------------------------------------------------------
# FLOWS TAB
# ------------------------------------------------------------------
with tab_flows:
    st.subheader("📊 Network Flows & Suspicious Activity")

    if flows is None:
        st.info("Upload a **Network Flow** file to see flow analytics.")
    else:
        st.markdown("#### Raw Flow Data")
        st.dataframe(flows, use_container_width=True, height=260)

        if suspicious is not None and not suspicious.empty:
            st.markdown("#### 🚨 Suspicious Flows (based on bytes, ports, file types)")
            st.dataframe(suspicious, use_container_width=True, height=260)

            # Download button for suspicious flows
            csv_bytes = suspicious.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Suspicious Flows (CSV)",
                data=csv_bytes,
                file_name="flows_suspicious.csv",
                mime="text/csv",
            )

            # Charts
            st.markdown("#### 🔍 Flow Visuals")

            c1, c2 = st.columns(2)

            # Top destination IPs by bytes
            with c1:
                top_dst = (
                    suspicious.groupby("dst_ip")["bytes"]
                    .sum()
                    .reset_index()
                    .sort_values("bytes", ascending=False)
                    .head(10)
                )
                if not top_dst.empty:
                    chart_dst = (
                        alt.Chart(top_dst)
                        .mark_bar()
                        .encode(
                            x=alt.X("bytes:Q", title="Total Bytes"),
                            y=alt.Y("dst_ip:N", sort="-x", title="Destination IP"),
                            tooltip=["dst_ip", "bytes"],
                        )
                        .properties(title="Top Destination IPs by Bytes")
                    )
                    st.altair_chart(chart_dst, use_container_width=True)

            # File type distribution
            with c2:
                file_dist = (
                    suspicious.groupby("file_type")
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                )
                if not file_dist.empty:
                    chart_file = (
                        alt.Chart(file_dist)
                        .mark_arc(innerRadius=40)
                        .encode(
                            theta="count:Q",
                            color=alt.Color("file_type:N", title="File Type"),
                            tooltip=["file_type", "count"],
                        )
                        .properties(title="File Type Distribution")
                    )
                    st.altair_chart(chart_file, use_container_width=True)

            # Port distribution
            ports = (
                flows.groupby("dst_port")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            if not ports.empty:
                # Label suspicious ports
                ports["port_category"] = ports["dst_port"].apply(
                    lambda p: "Suspicious" if p in SUSPICIOUS_PORTS else "Normal"
                )

                chart_ports = (
                    alt.Chart(ports)
                    .mark_bar()
                    .encode(
                        x=alt.X("dst_port:O", title="Destination Port"),
                        y=alt.Y("count:Q", title="Number of Flows"),
                        color=alt.Color(
                            "port_category:N",
                            scale=alt.Scale(
                                domain=["Suspicious", "Normal"],
                                range=["#FF6B6B", "#4CAF50"],
                            ),
                            legend=alt.Legend(title="Port Type"),
                        ),
                        tooltip=["dst_port", "count", "port_category"],
                    )
                    .properties(title="Port Usage (Suspicious vs Normal)")
                )
                st.altair_chart(chart_ports, use_container_width=True)

        if beaconing is not None and not beaconing.empty:
            st.markdown("#### 📡 Potential Beaconing (repeated connections)")
            st.dataframe(beaconing, use_container_width=True, height=200)

# ------------------------------------------------------------------
# FIREWALL TAB
# ------------------------------------------------------------------
with tab_fw:
    st.subheader("🛡 Firewall Logs")

    if fw_logs is None:
        st.info("Upload a **Firewall Log** file to see firewall analytics.")
    else:
        st.markdown("#### Raw Firewall Events")
        st.dataframe(fw_logs, use_container_width=True, height=260)

        # Download firewall logs
        fw_csv = fw_logs.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Firewall Logs (CSV)",
            data=fw_csv,
            file_name="firewall_logs.csv",
            mime="text/csv",
        )

        st.markdown("#### 🔥 Firewall Actions (Allow vs Block)")
        summary = summarize_firewall_actions(fw_logs)
        if not summary.empty:
            chart_fw = (
                alt.Chart(summary)
                .mark_bar()
                .encode(
                    x=alt.X("action:N", title="Action"),
                    y=alt.Y("count:Q", title="Count of Records"),
                    color=alt.Color(
                        "action:N",
                        scale=alt.Scale(
                            domain=["ALLOW", "BLOCK"],
                            range=["#4CAF50", "#FF6B6B"],
                        ),
                        legend=None,
                    ),
                    tooltip=["action", "count"],
                )
                .properties(title="Firewall Actions")
            )
            st.altair_chart(chart_fw, use_container_width=True)

        st.markdown("#### 🚫 Top Blocked Destinations")
        top_block = top_blocked_destinations(fw_logs)
        if not top_block.empty:
            st.dataframe(top_block, use_container_width=True, height=200)

# ------------------------------------------------------------------
# THREAT INTEL TAB
# ------------------------------------------------------------------
with tab_ti:
    st.subheader("🧠 Threat Intel & Risk View")

    if ti_enriched is None or ti_enriched.empty:
        st.info(
            "Suspicious flows with threat intel will appear here once you upload a "
            "valid **Network Flow** file."
        )
    else:
        st.markdown("#### Enriched Suspicious Flows with Risk Scores")
        st.dataframe(ti_enriched, use_container_width=True, height=280)

        # Download button
        ti_csv = ti_enriched.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download TI-Enriched Flows (CSV)",
            data=ti_csv,
            file_name="flows_threat_intel.csv",
            mime="text/csv",
        )

        c1, c2 = st.columns(2)

        # Top high-risk connections
        with c1:
            top_risk = (
                ti_enriched.sort_values("risk_score", ascending=False)
                .head(10)[["src_ip", "dst_ip", "risk_score", "risk_level"]]
            )
            if not top_risk.empty:
                chart_risk = (
                    alt.Chart(top_risk)
                    .mark_bar()
                    .encode(
                        x=alt.X("risk_score:Q", title="Risk Score"),
                        y=alt.Y("dst_ip:N", sort="-x", title="Destination IP"),
                        color=alt.Color(
                            "risk_level:N",
                            scale=alt.Scale(
                                domain=["HIGH", "MEDIUM", "LOW"],
                                range=["#FF4B4B", "#FFC857", "#4CAF50"],
                            ),
                            legend=alt.Legend(title="Risk Level"),
                        ),
                        tooltip=["src_ip", "dst_ip", "risk_score", "risk_level"],
                    )
                    .properties(title="Top High-Risk Destinations")
                )
                st.altair_chart(chart_risk, use_container_width=True)

        # Geo “map” – country distribution bar
        with c2:
            by_country = (
                ti_enriched.groupby("country")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            if not by_country.empty:
                chart_geo = (
                    alt.Chart(by_country)
                    .mark_bar()
                    .encode(
                        x=alt.X("country:N", title="Country"),
                        y=alt.Y("count:Q", title="Number of Suspicious Flows"),
                        color=alt.Color("country:N", legend=None),
                        tooltip=["country", "count"],
                    )
                    .properties(title="GeoIP Country Distribution (Demo)")
                )
                st.altair_chart(chart_geo, use_container_width=True)

# ------------------------------------------------------------------
# SUMMARY TAB
# ------------------------------------------------------------------
with tab_summary:
    st.subheader("📈 Executive Summary")

    if flows is None and fw_logs is None:
        st.info("Upload at least one file to see summary statistics.")
    else:
        col_a, col_b, col_c = st.columns(3)

        # Metrics from flows
        if flows is not None:
            kpis = compute_flow_kpis(flows)
            st.markdown("#### Network Overview")
            with col_a:
                st.metric("Total Flows", f"{kpis['total_flows']:,}")
            with col_b:
                st.metric("Unique Sources", f"{kpis['unique_sources']:,}")
            with col_c:
                st.metric("Unique Destinations", f"{kpis['unique_destinations']:,}")

            if suspicious is not None:
                st.metric(
                    "Suspicious Flows Detected",
                    f"{len(suspicious):,}",
                    delta=None,
                )

        if fw_logs is not None:
            st.markdown("#### Firewall Snapshot")
            fw_summary = summarize_firewall_actions(fw_logs)
            if not fw_summary.empty:
                allow = int(
                    fw_summary.loc[fw_summary["action"] == "ALLOW", "count"].sum()
                )
                block = int(
                    fw_summary.loc[fw_summary["action"] == "BLOCK", "count"].sum()
                )

                c1, c2 = st.columns(2)
                with c1:
                    st.metric("Allowed Connections", f"{allow:,}")
                with c2:
                    st.metric("Blocked Connections", f"{block:,}")

        if ti_enriched is not None and not ti_enriched.empty:
            st.markdown("#### Risk Distribution")
            risk_counts = (
                ti_enriched.groupby("risk_level")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            chart_levels = (
                alt.Chart(risk_counts)
                .mark_bar()
                .encode(
                    x=alt.X("risk_level:N", title="Risk Level"),
                    y=alt.Y("count:Q", title="Number of Flows"),
                    color=alt.Color(
                        "risk_level:N",
                        scale=alt.Scale(
                            domain=["HIGH", "MEDIUM", "LOW"],
                            range=["#FF4B4B", "#FFC857", "#4CAF50"],
                        ),
                        legend=None,
                    ),
                    tooltip=["risk_level", "count"],
                )
                .properties(title="Risk Level Breakdown")
            )
            st.altair_chart(chart_levels, use_container_width=True)

        st.markdown("---")
        st.markdown(
            "_FlowSleuth Hybrid Mode:_ combines quick heuristics, simple threat intel, "
            "and clean visuals so you can explain the story of the incident in minutes."
        )
