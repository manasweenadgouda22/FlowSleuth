"""
pcap_analysis.py – helpers for analysing flow-style network data.
"""

import pandas as pd

from config import (
    FLOW_REQUIRED_COLUMNS,
    HIGH_RISK_EXTENSIONS,
    SUSPICIOUS_PORTS,
    MIN_BYTES_FOR_DOWNLOAD,
    MIN_CONNECTIONS_FOR_BEACON,
)


def _read_csv_or_excel(path_or_buffer):
    """Support both CSV and Excel for uploads."""
    name = getattr(path_or_buffer, "name", str(path_or_buffer))
    if name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path_or_buffer)
    return pd.read_csv(path_or_buffer)


def load_flows(path_or_buffer: object) -> pd.DataFrame:
    """
    Load network flows and validate required columns.
    Accepts a file path or an uploaded file-like object.
    """
    df = _read_csv_or_excel(path_or_buffer)

    missing = [c for c in FLOW_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing flow columns: {missing}")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)
    df["file_type"] = df["file_type"].astype(str).str.strip().str.lower()

    return df


def flag_suspicious_downloads(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add boolean flags for big transfers, suspicious ports, and risky file types.
    """
    df = df.copy()
    df["is_big_transfer"] = df["bytes"] >= MIN_BYTES_FOR_DOWNLOAD
    df["is_suspicious_port"] = df["dst_port"].isin(SUSPICIOUS_PORTS)
    df["is_risky_extension"] = df["file_type"].isin(HIGH_RISK_EXTENSIONS)
    return df


def detect_beaconing(df: pd.DataFrame) -> pd.DataFrame:
    """
    Very simple beacon-like detection: count how many times each src_ip talks
    to a dst_ip and flag those with many repeated connections.
    """
    grouped = (
        df.groupby(["src_ip", "dst_ip"])
        .size()
        .reset_index(name="connection_count")
        .sort_values("connection_count", ascending=False)
    )
    return grouped[grouped["connection_count"] >= MIN_CONNECTIONS_FOR_BEACON]


def summarize_suspicious(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return only rows which look suspicious based on simple flags.
    """
    mask = df["is_big_transfer"] | df["is_suspicious_port"] | df["is_risky_extension"]
    suspicious = df[mask].copy()
    suspicious.sort_values("bytes", ascending=False, inplace=True)
    return suspicious


def compute_flow_kpis(df: pd.DataFrame) -> dict:
    """
    High-level metrics for the summary tab.
    """
    return {
        "total_flows": len(df),
        "unique_sources": df["src_ip"].nunique(),
        "unique_destinations": df["dst_ip"].nunique(),
        "total_bytes": int(df["bytes"].sum()),
    }
