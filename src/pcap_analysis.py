import pandas as pd
from .config import FLOW_REQUIRED_COLUMNS, HIGH_RISK_EXTENSIONS, SUSPICIOUS_PORTS, MIN_BYTES_FOR_DOWNLOAD, MIN_CONNECTIONS_FOR_BEACON

def load_flows(path: str) -> pd.DataFrame:
    """Load flow/PCAP metadata from CSV and ensure required columns exist."""
    df = pd.read_csv(path)
    missing = [c for c in FLOW_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required flow columns: {missing}")
    # Normalize timestamp to pandas datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def flag_suspicious_downloads(df: pd.DataFrame) -> pd.DataFrame:
    """Flag flows that look like potential file downloads based on size and destination port.

    Heuristics:
    - Bytes transferred larger than MIN_BYTES_FOR_DOWNLOAD.
    - Protocol is TCP and port in {80, 443, or SUSPICIOUS_PORTS}.
    """
    df = df.copy()
    suspicious_ports = set([80, 443] + SUSPICIOUS_PORTS)
    df["is_large_transfer"] = df["bytes"] >= MIN_BYTES_FOR_DOWNLOAD
    df["is_suspicious_port"] = df["dst_port"].astype(int).isin(suspicious_ports)
    df["suspicious_download"] = df["is_large_transfer"] & df["is_suspicious_port"]
    return df

def detect_beaconing(df: pd.DataFrame, window="5min") -> pd.DataFrame:
    """Detect simple beacon-style behaviour: many connections from a single src to same dst within a short window."""
    df = df.copy()
    df = df.sort_values("timestamp")
    grouped = df.set_index("timestamp").groupby(["src_ip", "dst_ip"]).rolling(window=window).size().reset_index(name="conn_count_window")
    df = df.merge(grouped, on=["timestamp", "src_ip", "dst_ip"], how="left")
    df["beacon_suspect"] = df["conn_count_window"].fillna(0) >= MIN_CONNECTIONS_FOR_BEACON
    return df

def summarize_suspicious(df: pd.DataFrame) -> pd.DataFrame:
    """Return only rows that look suspicious for display in the dashboard."""
    mask = df["suspicious_download"] | df.get("beacon_suspect", False)
    suspicious_df = df[mask].copy()
    return suspicious_df
