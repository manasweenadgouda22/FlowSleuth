import pandas as pd
from config import (
    FLOW_REQUIRED_COLUMNS,
    HIGH_RISK_EXTENSIONS,
    SUSPICIOUS_PORTS,
    MIN_BYTES_FOR_DOWNLOAD,
    MIN_CONNECTIONS_FOR_BEACON
)

def load_flows(path):
    df = pd.read_csv(path)
    missing = [c for c in FLOW_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing flow columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def flag_suspicious_downloads(df):
    df["is_big_transfer"] = df["bytes"] >= MIN_BYTES_FOR_DOWNLOAD
    df["is_suspicious_port"] = df["dst_port"].astype(int).isin(SUSPICIOUS_PORTS)
    df["is_high_risk_file"] = df["file_type"].astype(str).isin(HIGH_RISK_EXTENSIONS)
    return df

def detect_beaconing(df):
    counts = df.groupby(["src_ip", "dst_ip"]).size().reset_index(name="count")
    return counts[counts["count"] >= MIN_CONNECTIONS_FOR_BEACON]

def summarize_suspicious(df):
    return df[
        df["is_big_transfer"] |
        df["is_suspicious_port"] |
        df["is_high_risk_file"]
    ]
