import pandas as pd
from config import (
    FLOW_REQUIRED_COLUMNS,
    HIGH_RISK_EXTENSIONS,
    SUSPICIOUS_PORTS,
    MIN_BYTES_FOR_DOWNLOAD,
    MIN_CONNECTIONS_FOR_BEACON,
)

def load_flows(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FLOW_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required flow columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def flag_suspicious_downloads(df: pd.DataFrame) -> pd.DataFrame:
    df["is_suspicious"] = (
        (df["bytes"] >= MIN_BYTES_FOR_DOWNLOAD) |
        (df["dst_port"].isin(SUSPICIOUS_PORTS))
    )
    return df


def detect_beaconing(df: pd.DataFrame) -> pd.DataFrame:
    freq = (
        df.groupby(["dst_ip"]).size()
        .reset_index(name="connection_count")
        .query("connection_count >= @MIN_CONNECTIONS_FOR_BEACON")
    )
    df = df.merge(freq, on="dst_ip", how="left")
    df["connection_count"] = df["connection_count"].fillna(0)
    df["is_beaconing"] = df["connection_count"] >= MIN_CONNECTIONS_FOR_BEACON
    return df


def summarize_suspicious(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["is_suspicious"] | df["is_beaconing"]]
