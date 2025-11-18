import pandas as pd
from src.config import (
    FLOW_REQUIRED_COLUMNS,
    HIGH_RISK_EXTENSIONS,
    SUSPICIOUS_PORTS,
    MIN_BYTES_FOR_DOWNLOAD,
    MIN_CONNECTIONS_FOR_BEACON
)


def load_flows(file):
    """
    Load network flow data from CSV or Excel and validate required columns.
    File can be a Streamlit UploadedFile object.
    """
    fname = file.name.lower()

    # Accept CSV or Excel
    if fname.endswith(".csv"):
        df = pd.read_csv(file)
    elif fname.endswith(".xlsx") or fname.endswith(".xls"):
        df = pd.read_excel(file)
    else:
        raise ValueError("Unsupported file format. Upload CSV or Excel (.xlsx)")

    # Validate required columns
    missing = [c for c in FLOW_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing flow columns: {missing}")

    # Ensure timestamp becomes datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Normalize file_type column if exists
    if "file_type" in df.columns:
        df["file_type"] = df["file_type"].astype(str).str.lower().str.strip()

    return df


def flag_suspicious_downloads(df):
    """Mark possible suspicious downloads based on file type, size and ports."""
    df["is_big_transfer"] = df["bytes"] >= MIN_BYTES_FOR_DOWNLOAD
    df["is_suspicious_port"] = df["dst_port"].isin(SUSPICIOUS_PORTS)

    if "file_type" in df.columns:
        df["is_high_risk_ext"] = df["file_type"].isin(HIGH_RISK_EXTENSIONS)
    else:
        df["is_high_risk_ext"] = False

    return df


def detect_beaconing(df):
    """Detect repeated (src_ip → dst_ip) connections suggesting beaconing."""
    counts = df.groupby(["src_ip", "dst_ip"]).size().reset_index(name="count")
    return counts[counts["count"] >= MIN_CONNECTIONS_FOR_BEACON]


def summarize_suspicious(df):
    """Return only rows matching any suspicious criteria."""
    suspicious_mask = (
        df["is_big_transfer"] |
        df["is_suspicious_port"] |
        df["is_high_risk_ext"]
    )
    return df[suspicious_mask]
