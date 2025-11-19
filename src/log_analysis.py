"""
log_analysis.py – helpers for analysing firewall logs.
"""

import pandas as pd

from config import FIREWALL_REQUIRED_COLUMNS


def _read_csv_or_excel(path_or_buffer):
    name = getattr(path_or_buffer, "name", str(path_or_buffer))
    if name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path_or_buffer)
    return pd.read_csv(path_or_buffer)


def load_firewall_logs(path_or_buffer: object) -> pd.DataFrame:
    """
    Load firewall logs and normalise basic fields.
    """
    df = _read_csv_or_excel(path_or_buffer)

    missing = [c for c in FIREWALL_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing firewall columns: {missing}")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
    df["action"] = df["action"].astype(str).str.upper().str.strip()
    df["rule_name"] = df["rule_name"].fillna("").astype(str).str.strip()

    # Fill “None” rule names with something friendly based on action/port
    mask_empty = df["rule_name"].eq("") | df["rule_name"].str.lower().eq("none")
    web_traffic = (df["dst_port"].isin([80, 443])) & df["action"].eq("ALLOW") & mask_empty
    df.loc[web_traffic, "rule_name"] = "Web Access Policy"

    dns_block = (df["dst_port"] == 53) & df["action"].eq("BLOCK") & mask_empty
    df.loc[dns_block, "rule_name"] = "DNS Block Policy"

    rdp_smb_block = (
        df["dst_port"].isin([3389, 445])
        & df["action"].eq("BLOCK")
        & mask_empty
    )
    df.loc[rdp_smb_block, "rule_name"] = "Remote Access Protection"

    df.loc[mask_empty & df["rule_name"].eq(""), "rule_name"] = "Default Firewall Policy"

    return df


def summarize_firewall_actions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Simple count of ALLOW vs BLOCK.
    """
    summary = (
        df.groupby("action")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    return summary


def top_blocked_destinations(df: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    """
    Top blocked destination IPs.
    """
    blocked = df[df["action"] == "BLOCK"]
    top = (
        blocked.groupby("dst_ip")
        .size()
        .reset_index(name="block_count")
        .sort_values("block_count", ascending=False)
        .head(limit)
    )
    return top
