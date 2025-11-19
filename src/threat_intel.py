"""
threat_intel.py – toy threat intel + risk scoring + GeoIP mapping.
"""

import pandas as pd

from config import (
    THREAT_FEED,
    RISK_WEIGHTS,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    IP_TO_COUNTRY,
)


def enrich_with_threat_intel(df: pd.DataFrame) -> pd.DataFrame:
    """
    Left-join a tiny in-memory threat feed on dst_ip.
    Adds:
      - ti_match (bool)
      - ti_label (str)
      - ti_score (int)
    """
    ti_df = pd.DataFrame(THREAT_FEED)
    ti_df = ti_df[ti_df["type"] == "ip"][["indicator", "label", "threat_score"]]
    ti_df = ti_df.rename(columns={"indicator": "dst_ip"})

    merged = df.copy()
    merged = merged.merge(ti_df, on="dst_ip", how="left")

    merged["ti_match"] = merged["threat_score"].notna()
    merged["ti_label"] = merged["label"].fillna("No known threat intel hit")
    merged["ti_score"] = merged["threat_score"].fillna(0).astype(int)

    merged.drop(columns=["label", "threat_score"], inplace=True)
    return merged


def apply_risk_scoring(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute a simple risk_score (0–100) based on detection flags + TI.
    Requires the DataFrame to already have:
        - is_big_transfer
        - is_suspicious_port
        - is_risky_extension
        - ti_match
        - ti_score
    """
    df = df.copy()

    base = 0
    base += df["ti_match"].astype(int) * RISK_WEIGHTS["ti_match"]
    base += df["is_suspicious_port"].astype(int) * RISK_WEIGHTS["suspicious_port"]
    base += df["is_big_transfer"].astype(int) * RISK_WEIGHTS["big_transfer"]
    base += df["is_risky_extension"].astype(int) * RISK_WEIGHTS["risky_extension"]

    # Add a scaled portion of the TI score
    df["risk_score"] = (base + (df["ti_score"] / 2)).clip(upper=100).astype(int)

    def _level(score: int) -> str:
        if score >= HIGH_RISK_THRESHOLD:
            return "HIGH"
        if score >= MEDIUM_RISK_THRESHOLD:
            return "MEDIUM"
        return "LOW"

    df["risk_level"] = df["risk_score"].apply(_level)
    return df


def add_geoip_country(df: pd.DataFrame, ip_column: str = "dst_ip") -> pd.DataFrame:
    """
    Add a basic 'country' column using the tiny in-memory IP_TO_COUNTRY map.
    This is purely for demo charts – not real GeoIP accuracy.
    """
    df = df.copy()
    df["country"] = df[ip_column].map(IP_TO_COUNTRY).fillna("Unknown")
    return df
