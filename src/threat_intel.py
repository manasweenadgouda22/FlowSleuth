import pandas as pd

def enrich_with_threat_intel(df):
    if df.empty:
        return df

    df = df.copy()
    df["threat_label"] = df["dst_ip"].apply(
        lambda ip: "KNOWN BOTNET" if ip.startswith("45.") else "UNKNOWN"
    )
    return df
