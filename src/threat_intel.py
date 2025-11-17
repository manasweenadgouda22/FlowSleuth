import pandas as pd

def enrich_with_threat_intel(df: pd.DataFrame) -> pd.DataFrame:
    bad_ips = {"185.199.110.153": "Known C2 Server", "45.155.205.233": "Malware Host"}
    df["threat_label"] = df["dst_ip"].map(bad_ips).fillna("Unknown")
    return df
