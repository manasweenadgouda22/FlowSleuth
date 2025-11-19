def enrich_with_threat_intel(df):
    df["threat_label"] = df["dst_ip"].apply(
        lambda ip: "Known Malware Server" if str(ip).startswith("91.") else "Clean"
    )
    return df
