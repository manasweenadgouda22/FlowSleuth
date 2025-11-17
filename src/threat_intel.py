import pandas as pd

def enrich_with_dummy_threat_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Placeholder threat-intel enrichment.

    In a full project you would:
    - Call VirusTotal / AbuseIPDB / OTX APIs.
    - Cache results to avoid repeated calls.
    - Normalize scores to a 0-100 scale.
    Here, we just generate fake scores based on simple patterns for demonstration.
    """
    df = df.copy()
    # Very naive: higher octets or private vs public decides a pseudo-score.
    def fake_score(ip: str) -> int:
        try:
            first_octet = int(ip.split(".")[0])
        except Exception:
            return 30
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            return 20  # internal; usually less risky as destination
        if first_octet >= 200:
            return 85
        if first_octet >= 150:
            return 65
        return 40

    df["threat_score"] = df["dst_ip"].astype(str).apply(fake_score)
    df["threat_level"] = pd.cut(
        df["threat_score"],
        bins=[0, 40, 70, 100],
        labels=["Low", "Medium", "High"],
        include_lowest=True
    )
    return df
