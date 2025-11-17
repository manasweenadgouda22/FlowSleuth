import pandas as pd
from config import FIREWALL_REQUIRED_COLUMNS

TIME_TOLERANCE_SEC = 60  # correlation time window

def load_firewall_logs(path: str) -> pd.DataFrame:
    """Load firewall logs, validate columns, normalize timestamp."""
    df = pd.read_csv(path)
    missing = [c for c in FIREWALL_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required firewall columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    return df


def correlate_with_flows(flows: pd.DataFrame, fw: pd.DataFrame) -> pd.DataFrame:
    """
    Correlate flow records with firewall events:
    - Joins on src_ip, dst_ip, dst_port
    - Connects closest FW timestamp within TIME_TOLERANCE_SEC
    - Scores severity based on firewall action
    """
    fw = fw.sort_values("timestamp")
    flows = flows.copy()
    flows["fw_action"] = None
    flows["fw_reason"] = None
    flows["fw_severity"] = 0

    for i, row in flows.iterrows():
        candidates = fw[
            (fw["src_ip"] == row["src_ip"]) &
            (fw["dst_ip"] == row["dst_ip"]) &
            (fw["dst_port"] == row["dst_port"])
        ]
        if candidates.empty:
            continue

        candidates["time_diff"] = (candidates["timestamp"] - row["timestamp"]).abs().dt.total_seconds()
        nearest = candidates.loc[candidates["time_diff"].idxmin()]

        if nearest["time_diff"] <= TIME_TOLERANCE_SEC:
            flows.at[i, "fw_action"] = nearest.get("action", "")
            flows.at[i, "fw_reason"] = nearest.get("reason", "")

            # Severity scoring
            if nearest.get("action") == "BLOCK":
                flows.at[i, "fw_severity"] = 3
            elif nearest.get("action") == "ALLOW":
                flows.at[i, "fw_severity"] = 1

    return flows
