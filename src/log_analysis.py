import pandas as pd
from .config import FIREWALL_REQUIRED_COLUMNS

def load_firewall_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FIREWALL_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required firewall columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def correlate_with_flows(flows: pd.DataFrame, fw: pd.DataFrame) -> pd.DataFrame:
    """Correlate flow records with firewall actions based on IP/port/timestamp (coarse join).

    This is intentionally simple for teaching/demo:
    - Join on src_ip, dst_ip, dst_port.
    - Keep nearest firewall entry in time.
    """
    fw_sorted = fw.sort_values("timestamp")
    merged = flows.merge(
        fw_sorted,
        on=["src_ip", "dst_ip", "dst_port"],
        suffixes=("_flow", "_fw"),
        how="left"
    )
    return merged
