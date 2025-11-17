import pandas as pd
from src.config import FIREWALL_REQUIRED_COLUMNS

def load_firewall_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FIREWALL_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required firewall columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df
